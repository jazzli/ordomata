"""Independent read-only inspection of repository-proposal evidence.

The inspector proves only the caller-named run.  It opens an existing SQLite
database without :class:`SQLiteStateStore`, holds one read transaction across
the durable run and its event history, and independently replays the strict
three-event proposal lineage.  It never repairs state, revalidates a live
repository, grants authority, or enables dispatch.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from typing import Any, Iterator

from .authorization import canonical_digest, canonical_json
from .errors import ConfigurationError, ValidationError
from .state import (
    RecordNotFoundError,
    _BASELINE_TABLE_NAMES,
    _expected_baseline_schema,
)


REPOSITORY_PROPOSAL_INSPECTION_SCHEMA_VERSION = 1
REPOSITORY_PROPOSAL_INSPECTION_KIND = "repository_proposal_inspection"

_RUNNER_ID = "repository-proposal-disabled"
_SELECTION_EVENT_TYPE = "repository_registration_selection"
_BINDING_EVENT_TYPE = "repository_proposal_attempt_binding"
_SELECTION_KIND = "repository_registration_selection"
_BINDING_KIND = "repository_proposal_attempt"
_REGISTRATION_EVIDENCE_KIND = "repository_registration_validation"
_STATUS_EVENT_TYPE = "status"
_CREATED_STATUS = "created"

_COVERAGE_VALUES = frozenset({"complete", "incomplete", "invalid"})
_MAX_RUN_CHARACTERS = 4096
_MAX_RUN_BYTES = 16_384
_MAX_EVENT_IDENTIFIER_CHARACTERS = 4096
_MAX_EVENT_IDENTIFIER_BYTES = 16_384
_MAX_SCHEMA_TEXT_BYTES = 65_536
_MAX_PAYLOAD_BYTES = 131_072
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 10_000
_MAX_INSPECTED_EVENT_COUNT = 4
_MAX_FINDINGS = 24
_MAX_STAGED_SNAPSHOT_BYTES = 512 * 1024 * 1024
_SNAPSHOT_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_INT64 = (2**63) - 1

_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\Z"
)

_SELECTION_PAYLOAD_KEYS = frozenset(
    {"schema_version", "selection", "selection_digest"}
)
_SELECTION_KEYS = frozenset(
    {
        "kind",
        "proposal_digest",
        "run_ref",
        "selection_mode",
        "selected_registration",
        "selected_registration_evidence_digest",
    }
)
_REGISTRATION_EVIDENCE_KEYS = frozenset(
    {
        "authority_granted",
        "dispatch_enabled",
        "filesystem_identity_ref",
        "isolation_requirements_digest",
        "kind",
        "path_policy_digest",
        "registration_digest",
        "registration_ref",
        "registration_version",
        "repository_ref",
        "resource_limits_digest",
        "review_policy_digest",
        "schema_version",
        "validation_mode",
        "verification_commands_digest",
    }
)
_BINDING_PAYLOAD_KEYS = frozenset(
    {"schema_version", "binding", "binding_digest"}
)
_BINDING_KEYS = frozenset(
    {
        "attempt",
        "authority_granted",
        "context_digest",
        "created_at_ref",
        "dispatch_enabled",
        "filesystem_identity_ref",
        "isolation_requirements_digest",
        "kind",
        "path_policy_digest",
        "permission_class",
        "proposal_digest",
        "proposal_ref",
        "proposal_version_ref",
        "registration_digest",
        "registration_evidence_digest",
        "registration_ref",
        "registration_selection_digest",
        "registration_version",
        "repository_ref",
        "resource_limits_digest",
        "review_policy_digest",
        "run_directory_ref",
        "run_ref",
        "runner_ref",
        "timeout_seconds",
        "validation_mode",
        "verification_commands_digest",
        "workspace_ref",
    }
)
_REGISTRATION_LINK_FIELDS = (
    "filesystem_identity_ref",
    "isolation_requirements_digest",
    "path_policy_digest",
    "registration_digest",
    "registration_ref",
    "registration_version",
    "repository_ref",
    "resource_limits_digest",
    "review_policy_digest",
    "verification_commands_digest",
)
_BINDING_DIGEST_FIELDS = _BINDING_KEYS - {
    "attempt",
    "authority_granted",
    "dispatch_enabled",
    "kind",
    "permission_class",
    "registration_version",
    "timeout_seconds",
    "validation_mode",
}
_REGISTRATION_DIGEST_FIELDS = _REGISTRATION_EVIDENCE_KEYS - {
    "authority_granted",
    "dispatch_enabled",
    "kind",
    "registration_version",
    "schema_version",
    "validation_mode",
}

_FINDING_ORDER = (
    "run_record_invalid",
    "runner_invalid",
    "permission_class_invalid",
    "history_cardinality_invalid",
    "created_event_invalid",
    "run_status_invalid",
    "unexpected_event",
    "event_limit_exceeded",
    "registration_selection_missing",
    "registration_selection_duplicate",
    "registration_selection_status_invalid",
    "registration_selection_payload_invalid",
    "registration_selection_event_identifier_mismatch",
    "repository_proposal_binding_missing",
    "repository_proposal_binding_duplicate",
    "repository_proposal_binding_status_invalid",
    "repository_proposal_binding_payload_invalid",
    "repository_proposal_binding_event_identifier_mismatch",
    "proposal_event_order_invalid",
    "durable_run_linkage_mismatch",
    "proposal_linkage_mismatch",
    "registration_component_linkage_mismatch",
    "disabled_semantics_mismatch",
)
_FINDING_CODES = frozenset(_FINDING_ORDER)
_FINDING_RANK = {code: index for index, code in enumerate(_FINDING_ORDER)}

_NOT_FOUND_MESSAGE = "requested repository proposal run was not found"
_INVALID_REQUEST_MESSAGE = "repository proposal inspection request is invalid"
_INVALID_DATABASE_MESSAGE = (
    "repository proposal inspection database is unreadable or malformed"
)
_CHANGED_DATABASE_MESSAGE = (
    "repository proposal inspection database changed during inspection"
)


@dataclass(frozen=True, slots=True)
class RepositoryProposalInspectionFinding:
    """One fixed, value-free repository-proposal inspection finding."""

    code: str

    def __post_init__(self) -> None:
        if self.code not in _FINDING_CODES:
            raise ValidationError(_INVALID_REQUEST_MESSAGE)

    def to_mapping(self) -> dict[str, str]:
        return {"code": self.code}


@dataclass(frozen=True, slots=True)
class RepositoryProposalInspectionReport:
    """Bounded proof for one caller-selected repository-proposal run."""

    run_ref: str
    coverage: str
    truncated: bool
    inspected_event_count: int
    permission_class: int | None
    current_status: str | None
    proposal_digest: str | None
    proposal_ref: str | None
    proposal_version_ref: str | None
    registration_digest: str | None
    registration_ref: str | None
    registration_version: str | None
    repository_ref: str | None
    registration_selection_digest: str | None
    repository_proposal_binding_digest: str | None
    selection_sequence: int | None
    binding_sequence: int | None
    findings: tuple[RepositoryProposalInspectionFinding, ...]

    def __post_init__(self) -> None:
        if (
            not _is_digest(self.run_ref)
            or self.coverage not in _COVERAGE_VALUES
            or type(self.truncated) is not bool
            or type(self.inspected_event_count) is not int
            or not 0
            <= self.inspected_event_count
            <= _MAX_INSPECTED_EVENT_COUNT
            or (
                self.permission_class is not None
                and (
                    type(self.permission_class) is not int
                    or self.permission_class not in (0, 1)
                )
            )
            or self.current_status not in (None, _CREATED_STATUS)
            or type(self.findings) is not tuple
            or len(self.findings) > _MAX_FINDINGS
            or any(
                type(finding) is not RepositoryProposalInspectionFinding
                for finding in self.findings
            )
        ):
            raise ValidationError(_INVALID_REQUEST_MESSAGE)
        digest_fields = (
            self.proposal_digest,
            self.proposal_ref,
            self.proposal_version_ref,
            self.registration_digest,
            self.registration_ref,
            self.repository_ref,
            self.registration_selection_digest,
            self.repository_proposal_binding_digest,
        )
        if any(value is not None and not _is_digest(value) for value in digest_fields):
            raise ValidationError(_INVALID_REQUEST_MESSAGE)
        if self.registration_version is not None and (
            type(self.registration_version) is not str
            or _VERSION_PATTERN.fullmatch(self.registration_version) is None
        ):
            raise ValidationError(_INVALID_REQUEST_MESSAGE)
        for sequence in (self.selection_sequence, self.binding_sequence):
            if sequence is not None and (
                type(sequence) is not int or not 0 < sequence <= _MAX_INT64
            ):
                raise ValidationError(_INVALID_REQUEST_MESSAGE)
        finding_codes = tuple(finding.code for finding in self.findings)
        if (
            len(set(finding_codes)) != len(finding_codes)
            or finding_codes
            != tuple(sorted(finding_codes, key=_FINDING_RANK.__getitem__))
        ):
            raise ValidationError(_INVALID_REQUEST_MESSAGE)
        selection_fields = (
            self.proposal_digest,
            self.registration_digest,
            self.registration_ref,
            self.registration_version,
            self.repository_ref,
            self.registration_selection_digest,
            self.selection_sequence,
        )
        binding_fields = (
            self.proposal_ref,
            self.proposal_version_ref,
            self.repository_proposal_binding_digest,
            self.binding_sequence,
        )
        if self.coverage == "complete":
            valid_variant = (
                not self.truncated
                and self.inspected_event_count == 3
                and self.permission_class in (0, 1)
                and self.current_status == _CREATED_STATUS
                and all(value is not None for value in selection_fields)
                and all(value is not None for value in binding_fields)
                and self.selection_sequence < self.binding_sequence
                and not self.findings
            )
        elif self.coverage == "incomplete":
            created_only = (
                self.inspected_event_count == 1
                and all(value is None for value in selection_fields)
                and all(value is None for value in binding_fields)
                and finding_codes
                == (
                    "registration_selection_missing",
                    "repository_proposal_binding_missing",
                )
            )
            selection_only = (
                self.inspected_event_count == 2
                and all(value is not None for value in selection_fields)
                and all(value is None for value in binding_fields)
                and finding_codes
                == ("repository_proposal_binding_missing",)
            )
            valid_variant = (
                not self.truncated
                and self.permission_class in (0, 1)
                and self.current_status == _CREATED_STATUS
                and (created_only or selection_only)
            )
        else:
            valid_variant = (
                bool(self.findings)
                and all(value is None for value in selection_fields)
                and all(value is None for value in binding_fields)
                and (
                    not self.truncated
                    or "event_limit_exceeded" in finding_codes
                )
            )
        if not valid_variant:
            raise ValidationError(_INVALID_REQUEST_MESSAGE)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def evidence_complete(self) -> bool:
        return self.coverage == "complete"

    @property
    def clean(self) -> bool:
        return (
            self.evidence_complete
            and not self.truncated
            and not self.findings
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": REPOSITORY_PROPOSAL_INSPECTION_SCHEMA_VERSION,
            "kind": REPOSITORY_PROPOSAL_INSPECTION_KIND,
            "inspection_scope": "single_run",
            "inspection_mode": "read_only",
            "validation_mode": "read_only",
            "repair_performed": False,
            "dispatch_enabled": False,
            "authority_granted": False,
            "run_ref": self.run_ref,
            "coverage": self.coverage,
            "truncated": self.truncated,
            "clean": self.clean,
            "evidence_complete": self.evidence_complete,
            "inspected_event_count": self.inspected_event_count,
            "permission_class": self.permission_class,
            "current_status": self.current_status,
            "proposal_digest": self.proposal_digest,
            "proposal_ref": self.proposal_ref,
            "proposal_version_ref": self.proposal_version_ref,
            "registration_digest": self.registration_digest,
            "registration_ref": self.registration_ref,
            "registration_version": self.registration_version,
            "repository_ref": self.repository_ref,
            "registration_selection_digest": (
                self.registration_selection_digest
            ),
            "repository_proposal_binding_digest": (
                self.repository_proposal_binding_digest
            ),
            "selection_sequence": self.selection_sequence,
            "binding_sequence": self.binding_sequence,
            "finding_count": self.finding_count,
            "findings": [finding.to_mapping() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class _RunFacts:
    run_id_valid: bool
    task_id: str | None
    task_version: str | None
    runner_id: str | None
    workspace: str | None
    run_directory: str | None
    context_digest: str | None
    permission_class: int | None
    timeout_seconds: int | None
    attempt: int | None
    created_at: int | float | None

    @property
    def scalar_valid(self) -> bool:
        return (
            self.run_id_valid
            and self.task_id is not None
            and self.task_version is not None
            and self.runner_id is not None
            and self.workspace is not None
            and self.run_directory is not None
            and self.context_digest is not None
            and self.permission_class in (0, 1)
            and self.timeout_seconds is not None
            and self.attempt is not None
            and self.created_at is not None
        )


@dataclass(frozen=True, slots=True)
class _EventCounts:
    total: int
    status_events: int
    status_values: int
    selections: int
    bindings: int
    unexpected: int
    first_sequence: int | None


@dataclass(frozen=True, slots=True)
class _EventFacts:
    sequence: int | None
    event_type: str | None
    event_id: str | None
    status: str | None
    payload_json: str | None
    occurred_at: int | float | None

    @property
    def metadata_valid(self) -> bool:
        return self.sequence is not None and self.occurred_at is not None


@dataclass(frozen=True, slots=True)
class _SelectionFacts:
    selection: dict[str, Any]
    selected_registration: dict[str, Any]
    selection_digest: str
    fixed_semantics_valid: bool


@dataclass(frozen=True, slots=True)
class _BindingFacts:
    binding: dict[str, Any]
    binding_digest: str
    fixed_semantics_valid: bool


def inspect_repository_proposal_evidence(
    database_path: str | os.PathLike[str],
    *,
    run_id: str,
) -> RepositoryProposalInspectionReport:
    """Inspect one durable repository-proposal lineage without effects.

    ``clean`` is scoped only to ``run_id``.  A clean result is integrity
    evidence, not an authorization decision or permission to execute.
    """

    requested_run_id = _validate_run_id(run_id)
    run_ref = canonical_digest({"run_id": requested_run_id})
    database = _database_path(database_path)
    try:
        with _read_only_database_uri(database) as uri:
            return _inspect_snapshot(
                uri,
                run_id=requested_run_id,
                run_ref=run_ref,
            )
    except (RecordNotFoundError, ValidationError):
        raise
    except ConfigurationError as error:
        if str(error) == _CHANGED_DATABASE_MESSAGE:
            raise
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE) from None
    except (
        OSError,
        OverflowError,
        RecursionError,
        sqlite3.Error,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE) from None


def _validate_run_id(value: Any) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > _MAX_RUN_CHARACTERS
        or "\x00" in value
        or any(
            ord(character) < 32 and character not in "\t\n\r"
            for character in value
        )
    ):
        raise ValidationError(_INVALID_REQUEST_MESSAGE)
    try:
        if len(value.encode("utf-8")) > _MAX_RUN_BYTES:
            raise ValidationError(_INVALID_REQUEST_MESSAGE)
    except UnicodeError:
        raise ValidationError(_INVALID_REQUEST_MESSAGE) from None
    return value


def _database_path(value: Any) -> Path:
    try:
        if not isinstance(value, (str, os.PathLike)):
            raise TypeError
        return Path(value).absolute()
    except (OSError, TypeError, ValueError):
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE) from None


def _inspect_snapshot(
    uri: str,
    *,
    run_id: str,
    run_ref: str,
) -> RepositoryProposalInspectionReport:
    connection: sqlite3.Connection | None = None
    failure: BaseException | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        query_only = connection.execute("PRAGMA query_only").fetchone()
        if query_only is None or query_only[0] != 1:
            raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("BEGIN")
        database_encoding = _database_text_encoding(connection)
        _require_baseline_schema(
            connection,
            database_encoding=database_encoding,
        )
        run = _read_run(
            connection,
            run_id=run_id,
            database_encoding=database_encoding,
        )
        events, truncated = _read_event_window(
            connection,
            run_id=run_id,
            database_encoding=database_encoding,
        )
        if truncated:
            return _build_truncated_report(run_ref=run_ref, run=run)
        counts = _event_counts(events)
        status_event = _unique_event(events, _STATUS_EVENT_TYPE)
        selection_event = _unique_event(events, _SELECTION_EVENT_TYPE)
        binding_event = _unique_event(events, _BINDING_EVENT_TYPE)
        return _build_report(
            run_id=run_id,
            run_ref=run_ref,
            run=run,
            counts=counts,
            status_event=status_event,
            selection_event=selection_event,
            binding_event=binding_event,
        )
    except BaseException as error:
        failure = error
        raise
    finally:
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.rollback()
            except sqlite3.Error:
                if failure is None:
                    raise ConfigurationError(_INVALID_DATABASE_MESSAGE) from None
            finally:
                try:
                    connection.close()
                except sqlite3.Error:
                    if failure is None:
                        raise ConfigurationError(
                            _INVALID_DATABASE_MESSAGE
                        ) from None


def _database_text_encoding(connection: sqlite3.Connection) -> str:
    row = connection.execute("PRAGMA encoding").fetchone()
    if row is None or type(row[0]) is not str:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
    encoding = {
        "UTF-8": "utf-8",
        "UTF-16le": "utf-16-le",
        "UTF-16be": "utf-16-be",
    }.get(row[0])
    if encoding is None:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
    return encoding


def _require_baseline_schema(
    connection: sqlite3.Connection,
    *,
    database_encoding: str,
) -> None:
    expected = _expected_baseline_schema()
    expected_names = tuple(sorted({key[1] for key in expected}))
    baseline_tables = tuple(sorted(_BASELINE_TABLE_NAMES))
    placeholders = ",".join("?" for _ in expected_names)
    table_placeholders = ",".join("?" for _ in baseline_tables)
    rows = connection.execute(
        f"""
        SELECT
            rowid AS schema_rowid,
            CASE type
                WHEN 'table' THEN 'table'
                WHEN 'index' THEN 'index'
                WHEN 'trigger' THEN 'trigger'
                WHEN 'view' THEN 'view'
                ELSE NULL
            END AS object_type,
            typeof(name) AS name_storage_type,
            typeof(tbl_name) AS table_storage_type,
            typeof(sql) AS sql_storage_type
        FROM sqlite_master
        WHERE sql IS NOT NULL
          AND type IN ('table', 'index', 'trigger', 'view')
          AND (
              name IN ({placeholders})
              OR tbl_name IN ({table_placeholders})
          )
        ORDER BY type, name
        LIMIT ?
        """,
        (*expected_names, *baseline_tables, len(expected) + 1),
    ).fetchall()
    actual: dict[tuple[str, str], tuple[str, str, str]] = {}
    for row in rows:
        row_id = row["schema_rowid"]
        object_type = row["object_type"]
        if type(row_id) is not int or type(object_type) is not str:
            raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
        name = _read_bounded_text_column(
            connection,
            table="sqlite_master",
            column="name",
            row_id=row_id,
            storage_type=row["name_storage_type"],
            characters=256,
            bytes_=256,
            database_encoding=database_encoding,
        )
        table_name = _read_bounded_text_column(
            connection,
            table="sqlite_master",
            column="tbl_name",
            row_id=row_id,
            storage_type=row["table_storage_type"],
            characters=256,
            bytes_=256,
            database_encoding=database_encoding,
        )
        sql = _read_bounded_text_column(
            connection,
            table="sqlite_master",
            column="sql",
            row_id=row_id,
            storage_type=row["sql_storage_type"],
            characters=_MAX_SCHEMA_TEXT_BYTES,
            bytes_=_MAX_SCHEMA_TEXT_BYTES,
            database_encoding=database_encoding,
        )
        if name is None or table_name is None or sql is None:
            raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
        actual[(object_type, name)] = (
            object_type,
            table_name,
            " ".join(sql.split()),
        )
    if actual != expected:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)


def _read_bounded_text_column(
    connection: sqlite3.Connection,
    *,
    table: str,
    column: str,
    row_id: int,
    storage_type: Any,
    characters: int,
    bytes_: int,
    database_encoding: str,
) -> str | None:
    if storage_type != "text":
        return None
    blob: sqlite3.Blob | None = None
    try:
        blob = connection.blobopen(table, column, row_id, readonly=True)
        blob_size = len(blob)
        native_byte_limit = bytes_ * (2 if database_encoding != "utf-8" else 1)
        if blob_size > native_byte_limit:
            return None
        raw = blob.read()
    except (OverflowError, sqlite3.Error, TypeError, ValueError):
        return None
    finally:
        if blob is not None:
            blob.close()
    if type(raw) is not bytes or len(raw) != blob_size:
        return None
    try:
        value = raw.decode(database_encoding)
    except UnicodeError:
        return None
    try:
        utf8_size = len(value.encode("utf-8"))
    except UnicodeError:
        return None
    return value if len(value) <= characters and utf8_size <= bytes_ else None


def _read_run(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    database_encoding: str,
) -> _RunFacts:
    row = connection.execute(
        """
        SELECT
            rowid AS run_rowid,
            typeof(run_id) AS run_id_storage_type,
            typeof(task_id) AS task_id_storage_type,
            typeof(task_version) AS task_version_storage_type,
            typeof(runner_id) AS runner_id_storage_type,
            typeof(workspace) AS workspace_storage_type,
            typeof(run_directory) AS run_directory_storage_type,
            typeof(context_digest) AS context_digest_storage_type,
            CASE WHEN typeof(permission_class) = 'integer'
                 THEN permission_class ELSE NULL END AS permission_class,
            CASE WHEN typeof(timeout_seconds) = 'integer'
                 THEN timeout_seconds ELSE NULL END AS timeout_seconds,
            CASE WHEN typeof(attempt) = 'integer'
                 THEN attempt ELSE NULL END AS attempt,
            CASE WHEN typeof(created_at) IN ('integer', 'real')
                 THEN created_at ELSE NULL END AS created_at
        FROM runs WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise RecordNotFoundError(_NOT_FOUND_MESSAGE)
    row_id = row["run_rowid"]
    if type(row_id) is not int:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)

    def text(
        column: str,
        *,
        characters: int = _MAX_RUN_CHARACTERS,
        bytes_: int = _MAX_RUN_BYTES,
    ) -> str | None:
        return _read_bounded_text_column(
            connection,
            table="runs",
            column=column,
            row_id=row_id,
            storage_type=row[f"{column}_storage_type"],
            characters=characters,
            bytes_=bytes_,
            database_encoding=database_encoding,
        )

    persisted_run_id = text("run_id")
    task_id = text("task_id")
    task_version = text("task_version")
    runner_id = text("runner_id")
    workspace = text("workspace")
    run_directory = text("run_directory")
    context_digest = _normalise_digest(
        text("context_digest", characters=71, bytes_=71)
    )
    permission_class = row["permission_class"]
    if type(permission_class) is not int or permission_class not in (0, 1):
        permission_class = None
    timeout_seconds = row["timeout_seconds"]
    if (
        type(timeout_seconds) is not int
        or not 0 < timeout_seconds <= _MAX_INT64
    ):
        timeout_seconds = None
    attempt = row["attempt"]
    if type(attempt) is not int or not 0 < attempt <= _MAX_INT64:
        attempt = None
    created_at = row["created_at"]
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, (int, float))
        or not math.isfinite(float(created_at))
        or created_at < 0
    ):
        created_at = None
    return _RunFacts(
        run_id_valid=persisted_run_id == run_id,
        task_id=_valid_run_text(task_id),
        task_version=_valid_run_text(task_version),
        runner_id=_valid_run_text(runner_id),
        workspace=_valid_run_text(workspace),
        run_directory=_valid_run_text(run_directory),
        context_digest=context_digest,
        permission_class=permission_class,
        timeout_seconds=timeout_seconds,
        attempt=attempt,
        created_at=created_at,
    )


def _valid_run_text(value: Any) -> str | None:
    if type(value) is not str or not value.strip() or "\x00" in value:
        return None
    if any(
        ord(character) < 32 and character not in "\t\n\r"
        for character in value
    ):
        return None
    return value


def _read_event_window(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    database_encoding: str,
) -> tuple[tuple[_EventFacts, ...], bool]:
    rows = connection.execute(
        """
        SELECT sequence
        FROM run_events INDEXED BY run_events_run_sequence
        WHERE run_id = ?
        ORDER BY sequence
        LIMIT ?
        """,
        (run_id, _MAX_INSPECTED_EVENT_COUNT + 1),
    ).fetchall()
    sequences = tuple(row["sequence"] for row in rows)
    if any(
        type(sequence) is not int or not 0 < sequence <= _MAX_INT64
        for sequence in sequences
    ):
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
    if len(sequences) > _MAX_INSPECTED_EVENT_COUNT:
        return (), True
    return (
        tuple(
            _read_event_at_sequence(
                connection,
                run_id=run_id,
                sequence=sequence,
                database_encoding=database_encoding,
            )
            for sequence in sequences
        ),
        False,
    )


def _read_event_at_sequence(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    sequence: int,
    database_encoding: str,
) -> _EventFacts:
    row = connection.execute(
        """
        SELECT
            CASE WHEN typeof(sequence) = 'integer'
                 THEN sequence ELSE NULL END AS sequence,
            typeof(event_type) AS event_type_storage_type,
            typeof(event_id) AS event_id_storage_type,
            typeof(status) AS status_storage_type,
            typeof(payload_json) AS payload_storage_type,
            CASE WHEN typeof(occurred_at) IN ('integer', 'real')
                 THEN occurred_at ELSE NULL END AS occurred_at
        FROM run_events
        WHERE sequence = ? AND run_id = ?
        """,
        (sequence, run_id),
    ).fetchone()
    if row is None:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
    sequence = row["sequence"]
    if type(sequence) is not int or not 0 < sequence <= _MAX_INT64:
        sequence = None
    occurred_at = row["occurred_at"]
    if (
        isinstance(occurred_at, bool)
        or not isinstance(occurred_at, (int, float))
        or not math.isfinite(float(occurred_at))
        or occurred_at < 0
    ):
        occurred_at = None
    event_type = _read_bounded_text_column(
        connection,
        table="run_events",
        column="event_type",
        row_id=sequence,
        storage_type=row["event_type_storage_type"],
        characters=_MAX_RUN_CHARACTERS,
        bytes_=_MAX_RUN_BYTES,
        database_encoding=database_encoding,
    )
    event_id = _read_bounded_text_column(
        connection,
        table="run_events",
        column="event_id",
        row_id=sequence,
        storage_type=row["event_id_storage_type"],
        characters=_MAX_EVENT_IDENTIFIER_CHARACTERS,
        bytes_=_MAX_EVENT_IDENTIFIER_BYTES,
        database_encoding=database_encoding,
    )
    payload_json = _read_bounded_text_column(
        connection,
        table="run_events",
        column="payload_json",
        row_id=sequence,
        storage_type=row["payload_storage_type"],
        characters=_MAX_PAYLOAD_BYTES,
        bytes_=_MAX_PAYLOAD_BYTES,
        database_encoding=database_encoding,
    )
    status_storage_type = row["status_storage_type"]
    if status_storage_type == "null":
        status = None
    else:
        status = _read_bounded_text_column(
            connection,
            table="run_events",
            column="status",
            row_id=sequence,
            storage_type=status_storage_type,
            characters=32,
            bytes_=32,
            database_encoding=database_encoding,
        )
        if status is None:
            status = "__invalid__"
    return _EventFacts(
        sequence=sequence,
        event_type=event_type,
        event_id=event_id,
        status=status,
        payload_json=payload_json,
        occurred_at=occurred_at,
    )


def _event_counts(events: tuple[_EventFacts, ...]) -> _EventCounts:
    return _EventCounts(
        total=len(events),
        status_events=sum(
            event.event_type == _STATUS_EVENT_TYPE for event in events
        ),
        status_values=sum(event.status is not None for event in events),
        selections=sum(
            event.event_type == _SELECTION_EVENT_TYPE for event in events
        ),
        bindings=sum(
            event.event_type == _BINDING_EVENT_TYPE for event in events
        ),
        unexpected=sum(
            event.event_type
            not in {
                _STATUS_EVENT_TYPE,
                _SELECTION_EVENT_TYPE,
                _BINDING_EVENT_TYPE,
            }
            for event in events
        ),
        first_sequence=events[0].sequence if events else None,
    )


def _unique_event(
    events: tuple[_EventFacts, ...],
    event_type: str,
) -> _EventFacts | None:
    matches = tuple(event for event in events if event.event_type == event_type)
    return matches[0] if len(matches) == 1 else None


def _build_truncated_report(
    *,
    run_ref: str,
    run: _RunFacts,
) -> RepositoryProposalInspectionReport:
    codes = {"history_cardinality_invalid", "event_limit_exceeded"}
    if not run.scalar_valid:
        codes.add("run_record_invalid")
    if run.runner_id != _RUNNER_ID:
        codes.add("runner_invalid")
    if run.permission_class not in (0, 1):
        codes.add("permission_class_invalid")
    return RepositoryProposalInspectionReport(
        run_ref=run_ref,
        coverage="invalid",
        truncated=True,
        inspected_event_count=_MAX_INSPECTED_EVENT_COUNT,
        permission_class=run.permission_class,
        current_status=None,
        proposal_digest=None,
        proposal_ref=None,
        proposal_version_ref=None,
        registration_digest=None,
        registration_ref=None,
        registration_version=None,
        repository_ref=None,
        registration_selection_digest=None,
        repository_proposal_binding_digest=None,
        selection_sequence=None,
        binding_sequence=None,
        findings=_findings(codes),
    )


def _build_report(
    *,
    run_id: str,
    run_ref: str,
    run: _RunFacts,
    counts: _EventCounts,
    status_event: _EventFacts | None,
    selection_event: _EventFacts | None,
    binding_event: _EventFacts | None,
) -> RepositoryProposalInspectionReport:
    codes: set[str] = set()
    truncated = counts.total > _MAX_INSPECTED_EVENT_COUNT
    if truncated:
        codes.add("event_limit_exceeded")

    if not run.scalar_valid:
        codes.add("run_record_invalid")
    if run.runner_id != _RUNNER_ID:
        codes.add("runner_invalid")
    if run.permission_class not in (0, 1):
        codes.add("permission_class_invalid")

    created_valid = _created_event_valid(
        status_event,
        run_id=run_id,
        run=run,
        counts=counts,
    )
    if not created_valid:
        codes.add("created_event_invalid")
    current_status = (
        _CREATED_STATUS
        if created_valid and counts.status_values == 1
        else None
    )
    if current_status != _CREATED_STATUS:
        codes.add("run_status_invalid")

    if counts.unexpected:
        codes.add("unexpected_event")
    if counts.selections == 0:
        codes.add("registration_selection_missing")
    elif counts.selections > 1:
        codes.add("registration_selection_duplicate")
    if counts.bindings == 0:
        codes.add("repository_proposal_binding_missing")
    elif counts.bindings > 1:
        codes.add("repository_proposal_binding_duplicate")

    selection: _SelectionFacts | None = None
    selection_specific_valid = False
    if selection_event is not None:
        if selection_event.status is not None:
            codes.add("registration_selection_status_invalid")
        if not selection_event.metadata_valid:
            codes.add("registration_selection_payload_invalid")
        selection = _parse_selection(selection_event.payload_json)
        if selection is None:
            codes.add("registration_selection_payload_invalid")
        else:
            if selection_event.event_id != selection.selection_digest:
                codes.add(
                    "registration_selection_event_identifier_mismatch"
                )
            if not selection.fixed_semantics_valid:
                codes.add("disabled_semantics_mismatch")
            if selection.selection["run_ref"] != run_ref:
                codes.add("durable_run_linkage_mismatch")
            selection_specific_valid = not any(
                code in codes
                for code in (
                    "registration_selection_status_invalid",
                    "registration_selection_payload_invalid",
                    "registration_selection_event_identifier_mismatch",
                    "disabled_semantics_mismatch",
                    "durable_run_linkage_mismatch",
                )
            )

    binding: _BindingFacts | None = None
    binding_specific_valid = False
    if binding_event is not None:
        if binding_event.status is not None:
            codes.add("repository_proposal_binding_status_invalid")
        if not binding_event.metadata_valid:
            codes.add("repository_proposal_binding_payload_invalid")
        binding = _parse_binding(binding_event.payload_json)
        if binding is None:
            codes.add("repository_proposal_binding_payload_invalid")
        else:
            if binding_event.event_id != binding.binding_digest:
                codes.add(
                    "repository_proposal_binding_event_identifier_mismatch"
                )
            if not binding.fixed_semantics_valid:
                codes.add("disabled_semantics_mismatch")

    if binding is not None:
        if run.scalar_valid and not _binding_matches_run(
            binding.binding,
            run=run,
            run_ref=run_ref,
        ):
            codes.add("durable_run_linkage_mismatch")
        if selection is None:
            codes.add("proposal_event_order_invalid")
        else:
            if (
                binding.binding["proposal_digest"]
                != selection.selection["proposal_digest"]
            ):
                codes.add("proposal_linkage_mismatch")
            if not _binding_matches_registration(
                binding.binding,
                selection=selection,
            ):
                codes.add("registration_component_linkage_mismatch")

    if (
        status_event is not None
        and selection_event is not None
        and (
            status_event.sequence is None
            or selection_event.sequence is None
            or status_event.sequence >= selection_event.sequence
        )
    ):
        codes.add("proposal_event_order_invalid")
    if (
        selection_event is not None
        and binding_event is not None
        and (
            selection_event.sequence is None
            or binding_event.sequence is None
            or selection_event.sequence >= binding_event.sequence
        )
    ):
        codes.add("proposal_event_order_invalid")

    exact_prefix_counts = (
        counts.status_events == 1
        and counts.status_values == 1
        and counts.unexpected == 0
        and (
            (counts.total, counts.selections, counts.bindings)
            in ((1, 0, 0), (2, 1, 0), (3, 1, 1))
        )
    )
    if not exact_prefix_counts:
        codes.add("history_cardinality_invalid")

    binding_specific_valid = (
        binding is not None
        and not any(
            code in codes
            for code in (
                "repository_proposal_binding_status_invalid",
                "repository_proposal_binding_payload_invalid",
                "repository_proposal_binding_event_identifier_mismatch",
                "disabled_semantics_mismatch",
                "durable_run_linkage_mismatch",
                "proposal_linkage_mismatch",
                "registration_component_linkage_mismatch",
            )
        )
    )

    incomplete_allowed = {
        "registration_selection_missing",
        "repository_proposal_binding_missing",
    }
    created_only_prefix = (
        counts.total == 1
        and counts.selections == 0
        and counts.bindings == 0
        and codes == incomplete_allowed
    )
    selection_prefix = (
        counts.total == 2
        and counts.selections == 1
        and counts.bindings == 0
        and selection_specific_valid
        and codes == {"repository_proposal_binding_missing"}
    )
    if not codes and counts.total == 3 and binding_specific_valid:
        coverage = "complete"
    elif created_only_prefix or selection_prefix:
        coverage = "incomplete"
    else:
        coverage = "invalid"

    expose_selection = coverage in ("complete", "incomplete") and selection is not None
    expose_binding = coverage == "complete" and binding is not None
    selected = selection.selected_registration if expose_selection else None
    binding_value = binding.binding if expose_binding else None
    findings = _findings(codes)
    return RepositoryProposalInspectionReport(
        run_ref=run_ref,
        coverage=coverage,
        truncated=truncated,
        inspected_event_count=min(
            counts.total,
            _MAX_INSPECTED_EVENT_COUNT,
        ),
        permission_class=run.permission_class,
        current_status=current_status,
        proposal_digest=(
            selection.selection["proposal_digest"]
            if expose_selection
            else None
        ),
        proposal_ref=(
            binding_value["proposal_ref"] if binding_value is not None else None
        ),
        proposal_version_ref=(
            binding_value["proposal_version_ref"]
            if binding_value is not None
            else None
        ),
        registration_digest=(
            selected["registration_digest"] if selected is not None else None
        ),
        registration_ref=(
            selected["registration_ref"] if selected is not None else None
        ),
        registration_version=(
            selected["registration_version"] if selected is not None else None
        ),
        repository_ref=(
            selected["repository_ref"] if selected is not None else None
        ),
        registration_selection_digest=(
            selection.selection_digest if expose_selection else None
        ),
        repository_proposal_binding_digest=(
            binding.binding_digest if expose_binding else None
        ),
        selection_sequence=(
            selection_event.sequence
            if expose_selection and selection_event is not None
            else None
        ),
        binding_sequence=(
            binding_event.sequence
            if expose_binding and binding_event is not None
            else None
        ),
        findings=findings,
    )


def _created_event_valid(
    event: _EventFacts | None,
    *,
    run_id: str,
    run: _RunFacts,
    counts: _EventCounts,
) -> bool:
    if (
        event is None
        or not event.metadata_valid
        or event.event_id is None
        or not _created_event_identifier_valid(event.event_id, run_id=run_id)
        or event.sequence != counts.first_sequence
        or event.status != _CREATED_STATUS
        or event.payload_json is None
        or run.created_at is None
        or event.occurred_at != run.created_at
    ):
        return False
    payload = _load_payload(event.payload_json)
    return payload == {}


def _created_event_identifier_valid(value: str, *, run_id: str) -> bool:
    prefix = f"{run_id}:created:"
    suffix = value[len(prefix) :] if value.startswith(prefix) else ""
    return (
        len(value) == len(prefix) + 32
        and re.fullmatch(
            r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}",
            suffix,
        )
        is not None
    )


def _parse_selection(payload_json: str | None) -> _SelectionFacts | None:
    payload = _load_payload(payload_json)
    if not _exact_object(payload, _SELECTION_PAYLOAD_KEYS):
        return None
    selection = payload["selection"]
    if not _exact_object(selection, _SELECTION_KEYS):
        return None
    selected = selection["selected_registration"]
    if not _exact_object(selected, _REGISTRATION_EVIDENCE_KEYS):
        return None
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or selection["kind"] != _SELECTION_KIND
        or not _is_digest(selection["proposal_digest"])
        or not _is_digest(selection["run_ref"])
        or not _is_digest(
            selection["selected_registration_evidence_digest"]
        )
        or not _is_digest(payload["selection_digest"])
        or type(selected["schema_version"]) is not int
        or selected["schema_version"] != 1
        or selected["kind"] != _REGISTRATION_EVIDENCE_KIND
        or type(selected["registration_version"]) is not str
        or _VERSION_PATTERN.fullmatch(selected["registration_version"])
        is None
        or any(not _is_digest(selected[name]) for name in _REGISTRATION_DIGEST_FIELDS)
    ):
        return None
    if (
        selection["selected_registration_evidence_digest"]
        != _safe_digest(selected)
        or payload["selection_digest"] != _safe_digest(selection)
    ):
        return None
    fixed = (
        type(selection["selection_mode"]) is str
        and selection["selection_mode"] == "controller_owned"
        and type(selected["validation_mode"]) is str
        and selected["validation_mode"] == "read_only"
        and type(selected["dispatch_enabled"]) is bool
        and selected["dispatch_enabled"] is False
        and type(selected["authority_granted"]) is bool
        and selected["authority_granted"] is False
    )
    return _SelectionFacts(
        selection=selection,
        selected_registration=selected,
        selection_digest=payload["selection_digest"],
        fixed_semantics_valid=fixed,
    )


def _parse_binding(payload_json: str | None) -> _BindingFacts | None:
    payload = _load_payload(payload_json)
    if not _exact_object(payload, _BINDING_PAYLOAD_KEYS):
        return None
    binding = payload["binding"]
    if not _exact_object(binding, _BINDING_KEYS):
        return None
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or binding["kind"] != _BINDING_KIND
        or not _is_digest(payload["binding_digest"])
        or type(binding["attempt"]) is not int
        or not 0 < binding["attempt"] <= _MAX_INT64
        or type(binding["timeout_seconds"]) is not int
        or not 0 < binding["timeout_seconds"] <= _MAX_INT64
        or type(binding["permission_class"]) is not int
        or binding["permission_class"] not in (0, 1)
        or type(binding["registration_version"]) is not str
        or _VERSION_PATTERN.fullmatch(binding["registration_version"])
        is None
        or any(not _is_digest(binding[name]) for name in _BINDING_DIGEST_FIELDS)
        or payload["binding_digest"] != _safe_digest(binding)
    ):
        return None
    fixed = (
        type(binding["validation_mode"]) is str
        and binding["validation_mode"] == "read_only"
        and type(binding["dispatch_enabled"]) is bool
        and binding["dispatch_enabled"] is False
        and type(binding["authority_granted"]) is bool
        and binding["authority_granted"] is False
    )
    return _BindingFacts(
        binding=binding,
        binding_digest=payload["binding_digest"],
        fixed_semantics_valid=fixed,
    )


def _binding_matches_run(
    binding: dict[str, Any],
    *,
    run: _RunFacts,
    run_ref: str,
) -> bool:
    assert run.scalar_valid
    return binding == binding | {
        "attempt": run.attempt,
        "context_digest": run.context_digest,
        "created_at_ref": canonical_digest({"created_at": run.created_at}),
        "permission_class": run.permission_class,
        "proposal_ref": canonical_digest({"proposal_id": run.task_id}),
        "proposal_version_ref": canonical_digest(
            {"proposal_version": run.task_version}
        ),
        "run_directory_ref": canonical_digest(
            {"run_directory": run.run_directory}
        ),
        "run_ref": run_ref,
        "runner_ref": canonical_digest({"runner_id": run.runner_id}),
        "timeout_seconds": run.timeout_seconds,
        "workspace_ref": canonical_digest({"workspace": run.workspace}),
    }


def _binding_matches_registration(
    binding: dict[str, Any],
    *,
    selection: _SelectionFacts,
) -> bool:
    selected = selection.selected_registration
    return (
        binding["registration_evidence_digest"]
        == selection.selection["selected_registration_evidence_digest"]
        and binding["registration_selection_digest"]
        == selection.selection_digest
        and all(binding[name] == selected[name] for name in _REGISTRATION_LINK_FIELDS)
    )


def _load_payload(value: Any) -> dict[str, Any] | None:
    if type(value) is not str:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return None
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        return None
    try:
        decoded = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except (RecursionError, UnicodeError, ValueError):
        return None
    if type(decoded) is not dict or not _bounded_json(decoded):
        return None
    try:
        if canonical_json(decoded) != value:
            return None
    except (RecursionError, TypeError, UnicodeError, ValueError):
        return None
    return decoded


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError


def _bounded_json(value: Any) -> bool:
    nodes = 0
    text_bytes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            return False
        if item is None or type(item) is bool:
            continue
        if type(item) is int:
            if item.bit_length() > 63:
                return False
            continue
        if type(item) is float:
            if not math.isfinite(item):
                return False
            continue
        if type(item) is str:
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                return False
            if text_bytes > _MAX_PAYLOAD_BYTES:
                return False
            continue
        if type(item) is list:
            stack.extend((child, depth + 1) for child in item)
            continue
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    return False
                try:
                    text_bytes += len(key.encode("utf-8"))
                except UnicodeError:
                    return False
                if text_bytes > _MAX_PAYLOAD_BYTES:
                    return False
                stack.append((child, depth + 1))
            continue
        return False
    return True


def _exact_object(value: Any, keys: frozenset[str]) -> bool:
    return type(value) is dict and frozenset(value) == keys


def _safe_digest(value: Any) -> str | None:
    try:
        return canonical_digest(value)
    except (RecursionError, TypeError, UnicodeError, ValueError):
        return None


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _normalise_digest(value: Any) -> str | None:
    if type(value) is not str:
        return None
    normalised = value if value.startswith("sha256:") else "sha256:" + value
    return normalised if _is_digest(normalised) else None


def _findings(codes: set[str]) -> tuple[RepositoryProposalInspectionFinding, ...]:
    ordered = sorted(
        (code for code in codes if code in _FINDING_CODES),
        key=_FINDING_RANK.__getitem__,
    )
    return tuple(
        RepositoryProposalInspectionFinding(code)
        for code in ordered[:_MAX_FINDINGS]
    )


@contextmanager
def _read_only_database_uri(database: Path) -> Iterator[str]:
    before = _database_signature(database)
    if before[3] is not None:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
    wal_signature = before[1]
    if (
        before[0][2] > _MAX_STAGED_SNAPSHOT_BYTES
        or (
            wal_signature is not None
            and wal_signature[2]
            > _MAX_STAGED_SNAPSHOT_BYTES - before[0][2]
        )
    ):
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)

    with tempfile.TemporaryDirectory(
        prefix="ordomata-proposal-inspect-"
    ) as temporary:
        snapshot = Path(temporary) / "state.sqlite3"
        snapshot_wal = Path(str(snapshot) + "-wal")
        source_wal = Path(str(database) + "-wal")
        try:
            try:
                _copy_snapshot_file(
                    database,
                    snapshot,
                    expected_signature=before[0],
                )
                journal_mode = _sqlite_header_journal_mode(snapshot)
                if journal_mode == "rollback" and (
                    wal_signature is not None or before[2] is not None
                ):
                    raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
                if (
                    journal_mode == "wal"
                    and wal_signature is None
                    and before[2] is not None
                ):
                    raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
                if wal_signature is not None:
                    _copy_snapshot_file(
                        source_wal,
                        snapshot_wal,
                        expected_signature=wal_signature,
                    )
            except ConfigurationError:
                raise
            except OSError:
                raise ConfigurationError(
                    _INVALID_DATABASE_MESSAGE
                ) from None
            _require_unchanged(database, before)
            immutable = "&immutable=1" if wal_signature is None else ""
            yield snapshot.as_uri() + f"?mode=ro{immutable}"
        finally:
            _require_unchanged(database, before)


def _copy_snapshot_file(
    source: Path,
    destination: Path,
    *,
    expected_signature: tuple[int, int, int, int],
) -> None:
    expected_size = expected_signature[2]
    source_stream = None
    source_descriptor: int | None = None
    destination_stream = None
    destination_descriptor: int | None = None
    failure: BaseException | None = None
    try:
        try:
            source_descriptor = os.open(
                source,
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            try:
                current_signature = _file_signature(source, required=True)
            except (ConfigurationError, RecordNotFoundError):
                raise ConfigurationError(
                    _CHANGED_DATABASE_MESSAGE
                ) from None
            if current_signature != expected_signature:
                raise ConfigurationError(
                    _CHANGED_DATABASE_MESSAGE
                ) from None
            raise error
        source_metadata = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or _metadata_signature(source_metadata) != expected_signature
        ):
            raise ConfigurationError(_CHANGED_DATABASE_MESSAGE)
        source_stream = os.fdopen(
            source_descriptor,
            "rb",
            buffering=0,
        )
        source_descriptor = None
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        destination_stream = os.fdopen(
            destination_descriptor,
            "wb",
            buffering=0,
        )
        destination_descriptor = None
        remaining = expected_size
        while remaining:
            chunk = source_stream.read(
                min(remaining, _SNAPSHOT_COPY_CHUNK_BYTES)
            )
            if not chunk:
                raise ConfigurationError(_CHANGED_DATABASE_MESSAGE)
            view = memoryview(chunk)
            while view:
                written = destination_stream.write(view)
                if written is None or written <= 0:
                    raise OSError
                view = view[written:]
            remaining -= len(chunk)
        if source_stream.read(1) != b"":
            raise ConfigurationError(_CHANGED_DATABASE_MESSAGE)
        if (
            _metadata_signature(os.fstat(source_stream.fileno()))
            != expected_signature
        ):
            raise ConfigurationError(_CHANGED_DATABASE_MESSAGE)
    except BaseException as error:
        failure = error
        raise
    finally:
        cleanup_failure: BaseException | None = None
        if destination_stream is not None:
            try:
                destination_stream.close()
            except BaseException as error:
                cleanup_failure = error
        elif destination_descriptor is not None:
            try:
                os.close(destination_descriptor)
            except BaseException as error:
                cleanup_failure = error
        if source_stream is not None:
            try:
                source_stream.close()
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error
        elif source_descriptor is not None:
            try:
                os.close(source_descriptor)
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error
        if failure is None and cleanup_failure is not None:
            raise cleanup_failure


def _database_signature(
    database: Path,
) -> tuple[
    tuple[int, int, int, int],
    tuple[int, int, int, int] | None,
    tuple[int, int, int, int] | None,
    tuple[int, int, int, int] | None,
]:
    main = _file_signature(database, required=True)
    assert main is not None
    wal = _file_signature(Path(str(database) + "-wal"), required=False)
    shm = _file_signature(Path(str(database) + "-shm"), required=False)
    journal = _file_signature(
        Path(str(database) + "-journal"),
        required=False,
    )
    return main, wal, shm, journal


def _require_unchanged(
    database: Path,
    expected: tuple[
        tuple[int, int, int, int],
        tuple[int, int, int, int] | None,
        tuple[int, int, int, int] | None,
        tuple[int, int, int, int] | None,
    ],
) -> None:
    try:
        current = _database_signature(database)
    except (ConfigurationError, RecordNotFoundError):
        raise ConfigurationError(_CHANGED_DATABASE_MESSAGE) from None
    if current != expected:
        raise ConfigurationError(_CHANGED_DATABASE_MESSAGE)


def _sqlite_header_journal_mode(database: Path) -> str:
    try:
        with database.open("rb") as stream:
            header = stream.read(100)
    except OSError:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE) from None
    if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
    if header[18:20] == b"\x01\x01":
        return "rollback"
    if header[18:20] == b"\x02\x02":
        return "wal"
    raise ConfigurationError(_INVALID_DATABASE_MESSAGE)


def _file_signature(
    path: Path,
    *,
    required: bool,
) -> tuple[int, int, int, int] | None:
    try:
        if path.is_symlink():
            raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
        metadata = path.stat()
    except FileNotFoundError:
        if not required:
            return None
        raise RecordNotFoundError(_NOT_FOUND_MESSAGE) from None
    except (ConfigurationError, RecordNotFoundError):
        raise
    except OSError:
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE) from None
    if not path.is_file():
        raise ConfigurationError(_INVALID_DATABASE_MESSAGE)
    return _metadata_signature(metadata)


def _metadata_signature(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


__all__ = [
    "REPOSITORY_PROPOSAL_INSPECTION_KIND",
    "REPOSITORY_PROPOSAL_INSPECTION_SCHEMA_VERSION",
    "RepositoryProposalInspectionFinding",
    "RepositoryProposalInspectionReport",
    "inspect_repository_proposal_evidence",
]
