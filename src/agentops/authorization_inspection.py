"""Read-only inspection of non-authoritative authorization shadow evidence.

The inspector intentionally does not use :class:`SQLiteStateStore`: opening a
state store initialises schema and WAL state, while this module must never
mutate an inspected repository.  It exposes only a bounded, whitelisted
projection of the audit stream.  Raw authorization requests, decisions,
reason details, obligation values, paths, profiles, and evidence source
identifiers never leave this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
from typing import Any, Iterator

from .authorization import (
    ActionAttributes,
    ActionVerb,
    AuthorizationEffect,
    BlastRadius,
    ConsequenceVector,
    EvidenceSource,
    ImpactLevel,
    Reach,
    ResourceAttributes,
    canonical_digest,
    derive_permission_class_from_attributes,
)
from .errors import ConfigurationError
from .models import PermissionClass, RunStatus
from .state import RecordNotFoundError


AUTHORIZATION_SHADOW_EVENT_TYPE = "authorization_shadow_decision"
ADMISSION_SCOPE = "task_attempt_admission_only"
DISPATCH_SCOPE = "runner_model_dispatch_only"
PUBLICATION_SCOPE = "local_candidate_publication_only"
KNOWN_ACTION_SCOPES = frozenset(
    {ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE}
)
SUPPORTED_SHADOW_SCHEMA_VERSIONS = frozenset({1, 2})

_FLOW_STATE_BY_SCOPE = {
    ADMISSION_SCOPE: "admission_proposed",
    DISPATCH_SCOPE: "runner_dispatch_proposed",
    PUBLICATION_SCOPE: "local_candidate_publication_proposed",
}

_KNOWN_ATTRIBUTES = frozenset(
    {"subject", "action", "resource", "environment", "consequences"}
)
_KNOWN_EVIDENCE_SOURCES = frozenset(item.value for item in EvidenceSource)
_KNOWN_EFFECTS = frozenset(item.value for item in AuthorizationEffect)
_KNOWN_STATUSES = frozenset(item.value for item in RunStatus)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_AUTHORIZATION_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}")
_SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SENSITIVE_IDENTIFIER_MARKERS = (
    "access_token",
    "api_key",
    "client_secret",
    "credential",
    "github_pat_",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_token",
)
_SENSITIVE_IDENTIFIER_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "sk-", "xox")
_MAX_RUNS = 250
_MAX_SHADOW_EVENTS_PER_RUN = 16
_MAX_EVIDENCE_RECORDS = 32
_MAX_PAYLOAD_BYTES = 512 * 1024
_MISSING = object()


@dataclass(frozen=True, slots=True)
class EvidenceFreshnessInspection:
    """A secret-free temporal projection of one attribute-evidence record."""

    attribute: str | None
    source: str | None
    authenticated: bool | None
    observed_at: float | None
    expires_at: float | None
    fresh_at_evaluation: bool | None
    fresh_now: bool | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "attribute": self.attribute,
            "source": self.source,
            "authenticated": self.authenticated,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "fresh_at_evaluation": self.fresh_at_evaluation,
            "fresh_now": self.fresh_now,
        }


@dataclass(frozen=True, slots=True)
class ShadowDecisionInspection:
    """Sanitized integrity and parity findings for one shadow event."""

    sequence: int
    occurred_at: float | None
    action_scope: str | None
    effect: str | None
    derived_permission_class: int | None
    recomputed_derived_permission_class: int | None
    requested_permission_class: int | None
    legacy_executable: bool | None
    recomputed_legacy_executable: bool | None
    reported_execution_parity: bool | None
    recomputed_execution_parity: bool | None
    reported_authority_ceiling_parity: bool | None
    recomputed_authority_ceiling_parity: bool | None
    request_digest_valid: bool | None
    decision_digest_valid: bool | None
    evidence: tuple[EvidenceFreshnessInspection, ...]
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return (
            self.recomputed_execution_parity is not True
            or bool(self.integrity_issues)
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "occurred_at": self.occurred_at,
            "action_scope": self.action_scope,
            "effect": self.effect,
            "derived_permission_class": self.derived_permission_class,
            "recomputed_derived_permission_class": (
                self.recomputed_derived_permission_class
            ),
            "requested_permission_class": self.requested_permission_class,
            "legacy_executable": self.legacy_executable,
            "recomputed_legacy_executable": self.recomputed_legacy_executable,
            "reported_execution_parity": self.reported_execution_parity,
            "recomputed_execution_parity": self.recomputed_execution_parity,
            "reported_authority_ceiling_parity": (
                self.reported_authority_ceiling_parity
            ),
            "recomputed_authority_ceiling_parity": (
                self.recomputed_authority_ceiling_parity
            ),
            "request_digest_valid": self.request_digest_valid,
            "decision_digest_valid": self.decision_digest_valid,
            "evidence": [item.to_mapping() for item in self.evidence],
            "integrity_issues": list(self.integrity_issues),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True, slots=True)
class RunAuthorizationInspection:
    """Coverage and shadow-decision findings for one immutable run."""

    run_id: str | None
    run_ref: str
    permission_class: int | None
    attempt: int | None
    latest_status: str | None
    expected_scopes: tuple[str, ...]
    observed_scopes: tuple[str, ...]
    missing_scopes: tuple[str, ...]
    events: tuple[ShadowDecisionInspection, ...]
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return (
            bool(self.missing_scopes)
            or bool(self.integrity_issues)
            or any(event.attention_required for event in self.events)
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "run_ref": self.run_ref,
            "permission_class": self.permission_class,
            "attempt": self.attempt,
            "latest_status": self.latest_status,
            "expected_scopes": list(self.expected_scopes),
            "observed_scopes": list(self.observed_scopes),
            "missing_scopes": list(self.missing_scopes),
            "events": [event.to_mapping() for event in self.events],
            "integrity_issues": list(self.integrity_issues),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationInspectionReport:
    """Bounded, CLI-ready authorization inspection result."""

    generated_at: float
    database_present: bool
    mismatches_only: bool
    truncated: bool
    inspected_run_count: int
    inspected_event_count: int
    parity_mismatch_count: int
    authority_ceiling_mismatch_count: int
    coverage_gap_count: int
    integrity_issue_count: int
    runs: tuple[RunAuthorizationInspection, ...]

    @property
    def clean(self) -> bool:
        return (
            self.parity_mismatch_count == 0
            and self.authority_ceiling_mismatch_count == 0
            and self.coverage_gap_count == 0
            and self.integrity_issue_count == 0
            and not self.truncated
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "database_present": self.database_present,
            "mismatches_only": self.mismatches_only,
            "truncated": self.truncated,
            "clean": self.clean,
            "inspected_run_count": self.inspected_run_count,
            "inspected_event_count": self.inspected_event_count,
            "parity_mismatch_count": self.parity_mismatch_count,
            "authority_ceiling_mismatch_count": (
                self.authority_ceiling_mismatch_count
            ),
            "coverage_gap_count": self.coverage_gap_count,
            "integrity_issue_count": self.integrity_issue_count,
            "runs": [run.to_mapping() for run in self.runs],
        }


@dataclass(frozen=True, slots=True)
class _RunFacts:
    raw_run_id: str
    run_id: str | None
    run_ref: str
    permission_class: int | None
    attempt: int | None
    latest_status: str | None
    running_observed: bool
    succeeded_observed: bool
    artifact_observed: bool
    shadow_event_count: int
    billing_sequence: int | None
    running_sequence: int | None
    accounting_sequence: int | None
    runner_event_sequence: int | None
    terminal_sequence: int | None
    issues: tuple[str, ...]


def inspect_authorization_shadows(
    database_path: str | Path,
    *,
    run_id: str | None = None,
    mismatches_only: bool = False,
    now: float | None = None,
) -> AuthorizationInspectionReport:
    """Inspect bounded shadow evidence without creating or changing state.

    A missing database is a clean empty result for an unfiltered inspection.
    A specifically requested missing run raises :class:`RecordNotFoundError`.
    Database, schema, and read failures are reported as a fixed
    :class:`ConfigurationError` so SQLite text or private paths cannot leak.
    """

    evaluated_now = _finite_timestamp(time.time() if now is None else now)
    requested_run_id = _validate_requested_run_id(run_id)
    path = Path(database_path)

    try:
        exists = path.exists()
    except OSError as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error
    if not exists:
        if requested_run_id is not None:
            raise RecordNotFoundError("requested authorization run was not found")
        return _empty_report(evaluated_now, mismatches_only=mismatches_only)
    try:
        if path.is_symlink() or not path.is_file():
            raise ConfigurationError(
                "authorization inspection database is unreadable or malformed"
            )
        resolved = path.resolve(strict=True)
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error

    try:
        with _read_only_database_uri(resolved) as database_uri:
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(
                    database_uri,
                    uri=True,
                    timeout=1.0,
                    isolation_level=None,
                )
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                query_only = connection.execute("PRAGMA query_only").fetchone()
                if query_only is None or int(query_only[0]) != 1:
                    raise sqlite3.DatabaseError(
                        "query-only mode was not established"
                    )
                connection.execute("PRAGMA temp_store = MEMORY")
                facts, run_truncated = _read_run_facts(
                    connection,
                    requested_run_id=requested_run_id,
                )
                if requested_run_id is not None and not facts:
                    raise RecordNotFoundError(
                        "requested authorization run was not found"
                    )
                event_rows = _read_shadow_events(connection, facts)
            finally:
                if connection is not None:
                    connection.close()
    except RecordNotFoundError:
        raise
    except ConfigurationError:
        raise
    except (sqlite3.Error, ValueError, TypeError, OverflowError) as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error

    rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in event_rows:
        raw_event_run_id = row["run_id"]
        if isinstance(raw_event_run_id, str) and raw_event_run_id in rows_by_run:
            rows_by_run[raw_event_run_id].append(row)

    all_runs: list[RunAuthorizationInspection] = []
    event_truncated = False
    for fact in facts:
        event_rows_for_run = rows_by_run[fact.raw_run_id]
        events = tuple(
            _inspect_event(
                row,
                now=evaluated_now,
                expected_run_id=fact.raw_run_id,
                expected_permission_class=fact.permission_class,
            )
            for row in event_rows_for_run
        )
        expected = {ADMISSION_SCOPE}
        if fact.running_observed:
            expected.add(DISPATCH_SCOPE)
        if fact.succeeded_observed or fact.artifact_observed:
            expected.add(PUBLICATION_SCOPE)
        observed_counts: dict[str, int] = {}
        for event in events:
            if event.action_scope is not None:
                observed_counts[event.action_scope] = (
                    observed_counts.get(event.action_scope, 0) + 1
                )
        run_issues = list(fact.issues)
        if any(count > 1 for count in observed_counts.values()):
            run_issues.append("duplicate_boundary_event")
        if fact.shadow_event_count > _MAX_SHADOW_EVENTS_PER_RUN:
            run_issues.append("shadow_event_limit_exceeded")
            event_truncated = True
        sequences_by_scope = {
            event.action_scope: event.sequence
            for event in events
            if event.action_scope is not None
        }
        admission_sequence = sequences_by_scope.get(ADMISSION_SCOPE)
        if admission_sequence is not None:
            if (
                fact.billing_sequence is not None
                and admission_sequence >= fact.billing_sequence
            ) or (
                fact.running_sequence is not None
                and admission_sequence >= fact.running_sequence
            ):
                run_issues.append("admission_boundary_order_invalid")
        dispatch_sequence = sequences_by_scope.get(DISPATCH_SCOPE)
        if dispatch_sequence is not None:
            if (
                fact.running_sequence is None
                or dispatch_sequence <= fact.running_sequence
                or (
                    fact.accounting_sequence is not None
                    and dispatch_sequence >= fact.accounting_sequence
                )
                or (
                    fact.runner_event_sequence is not None
                    and dispatch_sequence >= fact.runner_event_sequence
                )
            ):
                run_issues.append("dispatch_boundary_order_invalid")
        publication_sequence = sequences_by_scope.get(PUBLICATION_SCOPE)
        if publication_sequence is not None:
            if (
                fact.accounting_sequence is None
                or publication_sequence <= fact.accounting_sequence
                or (
                    fact.terminal_sequence is not None
                    and publication_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("publication_boundary_order_invalid")
        observed = tuple(sorted(observed_counts))
        missing = tuple(sorted(expected.difference(observed_counts)))
        all_runs.append(
            RunAuthorizationInspection(
                run_id=fact.run_id,
                run_ref=fact.run_ref,
                permission_class=fact.permission_class,
                attempt=fact.attempt,
                latest_status=fact.latest_status,
                expected_scopes=tuple(sorted(expected)),
                observed_scopes=observed,
                missing_scopes=missing,
                events=events,
                integrity_issues=tuple(sorted(set(run_issues))),
            )
        )

    inspected_event_count = sum(len(run.events) for run in all_runs)
    parity_mismatch_count = sum(
        event.recomputed_execution_parity is False
        for run in all_runs
        for event in run.events
    )
    authority_ceiling_mismatch_count = sum(
        event.recomputed_authority_ceiling_parity is False
        for run in all_runs
        for event in run.events
    )
    coverage_gap_count = sum(len(run.missing_scopes) for run in all_runs)
    integrity_issue_count = sum(
        len(run.integrity_issues)
        + sum(len(event.integrity_issues) for event in run.events)
        for run in all_runs
    )
    projected_runs = (
        tuple(run for run in all_runs if run.attention_required)
        if mismatches_only
        else tuple(all_runs)
    )
    return AuthorizationInspectionReport(
        generated_at=evaluated_now,
        database_present=True,
        mismatches_only=mismatches_only,
        truncated=run_truncated or event_truncated,
        inspected_run_count=len(all_runs),
        inspected_event_count=inspected_event_count,
        parity_mismatch_count=parity_mismatch_count,
        authority_ceiling_mismatch_count=authority_ceiling_mismatch_count,
        coverage_gap_count=coverage_gap_count,
        integrity_issue_count=integrity_issue_count,
        runs=projected_runs,
    )


def _empty_report(
    generated_at: float,
    *,
    mismatches_only: bool,
) -> AuthorizationInspectionReport:
    return AuthorizationInspectionReport(
        generated_at=generated_at,
        database_present=False,
        mismatches_only=mismatches_only,
        truncated=False,
        inspected_run_count=0,
        inspected_event_count=0,
        parity_mismatch_count=0,
        authority_ceiling_mismatch_count=0,
        coverage_gap_count=0,
        integrity_issue_count=0,
        runs=(),
    )


@contextmanager
def _read_only_database_uri(database: Path) -> Iterator[str]:
    """Yield a read-only URI without creating sidecars beside the source.

    SQLite may create ``-shm`` and ``-wal`` files even for a ``mode=ro``
    connection to a WAL database.  A quiescent database is therefore opened
    with ``immutable=1`` and checked for concurrent changes.  If a WAL is
    present, the main file and WAL are copied into an owner-private temporary
    directory after a before/after consistency check; SQLite may create its
    coordination sidecars only there.
    """

    before = _database_signature(database)
    if before[1] is None:
        try:
            yield database.as_uri() + "?mode=ro&immutable=1"
        finally:
            if _database_signature(database) != before:
                raise ConfigurationError(
                    "authorization inspection database changed during inspection"
                )
        return

    with tempfile.TemporaryDirectory(prefix="agentops-auth-inspect-") as temporary:
        snapshot = Path(temporary) / "state.sqlite3"
        snapshot_wal = Path(str(snapshot) + "-wal")
        source_wal = Path(str(database) + "-wal")
        try:
            shutil.copyfile(database, snapshot)
            shutil.copyfile(source_wal, snapshot_wal)
        except OSError as error:
            raise ConfigurationError(
                "authorization inspection database is unreadable or malformed"
            ) from error
        if _database_signature(database) != before:
            raise ConfigurationError(
                "authorization inspection database changed during inspection"
            )
        yield snapshot.as_uri() + "?mode=ro"


def _database_signature(
    database: Path,
) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int] | None]:
    main = _file_signature(database, required=True)
    assert main is not None
    wal = _file_signature(Path(str(database) + "-wal"), required=False)
    return main, wal


def _file_signature(
    path: Path,
    *,
    required: bool,
) -> tuple[int, int, int, int] | None:
    try:
        if path.is_symlink():
            raise ConfigurationError(
                "authorization inspection database is unreadable or malformed"
            )
        metadata = path.stat()
    except FileNotFoundError:
        if not required:
            return None
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from None
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error
    if not path.is_file():
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _read_run_facts(
    connection: sqlite3.Connection,
    *,
    requested_run_id: str | None,
) -> tuple[tuple[_RunFacts, ...], bool]:
    where = "" if requested_run_id is None else "WHERE r.run_id = ?"
    parameters: tuple[Any, ...] = (
        (_MAX_RUNS + 1,)
        if requested_run_id is None
        else (requested_run_id, 2)
    )
    rows = connection.execute(
        f"""
        SELECT
            r.run_id,
            r.permission_class,
            r.attempt,
            EXISTS (
                SELECT 1 FROM run_events running
                WHERE running.run_id = r.run_id AND running.status = 'running'
            ) AS running_observed,
            EXISTS (
                SELECT 1 FROM run_events succeeded
                WHERE succeeded.run_id = r.run_id AND succeeded.status = 'succeeded'
            ) AS succeeded_observed,
            EXISTS (
                SELECT 1 FROM run_artifacts artifact
                WHERE artifact.run_id = r.run_id
            ) AS artifact_observed,
            (
                SELECT latest.status FROM run_events latest
                WHERE latest.run_id = r.run_id AND latest.status IS NOT NULL
                ORDER BY latest.sequence DESC LIMIT 1
            ) AS latest_status,
            (
                SELECT COUNT(*) FROM run_events shadow
                WHERE shadow.run_id = r.run_id
                  AND shadow.event_type = ?
            ) AS shadow_event_count
            ,(
                SELECT MIN(billing.sequence) FROM run_events billing
                WHERE billing.run_id = r.run_id
                  AND billing.event_type = 'billing_assessment'
            ) AS billing_sequence
            ,(
                SELECT MIN(running.sequence) FROM run_events running
                WHERE running.run_id = r.run_id
                  AND running.status = 'running'
            ) AS running_sequence
            ,(
                SELECT MIN(accounting.sequence) FROM run_events accounting
                WHERE accounting.run_id = r.run_id
                  AND accounting.event_type = 'execution_accounting'
            ) AS accounting_sequence
            ,(
                SELECT MIN(observed.sequence) FROM run_events observed
                WHERE observed.run_id = r.run_id
                  AND observed.event_type = 'runner_event_observed'
            ) AS runner_event_sequence
            ,(
                SELECT MIN(terminal.sequence) FROM run_events terminal
                WHERE terminal.run_id = r.run_id
                  AND terminal.status IN (
                      'succeeded', 'failed', 'blocked', 'quarantined', 'cancelled'
                  )
            ) AS terminal_sequence
        FROM runs r
        {where}
        ORDER BY r.created_at DESC, r.run_id DESC
        LIMIT ?
        """,
        (AUTHORIZATION_SHADOW_EVENT_TYPE, *parameters),
    ).fetchall()
    truncated = requested_run_id is None and len(rows) > _MAX_RUNS
    selected = rows[:_MAX_RUNS]
    facts: list[_RunFacts] = []
    for row in selected:
        raw_run_id = row["run_id"]
        if not isinstance(raw_run_id, str):
            raise sqlite3.DatabaseError("invalid run identity")
        issues: list[str] = []
        safe_run_id = _safe_run_identifier(raw_run_id)
        if safe_run_id is None:
            issues.append("run_identifier_unsafe")
        permission_class = _permission_class(row["permission_class"])
        if permission_class is None:
            issues.append("run_permission_class_invalid")
        attempt = row["attempt"]
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0:
            attempt = None
            issues.append("run_attempt_invalid")
        latest_status = row["latest_status"]
        if latest_status is not None and latest_status not in _KNOWN_STATUSES:
            latest_status = None
            issues.append("run_status_invalid")
        shadow_event_count = row["shadow_event_count"]
        if (
            isinstance(shadow_event_count, bool)
            or not isinstance(shadow_event_count, int)
            or shadow_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid shadow event count")
        billing_sequence = _optional_sequence(row["billing_sequence"])
        running_sequence = _optional_sequence(row["running_sequence"])
        accounting_sequence = _optional_sequence(row["accounting_sequence"])
        runner_event_sequence = _optional_sequence(row["runner_event_sequence"])
        terminal_sequence = _optional_sequence(row["terminal_sequence"])
        facts.append(
            _RunFacts(
                raw_run_id=raw_run_id,
                run_id=safe_run_id,
                run_ref=canonical_digest({"run_id": raw_run_id}),
                permission_class=permission_class,
                attempt=attempt,
                latest_status=latest_status,
                running_observed=bool(row["running_observed"]),
                succeeded_observed=bool(row["succeeded_observed"]),
                artifact_observed=bool(row["artifact_observed"]),
                shadow_event_count=shadow_event_count,
                billing_sequence=billing_sequence,
                running_sequence=running_sequence,
                accounting_sequence=accounting_sequence,
                runner_event_sequence=runner_event_sequence,
                terminal_sequence=terminal_sequence,
                issues=tuple(issues),
            )
        )
    return tuple(facts), truncated


def _read_shadow_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        AUTHORIZATION_SHADOW_EVENT_TYPE,
        *(fact.raw_run_id for fact in facts),
        _MAX_SHADOW_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_shadow_events AS (
            SELECT
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS boundary_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT run_id, sequence, occurred_at, payload_json
        FROM ranked_shadow_events
        WHERE boundary_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _inspect_event(
    row: sqlite3.Row,
    *,
    now: float,
    expected_run_id: str,
    expected_permission_class: int | None,
) -> ShadowDecisionInspection:
    issues: list[str] = []
    sequence = row["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        sequence = 0
        issues.append("event_sequence_invalid")
    occurred_at = _optional_timestamp(row["occurred_at"])
    if occurred_at is None:
        issues.append("event_timestamp_invalid")
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str):
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_json_invalid"],
        )
    if len(payload_json.encode("utf-8", errors="replace")) > _MAX_PAYLOAD_BYTES:
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_too_large"],
        )
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_json_invalid"],
        )
    if not isinstance(payload, Mapping):
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_shape_invalid"],
        )

    schema_version = payload.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version not in SUPPORTED_SHADOW_SCHEMA_VERSIONS
    ):
        issues.append("schema_version_invalid")
    if payload.get("mode") != "shadow":
        issues.append("mode_invalid")
    raw_scope = payload.get("action_scope")
    action_scope = _known_string(raw_scope, KNOWN_ACTION_SCOPES)
    if action_scope is None:
        issues.append("action_scope_invalid")

    raw_effect = payload.get("effect")
    effect = _known_string(raw_effect, _KNOWN_EFFECTS)
    if effect is None:
        issues.append("effect_invalid")
    derived_permission_class = _permission_class(
        payload.get("derived_permission_class")
    )
    if (
        derived_permission_class is None
        and payload.get("derived_permission_class") is not None
    ):
        issues.append("derived_permission_class_invalid")
    requested_permission_class = _permission_class(
        payload.get("requested_permission_class")
    )
    if schema_version == 2:
        if requested_permission_class is None:
            issues.append("requested_permission_class_invalid")
        elif (
            expected_permission_class is not None
            and requested_permission_class != expected_permission_class
        ):
            issues.append("requested_permission_class_run_mismatch")
    legacy_executable = _optional_boolean(payload.get("legacy_executable"))
    if legacy_executable is None:
        issues.append("legacy_executable_invalid")
    recomputed_legacy_executable = (
        expected_permission_class in {
            int(PermissionClass.READ_ONLY),
            int(PermissionClass.LOCAL_DRAFT),
        }
        if expected_permission_class is not None
        else None
    )
    if (
        legacy_executable is not None
        and recomputed_legacy_executable is not None
        and legacy_executable != recomputed_legacy_executable
    ):
        issues.append("legacy_executable_run_mismatch")
    reported_parity = _optional_boolean(payload.get("execution_parity"))
    if reported_parity is None:
        issues.append("execution_parity_invalid")
    reported_authority_ceiling_parity = _optional_boolean(
        payload.get("authority_ceiling_parity")
    )
    if (
        schema_version == 2
        and reported_authority_ceiling_parity is None
        and not (
            effect == AuthorizationEffect.INDETERMINATE.value
            and payload.get("failure_stage")
            in {"request_construction", "evaluation"}
        )
    ):
        issues.append("authority_ceiling_parity_invalid")

    request = payload.get("request")
    request_digest = payload.get("request_digest")
    failure_stage = payload.get("failure_stage")
    if schema_version == 2:
        issues.extend(
            _inspect_task_intent_projection(
                payload,
                request=request,
                failure_stage=failure_stage,
                action_scope=action_scope,
            )
        )
    request_failure = (
        effect == AuthorizationEffect.INDETERMINATE.value
        and failure_stage == "request_construction"
        and request is None
        and request_digest is None
    )
    request_digest_valid: bool | None = None
    if not request_failure:
        if not _is_request_shape(request):
            issues.append("request_shape_invalid")
        if isinstance(request, Mapping):
            request_digest_valid = _digest_matches(request_digest, request)
            if request_digest_valid is not True:
                issues.append("request_digest_mismatch")
        else:
            request_digest_valid = False
            issues.append("request_digest_mismatch")

    if (
        schema_version == 2
        and action_scope is not None
        and isinstance(request, Mapping)
    ):
        issues.extend(
            _inspect_boundary_projection(
                request,
                action_scope=action_scope,
                expected_run_id=expected_run_id,
            )
        )

    recomputed_derived_permission_class: int | None = None
    if isinstance(request, Mapping):
        (
            recomputed_derived_permission_class,
            class_derivation_issues,
        ) = _recompute_derived_permission_class(request)
        issues.extend(class_derivation_issues)

    decision = payload.get("decision")
    decision_digest = payload.get("decision_digest")
    evaluation_failure = (
        effect == AuthorizationEffect.INDETERMINATE.value
        and isinstance(failure_stage, str)
        and failure_stage in {"request_construction", "evaluation"}
        and decision is None
        and decision_digest is None
    )
    decision_digest_valid: bool | None = None
    if not evaluation_failure:
        if not _is_decision_shape(decision):
            issues.append("decision_shape_invalid")
        if isinstance(decision, Mapping):
            decision_digest_valid = _digest_matches(decision_digest, decision)
            if decision_digest_valid is not True:
                issues.append("decision_digest_mismatch")
        else:
            decision_digest_valid = False
            issues.append("decision_digest_mismatch")

    if isinstance(request, Mapping) and isinstance(decision, Mapping):
        if decision.get("request_digest") != request_digest:
            issues.append("decision_request_digest_mismatch")
        if decision.get("request_id") != request.get("request_id"):
            issues.append("decision_request_identifier_mismatch")
    if isinstance(decision, Mapping):
        projection_keys = (
            "effect",
            "policy_bundle_id",
            "policy_version",
            "policy_digest",
            "derived_permission_class",
            "reason_codes",
            "matched_rule_ids",
            "evidence_refs",
            "obligations",
        )
        if any(
            payload.get(key, _MISSING) != decision.get(key, _MISSING)
            for key in projection_keys
        ):
            issues.append("top_level_decision_projection_mismatch")
    if (
        not evaluation_failure
        and derived_permission_class is not None
        and recomputed_derived_permission_class is not None
        and derived_permission_class != recomputed_derived_permission_class
    ):
        issues.append("derived_permission_class_mismatch")

    evidence, evidence_issues = _inspect_evidence(request, now=now)
    issues.extend(evidence_issues)
    recomputed_parity = (
        None
        if effect is None or recomputed_legacy_executable is None
        else (
            effect == AuthorizationEffect.PERMIT.value
        ) == recomputed_legacy_executable
    )
    if (
        reported_parity is not None
        and recomputed_parity is not None
        and reported_parity != recomputed_parity
    ):
        issues.append("execution_parity_mismatch")
    recomputed_authority_ceiling_parity = (
        recomputed_derived_permission_class <= expected_permission_class
        if (
            recomputed_derived_permission_class is not None
            and expected_permission_class is not None
        )
        else None
    )
    if (
        reported_authority_ceiling_parity is not None
        and recomputed_authority_ceiling_parity is not None
        and reported_authority_ceiling_parity
        != recomputed_authority_ceiling_parity
    ):
        issues.append("authority_ceiling_parity_mismatch")
    if recomputed_authority_ceiling_parity is False:
        issues.append("derived_class_exceeds_run_authority")
    return ShadowDecisionInspection(
        sequence=sequence,
        occurred_at=occurred_at,
        action_scope=action_scope,
        effect=effect,
        derived_permission_class=derived_permission_class,
        recomputed_derived_permission_class=(
            recomputed_derived_permission_class
        ),
        requested_permission_class=requested_permission_class,
        legacy_executable=legacy_executable,
        recomputed_legacy_executable=recomputed_legacy_executable,
        reported_execution_parity=reported_parity,
        recomputed_execution_parity=recomputed_parity,
        reported_authority_ceiling_parity=(
            reported_authority_ceiling_parity
        ),
        recomputed_authority_ceiling_parity=(
            recomputed_authority_ceiling_parity
        ),
        request_digest_valid=request_digest_valid,
        decision_digest_valid=decision_digest_valid,
        evidence=evidence,
        integrity_issues=tuple(sorted(set(issues))),
    )


def _inspect_task_intent_projection(
    payload: Mapping[str, Any],
    *,
    request: Any,
    failure_stage: Any,
    action_scope: str | None,
) -> tuple[str, ...]:
    """Validate the safe schema-v2 intent projection without emitting it."""

    intent = payload.get("task_authorization_intent")
    intent_digest = payload.get("intent_digest")
    intent_source = payload.get("intent_source")
    if (
        failure_stage == "request_construction"
        and intent is None
        and intent_digest is None
        and intent_source is None
    ):
        return ()

    issues: list[str] = []
    allowed_sources = (
        {"controller_boundary_projection"}
        if action_scope == PUBLICATION_SCOPE
        else {"legacy_permission_class_fallback", "task_contract"}
    )
    if intent_source not in allowed_sources:
        issues.append("task_intent_source_invalid")
    if not _is_task_intent_shape(intent):
        issues.append("task_intent_shape_invalid")
        return tuple(issues)
    assert isinstance(intent, Mapping)
    if not _digest_matches(intent_digest, intent):
        issues.append("task_intent_digest_mismatch")
    if isinstance(request, Mapping):
        request_action = request.get("action")
        request_resource = request.get("resource")
        request_consequences = request.get("consequences")
        intent_action = intent["action"]
        intent_resource = intent["resource"]
        intent_consequences = intent["consequences"]
        assert isinstance(intent_action, Mapping)
        assert isinstance(intent_resource, Mapping)
        action_matches = isinstance(request_action, Mapping) and all(
            request_action.get(key, _MISSING) == value
            for key, value in intent_action.items()
        )
        resource_matches = isinstance(request_resource, Mapping) and all(
            request_resource.get(key, _MISSING) == value
            for key, value in intent_resource.items()
        )
        if (
            not action_matches
            or not resource_matches
            or request_consequences != intent_consequences
        ):
            issues.append("task_intent_request_projection_mismatch")
    if action_scope == PUBLICATION_SCOPE:
        issues.extend(_inspect_publication_intent(intent))
    return tuple(issues)


def _recompute_derived_permission_class(
    request: Mapping[str, Any],
) -> tuple[int | None, tuple[str, ...]]:
    """Derive the class from validated canonical request attributes."""

    try:
        action_value = request["action"]
        resource_value = request["resource"]
        consequences_value = request["consequences"]
        if not all(
            isinstance(value, Mapping)
            for value in (action_value, resource_value, consequences_value)
        ):
            raise ValueError("invalid class derivation projection")
        assert isinstance(action_value, Mapping)
        assert isinstance(resource_value, Mapping)
        assert isinstance(consequences_value, Mapping)
        if action_value.get("descriptive_claims") != []:
            raise ValueError("shadow class derivation does not accept claims")
        action = ActionAttributes(
            verb=ActionVerb(action_value["verb"]),
            operation=action_value["operation"],
            parameters_digest=action_value["parameters_digest"],
            intended_effect=action_value["intended_effect"],
            tool_id=action_value.get("tool_id"),
            descriptive_claims=(),
        )
        resource = ResourceAttributes(
            resource_type=resource_value["resource_type"],
            identifier=resource_value["identifier"],
            version=resource_value["version"],
            owner=resource_value["owner"],
            trust_boundary=resource_value["trust_boundary"],
            protected=resource_value["protected"],
            sensitivity=ImpactLevel(resource_value["sensitivity"]),
            repository_id=resource_value.get("repository_id"),
            content_digest=resource_value.get("content_digest"),
        )
        consequences = ConsequenceVector(
            confidentiality=ImpactLevel(
                consequences_value["confidentiality"]
            ),
            integrity=ImpactLevel(consequences_value["integrity"]),
            availability=ImpactLevel(consequences_value["availability"]),
            reach=Reach(consequences_value["reach"]),
            destructive=consequences_value["destructive"],
            reversible=consequences_value["reversible"],
            sensitivity=ImpactLevel(consequences_value["sensitivity"]),
            blast_radius=BlastRadius(consequences_value["blast_radius"]),
        )
        derived = derive_permission_class_from_attributes(
            action,
            resource,
            consequences,
        )
    except (KeyError, TypeError, ValueError):
        return None, ("class_derivation_input_invalid",)
    return int(derived), ()


def _inspect_publication_intent(
    intent: Mapping[str, Any],
) -> tuple[str, ...]:
    """Validate controller-owned facts in the local-publication projection."""

    action = intent["action"]
    resource = intent["resource"]
    consequences = intent["consequences"]
    assert isinstance(action, Mapping)
    assert isinstance(resource, Mapping)
    assert isinstance(consequences, Mapping)
    issues: list[str] = []
    if (
        action.get("verb") != ActionVerb.CREATE.value
        or action.get("operation") != "artifact.publish_local_candidate"
        or action.get("intended_effect")
        != "create_isolated_local_candidate"
    ):
        issues.append("publication_intent_action_invalid")
    if (
        resource.get("resource_type") != "local_candidate_artifact"
        or resource.get("trust_boundary") != "isolated_run_workspace"
    ):
        issues.append("publication_intent_resource_invalid")
    if (
        consequences.get("reach") != Reach.LOCAL.value
        or consequences.get("destructive") is not False
        or consequences.get("reversible") is not True
        or consequences.get("blast_radius")
        != BlastRadius.SINGLE_RESOURCE.value
    ):
        issues.append("publication_intent_consequences_invalid")
    return tuple(issues)


def _inspect_boundary_projection(
    request: Mapping[str, Any],
    *,
    action_scope: str,
    expected_run_id: str,
) -> tuple[str, ...]:
    """Bind a v2 boundary label to controller-owned request attributes."""

    issues: list[str] = []
    if request.get("request_id") != f"{action_scope}:{expected_run_id}":
        issues.append("boundary_request_identifier_mismatch")
    subject = request.get("subject")
    if (
        not isinstance(subject, Mapping)
        or subject.get("session_id") != f"attempt:{expected_run_id}"
    ):
        issues.append("boundary_session_identifier_mismatch")
    environment = request.get("environment")
    if (
        not isinstance(environment, Mapping)
        or environment.get("flow_state") != _FLOW_STATE_BY_SCOPE[action_scope]
    ):
        issues.append("boundary_flow_state_mismatch")
    resource = request.get("resource")
    if isinstance(resource, Mapping) and isinstance(
        resource.get("resource_type"), str
    ):
        expected_identifier = canonical_digest(
            {
                "action_scope": action_scope,
                "resource_type": resource["resource_type"],
                "run_id": expected_run_id,
            }
        )
        if resource.get("identifier") != expected_identifier:
            issues.append("boundary_resource_identifier_mismatch")
    else:
        issues.append("boundary_resource_identifier_mismatch")
    return tuple(issues)


def _inspect_evidence(
    request: Any,
    *,
    now: float,
) -> tuple[tuple[EvidenceFreshnessInspection, ...], tuple[str, ...]]:
    if not isinstance(request, Mapping):
        return (), ()
    raw_evidence = request.get("evidence")
    if not isinstance(raw_evidence, list):
        return (), ("evidence_shape_invalid",)
    issues: list[str] = []
    if len(raw_evidence) > _MAX_EVIDENCE_RECORDS:
        issues.append("evidence_limit_exceeded")
    environment = request.get("environment")
    evaluated_at = (
        _optional_timestamp(environment.get("evaluated_at"))
        if isinstance(environment, Mapping)
        else None
    )
    if evaluated_at is None:
        issues.append("evidence_evaluation_timestamp_invalid")
    seen_identifiers: set[str] = set()
    results: list[EvidenceFreshnessInspection] = []
    for record in raw_evidence[:_MAX_EVIDENCE_RECORDS]:
        if not isinstance(record, Mapping):
            issues.append("evidence_record_invalid")
            results.append(
                EvidenceFreshnessInspection(None, None, None, None, None, None, None)
            )
            continue
        if set(record) != {
            "attribute",
            "authenticated",
            "evidence_id",
            "expires_at",
            "observed_at",
            "source",
            "source_id",
            "value_digest",
        }:
            issues.append("evidence_record_shape_invalid")
        raw_attribute = record.get("attribute")
        attribute = _known_string(raw_attribute, _KNOWN_ATTRIBUTES)
        if attribute is None:
            issues.append("evidence_attribute_invalid")
        raw_source = record.get("source")
        source = _known_string(raw_source, _KNOWN_EVIDENCE_SOURCES)
        if source is None:
            issues.append("evidence_source_invalid")
        authenticated = _optional_boolean(record.get("authenticated"))
        if authenticated is None:
            issues.append("evidence_authentication_invalid")
        elif authenticated is False:
            issues.append("evidence_unauthenticated")
        observed_at = _optional_timestamp(record.get("observed_at"))
        expires_at = _optional_timestamp(record.get("expires_at"))
        if observed_at is None or expires_at is None or expires_at <= observed_at:
            issues.append("evidence_interval_invalid")
            valid_interval = False
        else:
            valid_interval = True
        evidence_id = record.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            issues.append("evidence_identifier_invalid")
        elif evidence_id in seen_identifiers:
            issues.append("evidence_identifier_duplicate")
        else:
            seen_identifiers.add(evidence_id)
        source_id = record.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            issues.append("evidence_source_identifier_invalid")
        value_digest = record.get("value_digest")
        if not _is_digest(value_digest):
            issues.append("evidence_value_digest_invalid")
        elif attribute is not None:
            expected_value = request.get(attribute, _MISSING)
            try:
                expected_digest = canonical_digest(expected_value)
            except (TypeError, ValueError, RecursionError):
                issues.append("evidence_value_digest_unverifiable")
            else:
                if value_digest != expected_digest:
                    issues.append("evidence_value_digest_mismatch")
        fresh_at_evaluation = (
            observed_at <= evaluated_at < expires_at
            if valid_interval and evaluated_at is not None
            else None
        )
        if fresh_at_evaluation is False:
            if (
                observed_at is not None
                and evaluated_at is not None
                and observed_at > evaluated_at
            ):
                issues.append("evidence_from_future_at_evaluation")
            else:
                issues.append("evidence_stale_at_evaluation")
        fresh_now = (
            observed_at <= now < expires_at if valid_interval else None
        )
        results.append(
            EvidenceFreshnessInspection(
                attribute=attribute,
                source=source,
                authenticated=authenticated,
                observed_at=observed_at,
                expires_at=expires_at,
                fresh_at_evaluation=fresh_at_evaluation,
                fresh_now=fresh_now,
            )
        )
    if seen_identifiers and len(seen_identifiers) != len(
        raw_evidence[:_MAX_EVIDENCE_RECORDS]
    ):
        issues.append("evidence_identifier_coverage_invalid")
    observed_attributes = {
        result.attribute for result in results if result.attribute is not None
    }
    if observed_attributes != _KNOWN_ATTRIBUTES:
        issues.append("evidence_attribute_coverage_invalid")
    return tuple(results), tuple(sorted(set(issues)))


def _invalid_event(
    sequence: int,
    occurred_at: float | None,
    issues: list[str],
) -> ShadowDecisionInspection:
    return ShadowDecisionInspection(
        sequence=sequence,
        occurred_at=occurred_at,
        action_scope=None,
        effect=None,
        derived_permission_class=None,
        recomputed_derived_permission_class=None,
        requested_permission_class=None,
        legacy_executable=None,
        recomputed_legacy_executable=None,
        reported_execution_parity=None,
        recomputed_execution_parity=None,
        reported_authority_ceiling_parity=None,
        recomputed_authority_ceiling_parity=None,
        request_digest_valid=None,
        decision_digest_valid=None,
        evidence=(),
        integrity_issues=tuple(sorted(set(issues))),
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _is_request_shape(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value) != {
        "action",
        "consequences",
        "environment",
        "evidence",
        "request_id",
        "resource",
        "subject",
    }:
        return False
    action = value.get("action")
    consequences = value.get("consequences")
    environment = value.get("environment")
    resource = value.get("resource")
    subject = value.get("subject")
    return (
        isinstance(action, Mapping)
        and set(action)
        == {
            "descriptive_claims",
            "intended_effect",
            "operation",
            "parameters_digest",
            "tool_id",
            "verb",
        }
        and isinstance(consequences, Mapping)
        and set(consequences)
        == {
            "availability",
            "blast_radius",
            "confidentiality",
            "destructive",
            "integrity",
            "reach",
            "reversible",
            "sensitivity",
        }
        and isinstance(environment, Mapping)
        and set(environment)
        == {
            "approval_grants",
            "billing_route",
            "capacity_state",
            "circuit_state",
            "evaluated_at",
            "flow_state",
            "isolation_state",
            "network_state",
            "paid_continuation_protection",
        }
        and isinstance(value.get("evidence"), list)
        and isinstance(value.get("request_id"), str)
        and isinstance(resource, Mapping)
        and set(resource)
        == {
            "content_digest",
            "identifier",
            "owner",
            "protected",
            "repository_id",
            "resource_type",
            "sensitivity",
            "trust_boundary",
            "version",
        }
        and isinstance(subject, Mapping)
        and set(subject)
        == {
            "controller_id",
            "principal_id",
            "profile_id",
            "role",
            "role_version",
            "runner_id",
            "session_id",
        }
    )


def _is_task_intent_shape(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "action",
        "consequences",
        "resource",
    }:
        return False
    action = value.get("action")
    resource = value.get("resource")
    consequences = value.get("consequences")
    if not isinstance(action, Mapping) or set(action) != {
        "intended_effect",
        "operation",
        "verb",
    }:
        return False
    if not isinstance(resource, Mapping) or set(resource) != {
        "protected",
        "resource_type",
        "sensitivity",
        "trust_boundary",
    }:
        return False
    if not isinstance(consequences, Mapping) or set(consequences) != {
        "availability",
        "blast_radius",
        "confidentiality",
        "destructive",
        "integrity",
        "reach",
        "reversible",
        "sensitivity",
    }:
        return False
    impact_values = frozenset(item.value for item in ImpactLevel)
    return (
        action.get("verb") in {item.value for item in ActionVerb}
        and _bounded_authorization_identifier(action.get("operation"))
        and _bounded_authorization_identifier(action.get("intended_effect"))
        and _bounded_authorization_identifier(resource.get("resource_type"))
        and _bounded_authorization_identifier(resource.get("trust_boundary"))
        and isinstance(resource.get("protected"), bool)
        and resource.get("sensitivity") in impact_values
        and consequences.get("availability") in impact_values
        and consequences.get("confidentiality") in impact_values
        and consequences.get("integrity") in impact_values
        and consequences.get("sensitivity") in impact_values
        and consequences.get("reach") in {item.value for item in Reach}
        and consequences.get("blast_radius")
        in {item.value for item in BlastRadius}
        and isinstance(consequences.get("destructive"), bool)
        and isinstance(consequences.get("reversible"), bool)
    )


def _bounded_authorization_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(value) is not None
    )


def _is_decision_shape(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value) != {
        "derived_permission_class",
        "effect",
        "evidence_refs",
        "expires_at",
        "issued_at",
        "matched_rule_ids",
        "obligations",
        "policy_bundle_id",
        "policy_digest",
        "policy_version",
        "reason_codes",
        "reason_details",
        "request_digest",
        "request_id",
    }:
        return False
    return (
        _known_string(value.get("effect"), _KNOWN_EFFECTS) is not None
        and _permission_class(value.get("derived_permission_class")) is not None
        and isinstance(value.get("evidence_refs"), list)
        and isinstance(value.get("matched_rule_ids"), list)
        and isinstance(value.get("obligations"), list)
        and isinstance(value.get("reason_codes"), list)
        and isinstance(value.get("reason_details"), list)
        and isinstance(value.get("policy_bundle_id"), str)
        and isinstance(value.get("policy_version"), str)
        and _is_digest(value.get("policy_digest"))
        and _is_digest(value.get("request_digest"))
        and isinstance(value.get("request_id"), str)
        and _optional_timestamp(value.get("issued_at")) is not None
        and _optional_timestamp(value.get("expires_at")) is not None
    )


def _digest_matches(reported: Any, value: Mapping[str, Any]) -> bool:
    if not _is_digest(reported):
        return False
    try:
        return reported == canonical_digest(value)
    except (TypeError, ValueError, RecursionError):
        return False


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _known_string(value: Any, allowed: frozenset[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _safe_run_identifier(value: str) -> str | None:
    folded = value.casefold()
    if _SAFE_IDENTIFIER_PATTERN.fullmatch(value) is None:
        return None
    if any(marker in folded for marker in _SENSITIVE_IDENTIFIER_MARKERS):
        return None
    if folded.startswith(_SENSITIVE_IDENTIFIER_PREFIXES):
        return None
    return value


def _permission_class(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return int(PermissionClass(value))
    except ValueError:
        return None


def _optional_sequence(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise sqlite3.DatabaseError("invalid event sequence")
    return value


def _optional_boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) and numeric >= 0 else None


def _finite_timestamp(value: Any) -> float:
    timestamp = _optional_timestamp(value)
    if timestamp is None:
        raise ConfigurationError("authorization inspection time must be finite")
    return timestamp


def _validate_requested_run_id(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or "\x00" in value
        or any(
            ord(character) < 32 and character not in "\t\n\r"
            for character in value
        )
    ):
        raise ConfigurationError("authorization inspection run identifier is invalid")
    return value


__all__ = [
    "ADMISSION_SCOPE",
    "AUTHORIZATION_SHADOW_EVENT_TYPE",
    "AuthorizationInspectionReport",
    "DISPATCH_SCOPE",
    "EvidenceFreshnessInspection",
    "KNOWN_ACTION_SCOPES",
    "PUBLICATION_SCOPE",
    "RunAuthorizationInspection",
    "ShadowDecisionInspection",
    "SUPPORTED_SHADOW_SCHEMA_VERSIONS",
    "inspect_authorization_shadows",
]
