"""Append-only SQLite state for local orchestration.

The database stores metadata and audit evidence, never prompts, transcripts,
artifact contents, environment values, or credentials.  Run lifecycle changes
are represented by appended events instead of updates.  SQLite triggers make
that invariant hold even if a caller bypasses this module's Python API.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any, Iterator
from uuid import uuid4

from .billing import BillingDispatchReservation
from .errors import AgentOpsError, BillingRouteBlocked, ValidationError
from .models import (
    BillingRouteAssessment,
    CapacityState,
    CircuitBreakerState,
    PermissionClass,
    RunRequest,
    RunStatus,
)


class StateStoreError(AgentOpsError):
    """The local state store could not satisfy an operation."""


class DuplicateRecordError(StateStoreError):
    """An immutable record already exists with the requested identity."""


class RecordNotFoundError(StateStoreError):
    """A requested immutable record does not exist."""


class InvalidStateTransition(ValidationError):
    """A run status transition violates the append-only lifecycle."""


class SecretPersistenceError(ValidationError):
    """A value that resembles credential material was rejected."""


@dataclass(frozen=True, slots=True)
class RunRecord:
    """Immutable metadata for one bounded runner attempt.

    Deliberately absent are the prompt, transcript, environment, and output.
    Those values may contain repository-private or credential material.
    """

    run_id: str
    task_id: str
    task_version: str
    runner_id: str
    workspace: str
    run_directory: str
    context_digest: str
    permission_class: PermissionClass
    timeout_seconds: int
    attempt: int
    created_at: float


@dataclass(frozen=True, slots=True)
class RunEventRecord:
    """One immutable event in a run's ordered audit trail."""

    sequence: int
    event_id: str
    run_id: str
    event_type: str
    status: RunStatus | None
    payload_json: str
    occurred_at: float

    @property
    def payload(self) -> Any:
        """Return a fresh decoded copy of the event's JSON payload."""

        return json.loads(self.payload_json)


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """Immutable metadata pointing at an artifact; content is not persisted."""

    artifact_id: str
    run_id: str
    kind: str
    path: str
    sha256: str
    media_type: str | None
    size_bytes: int | None
    created_at: float


@dataclass(frozen=True, slots=True)
class LeaseRecord:
    """Mutable, expiring coordination state used to prevent concurrent work."""

    lease_key: str
    owner_id: str
    acquired_at: float
    renewed_at: float
    expires_at: float


@dataclass(frozen=True, slots=True)
class ScheduleClaimRecord:
    """Immutable proof that a particular schedule slot was dispatched."""

    claim_id: str
    schedule_id: str
    slot_id: str
    scheduled_for: float
    claimed_at: float
    deadline_at: float
    owner_id: str
    lease_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BillingCapacityEventRecord:
    """One sanitized append-only included-capacity observation."""

    sequence: int
    event_id: str
    runner_id: str
    account_identity_fingerprint: str | None
    profile_id: str | None
    run_id: str | None
    capacity_state: CapacityState
    reason_code: str
    reset_at: float | None
    occurred_at: float


@dataclass(frozen=True, slots=True)
class BillingCircuitEventRecord:
    """One append-only transition for an account/profile billing breaker."""

    sequence: int
    event_id: str
    runner_id: str
    account_identity_fingerprint: str | None
    profile_id: str | None
    run_id: str | None
    state: CircuitBreakerState
    reason_code: str
    occurred_at: float


_SENSITIVE_KEY_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "cookie",
        "credentials",
        "credential",
        "password",
        "passwd",
        "private_key",
        "refresh_token",
        "secret",
        "session_token",
        "access_token",
        "token",
    }
)
_SENSITIVE_KEY_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_client_secret",
    "_credential",
    "_credentials",
    "_password",
    "_private_key",
    "_refresh_token",
    "_session_token",
    "_access_token",
    "_token",
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|password|client[_-]?secret)\s*[:=]\s*\S{8,}"),
)
_STATUS_TRANSITIONS: Mapping[RunStatus, frozenset[RunStatus]] = {
    RunStatus.CREATED: frozenset(
        {
            RunStatus.RUNNING,
            RunStatus.FAILED,
            RunStatus.BLOCKED,
            RunStatus.QUARANTINED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.RUNNING: frozenset(
        {
            RunStatus.SUCCEEDED,
            RunStatus.FAILED,
            RunStatus.BLOCKED,
            RunStatus.QUARANTINED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.BLOCKED: frozenset(
        {RunStatus.RUNNING, RunStatus.QUARANTINED, RunStatus.CANCELLED}
    ),
    RunStatus.SUCCEEDED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.QUARANTINED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
}


def _validate_text(value: str, field_name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    if len(value) > maximum:
        raise ValidationError(f"{field_name} exceeds {maximum} characters")
    if "\x00" in value or any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ValidationError(f"{field_name} contains control characters")
    _reject_secret_string(value, field_name)
    return value


def _validate_timestamp(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        raise ValidationError(f"{field_name} must be a non-negative finite number")
    return numeric


def _normalise_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")


def _reject_secret_string(value: str, location: str) -> None:
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(value):
            raise SecretPersistenceError(
                f"credential-like material rejected at {location}; value was not recorded"
            )


def _assert_secret_free(value: Any, location: str = "payload") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError(f"{location} contains a non-finite number")
        return
    if isinstance(value, str):
        _reject_secret_string(value, location)
        return
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"{location} contains a non-string object key")
            normalised = _normalise_key(key)
            if normalised in _SENSITIVE_KEY_NAMES or normalised.endswith(
                _SENSITIVE_KEY_SUFFIXES
            ):
                raise SecretPersistenceError(
                    f"sensitive field name rejected at {location}.{key}; value was not recorded"
                )
            _assert_secret_free(nested, f"{location}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _assert_secret_free(nested, f"{location}[{index}]")
        return
    raise ValidationError(f"{location} contains a non-JSON value of type {type(value).__name__}")


def _canonical_json(value: Any) -> str:
    _assert_secret_free(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValidationError("payload must be valid finite JSON") from error


class SQLiteStateStore:
    """Small SQLite repository with database-enforced audit immutability."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.database_path = str(database_path)
        self._clock = clock
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=timeout_seconds,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        try:
            if self.database_path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialise_schema()
        except BaseException:
            self._connection.close()
            raise

    def __enter__(self) -> SQLiteStateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _initialise_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            task_version TEXT NOT NULL,
            runner_id TEXT NOT NULL,
            workspace TEXT NOT NULL,
            run_directory TEXT NOT NULL,
            context_digest TEXT NOT NULL,
            permission_class INTEGER NOT NULL CHECK (permission_class IN (0, 1)),
            timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds > 0),
            attempt INTEGER NOT NULL CHECK (attempt > 0),
            created_at REAL NOT NULL CHECK (created_at >= 0)
        );

        CREATE TABLE IF NOT EXISTS run_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            event_type TEXT NOT NULL,
            status TEXT NULL CHECK (
                status IS NULL OR status IN (
                    'created', 'running', 'succeeded', 'failed',
                    'blocked', 'quarantined', 'cancelled'
                )
            ),
            payload_json TEXT NOT NULL,
            occurred_at REAL NOT NULL CHECK (occurred_at >= 0)
        );
        CREATE INDEX IF NOT EXISTS run_events_run_sequence
            ON run_events(run_id, sequence);

        CREATE TABLE IF NOT EXISTS run_artifacts (
            artifact_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            kind TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
            media_type TEXT NULL,
            size_bytes INTEGER NULL CHECK (size_bytes IS NULL OR size_bytes >= 0),
            created_at REAL NOT NULL CHECK (created_at >= 0)
        );
        CREATE INDEX IF NOT EXISTS run_artifacts_run
            ON run_artifacts(run_id, created_at, artifact_id);

        CREATE TABLE IF NOT EXISTS leases (
            lease_key TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            acquired_at REAL NOT NULL CHECK (acquired_at >= 0),
            renewed_at REAL NOT NULL CHECK (renewed_at >= acquired_at),
            expires_at REAL NOT NULL CHECK (expires_at > renewed_at)
        );

        CREATE TABLE IF NOT EXISTS schedule_claims (
            claim_id TEXT PRIMARY KEY,
            schedule_id TEXT NOT NULL,
            slot_id TEXT NOT NULL,
            scheduled_for REAL NOT NULL CHECK (scheduled_for >= 0),
            claimed_at REAL NOT NULL CHECK (claimed_at >= 0),
            deadline_at REAL NOT NULL CHECK (deadline_at > claimed_at),
            owner_id TEXT NOT NULL,
            lease_keys_json TEXT NOT NULL,
            UNIQUE(schedule_id, slot_id)
        );
        CREATE INDEX IF NOT EXISTS schedule_claims_schedule
            ON schedule_claims(schedule_id, scheduled_for, claim_id);

        CREATE TABLE IF NOT EXISTS billing_capacity_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            runner_id TEXT NOT NULL,
            account_identity_fingerprint TEXT NULL CHECK (
                account_identity_fingerprint IS NULL OR
                length(account_identity_fingerprint) = 64
            ),
            profile_id TEXT NULL,
            run_id TEXT NULL,
            capacity_state TEXT NOT NULL CHECK (
                capacity_state IN (
                    'available', 'limit_reached', 'blocked_until_reset',
                    'cooldown', 'unknown', 'not_applicable'
                )
            ),
            reason_code TEXT NOT NULL,
            reset_at REAL NULL CHECK (reset_at IS NULL OR reset_at >= 0),
            occurred_at REAL NOT NULL CHECK (occurred_at >= 0)
        );
        CREATE INDEX IF NOT EXISTS billing_capacity_scope_sequence
            ON billing_capacity_events(
                runner_id, account_identity_fingerprint, profile_id, sequence
            );

        CREATE TABLE IF NOT EXISTS billing_circuit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            runner_id TEXT NOT NULL,
            account_identity_fingerprint TEXT NULL CHECK (
                account_identity_fingerprint IS NULL OR
                length(account_identity_fingerprint) = 64
            ),
            profile_id TEXT NULL,
            run_id TEXT NULL,
            state TEXT NOT NULL CHECK (state IN ('open', 'closed')),
            reason_code TEXT NOT NULL,
            occurred_at REAL NOT NULL CHECK (occurred_at >= 0)
        );
        CREATE INDEX IF NOT EXISTS billing_circuit_scope_sequence
            ON billing_circuit_events(
                runner_id, account_identity_fingerprint, profile_id, sequence
            );

        CREATE TRIGGER IF NOT EXISTS runs_no_update
        BEFORE UPDATE ON runs BEGIN
            SELECT RAISE(ABORT, 'runs are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS runs_no_delete
        BEFORE DELETE ON runs BEGIN
            SELECT RAISE(ABORT, 'runs are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS run_events_no_update
        BEFORE UPDATE ON run_events BEGIN
            SELECT RAISE(ABORT, 'run events are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS run_events_no_delete
        BEFORE DELETE ON run_events BEGIN
            SELECT RAISE(ABORT, 'run events are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS run_artifacts_no_update
        BEFORE UPDATE ON run_artifacts BEGIN
            SELECT RAISE(ABORT, 'run artifacts are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS run_artifacts_no_delete
        BEFORE DELETE ON run_artifacts BEGIN
            SELECT RAISE(ABORT, 'run artifacts are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS schedule_claims_no_update
        BEFORE UPDATE ON schedule_claims BEGIN
            SELECT RAISE(ABORT, 'schedule claims are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS schedule_claims_no_delete
        BEFORE DELETE ON schedule_claims BEGIN
            SELECT RAISE(ABORT, 'schedule claims are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS billing_capacity_events_no_update
        BEFORE UPDATE ON billing_capacity_events BEGIN
            SELECT RAISE(ABORT, 'billing capacity events are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS billing_capacity_events_no_delete
        BEFORE DELETE ON billing_capacity_events BEGIN
            SELECT RAISE(ABORT, 'billing capacity events are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS billing_circuit_events_no_update
        BEFORE UPDATE ON billing_circuit_events BEGIN
            SELECT RAISE(ABORT, 'billing circuit events are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS billing_circuit_events_no_delete
        BEFORE DELETE ON billing_circuit_events BEGIN
            SELECT RAISE(ABORT, 'billing circuit events are append-only');
        END;
        """
        with self._lock:
            self._connection.executescript(schema)

    def create_run(self, record: RunRecord) -> RunRecord:
        """Append a run and its initial ``created`` status atomically."""

        self._validate_run(record)
        event_id = f"{record.run_id}:created:{uuid4().hex}"
        with self._transaction() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO runs (
                        run_id, task_id, task_version, runner_id, workspace,
                        run_directory, context_digest, permission_class,
                        timeout_seconds, attempt, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.run_id,
                        record.task_id,
                        record.task_version,
                        record.runner_id,
                        record.workspace,
                        record.run_directory,
                        record.context_digest,
                        int(record.permission_class),
                        record.timeout_seconds,
                        record.attempt,
                        record.created_at,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO run_events (
                        event_id, run_id, event_type, status, payload_json, occurred_at
                    ) VALUES (?, ?, 'status', ?, '{}', ?)
                    """,
                    (event_id, record.run_id, RunStatus.CREATED.value, record.created_at),
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateRecordError(
                    f"run already exists or violates an immutable constraint: {record.run_id}"
                ) from error
        return record

    def create_run_from_request(
        self,
        request: RunRequest,
        *,
        runner_id: str,
        context_digest: str,
        created_at: float | None = None,
    ) -> RunRecord:
        """Persist only the safe metadata subset of a :class:`RunRequest`."""

        record = RunRecord(
            run_id=request.run_id,
            task_id=request.task_id,
            task_version=request.task_version,
            runner_id=runner_id,
            workspace=str(request.workspace),
            run_directory=str(request.run_directory),
            context_digest=context_digest,
            permission_class=request.permission_class,
            timeout_seconds=request.timeout_seconds,
            attempt=request.attempt,
            created_at=self._now(created_at),
        )
        return self.create_run(record)

    def _validate_run(self, record: RunRecord) -> None:
        for field_name in (
            "run_id",
            "task_id",
            "task_version",
            "runner_id",
            "workspace",
            "run_directory",
            "context_digest",
        ):
            _validate_text(str(getattr(record, field_name)), field_name)
        if record.permission_class not in (
            PermissionClass.READ_ONLY,
            PermissionClass.LOCAL_DRAFT,
        ):
            raise ValidationError("only permission classes 0 and 1 may be persisted")
        if isinstance(record.timeout_seconds, bool) or record.timeout_seconds <= 0:
            raise ValidationError("timeout_seconds must be a positive integer")
        if isinstance(record.attempt, bool) or record.attempt <= 0:
            raise ValidationError("attempt must be a positive integer")
        _validate_timestamp(record.created_at, "created_at")

    def get_run(self, run_id: str) -> RunRecord:
        _validate_text(run_id, "run_id")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"run not found: {run_id}")
        return self._run_from_row(row)

    def list_runs(self, *, task_id: str | None = None) -> tuple[RunRecord, ...]:
        with self._lock:
            if task_id is None:
                rows = self._connection.execute(
                    "SELECT * FROM runs ORDER BY created_at, run_id"
                ).fetchall()
            else:
                _validate_text(task_id, "task_id")
                rows = self._connection.execute(
                    "SELECT * FROM runs WHERE task_id = ? ORDER BY created_at, run_id",
                    (task_id,),
                ).fetchall()
        return tuple(self._run_from_row(row) for row in rows)

    def append_event(
        self,
        run_id: str,
        event_type: str,
        payload: Any | None = None,
        *,
        status: RunStatus | None = None,
        event_id: str | None = None,
        occurred_at: float | None = None,
    ) -> RunEventRecord:
        """Append an event, validating status transitions inside one transaction."""

        _validate_text(run_id, "run_id")
        _validate_text(event_type, "event_type", maximum=256)
        selected_event_id = event_id or uuid4().hex
        _validate_text(selected_event_id, "event_id")
        payload_json = _canonical_json({} if payload is None else payload)
        timestamp = self._now(occurred_at)
        if status is not None and not isinstance(status, RunStatus):
            raise ValidationError("status must be a RunStatus")

        with self._transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone() is None:
                raise RecordNotFoundError(f"run not found: {run_id}")
            if status is not None:
                current = connection.execute(
                    """
                    SELECT status FROM run_events
                    WHERE run_id = ? AND status IS NOT NULL
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (run_id,),
                ).fetchone()
                if current is None:
                    raise StateStoreError(f"run has no initial status event: {run_id}")
                current_status = RunStatus(current["status"])
                if status not in _STATUS_TRANSITIONS[current_status]:
                    raise InvalidStateTransition(
                        f"invalid run transition {current_status.value} -> {status.value}"
                    )
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO run_events (
                        event_id, run_id, event_type, status, payload_json, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        selected_event_id,
                        run_id,
                        event_type,
                        None if status is None else status.value,
                        payload_json,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateRecordError(f"event already exists: {selected_event_id}") from error
            sequence = int(cursor.lastrowid)
        return RunEventRecord(
            sequence=sequence,
            event_id=selected_event_id,
            run_id=run_id,
            event_type=event_type,
            status=status,
            payload_json=payload_json,
            occurred_at=timestamp,
        )

    def current_status(self, run_id: str) -> RunStatus:
        _validate_text(run_id, "run_id")
        with self._lock:
            row = self._connection.execute(
                """
                SELECT status FROM run_events
                WHERE run_id = ? AND status IS NOT NULL
                ORDER BY sequence DESC LIMIT 1
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"run not found or has no status: {run_id}")
        return RunStatus(row["status"])

    def list_events(self, run_id: str) -> tuple[RunEventRecord, ...]:
        _validate_text(run_id, "run_id")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM run_events WHERE run_id = ? ORDER BY sequence",
                (run_id,),
            ).fetchall()
        return tuple(self._event_from_row(row) for row in rows)

    def append_artifact(self, record: ArtifactRecord) -> ArtifactRecord:
        """Append safe artifact metadata without reading or storing its content."""

        for field_name in ("artifact_id", "run_id", "kind", "path"):
            _validate_text(str(getattr(record, field_name)), field_name)
        if not re.fullmatch(r"[0-9a-f]{64}", record.sha256):
            raise ValidationError("sha256 must be 64 lowercase hexadecimal characters")
        if record.media_type is not None:
            _validate_text(record.media_type, "media_type", maximum=256)
        if record.size_bytes is not None and (
            isinstance(record.size_bytes, bool) or record.size_bytes < 0
        ):
            raise ValidationError("size_bytes must be a non-negative integer or None")
        _validate_timestamp(record.created_at, "created_at")

        with self._transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (record.run_id,)
            ).fetchone() is None:
                raise RecordNotFoundError(f"run not found: {record.run_id}")
            try:
                connection.execute(
                    """
                    INSERT INTO run_artifacts (
                        artifact_id, run_id, kind, path, sha256,
                        media_type, size_bytes, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.artifact_id,
                        record.run_id,
                        record.kind,
                        record.path,
                        record.sha256,
                        record.media_type,
                        record.size_bytes,
                        record.created_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateRecordError(
                    f"artifact already exists: {record.artifact_id}"
                ) from error
        return record

    def list_artifacts(self, run_id: str) -> tuple[ArtifactRecord, ...]:
        _validate_text(run_id, "run_id")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM run_artifacts
                WHERE run_id = ? ORDER BY created_at, artifact_id
                """,
                (run_id,),
            ).fetchall()
        return tuple(self._artifact_from_row(row) for row in rows)

    def try_acquire_lease(
        self,
        lease_key: str,
        owner_id: str,
        ttl_seconds: float,
        *,
        now: float | None = None,
    ) -> LeaseRecord | None:
        """Acquire an absent/expired lease, or renew one already owned."""

        _validate_text(lease_key, "lease_key")
        _validate_text(owner_id, "owner_id")
        timestamp = self._now(now)
        ttl = self._positive_duration(ttl_seconds, "ttl_seconds")
        expires_at = timestamp + ttl
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE lease_key = ?", (lease_key,)
            ).fetchone()
            if row is not None and row["expires_at"] > timestamp and row["owner_id"] != owner_id:
                return None
            acquired_at = timestamp if row is None or row["owner_id"] != owner_id else row["acquired_at"]
            connection.execute(
                """
                INSERT INTO leases (lease_key, owner_id, acquired_at, renewed_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(lease_key) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    acquired_at = excluded.acquired_at,
                    renewed_at = excluded.renewed_at,
                    expires_at = excluded.expires_at
                """,
                (lease_key, owner_id, acquired_at, timestamp, expires_at),
            )
        return LeaseRecord(lease_key, owner_id, acquired_at, timestamp, expires_at)

    def get_lease(
        self, lease_key: str, *, now: float | None = None, include_expired: bool = False
    ) -> LeaseRecord | None:
        _validate_text(lease_key, "lease_key")
        timestamp = self._now(now)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM leases WHERE lease_key = ?", (lease_key,)
            ).fetchone()
        if row is None or (not include_expired and row["expires_at"] <= timestamp):
            return None
        return self._lease_from_row(row)

    def release_lease(self, lease_key: str, owner_id: str) -> bool:
        _validate_text(lease_key, "lease_key")
        _validate_text(owner_id, "owner_id")
        with self._transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                (lease_key, owner_id),
            )
        return cursor.rowcount == 1

    def release_leases(self, lease_keys: Iterable[str], owner_id: str) -> int:
        keys = tuple(dict.fromkeys(lease_keys))
        for key in keys:
            _validate_text(key, "lease_key")
        _validate_text(owner_id, "owner_id")
        with self._transaction() as connection:
            released = 0
            for key in keys:
                cursor = connection.execute(
                    "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                    (key, owner_id),
                )
                released += cursor.rowcount
        return released

    def assert_billing_capacity_clear(
        self,
        *,
        runner_id: str,
        account_identity_fingerprint: str | None,
        profile_id: str | None,
        assessment_capacity_state: CapacityState,
        capacity_observed_at: float | None,
        now: float | None = None,
    ) -> None:
        """Read-only durable capacity check for routing and preflight.

        Unlike dispatch reservation, this method never appends recovery
        evidence.  The later atomic reservation repeats the check and records
        any successful re-verification before it acquires its leases.
        """

        self._validate_billing_scope(
            runner_id,
            account_identity_fingerprint,
            profile_id,
            None,
        )
        if not isinstance(assessment_capacity_state, CapacityState):
            raise ValidationError(
                "assessment_capacity_state must be a CapacityState"
            )
        timestamp = self._now(now)
        observed_at = (
            None
            if capacity_observed_at is None
            else _validate_timestamp(capacity_observed_at, "capacity_observed_at")
        )
        scopes = tuple(
            dict.fromkeys(
                (
                    (None, None),
                    (None, profile_id),
                    (account_identity_fingerprint, None),
                    (account_identity_fingerprint, profile_id),
                )
            )
        )
        with self._lock:
            blocking_capacity_rows = self._latest_blocking_capacity_rows(
                self._connection,
                runner_id=runner_id,
                scopes=scopes,
            )
        if blocking_capacity_rows and not self._capacity_is_reverified(
            blocking_capacity_rows,
            assessment_capacity_state=assessment_capacity_state,
            capacity_observed_at=observed_at,
            now=timestamp,
        ):
            raise BillingRouteBlocked(
                "Live subscription execution is blocked by durable capacity state."
            )

    def try_reserve_billing_dispatch(
        self,
        *,
        runner_id: str,
        account_identity_fingerprint: str,
        profile_id: str | None,
        owner_id: str,
        ttl_seconds: float,
        assessment_capacity_state: CapacityState = CapacityState.UNKNOWN,
        capacity_observed_at: float | None = None,
        now: float | None = None,
        reservation_id: str | None = None,
    ) -> BillingDispatchReservation | None:
        """Atomically check billing state and reserve capacity scopes.

        Returning ``None`` means another live dispatch already owns either the
        account scope or the selected profile scope.  An open breaker or
        unreverified durable capacity block raises ``BillingRouteBlocked``.
        The method never waits for an existing lease to expire and never
        performs a model or provider operation.
        """

        self._validate_billing_scope(
            runner_id,
            account_identity_fingerprint,
            profile_id,
            None,
        )
        if account_identity_fingerprint is None:
            raise ValidationError(
                "a verified account fingerprint is required for billing dispatch"
            )
        _validate_text(owner_id, "owner_id", maximum=256)
        selected_reservation_id = reservation_id or uuid4().hex
        _validate_text(selected_reservation_id, "reservation_id", maximum=256)
        timestamp = self._now(now)
        ttl = self._positive_duration(ttl_seconds, "ttl_seconds")
        if not isinstance(assessment_capacity_state, CapacityState):
            raise ValidationError(
                "assessment_capacity_state must be a CapacityState"
            )
        observed_at = (
            None
            if capacity_observed_at is None
            else _validate_timestamp(capacity_observed_at, "capacity_observed_at")
        )
        expires_at = timestamp + ttl
        lease_keys = self._billing_dispatch_lease_keys(
            runner_id=runner_id,
            account_identity_fingerprint=account_identity_fingerprint,
            profile_id=profile_id,
        )
        scopes = tuple(
            dict.fromkeys(
                (
                    (None, None),
                    (None, profile_id),
                    (account_identity_fingerprint, None),
                    (account_identity_fingerprint, profile_id),
                )
            )
        )

        with self._transaction() as connection:
            for fingerprint, selected_profile_id in scopes:
                current = connection.execute(
                    """
                    SELECT state FROM billing_circuit_events
                    WHERE runner_id = ?
                      AND (
                        account_identity_fingerprint = ? OR
                        (account_identity_fingerprint IS NULL AND ? IS NULL)
                      )
                      AND (
                        profile_id = ? OR (profile_id IS NULL AND ? IS NULL)
                      )
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (
                        runner_id,
                        fingerprint,
                        fingerprint,
                        selected_profile_id,
                        selected_profile_id,
                    ),
                ).fetchone()
                if current is not None and current["state"] == CircuitBreakerState.OPEN.value:
                    raise BillingRouteBlocked(
                        "Live subscription execution is blocked by a durable billing circuit."
                    )

            active_reservation = False
            expired_reservation = False
            for lease_key in lease_keys:
                lease = connection.execute(
                    "SELECT owner_id, expires_at FROM leases WHERE lease_key = ?",
                    (lease_key,),
                ).fetchone()
                if lease is not None:
                    if lease["expires_at"] > timestamp:
                        active_reservation = True
                    else:
                        expired_reservation = True

            if active_reservation:
                return None
            if expired_reservation:
                # A crashed process cannot provide postflight billing proof.
                # Convert its stale coordination record into durable broad and
                # account breakers rather than silently recycling the lease.
                stale_scopes = tuple(
                    dict.fromkeys(
                        (
                            (account_identity_fingerprint, None),
                            (account_identity_fingerprint, profile_id),
                            (None, None),
                            (None, profile_id),
                        )
                    )
                )
                for fingerprint, selected_profile_id in stale_scopes:
                    connection.execute(
                        """
                        INSERT INTO billing_circuit_events (
                            event_id, runner_id, account_identity_fingerprint,
                            profile_id, run_id, state, reason_code, occurred_at
                        ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?)
                        """,
                        (
                            uuid4().hex,
                            runner_id,
                            fingerprint,
                            selected_profile_id,
                            CircuitBreakerState.OPEN.value,
                            "billing_dispatch_reservation_expired",
                            timestamp,
                        ),
                    )
                for lease_key in lease_keys:
                    connection.execute(
                        "DELETE FROM leases WHERE lease_key = ? AND expires_at <= ?",
                        (lease_key, timestamp),
                    )
            else:
                blocking_capacity_rows = self._latest_blocking_capacity_rows(
                    connection,
                    runner_id=runner_id,
                    scopes=scopes,
                )

                if blocking_capacity_rows:
                    reverified = self._capacity_is_reverified(
                        blocking_capacity_rows,
                        assessment_capacity_state=assessment_capacity_state,
                        capacity_observed_at=observed_at,
                        now=timestamp,
                    )
                    if not reverified:
                        raise BillingRouteBlocked(
                            "Live subscription execution is blocked by durable capacity state."
                        )
                    for row in blocking_capacity_rows:
                        connection.execute(
                            """
                            INSERT INTO billing_capacity_events (
                                event_id, runner_id,
                                account_identity_fingerprint, profile_id,
                                run_id, capacity_state, reason_code, reset_at,
                                occurred_at
                            ) VALUES (?, ?, ?, ?, NULL, ?, ?, NULL, ?)
                            """,
                            (
                                uuid4().hex,
                                runner_id,
                                row["account_identity_fingerprint"],
                                row["profile_id"],
                                CapacityState.AVAILABLE.value,
                                "preflight_capacity_reverified",
                                observed_at,
                            ),
                        )

                for lease_key in lease_keys:
                    connection.execute(
                        """
                        INSERT INTO leases (
                            lease_key, owner_id, acquired_at, renewed_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(lease_key) DO UPDATE SET
                            owner_id = excluded.owner_id,
                            acquired_at = excluded.acquired_at,
                            renewed_at = excluded.renewed_at,
                            expires_at = excluded.expires_at
                        """,
                        (lease_key, owner_id, timestamp, timestamp, expires_at),
                    )

        if expired_reservation:
            raise BillingRouteBlocked(
                "Live subscription execution is blocked after an expired billing reservation."
            )

        return BillingDispatchReservation(
            reservation_id=selected_reservation_id,
            runner_id=runner_id,
            account_identity_fingerprint=account_identity_fingerprint,
            profile_id=profile_id,
            owner_id=owner_id,
            lease_keys=lease_keys,
            acquired_at=timestamp,
            expires_at=expires_at,
        )

    def complete_billing_dispatch(
        self,
        reservation: BillingDispatchReservation,
        *,
        run_id: str,
        capacity_state: CapacityState,
        capacity_reason_code: str,
        circuit_breaker_required: bool,
        broad_scope_required: bool,
        reason_code: str,
        now: float | None = None,
    ) -> None:
        """Open any required breaker before atomically releasing a reservation.

        Losing or outliving the reservation is itself unsafe.  In that case a
        profile-wide breaker is opened before the method raises, ensuring a
        later dispatch fails closed after the coordination fault is observed.
        """

        if not isinstance(reservation, BillingDispatchReservation):
            raise ValidationError("reservation must be a BillingDispatchReservation")
        self._validate_billing_scope(
            reservation.runner_id,
            reservation.account_identity_fingerprint,
            reservation.profile_id,
            run_id,
        )
        _validate_text(reservation.reservation_id, "reservation_id", maximum=256)
        _validate_text(reservation.owner_id, "owner_id", maximum=256)
        if (
            not isinstance(capacity_state, CapacityState)
            or capacity_state is CapacityState.NOT_APPLICABLE
        ):
            raise ValidationError(
                "capacity_state must be an applicable CapacityState"
            )
        self._validate_reason_code(capacity_reason_code)
        if not isinstance(circuit_breaker_required, bool):
            raise ValidationError("circuit_breaker_required must be a boolean")
        if not isinstance(broad_scope_required, bool):
            raise ValidationError("broad_scope_required must be a boolean")
        self._validate_reason_code(reason_code)
        timestamp = self._now(now)
        expected_lease_keys = self._billing_dispatch_lease_keys(
            runner_id=reservation.runner_id,
            account_identity_fingerprint=reservation.account_identity_fingerprint,
            profile_id=reservation.profile_id,
        )
        if reservation.lease_keys != expected_lease_keys:
            raise ValidationError("billing dispatch reservation scope is invalid")

        reservation_lost = False
        with self._transaction() as connection:
            for lease_key in reservation.lease_keys:
                lease = connection.execute(
                    "SELECT owner_id, expires_at FROM leases WHERE lease_key = ?",
                    (lease_key,),
                ).fetchone()
                if (
                    lease is None
                    or lease["owner_id"] != reservation.owner_id
                    or lease["expires_at"] <= timestamp
                ):
                    reservation_lost = True

            selected_capacity_state = (
                CapacityState.UNKNOWN if reservation_lost else capacity_state
            )
            selected_capacity_reason = (
                "billing_dispatch_reservation_lost"
                if reservation_lost
                else capacity_reason_code
            )
            capacity_scopes: list[tuple[str | None, str | None]] = [
                (reservation.account_identity_fingerprint, None),
                (
                    reservation.account_identity_fingerprint,
                    reservation.profile_id,
                ),
            ]
            if reservation_lost:
                capacity_scopes.extend(
                    ((None, None), (None, reservation.profile_id))
                )
            for fingerprint, profile_id in tuple(dict.fromkeys(capacity_scopes)):
                connection.execute(
                    """
                    INSERT INTO billing_capacity_events (
                        event_id, runner_id, account_identity_fingerprint,
                        profile_id, run_id, capacity_state, reason_code,
                        reset_at, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
                    """,
                    (
                        uuid4().hex,
                        reservation.runner_id,
                        fingerprint,
                        profile_id,
                        run_id,
                        selected_capacity_state.value,
                        selected_capacity_reason,
                        timestamp,
                    ),
                )

            should_open = circuit_breaker_required or reservation_lost
            open_broad = broad_scope_required or reservation_lost
            selected_reason = (
                "billing_dispatch_reservation_lost"
                if reservation_lost
                else reason_code
            )
            if should_open:
                scopes: list[tuple[str | None, str | None]] = [
                    (reservation.account_identity_fingerprint, None),
                    (
                        reservation.account_identity_fingerprint,
                        reservation.profile_id,
                    )
                ]
                if open_broad:
                    scopes.append((None, None))
                    scopes.append((None, reservation.profile_id))
                for fingerprint, profile_id in tuple(dict.fromkeys(scopes)):
                    connection.execute(
                        """
                        INSERT INTO billing_circuit_events (
                            event_id, runner_id, account_identity_fingerprint,
                            profile_id, run_id, state, reason_code, occurred_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uuid4().hex,
                            reservation.runner_id,
                            fingerprint,
                            profile_id,
                            run_id,
                            CircuitBreakerState.OPEN.value,
                            selected_reason,
                            timestamp,
                        ),
                    )

            for lease_key in reservation.lease_keys:
                connection.execute(
                    "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                    (lease_key, reservation.owner_id),
                )

        if reservation_lost:
            raise StateStoreError(
                "billing dispatch reservation was lost before completion"
            )

    @staticmethod
    def _billing_dispatch_lease_keys(
        *,
        runner_id: str,
        account_identity_fingerprint: str,
        profile_id: str | None,
    ) -> tuple[str, ...]:
        profile_material = "<all-profiles>" if profile_id is None else profile_id
        profile_digest = hashlib.sha256(profile_material.encode("utf-8")).hexdigest()
        return tuple(
            sorted(
                (
                    f"billing-dispatch:v1:{runner_id}:account:{account_identity_fingerprint}",
                    f"billing-dispatch:v1:{runner_id}:profile:{profile_digest}",
                )
            )
        )

    @staticmethod
    def _latest_blocking_capacity_rows(
        connection: sqlite3.Connection,
        *,
        runner_id: str,
        scopes: Sequence[tuple[str | None, str | None]],
    ) -> list[sqlite3.Row]:
        blocking: list[sqlite3.Row] = []
        for fingerprint, profile_id in scopes:
            capacity = connection.execute(
                """
                SELECT * FROM billing_capacity_events
                WHERE runner_id = ?
                  AND (
                    account_identity_fingerprint = ? OR
                    (account_identity_fingerprint IS NULL AND ? IS NULL)
                  )
                  AND (
                    profile_id = ? OR (profile_id IS NULL AND ? IS NULL)
                  )
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    runner_id,
                    fingerprint,
                    fingerprint,
                    profile_id,
                    profile_id,
                ),
            ).fetchone()
            if capacity is not None and CapacityState(
                capacity["capacity_state"]
            ) in {
                CapacityState.LIMIT_REACHED,
                CapacityState.BLOCKED_UNTIL_RESET,
                CapacityState.COOLDOWN,
                CapacityState.UNKNOWN,
            }:
                blocking.append(capacity)
        return blocking

    @staticmethod
    def _capacity_is_reverified(
        blocking_capacity_rows: Sequence[sqlite3.Row],
        *,
        assessment_capacity_state: CapacityState,
        capacity_observed_at: float | None,
        now: float,
    ) -> bool:
        return (
            assessment_capacity_state is CapacityState.AVAILABLE
            and capacity_observed_at is not None
            and capacity_observed_at <= now
            and all(
                capacity_observed_at > row["occurred_at"]
                and (
                    row["reset_at"] is None
                    or capacity_observed_at > row["reset_at"]
                )
                for row in blocking_capacity_rows
            )
        )

    def try_claim_schedule_slot(
        self,
        *,
        claim_id: str,
        schedule_id: str,
        slot_id: str,
        scheduled_for: float,
        claimed_at: float,
        deadline_at: float,
        owner_id: str,
        lease_keys: Sequence[str],
    ) -> ScheduleClaimRecord | None:
        """Atomically reserve a schedule slot and all requested resources.

        A slot remains claimed forever, preventing a completed or crashed job
        from being dispatched twice.  Resource leases may expire or be released
        and are therefore the only mutable rows involved.
        """

        for field_name, value in (
            ("claim_id", claim_id),
            ("schedule_id", schedule_id),
            ("slot_id", slot_id),
            ("owner_id", owner_id),
        ):
            _validate_text(value, field_name)
        scheduled = _validate_timestamp(scheduled_for, "scheduled_for")
        claimed = _validate_timestamp(claimed_at, "claimed_at")
        deadline = _validate_timestamp(deadline_at, "deadline_at")
        if deadline <= claimed:
            raise ValidationError("deadline_at must be later than claimed_at")
        keys = tuple(sorted(set(lease_keys)))
        if not keys:
            raise ValidationError("at least one lease key is required")
        if len(keys) != len(tuple(lease_keys)):
            raise ValidationError("lease_keys must be unique")
        for key in keys:
            _validate_text(key, "lease_key")
        lease_keys_json = _canonical_json(keys)

        with self._transaction() as connection:
            duplicate = connection.execute(
                """
                SELECT 1 FROM schedule_claims
                WHERE schedule_id = ? AND slot_id = ?
                """,
                (schedule_id, slot_id),
            ).fetchone()
            if duplicate is not None:
                return None
            for key in keys:
                lease = connection.execute(
                    "SELECT * FROM leases WHERE lease_key = ?", (key,)
                ).fetchone()
                if lease is not None and lease["expires_at"] > claimed:
                    return None
            for key in keys:
                connection.execute(
                    """
                    INSERT INTO leases (
                        lease_key, owner_id, acquired_at, renewed_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(lease_key) DO UPDATE SET
                        owner_id = excluded.owner_id,
                        acquired_at = excluded.acquired_at,
                        renewed_at = excluded.renewed_at,
                        expires_at = excluded.expires_at
                    """,
                    (key, owner_id, claimed, claimed, deadline),
                )
            try:
                connection.execute(
                    """
                    INSERT INTO schedule_claims (
                        claim_id, schedule_id, slot_id, scheduled_for, claimed_at,
                        deadline_at, owner_id, lease_keys_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        schedule_id,
                        slot_id,
                        scheduled,
                        claimed,
                        deadline,
                        owner_id,
                        lease_keys_json,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateRecordError(f"schedule claim already exists: {claim_id}") from error
        return ScheduleClaimRecord(
            claim_id=claim_id,
            schedule_id=schedule_id,
            slot_id=slot_id,
            scheduled_for=scheduled,
            claimed_at=claimed,
            deadline_at=deadline,
            owner_id=owner_id,
            lease_keys=keys,
        )

    def get_schedule_claim(
        self, schedule_id: str, slot_id: str
    ) -> ScheduleClaimRecord | None:
        _validate_text(schedule_id, "schedule_id")
        _validate_text(slot_id, "slot_id")
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM schedule_claims
                WHERE schedule_id = ? AND slot_id = ?
                """,
                (schedule_id, slot_id),
            ).fetchone()
        return None if row is None else self._claim_from_row(row)

    def list_schedule_claims(
        self, *, schedule_id: str | None = None
    ) -> tuple[ScheduleClaimRecord, ...]:
        with self._lock:
            if schedule_id is None:
                rows = self._connection.execute(
                    "SELECT * FROM schedule_claims ORDER BY scheduled_for, claim_id"
                ).fetchall()
            else:
                _validate_text(schedule_id, "schedule_id")
                rows = self._connection.execute(
                    """
                    SELECT * FROM schedule_claims
                    WHERE schedule_id = ? ORDER BY scheduled_for, claim_id
                    """,
                    (schedule_id,),
                ).fetchall()
        return tuple(self._claim_from_row(row) for row in rows)

    def append_billing_capacity_event(
        self,
        *,
        runner_id: str,
        capacity_state: CapacityState,
        reason_code: str,
        account_identity_fingerprint: str | None = None,
        profile_id: str | None = None,
        run_id: str | None = None,
        reset_at: float | None = None,
        event_id: str | None = None,
        occurred_at: float | None = None,
    ) -> BillingCapacityEventRecord:
        """Append sanitized capacity state; numeric balances are not accepted."""

        self._validate_billing_scope(
            runner_id,
            account_identity_fingerprint,
            profile_id,
            run_id,
        )
        if not isinstance(capacity_state, CapacityState):
            raise ValidationError("capacity_state must be a CapacityState")
        self._validate_reason_code(reason_code)
        selected_event_id = event_id or uuid4().hex
        _validate_text(selected_event_id, "event_id")
        timestamp = self._now(occurred_at)
        selected_reset = (
            None if reset_at is None else _validate_timestamp(reset_at, "reset_at")
        )
        if selected_reset is not None and selected_reset <= timestamp:
            raise ValidationError("reset_at must be later than occurred_at")
        with self._transaction() as connection:
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO billing_capacity_events (
                        event_id, runner_id, account_identity_fingerprint,
                        profile_id, run_id, capacity_state, reason_code,
                        reset_at, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        selected_event_id,
                        runner_id,
                        account_identity_fingerprint,
                        profile_id,
                        run_id,
                        capacity_state.value,
                        reason_code,
                        selected_reset,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateRecordError(
                    f"billing capacity event already exists: {selected_event_id}"
                ) from error
        return BillingCapacityEventRecord(
            sequence=int(cursor.lastrowid),
            event_id=selected_event_id,
            runner_id=runner_id,
            account_identity_fingerprint=account_identity_fingerprint,
            profile_id=profile_id,
            run_id=run_id,
            capacity_state=capacity_state,
            reason_code=reason_code,
            reset_at=selected_reset,
            occurred_at=timestamp,
        )

    def latest_billing_capacity_event(
        self,
        *,
        runner_id: str,
        account_identity_fingerprint: str | None = None,
        profile_id: str | None = None,
    ) -> BillingCapacityEventRecord | None:
        self._validate_billing_scope(
            runner_id,
            account_identity_fingerprint,
            profile_id,
            None,
        )
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM billing_capacity_events
                WHERE runner_id = ?
                  AND (
                    account_identity_fingerprint = ? OR
                    (account_identity_fingerprint IS NULL AND ? IS NULL)
                  )
                  AND (profile_id = ? OR (profile_id IS NULL AND ? IS NULL))
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    runner_id,
                    account_identity_fingerprint,
                    account_identity_fingerprint,
                    profile_id,
                    profile_id,
                ),
            ).fetchone()
        return None if row is None else self._billing_capacity_from_row(row)

    def append_billing_circuit_event(
        self,
        *,
        runner_id: str,
        state: CircuitBreakerState,
        reason_code: str,
        account_identity_fingerprint: str | None = None,
        profile_id: str | None = None,
        run_id: str | None = None,
        event_id: str | None = None,
        occurred_at: float | None = None,
    ) -> BillingCircuitEventRecord:
        """Open or explicitly close a durable append-only billing breaker."""

        self._validate_billing_scope(
            runner_id,
            account_identity_fingerprint,
            profile_id,
            run_id,
        )
        if not isinstance(state, CircuitBreakerState):
            raise ValidationError("state must be a CircuitBreakerState")
        self._validate_reason_code(reason_code)
        selected_event_id = event_id or uuid4().hex
        _validate_text(selected_event_id, "event_id")
        timestamp = self._now(occurred_at)
        with self._transaction() as connection:
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO billing_circuit_events (
                        event_id, runner_id, account_identity_fingerprint,
                        profile_id, run_id, state, reason_code, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        selected_event_id,
                        runner_id,
                        account_identity_fingerprint,
                        profile_id,
                        run_id,
                        state.value,
                        reason_code,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateRecordError(
                    f"billing circuit event already exists: {selected_event_id}"
                ) from error
        return BillingCircuitEventRecord(
            sequence=int(cursor.lastrowid),
            event_id=selected_event_id,
            runner_id=runner_id,
            account_identity_fingerprint=account_identity_fingerprint,
            profile_id=profile_id,
            run_id=run_id,
            state=state,
            reason_code=reason_code,
            occurred_at=timestamp,
        )

    def current_billing_circuit(
        self,
        *,
        runner_id: str,
        account_identity_fingerprint: str | None = None,
        profile_id: str | None = None,
    ) -> BillingCircuitEventRecord | None:
        self._validate_billing_scope(
            runner_id,
            account_identity_fingerprint,
            profile_id,
            None,
        )
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM billing_circuit_events
                WHERE runner_id = ?
                  AND (
                    account_identity_fingerprint = ? OR
                    (account_identity_fingerprint IS NULL AND ? IS NULL)
                  )
                  AND (profile_id = ? OR (profile_id IS NULL AND ? IS NULL))
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    runner_id,
                    account_identity_fingerprint,
                    account_identity_fingerprint,
                    profile_id,
                    profile_id,
                ),
            ).fetchone()
        return None if row is None else self._billing_circuit_from_row(row)

    @staticmethod
    def _validate_billing_scope(
        runner_id: str,
        account_identity_fingerprint: str | None,
        profile_id: str | None,
        run_id: str | None,
    ) -> None:
        _validate_text(runner_id, "runner_id", maximum=128)
        if account_identity_fingerprint is not None and re.fullmatch(
            r"[0-9a-f]{64}", account_identity_fingerprint
        ) is None:
            raise ValidationError(
                "account_identity_fingerprint must be 64 lowercase hexadecimal characters"
            )
        if profile_id is not None:
            _validate_text(profile_id, "profile_id", maximum=256)
        if run_id is not None:
            _validate_text(run_id, "run_id", maximum=256)

    @staticmethod
    def _validate_reason_code(reason_code: str) -> None:
        if not isinstance(reason_code, str) or re.fullmatch(
            r"[a-z0-9_]{1,100}", reason_code
        ) is None:
            raise ValidationError("reason_code must be bounded snake_case")

    def _now(self, supplied: float | None) -> float:
        return _validate_timestamp(self._clock() if supplied is None else supplied, "timestamp")

    @staticmethod
    def _positive_duration(value: float, field_name: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"{field_name} must be a positive finite number")
        numeric = float(value)
        if not math.isfinite(numeric) or numeric <= 0:
            raise ValidationError(f"{field_name} must be a positive finite number")
        return numeric

    @staticmethod
    def _run_from_row(row: sqlite3.Row) -> RunRecord:
        return RunRecord(
            run_id=row["run_id"],
            task_id=row["task_id"],
            task_version=row["task_version"],
            runner_id=row["runner_id"],
            workspace=row["workspace"],
            run_directory=row["run_directory"],
            context_digest=row["context_digest"],
            permission_class=PermissionClass(row["permission_class"]),
            timeout_seconds=row["timeout_seconds"],
            attempt=row["attempt"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> RunEventRecord:
        return RunEventRecord(
            sequence=row["sequence"],
            event_id=row["event_id"],
            run_id=row["run_id"],
            event_type=row["event_type"],
            status=None if row["status"] is None else RunStatus(row["status"]),
            payload_json=row["payload_json"],
            occurred_at=row["occurred_at"],
        )

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> ArtifactRecord:
        return ArtifactRecord(
            artifact_id=row["artifact_id"],
            run_id=row["run_id"],
            kind=row["kind"],
            path=row["path"],
            sha256=row["sha256"],
            media_type=row["media_type"],
            size_bytes=row["size_bytes"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _lease_from_row(row: sqlite3.Row) -> LeaseRecord:
        return LeaseRecord(
            lease_key=row["lease_key"],
            owner_id=row["owner_id"],
            acquired_at=row["acquired_at"],
            renewed_at=row["renewed_at"],
            expires_at=row["expires_at"],
        )

    @staticmethod
    def _claim_from_row(row: sqlite3.Row) -> ScheduleClaimRecord:
        raw_keys = json.loads(row["lease_keys_json"])
        return ScheduleClaimRecord(
            claim_id=row["claim_id"],
            schedule_id=row["schedule_id"],
            slot_id=row["slot_id"],
            scheduled_for=row["scheduled_for"],
            claimed_at=row["claimed_at"],
            deadline_at=row["deadline_at"],
            owner_id=row["owner_id"],
            lease_keys=tuple(raw_keys),
        )

    @staticmethod
    def _billing_capacity_from_row(row: sqlite3.Row) -> BillingCapacityEventRecord:
        return BillingCapacityEventRecord(
            sequence=row["sequence"],
            event_id=row["event_id"],
            runner_id=row["runner_id"],
            account_identity_fingerprint=row["account_identity_fingerprint"],
            profile_id=row["profile_id"],
            run_id=row["run_id"],
            capacity_state=CapacityState(row["capacity_state"]),
            reason_code=row["reason_code"],
            reset_at=row["reset_at"],
            occurred_at=row["occurred_at"],
        )

    @staticmethod
    def _billing_circuit_from_row(row: sqlite3.Row) -> BillingCircuitEventRecord:
        return BillingCircuitEventRecord(
            sequence=row["sequence"],
            event_id=row["event_id"],
            runner_id=row["runner_id"],
            account_identity_fingerprint=row["account_identity_fingerprint"],
            profile_id=row["profile_id"],
            run_id=row["run_id"],
            state=CircuitBreakerState(row["state"]),
            reason_code=row["reason_code"],
            occurred_at=row["occurred_at"],
        )


class SQLiteBillingCircuitGuard:
    """Serialize live billing scopes and enforce durable breakers."""

    def __init__(
        self,
        store: SQLiteStateStore,
        *,
        profile_id: str | None = None,
    ) -> None:
        self.store = store
        self.profile_id = profile_id

    def assert_closed(self, assessment: BillingRouteAssessment) -> None:
        scopes = (
            (None, None),
            (None, self.profile_id),
            (assessment.account_identity_fingerprint, None),
            (assessment.account_identity_fingerprint, self.profile_id),
        )
        for fingerprint, profile_id in dict.fromkeys(scopes):
            current = self.store.current_billing_circuit(
                runner_id=assessment.runner_id,
                account_identity_fingerprint=fingerprint,
                profile_id=profile_id,
            )
            if current is not None and current.state is CircuitBreakerState.OPEN:
                raise BillingRouteBlocked(
                    "Live subscription execution is blocked by a durable billing circuit."
                )
        self.store.assert_billing_capacity_clear(
            runner_id=assessment.runner_id,
            account_identity_fingerprint=(
                assessment.account_identity_fingerprint
            ),
            profile_id=self.profile_id,
            assessment_capacity_state=assessment.capacity_state,
            capacity_observed_at=assessment.capacity_observed_at,
        )

    def reserve_dispatch(
        self,
        assessment: BillingRouteAssessment,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> BillingDispatchReservation | None:
        """Check all breaker scopes and acquire the dispatch leases atomically."""

        _validate_text(owner_id, "owner_id", maximum=256)
        fingerprint = assessment.account_identity_fingerprint
        if fingerprint is None:
            raise BillingRouteBlocked(
                "Live subscription execution requires a verified account scope."
            )
        reservation_id = uuid4().hex
        owner_digest = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()[:16]
        lease_owner = f"billing/{owner_digest}/{reservation_id}"
        return self.store.try_reserve_billing_dispatch(
            runner_id=assessment.runner_id,
            account_identity_fingerprint=fingerprint,
            profile_id=self.profile_id,
            owner_id=lease_owner,
            ttl_seconds=ttl_seconds,
            assessment_capacity_state=assessment.capacity_state,
            capacity_observed_at=assessment.capacity_observed_at,
            reservation_id=reservation_id,
        )

    def complete_dispatch(
        self,
        reservation: BillingDispatchReservation,
        *,
        run_id: str,
        capacity_state: CapacityState,
        capacity_reason_code: str,
        circuit_breaker_required: bool,
        broad_scope_required: bool,
        reason_code: str,
    ) -> None:
        """Persist an unsafe disposition, if any, before releasing leases."""

        self.store.complete_billing_dispatch(
            reservation,
            run_id=run_id,
            capacity_state=capacity_state,
            capacity_reason_code=capacity_reason_code,
            circuit_breaker_required=circuit_breaker_required,
            broad_scope_required=broad_scope_required,
            reason_code=reason_code,
        )


__all__ = [
    "ArtifactRecord",
    "BillingCapacityEventRecord",
    "BillingCircuitEventRecord",
    "DuplicateRecordError",
    "InvalidStateTransition",
    "LeaseRecord",
    "RecordNotFoundError",
    "RunEventRecord",
    "RunRecord",
    "SQLiteStateStore",
    "SQLiteBillingCircuitGuard",
    "ScheduleClaimRecord",
    "SecretPersistenceError",
    "StateStoreError",
]
