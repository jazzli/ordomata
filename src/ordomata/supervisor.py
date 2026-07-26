"""Durable foreground-supervisor control-plane primitives.

This module is deliberately narrower than the eventual worker supervisor.  It
persists mock-only flow specifications, optimistic flow/control revisions,
sticky cancellation, fenced attempt claims, and an internal completion outbox.
It does not dispatch a harness.  Runtime ABAC enforcement remains a prerequisite
for connecting these primitives to a worker executor.

The state database stores only bounded metadata and digests.  Prompts,
transcripts, artifact contents, credentials, and arbitrary paths are excluded.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any, Iterator
from urllib.parse import quote
from uuid import uuid4

from .errors import OrdomataError, ConfigurationError, ValidationError
from .authorization import (
    ActionAttributes,
    ActionVerb,
    AttributeEvidence,
    AuthorizationRequest,
    BlastRadius,
    CircuitState,
    ConsequenceVector,
    EnvironmentAttributes,
    EvidenceSource,
    ImpactLevel,
    IsolationState,
    NetworkState,
    PolicyBundle,
    Reach,
    ResourceAttributes,
    Role,
    ShadowAuthorizationEvaluator,
    SubjectAttributes,
    canonical_digest,
)
from .models import (
    BillingRoute,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
)
from .state import SQLiteStateStore, _canonical_json
from .schema import parse_json_document


class SupervisorError(OrdomataError):
    """The durable supervisor could not complete an expected operation."""


class StaleRevisionError(SupervisorError):
    """An optimistic write was based on a stale control or flow revision."""


class AdmissionConflictError(SupervisorError):
    """An admission key was replayed with different immutable inputs."""


class ClaimLostError(SupervisorError):
    """An attempt no longer owns every unexpired lease in its claim."""


class StaleReconciliationPlanError(SupervisorError):
    """The database no longer matches a previously inspected recovery plan."""


class FlowState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING = "waiting"
    BLOCKED = "blocked"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LOST = "lost"


class AttemptState(StrEnum):
    CREATED = "created"
    DISPATCHING = "dispatching"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LOST = "lost"


class SupervisorMode(StrEnum):
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    DRAINING = "draining"
    STOP_REQUESTED = "stop_requested"


_FINAL_FLOW_STATES = frozenset(
    {
        FlowState.SUCCEEDED,
        FlowState.FAILED,
        FlowState.TIMED_OUT,
        FlowState.CANCELLED,
    }
)
_FLOW_TRANSITIONS: Mapping[FlowState, frozenset[FlowState]] = {
    FlowState.QUEUED: frozenset(
        {FlowState.RUNNING, FlowState.TIMED_OUT, FlowState.CANCELLED}
    ),
    FlowState.RUNNING: frozenset(
        {
            FlowState.SUCCEEDED,
            FlowState.FAILED,
            FlowState.TIMED_OUT,
            FlowState.WAITING,
            FlowState.BLOCKED,
            FlowState.CANCELLED,
            FlowState.LOST,
        }
    ),
    FlowState.WAITING: frozenset({FlowState.QUEUED, FlowState.CANCELLED}),
    FlowState.BLOCKED: frozenset({FlowState.QUEUED, FlowState.CANCELLED}),
    FlowState.LOST: frozenset({FlowState.QUEUED, FlowState.CANCELLED}),
    FlowState.SUCCEEDED: frozenset(),
    FlowState.FAILED: frozenset(),
    FlowState.TIMED_OUT: frozenset(),
    FlowState.CANCELLED: frozenset(),
}
_CONTROL_TRANSITIONS: Mapping[SupervisorMode, frozenset[SupervisorMode]] = {
    SupervisorMode.STOPPED: frozenset({SupervisorMode.RUNNING}),
    SupervisorMode.RUNNING: frozenset(
        {
            SupervisorMode.PAUSED,
            SupervisorMode.DRAINING,
            SupervisorMode.STOP_REQUESTED,
        }
    ),
    SupervisorMode.PAUSED: frozenset(
        {
            SupervisorMode.RUNNING,
            SupervisorMode.DRAINING,
            SupervisorMode.STOP_REQUESTED,
        }
    ),
    SupervisorMode.DRAINING: frozenset({SupervisorMode.STOPPED}),
    SupervisorMode.STOP_REQUESTED: frozenset({SupervisorMode.STOPPED}),
}
_TERMINAL_ATTEMPT_FOR_FLOW: Mapping[FlowState, AttemptState] = {
    FlowState.SUCCEEDED: AttemptState.SUCCEEDED,
    FlowState.FAILED: AttemptState.FAILED,
    FlowState.BLOCKED: AttemptState.BLOCKED,
    FlowState.TIMED_OUT: AttemptState.TIMED_OUT,
    FlowState.CANCELLED: AttemptState.CANCELLED,
    FlowState.LOST: AttemptState.LOST,
    FlowState.WAITING: AttemptState.BLOCKED,
}
_REASON_CODE = re.compile(r"[a-z0-9_]{1,100}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_RESOURCE_KEY = re.compile(r"[a-z0-9][a-z0-9._:/-]{0,199}")
_MAX_JSON_BYTES = 262_144
_SCHEMA_VERSION = 3
_FOREGROUND_LEASE_KEY = "supervisor:foreground"


@dataclass(frozen=True, slots=True)
class FlowSpec:
    flow_id: str
    admission_key: str
    task_id: str
    task_version: str
    task_definition_digest: str
    context_digest: str
    runner_id: str
    profile_id: str
    permission_class: PermissionClass
    resource_keys: tuple[str, ...]
    available_at: float
    deadline_at: float | None
    attempt_timeout_seconds: int = 600
    mandatory_priority: int = 0
    blocker_priority: int = 0
    value_priority: int = 0
    evidence_priority: int = 0
    capacity_fit_priority: int = 0
    max_attempts: int = 1
    created_at: float = 0.0

    def immutable_mapping(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_version": self.task_version,
            "task_definition_digest": self.task_definition_digest,
            "context_digest": self.context_digest,
            "runner_id": self.runner_id,
            "profile_id": self.profile_id,
            "permission_class": int(self.permission_class),
            "resource_keys": list(self.resource_keys),
            "available_at": self.available_at,
            "deadline_at": self.deadline_at,
            "attempt_timeout_seconds": self.attempt_timeout_seconds,
            "mandatory_priority": self.mandatory_priority,
            "blocker_priority": self.blocker_priority,
            "value_priority": self.value_priority,
            "evidence_priority": self.evidence_priority,
            "capacity_fit_priority": self.capacity_fit_priority,
            "max_attempts": self.max_attempts,
        }

    @property
    def request_digest(self) -> str:
        return _sha256_text(_canonical_json(self.immutable_mapping()))


@dataclass(frozen=True, slots=True)
class FlowRevision:
    sequence: int
    event_id: str
    flow_id: str
    revision: int
    state: FlowState
    cancellation_requested: bool
    active_attempt_id: str | None
    reason_code: str
    occurred_at: float


@dataclass(frozen=True, slots=True)
class SupervisorAuthorizationObservation:
    sequence: int
    observation_id: str
    boundary: str
    flow_id: str
    request_digest: str
    decision_digest: str
    effect: str
    derived_permission_class: PermissionClass
    legacy_executable: bool
    execution_parity: bool
    payload: Mapping[str, Any]
    observed_at: float


@dataclass(frozen=True, slots=True)
class SupervisorAuthorizationFinding:
    code: str
    flow_id: str | None
    boundary: str | None
    observation_sequence: int | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "flow_id": self.flow_id,
            "boundary": self.boundary,
            "observation_sequence": self.observation_sequence,
        }


@dataclass(frozen=True, slots=True)
class SupervisorAuthorizationAudit:
    database_present: bool
    schema_present: bool
    observation_count: int
    expected_observation_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]

    @property
    def clean(self) -> bool:
        return not self.findings

    def to_mapping(self) -> dict[str, Any]:
        return {
            "database_present": self.database_present,
            "schema_present": self.schema_present,
            "observation_count": self.observation_count,
            "expected_observation_count": self.expected_observation_count,
            "finding_count": len(self.findings),
            "clean": self.clean,
            "findings": [finding.to_mapping() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class SupervisorControlRevision:
    sequence: int
    event_id: str
    revision: int
    mode: SupervisorMode
    actor_id: str
    reason_code: str
    occurred_at: float


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    attempt_id: str
    flow_id: str
    attempt_number: int
    run_id: str
    claimed_revision: int
    lease_owner: str
    lease_keys: tuple[str, ...]
    input_digest: str
    deadline_at: float
    created_at: float


@dataclass(frozen=True, slots=True)
class AttemptEvent:
    sequence: int
    event_id: str
    attempt_id: str
    revision: int
    state: AttemptState
    reason_code: str
    occurred_at: float


@dataclass(frozen=True, slots=True)
class AttemptClaim:
    flow: FlowSpec
    flow_revision: FlowRevision
    attempt: AttemptRecord


@dataclass(frozen=True, slots=True)
class CompletionIntent:
    outbox_id: str
    idempotency_key: str
    flow_id: str
    source_revision: int
    attempt_id: str | None
    envelope_json: str
    intent_digest: str
    operation_digest: str
    created_at: float

    @property
    def envelope(self) -> Any:
        return json.loads(self.envelope_json)


@dataclass(frozen=True, slots=True)
class CompletionReceipt:
    receipt_id: str
    outbox_id: str
    idempotency_key: str
    consumer_id: str
    result_digest: str
    delivered_at: float


@dataclass(frozen=True, slots=True)
class ReconciliationFinding:
    finding_id: str
    kind: str
    reason_code: str
    flow_id: str | None
    attempt_id: str | None
    expected_revision: int | None
    action: str | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "kind": self.kind,
            "reason_code": self.reason_code,
            "flow_id": self.flow_id,
            "attempt_id": self.attempt_id,
            "expected_revision": self.expected_revision,
            "action": self.action,
            "actionable": self.action is not None,
        }


@dataclass(frozen=True, slots=True)
class ReconciliationPlan:
    database_present: bool
    observed_at: float
    findings: tuple[ReconciliationFinding, ...]
    plan_digest: str

    @property
    def actionable_count(self) -> int:
        return sum(finding.action is not None for finding in self.findings)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "database_present": self.database_present,
            "observed_at": self.observed_at,
            "plan_digest": self.plan_digest,
            "finding_count": len(self.findings),
            "actionable_count": self.actionable_count,
            "findings": [finding.to_mapping() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class SupervisorStatus:
    database_present: bool
    schema_present: bool
    control_revision: int
    mode: SupervisorMode
    flow_counts: Mapping[str, int]
    pending_completion_count: int
    foreground_lease_active: bool
    dispatch_enabled: bool = False

    def to_mapping(self) -> dict[str, Any]:
        return {
            "database_present": self.database_present,
            "schema_present": self.schema_present,
            "control_revision": self.control_revision,
            "mode": self.mode.value,
            "flow_counts": dict(self.flow_counts),
            "pending_completion_count": self.pending_completion_count,
            "foreground_lease_active": self.foreground_lease_active,
            "dispatch_enabled": self.dispatch_enabled,
            "dispatch_blocker": "runtime_abac_enforcement_not_implemented",
        }


_MIGRATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS state_schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE,
    script_sha256 TEXT NOT NULL CHECK (length(script_sha256) = 64),
    applied_at REAL NOT NULL CHECK (applied_at >= 0)
);
CREATE TRIGGER IF NOT EXISTS state_schema_migrations_no_update
BEFORE UPDATE ON state_schema_migrations BEGIN
    SELECT RAISE(ABORT, 'schema migrations are append-only');
END;
CREATE TRIGGER IF NOT EXISTS state_schema_migrations_no_delete
BEFORE DELETE ON state_schema_migrations BEGIN
    SELECT RAISE(ABORT, 'schema migrations are append-only');
END;
"""


_SCHEMA_V2 = """
CREATE TABLE supervisor_control_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    mode TEXT NOT NULL CHECK (
        mode IN ('stopped', 'running', 'paused', 'draining', 'stop_requested')
    ),
    actor_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    occurred_at REAL NOT NULL CHECK (occurred_at >= 0)
);

CREATE TABLE supervisor_flows (
    flow_id TEXT PRIMARY KEY,
    admission_key TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    task_id TEXT NOT NULL,
    task_version TEXT NOT NULL,
    task_definition_digest TEXT NOT NULL CHECK (length(task_definition_digest) = 64),
    context_digest TEXT NOT NULL CHECK (length(context_digest) = 64),
    runner_id TEXT NOT NULL CHECK (runner_id = 'mock'),
    profile_id TEXT NOT NULL,
    permission_class INTEGER NOT NULL CHECK (permission_class IN (0, 1)),
    resource_keys_json TEXT NOT NULL CHECK (length(resource_keys_json) <= 262144),
    available_at REAL NOT NULL CHECK (available_at >= 0),
    deadline_at REAL NULL CHECK (deadline_at IS NULL OR deadline_at >= 0),
    attempt_timeout_seconds INTEGER NOT NULL CHECK (attempt_timeout_seconds > 0),
    mandatory_priority INTEGER NOT NULL CHECK (mandatory_priority IN (0, 1)),
    blocker_priority INTEGER NOT NULL CHECK (blocker_priority IN (0, 1)),
    value_priority INTEGER NOT NULL CHECK (value_priority BETWEEN 0 AND 100),
    evidence_priority INTEGER NOT NULL CHECK (evidence_priority BETWEEN 0 AND 100),
    capacity_fit_priority INTEGER NOT NULL CHECK (capacity_fit_priority BETWEEN 0 AND 100),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    created_at REAL NOT NULL CHECK (created_at >= 0)
);

CREATE TABLE supervisor_flow_revisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (
        state IN ('queued', 'running', 'waiting', 'blocked', 'succeeded',
                  'failed', 'timed_out', 'cancelled', 'lost')
    ),
    cancellation_requested INTEGER NOT NULL CHECK (cancellation_requested IN (0, 1)),
    active_attempt_id TEXT NULL,
    reason_code TEXT NOT NULL,
    occurred_at REAL NOT NULL CHECK (occurred_at >= 0),
    UNIQUE(flow_id, revision)
);
CREATE INDEX supervisor_flow_revisions_head
    ON supervisor_flow_revisions(flow_id, revision DESC);

CREATE TABLE supervisor_cancellation_requests (
    request_id TEXT PRIMARY KEY,
    flow_id TEXT NOT NULL UNIQUE REFERENCES supervisor_flows(flow_id),
    reason_code TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at REAL NOT NULL CHECK (requested_at >= 0)
);

CREATE TABLE supervisor_attempts (
    attempt_id TEXT PRIMARY KEY,
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    run_id TEXT NOT NULL UNIQUE,
    claimed_revision INTEGER NOT NULL CHECK (claimed_revision > 0),
    lease_owner TEXT NOT NULL UNIQUE,
    lease_keys_json TEXT NOT NULL CHECK (length(lease_keys_json) <= 262144),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    deadline_at REAL NOT NULL CHECK (deadline_at >= 0),
    created_at REAL NOT NULL CHECK (created_at >= 0),
    UNIQUE(flow_id, attempt_number)
);

CREATE TABLE supervisor_attempt_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL REFERENCES supervisor_attempts(attempt_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (
        state IN ('created', 'dispatching', 'running', 'succeeded', 'failed',
                  'blocked', 'timed_out', 'cancelled', 'lost')
    ),
    reason_code TEXT NOT NULL,
    occurred_at REAL NOT NULL CHECK (occurred_at >= 0),
    UNIQUE(attempt_id, revision)
);

CREATE TABLE supervisor_completion_outbox (
    outbox_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
    attempt_id TEXT NULL REFERENCES supervisor_attempts(attempt_id),
    envelope_json TEXT NOT NULL CHECK (length(envelope_json) <= 262144),
    intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 64),
    operation_digest TEXT NOT NULL CHECK (length(operation_digest) = 64),
    created_at REAL NOT NULL CHECK (created_at >= 0),
    UNIQUE(flow_id, source_revision)
);

CREATE TABLE supervisor_completion_delivery_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    outbox_id TEXT NOT NULL REFERENCES supervisor_completion_outbox(outbox_id),
    delivery_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('delivered', 'failed', 'unknown')),
    reason_code TEXT NOT NULL,
    occurred_at REAL NOT NULL CHECK (occurred_at >= 0),
    UNIQUE(outbox_id, delivery_id)
);

CREATE TABLE supervisor_completion_receipts (
    receipt_id TEXT PRIMARY KEY,
    outbox_id TEXT NOT NULL UNIQUE REFERENCES supervisor_completion_outbox(outbox_id),
    idempotency_key TEXT NOT NULL UNIQUE,
    consumer_id TEXT NOT NULL,
    result_digest TEXT NOT NULL CHECK (length(result_digest) = 64),
    delivered_at REAL NOT NULL CHECK (delivered_at >= 0)
);

CREATE TRIGGER supervisor_control_revision_contiguous
BEFORE INSERT ON supervisor_control_events
WHEN NEW.revision != COALESCE(
    (SELECT MAX(revision) + 1 FROM supervisor_control_events), 1
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor control revision is not contiguous');
END;
CREATE TRIGGER supervisor_control_transition_valid
BEFORE INSERT ON supervisor_control_events
WHEN NEW.revision > 1 AND NOT EXISTS (
    SELECT 1 FROM supervisor_control_events old
    WHERE old.revision = NEW.revision - 1 AND (
        (old.mode = 'stopped' AND NEW.mode = 'running') OR
        (old.mode = 'running' AND NEW.mode IN (
            'paused', 'draining', 'stop_requested'
        )) OR
        (old.mode = 'paused' AND NEW.mode IN (
            'running', 'draining', 'stop_requested'
        )) OR
        (old.mode IN ('draining', 'stop_requested') AND NEW.mode = 'stopped')
    )
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor control transition is invalid');
END;
CREATE TRIGGER supervisor_control_initial_mode
BEFORE INSERT ON supervisor_control_events
WHEN NEW.revision = 1 AND NEW.mode != 'running'
BEGIN
    SELECT RAISE(ABORT, 'supervisor control initial mode is invalid');
END;
CREATE TRIGGER supervisor_flow_revision_contiguous
BEFORE INSERT ON supervisor_flow_revisions
WHEN NEW.revision != COALESCE(
    (SELECT MAX(revision) + 1 FROM supervisor_flow_revisions
     WHERE flow_id = NEW.flow_id), 1
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor flow revision is not contiguous');
END;
CREATE TRIGGER supervisor_flow_initial_state
BEFORE INSERT ON supervisor_flow_revisions
WHEN NEW.revision = 1 AND (
    NEW.state != 'queued' OR NEW.cancellation_requested != 0 OR
    NEW.active_attempt_id IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor flow initial state is invalid');
END;
CREATE TRIGGER supervisor_flow_cancellation_sticky
BEFORE INSERT ON supervisor_flow_revisions
WHEN NEW.revision > 1 AND NEW.cancellation_requested < (
    SELECT cancellation_requested FROM supervisor_flow_revisions
    WHERE flow_id = NEW.flow_id ORDER BY revision DESC LIMIT 1
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor flow cancellation is sticky');
END;
CREATE TRIGGER supervisor_flow_active_attempt_shape
BEFORE INSERT ON supervisor_flow_revisions
WHEN (NEW.state = 'running' AND NEW.active_attempt_id IS NULL)
   OR (NEW.state != 'running' AND NEW.active_attempt_id IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'supervisor flow active attempt shape is invalid');
END;
CREATE TRIGGER supervisor_flow_transition_valid
BEFORE INSERT ON supervisor_flow_revisions
WHEN NEW.revision > 1 AND NOT EXISTS (
    SELECT 1 FROM supervisor_flow_revisions old
    WHERE old.flow_id = NEW.flow_id AND old.revision = NEW.revision - 1 AND (
        (old.state = 'queued' AND NEW.state IN (
            'running', 'timed_out', 'cancelled'
        )) OR
        (old.state = 'running' AND NEW.state IN (
            'succeeded', 'failed', 'timed_out', 'waiting', 'blocked',
            'cancelled', 'lost'
        )) OR
        (old.state = 'running' AND NEW.state = 'running'
            AND old.cancellation_requested = 0
            AND NEW.cancellation_requested = 1
            AND old.active_attempt_id = NEW.active_attempt_id) OR
        (old.state IN ('waiting', 'blocked', 'lost')
            AND NEW.state IN ('queued', 'cancelled'))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor flow transition is invalid');
END;
CREATE TRIGGER supervisor_attempt_revision_contiguous
BEFORE INSERT ON supervisor_attempt_events
WHEN NEW.revision != COALESCE(
    (SELECT MAX(revision) + 1 FROM supervisor_attempt_events
     WHERE attempt_id = NEW.attempt_id), 1
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt revision is not contiguous');
END;
CREATE TRIGGER supervisor_attempt_initial_state
BEFORE INSERT ON supervisor_attempt_events
WHEN NEW.revision = 1 AND NEW.state != 'created'
BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt initial state is invalid');
END;
CREATE TRIGGER supervisor_attempt_transition_valid
BEFORE INSERT ON supervisor_attempt_events
WHEN NEW.revision > 1 AND NOT EXISTS (
    SELECT 1 FROM supervisor_attempt_events old
    WHERE old.attempt_id = NEW.attempt_id AND old.revision = NEW.revision - 1 AND (
        (old.state = 'created' AND NEW.state IN (
            'dispatching', 'succeeded', 'failed', 'blocked',
            'timed_out', 'cancelled', 'lost'
        )) OR
        (old.state = 'dispatching' AND NEW.state IN (
            'running', 'succeeded', 'failed', 'blocked',
            'timed_out', 'cancelled', 'lost'
        )) OR
        (old.state = 'running' AND NEW.state IN (
            'succeeded', 'failed', 'blocked', 'timed_out', 'cancelled', 'lost'
        ))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt transition is invalid');
END;

CREATE TRIGGER supervisor_control_events_no_update
BEFORE UPDATE ON supervisor_control_events BEGIN
    SELECT RAISE(ABORT, 'supervisor control events are append-only');
END;
CREATE TRIGGER supervisor_control_events_no_delete
BEFORE DELETE ON supervisor_control_events BEGIN
    SELECT RAISE(ABORT, 'supervisor control events are append-only');
END;
CREATE TRIGGER supervisor_flows_no_update
BEFORE UPDATE ON supervisor_flows BEGIN
    SELECT RAISE(ABORT, 'supervisor flows are append-only');
END;
CREATE TRIGGER supervisor_flows_no_delete
BEFORE DELETE ON supervisor_flows BEGIN
    SELECT RAISE(ABORT, 'supervisor flows are append-only');
END;
CREATE TRIGGER supervisor_flow_revisions_no_update
BEFORE UPDATE ON supervisor_flow_revisions BEGIN
    SELECT RAISE(ABORT, 'supervisor flow revisions are append-only');
END;
CREATE TRIGGER supervisor_flow_revisions_no_delete
BEFORE DELETE ON supervisor_flow_revisions BEGIN
    SELECT RAISE(ABORT, 'supervisor flow revisions are append-only');
END;
CREATE TRIGGER supervisor_cancellation_requests_no_update
BEFORE UPDATE ON supervisor_cancellation_requests BEGIN
    SELECT RAISE(ABORT, 'supervisor cancellation requests are append-only');
END;
CREATE TRIGGER supervisor_cancellation_requests_no_delete
BEFORE DELETE ON supervisor_cancellation_requests BEGIN
    SELECT RAISE(ABORT, 'supervisor cancellation requests are append-only');
END;
CREATE TRIGGER supervisor_attempts_no_update
BEFORE UPDATE ON supervisor_attempts BEGIN
    SELECT RAISE(ABORT, 'supervisor attempts are append-only');
END;
CREATE TRIGGER supervisor_attempts_no_delete
BEFORE DELETE ON supervisor_attempts BEGIN
    SELECT RAISE(ABORT, 'supervisor attempts are append-only');
END;
CREATE TRIGGER supervisor_attempt_events_no_update
BEFORE UPDATE ON supervisor_attempt_events BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt events are append-only');
END;
CREATE TRIGGER supervisor_attempt_events_no_delete
BEFORE DELETE ON supervisor_attempt_events BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt events are append-only');
END;
CREATE TRIGGER supervisor_completion_outbox_no_update
BEFORE UPDATE ON supervisor_completion_outbox BEGIN
    SELECT RAISE(ABORT, 'supervisor completion outbox is append-only');
END;
CREATE TRIGGER supervisor_completion_outbox_no_delete
BEFORE DELETE ON supervisor_completion_outbox BEGIN
    SELECT RAISE(ABORT, 'supervisor completion outbox is append-only');
END;
CREATE TRIGGER supervisor_completion_delivery_events_no_update
BEFORE UPDATE ON supervisor_completion_delivery_events BEGIN
    SELECT RAISE(ABORT, 'supervisor completion delivery events are append-only');
END;
CREATE TRIGGER supervisor_completion_delivery_events_no_delete
BEFORE DELETE ON supervisor_completion_delivery_events BEGIN
    SELECT RAISE(ABORT, 'supervisor completion delivery events are append-only');
END;
CREATE TRIGGER supervisor_completion_receipts_no_update
BEFORE UPDATE ON supervisor_completion_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor completion receipts are append-only');
END;
CREATE TRIGGER supervisor_completion_receipts_no_delete
BEFORE DELETE ON supervisor_completion_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor completion receipts are append-only');
END;
"""


_SCHEMA_V3 = """
CREATE TABLE supervisor_authorization_shadow_baseline (
    entity_type TEXT NOT NULL CHECK (entity_type IN ('flow', 'attempt')),
    entity_id TEXT NOT NULL,
    PRIMARY KEY(entity_type, entity_id)
);
INSERT INTO supervisor_authorization_shadow_baseline (entity_type, entity_id)
    SELECT 'flow', flow_id FROM supervisor_flows;
INSERT INTO supervisor_authorization_shadow_baseline (entity_type, entity_id)
    SELECT 'attempt', attempt_id FROM supervisor_attempts;

CREATE TABLE supervisor_authorization_observations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id TEXT NOT NULL UNIQUE,
    boundary TEXT NOT NULL CHECK (boundary IN ('flow_admission', 'attempt_claim')),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    effect TEXT NOT NULL CHECK (effect IN ('permit', 'defer', 'deny', 'indeterminate')),
    derived_permission_class INTEGER NOT NULL CHECK (derived_permission_class IN (0, 1)),
    legacy_executable INTEGER NOT NULL CHECK (legacy_executable IN (0, 1)),
    execution_parity INTEGER NOT NULL CHECK (execution_parity IN (0, 1)),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    observed_at REAL NOT NULL CHECK (observed_at >= 0)
);
CREATE INDEX supervisor_authorization_observations_flow
    ON supervisor_authorization_observations(flow_id, sequence);
CREATE TRIGGER supervisor_authorization_observations_no_update
BEFORE UPDATE ON supervisor_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor authorization observations are append-only');
END;
CREATE TRIGGER supervisor_authorization_observations_no_delete
BEFORE DELETE ON supervisor_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor authorization observations are append-only');
END;
CREATE TRIGGER supervisor_authorization_shadow_baseline_no_update
BEFORE UPDATE ON supervisor_authorization_shadow_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_authorization_shadow_baseline_no_delete
BEFORE DELETE ON supervisor_authorization_shadow_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_authorization_shadow_baseline_no_insert
BEFORE INSERT ON supervisor_authorization_shadow_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor authorization baseline is frozen');
END;
"""


class SQLiteSupervisorStore:
    """Supervisor-specific event store sharing the existing local SQLite file."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = 5.0,
        id_factory: Callable[[], str] = lambda: uuid4().hex,
    ) -> None:
        self.database_path = str(database_path)
        if self.database_path == ":memory:":
            raise ConfigurationError(
                "the durable supervisor requires a file-backed SQLite database"
            )
        database = Path(database_path)
        if database.is_symlink() or database.parent.is_symlink():
            raise ConfigurationError(
                "the supervisor database and its parent must not be symlinks"
            )
        self._clock = clock
        self._id_factory = id_factory
        self._lock = threading.RLock()
        # Establish and validate the current baseline before applying the
        # additive supervisor migration.  No existing table is widened.
        try:
            with SQLiteStateStore(
                database_path,
                clock=clock,
                timeout_seconds=timeout_seconds,
            ):
                pass
        except sqlite3.Error as error:
            raise ConfigurationError(
                "supervisor state baseline is unreadable or malformed"
            ) from error
        try:
            self._connection = sqlite3.connect(
                self.database_path,
                timeout=timeout_seconds,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as error:
            raise ConfigurationError("supervisor state database could not be opened") from error
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialise_migrations()
        except BaseException as error:
            self._connection.close()
            if isinstance(error, sqlite3.Error):
                raise ConfigurationError(
                    "supervisor state is unreadable or malformed"
                ) from error
            raise

    def __enter__(self) -> SQLiteSupervisorStore:
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

    def _initialise_migrations(self) -> None:
        with self._lock:
            self._connection.executescript(
                "BEGIN IMMEDIATE;\n" + _MIGRATION_SCHEMA + "\nCOMMIT;"
            )
            _verify_migration_schema(self._connection)
            versions = {
                int(row["version"]): row
                for row in self._connection.execute(
                    "SELECT * FROM state_schema_migrations ORDER BY version"
                ).fetchall()
            }
            if versions and max(versions) > _SCHEMA_VERSION:
                raise ConfigurationError("state database uses an unsupported future schema")
            baseline_tables = {
                "runs",
                "run_events",
                "run_artifacts",
                "leases",
                "schedule_claims",
                "billing_capacity_events",
                "billing_circuit_events",
            }
            present = {
                row["name"]
                for row in self._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if not baseline_tables.issubset(present):
                raise ConfigurationError("state database baseline is incomplete")
            _verify_baseline_schema(self._connection)
            now = self._now(None)
            # Frozen pre-rename migration identity. Existing ledgers verify
            # this exact digest, so changing the spelling would strand state.
            baseline_digest = _sha256_text("agentops-baseline-schema-v1")
            if 1 not in versions:
                self._connection.execute(
                    """
                    INSERT INTO state_schema_migrations (
                        version, name, script_sha256, applied_at
                    ) VALUES (1, 'baseline_state', ?, ?)
                    """,
                    (baseline_digest, now),
                )
            elif (
                versions[1]["name"] != "baseline_state"
                or versions[1]["script_sha256"] != baseline_digest
            ):
                raise ConfigurationError("baseline schema migration record is invalid")
            migration_digest = _sha256_text(_SCHEMA_V2)
            if 2 not in versions:
                escaped_digest = migration_digest.replace("'", "''")
                self._connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + _SCHEMA_V2
                    + "\nINSERT INTO state_schema_migrations "
                    "(version, name, script_sha256, applied_at) VALUES "
                    f"(2, 'supervisor_control_plane', '{escaped_digest}', {now!r});\n"
                    "COMMIT;"
                )
            else:
                if (
                    versions[2]["name"] != "supervisor_control_plane"
                    or versions[2]["script_sha256"] != migration_digest
                ):
                    raise ConfigurationError("supervisor schema migration digest mismatch")
                required = {
                    "supervisor_control_events",
                    "supervisor_flows",
                    "supervisor_flow_revisions",
                    "supervisor_cancellation_requests",
                    "supervisor_attempts",
                    "supervisor_attempt_events",
                    "supervisor_completion_outbox",
                    "supervisor_completion_delivery_events",
                    "supervisor_completion_receipts",
                }
                if not required.issubset(present):
                    raise ConfigurationError("supervisor schema is incomplete")
            migration_v3_digest = _sha256_text(_SCHEMA_V3)
            if 3 not in versions:
                escaped_digest = migration_v3_digest.replace("'", "''")
                self._connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + _SCHEMA_V3
                    + "\nINSERT INTO state_schema_migrations "
                    "(version, name, script_sha256, applied_at) VALUES "
                    f"(3, 'supervisor_authorization_shadow', '{escaped_digest}', {now!r});\n"
                    "COMMIT;"
                )
            elif (
                versions[3]["name"] != "supervisor_authorization_shadow"
                or versions[3]["script_sha256"] != migration_v3_digest
            ):
                raise ConfigurationError(
                    "supervisor authorization schema migration digest mismatch"
                )
            _verify_supervisor_schema(self._connection)

    def current_control(self) -> SupervisorControlRevision:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM supervisor_control_events ORDER BY revision DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return SupervisorControlRevision(
                sequence=0,
                event_id="synthetic:stopped:0",
                revision=0,
                mode=SupervisorMode.STOPPED,
                actor_id="system",
                reason_code="initial_state",
                occurred_at=0.0,
            )
        return _control_from_row(row)

    def update_control(
        self,
        *,
        expected_revision: int,
        mode: SupervisorMode,
        actor_id: str,
        reason_code: str,
        occurred_at: float | None = None,
    ) -> SupervisorControlRevision:
        _validate_revision(expected_revision, allow_zero=True)
        if not isinstance(mode, SupervisorMode):
            raise ValidationError("mode must be a SupervisorMode")
        _validate_text(actor_id, "actor_id", maximum=256)
        _validate_reason(reason_code)
        timestamp = self._now(occurred_at)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_control_events ORDER BY revision DESC LIMIT 1"
            ).fetchone()
            current = (
                SupervisorControlRevision(
                    0, "synthetic:stopped:0", 0, SupervisorMode.STOPPED,
                    "system", "initial_state", 0.0
                )
                if row is None
                else _control_from_row(row)
            )
            if current.revision != expected_revision:
                raise StaleRevisionError("supervisor control revision is stale")
            if mode is current.mode:
                return current
            if mode not in _CONTROL_TRANSITIONS[current.mode]:
                raise ValidationError(
                    f"invalid supervisor transition {current.mode.value} -> {mode.value}"
                )
            event_id = self._new_id("control_event")
            revision = current.revision + 1
            cursor = connection.execute(
                """
                INSERT INTO supervisor_control_events (
                    event_id, revision, mode, actor_id, reason_code, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_id, revision, mode.value, actor_id, reason_code, timestamp),
            )
            sequence = int(cursor.lastrowid)
        return SupervisorControlRevision(
            sequence, event_id, revision, mode, actor_id, reason_code, timestamp
        )

    def admit_flow(self, spec: FlowSpec) -> tuple[FlowSpec, bool]:
        _validate_flow_spec(spec)
        resources_json = _bounded_json(list(spec.resource_keys), "resource_keys")
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM supervisor_flows WHERE admission_key = ?",
                (spec.admission_key,),
            ).fetchone()
            if existing is not None:
                stored = _flow_from_row(existing)
                if existing["request_digest"] != spec.request_digest:
                    raise AdmissionConflictError(
                        "admission key is already bound to different immutable inputs"
                    )
                return stored, False
            if connection.execute(
                "SELECT 1 FROM supervisor_flows WHERE flow_id = ?", (spec.flow_id,)
            ).fetchone() is not None:
                raise AdmissionConflictError("flow identifier already exists")
            connection.execute(
                """
                INSERT INTO supervisor_flows (
                    flow_id, admission_key, request_digest, task_id, task_version,
                    task_definition_digest, context_digest, runner_id, profile_id,
                    permission_class, resource_keys_json, available_at, deadline_at,
                    attempt_timeout_seconds,
                    mandatory_priority, blocker_priority, value_priority,
                    evidence_priority, capacity_fit_priority, max_attempts, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    spec.flow_id, spec.admission_key, spec.request_digest, spec.task_id,
                    spec.task_version, spec.task_definition_digest, spec.context_digest,
                    spec.runner_id, spec.profile_id, int(spec.permission_class),
                    resources_json, spec.available_at, spec.deadline_at,
                    spec.attempt_timeout_seconds,
                    spec.mandatory_priority, spec.blocker_priority, spec.value_priority,
                    spec.evidence_priority, spec.capacity_fit_priority,
                    spec.max_attempts, spec.created_at,
                ),
            )
            self._insert_flow_revision(
                connection,
                flow_id=spec.flow_id,
                revision=1,
                state=FlowState.QUEUED,
                cancellation_requested=False,
                active_attempt_id=None,
                reason_code="admitted",
                occurred_at=spec.created_at,
            )
            try:
                self._append_authorization_observation(
                    connection,
                    boundary="flow_admission",
                    spec=spec,
                    observed_at=spec.created_at,
                    legacy_executable=True,
                )
            except Exception:
                # Shadow evidence is deliberately non-authoritative. The
                # existing validated admission remains the compatibility gate.
                pass
        return spec, True

    def get_flow(self, flow_id: str) -> FlowSpec:
        _validate_text(flow_id, "flow_id")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM supervisor_flows WHERE flow_id = ?", (flow_id,)
            ).fetchone()
        if row is None:
            raise SupervisorError("flow was not found")
        return _flow_from_row(row)

    def current_flow_revision(self, flow_id: str) -> FlowRevision:
        _validate_text(flow_id, "flow_id")
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM supervisor_flow_revisions
                WHERE flow_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (flow_id,),
            ).fetchone()
        if row is None:
            raise SupervisorError("flow was not found")
        return _flow_revision_from_row(row)

    def list_flow_revisions(self, flow_id: str) -> tuple[FlowRevision, ...]:
        _validate_text(flow_id, "flow_id")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM supervisor_flow_revisions
                WHERE flow_id = ? ORDER BY revision
                """,
                (flow_id,),
            ).fetchall()
        return tuple(_flow_revision_from_row(row) for row in rows)

    def list_authorization_observations(
        self, flow_id: str
    ) -> tuple[SupervisorAuthorizationObservation, ...]:
        _validate_text(flow_id, "flow_id")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM supervisor_authorization_observations
                WHERE flow_id = ? ORDER BY sequence
                """,
                (flow_id,),
            ).fetchall()
        return tuple(_authorization_observation_from_row(row) for row in rows)

    def flow_state_counts(self) -> dict[str, int]:
        """Return the current event-sourced flow projection on this connection."""

        with self._lock:
            rows = self._connection.execute(
                """
                WITH heads AS (
                    SELECT r.* FROM supervisor_flow_revisions r
                    JOIN (
                        SELECT flow_id, MAX(revision) AS revision
                        FROM supervisor_flow_revisions GROUP BY flow_id
                    ) h ON h.flow_id = r.flow_id AND h.revision = r.revision
                )
                SELECT state, COUNT(*) AS count FROM heads GROUP BY state
                """
            ).fetchall()
        return {row["state"]: int(row["count"]) for row in rows}

    def acquire_foreground(
        self,
        instance_owner: str,
        *,
        ttl_seconds: float,
        now: float | None = None,
    ) -> bool:
        _validate_owner(instance_owner, "instance_owner")
        timestamp = self._now(now)
        ttl = _positive_duration(ttl_seconds, "ttl_seconds")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE lease_key = ?", (_FOREGROUND_LEASE_KEY,)
            ).fetchone()
            if row is not None and row["expires_at"] > timestamp:
                return row["owner_id"] == instance_owner
            connection.execute(
                """
                INSERT INTO leases (lease_key, owner_id, acquired_at, renewed_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(lease_key) DO UPDATE SET
                    owner_id=excluded.owner_id, acquired_at=excluded.acquired_at,
                    renewed_at=excluded.renewed_at, expires_at=excluded.expires_at
                """,
                (
                    _FOREGROUND_LEASE_KEY, instance_owner, timestamp, timestamp,
                    timestamp + ttl,
                ),
            )
        return True

    def renew_foreground(
        self,
        instance_owner: str,
        *,
        ttl_seconds: float,
        now: float | None = None,
    ) -> bool:
        _validate_owner(instance_owner, "instance_owner")
        timestamp = self._now(now)
        ttl = _positive_duration(ttl_seconds, "ttl_seconds")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE lease_key = ?", (_FOREGROUND_LEASE_KEY,)
            ).fetchone()
            if (
                row is None
                or row["owner_id"] != instance_owner
                or row["expires_at"] <= timestamp
                or row["renewed_at"] > timestamp
            ):
                return False
            connection.execute(
                """
                UPDATE leases SET renewed_at = ?, expires_at = ?
                WHERE lease_key = ? AND owner_id = ?
                """,
                (timestamp, timestamp + ttl, _FOREGROUND_LEASE_KEY, instance_owner),
            )
        return True

    def release_foreground(self, instance_owner: str) -> bool:
        _validate_owner(instance_owner, "instance_owner")
        with self._transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                (_FOREGROUND_LEASE_KEY, instance_owner),
            )
        return cursor.rowcount == 1

    def try_claim_next(
        self,
        *,
        instance_owner: str,
        expected_control_revision: int,
        ttl_seconds: float,
        now: float | None = None,
    ) -> AttemptClaim | None:
        """Atomically claim one mock flow.

        The CLI intentionally does not call this method until runtime ABAC
        enforcement exists.  It is present now so crash, race, and fencing
        semantics can be tested before a worker executor is connected.
        """

        _validate_owner(instance_owner, "instance_owner")
        _validate_revision(expected_control_revision, allow_zero=True)
        timestamp = self._now(now)
        ttl = _positive_duration(ttl_seconds, "ttl_seconds")
        with self._transaction() as connection:
            self._require_foreground(connection, instance_owner, timestamp)
            control = self._current_control_in(connection)
            if control.revision != expected_control_revision:
                raise StaleRevisionError("supervisor control revision is stale")
            if control.mode is not SupervisorMode.RUNNING:
                return None
            candidates = connection.execute(
                """
                WITH heads AS (
                    SELECT r.* FROM supervisor_flow_revisions r
                    JOIN (
                        SELECT flow_id, MAX(revision) AS revision
                        FROM supervisor_flow_revisions GROUP BY flow_id
                    ) h ON h.flow_id = r.flow_id AND h.revision = r.revision
                ), counts AS (
                    SELECT flow_id, COUNT(*) AS attempt_count
                    FROM supervisor_attempts GROUP BY flow_id
                )
                SELECT f.*, h.revision AS head_revision
                FROM supervisor_flows f
                JOIN heads h ON h.flow_id = f.flow_id
                LEFT JOIN counts c ON c.flow_id = f.flow_id
                WHERE h.state = 'queued'
                  AND h.cancellation_requested = 0
                  AND f.available_at <= ?
                  AND (f.deadline_at IS NULL OR f.deadline_at > ?)
                  AND COALESCE(c.attempt_count, 0) < f.max_attempts
                ORDER BY
                  f.mandatory_priority DESC,
                  CASE WHEN f.deadline_at IS NULL THEN 1 ELSE 0 END,
                  f.deadline_at,
                  f.blocker_priority DESC,
                  f.value_priority DESC,
                  f.evidence_priority DESC,
                  f.capacity_fit_priority DESC,
                  f.created_at,
                  f.flow_id
                """,
                (timestamp, timestamp),
            ).fetchall()
            for row in candidates:
                spec = _flow_from_row(row)
                revision = int(row["head_revision"])
                attempt_number = int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM supervisor_attempts WHERE flow_id = ?",
                        (spec.flow_id,),
                    ).fetchone()["count"]
                ) + 1
                nonce = self._new_id("claim")
                attempt_id = f"attempt-{nonce}"
                run_id = f"supervisor-{nonce}"
                lease_owner = f"attempt/{nonce}"
                lease_keys = tuple(sorted({f"flow:{spec.flow_id}", *spec.resource_keys}))
                if not self._leases_available(connection, lease_keys, timestamp):
                    continue
                hard_deadline = min(
                    timestamp + spec.attempt_timeout_seconds,
                    (
                        spec.deadline_at
                        if spec.deadline_at is not None
                        else timestamp + spec.attempt_timeout_seconds
                    ),
                )
                lease_expiry = min(timestamp + ttl, hard_deadline)
                if lease_expiry <= timestamp:
                    continue
                for key in lease_keys:
                    connection.execute(
                        """
                        INSERT INTO leases (
                            lease_key, owner_id, acquired_at, renewed_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(lease_key) DO UPDATE SET
                            owner_id=excluded.owner_id,
                            acquired_at=excluded.acquired_at,
                            renewed_at=excluded.renewed_at,
                            expires_at=excluded.expires_at
                        """,
                        (key, lease_owner, timestamp, timestamp, lease_expiry),
                    )
                input_digest = _sha256_text(
                    _canonical_json(
                        {
                            "flow_request_digest": spec.request_digest,
                            "attempt_number": attempt_number,
                            "control_revision": control.revision,
                        }
                    )
                )
                connection.execute(
                    """
                    INSERT INTO supervisor_attempts (
                        attempt_id, flow_id, attempt_number, run_id, claimed_revision,
                        lease_owner, lease_keys_json, input_digest, deadline_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attempt_id, spec.flow_id, attempt_number, run_id, revision,
                        lease_owner, _bounded_json(list(lease_keys), "lease_keys"),
                        input_digest, hard_deadline, timestamp,
                    ),
                )
                self._insert_attempt_event(
                    connection,
                    attempt_id=attempt_id,
                    revision=1,
                    state=AttemptState.CREATED,
                    reason_code="claim_created",
                    occurred_at=timestamp,
                )
                flow_revision = self._insert_flow_revision(
                    connection,
                    flow_id=spec.flow_id,
                    revision=revision + 1,
                    state=FlowState.RUNNING,
                    cancellation_requested=False,
                    active_attempt_id=attempt_id,
                    reason_code="attempt_claimed",
                    occurred_at=timestamp,
                )
                try:
                    self._append_authorization_observation(
                        connection,
                        boundary="attempt_claim",
                        spec=spec,
                        observed_at=timestamp,
                        legacy_executable=True,
                        attempt_id=attempt_id,
                    )
                except Exception:
                    # A shadow evaluator or evidence-write failure cannot
                    # change the legacy claim outcome.
                    pass
                attempt = AttemptRecord(
                    attempt_id, spec.flow_id, attempt_number, run_id, revision,
                    lease_owner, lease_keys, input_digest, hard_deadline, timestamp,
                )
                return AttemptClaim(spec, flow_revision, attempt)
        return None

    def _append_authorization_observation(
        self,
        connection: sqlite3.Connection,
        *,
        boundary: str,
        spec: FlowSpec,
        observed_at: float,
        legacy_executable: bool,
        attempt_id: str | None = None,
    ) -> None:
        request, policy = _supervisor_authorization_request(
            boundary=boundary,
            spec=spec,
            observed_at=observed_at,
            attempt_id=attempt_id,
        )
        decision = ShadowAuthorizationEvaluator().evaluate(request, policy)
        parity = (decision.effect.value == "permit") == legacy_executable
        payload = {
            "mode": "shadow",
            "boundary": boundary,
            "request": request.to_canonical(),
            "request_digest": request.digest,
            "decision": decision.to_canonical(),
            "decision_digest": decision.digest,
            "legacy_executable": legacy_executable,
            "execution_parity": parity,
        }
        connection.execute(
            """
            INSERT INTO supervisor_authorization_observations (
                observation_id, boundary, flow_id, request_digest,
                decision_digest, effect, derived_permission_class,
                legacy_executable, execution_parity, payload_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._new_id("authorization"), boundary, spec.flow_id,
                request.digest, decision.digest, decision.effect.value,
                int(decision.derived_permission_class), int(legacy_executable),
                int(parity), _bounded_json(payload, "authorization payload"),
                observed_at,
            ),
        )

    def mark_attempt_dispatching(
        self,
        claim: AttemptClaim,
        *,
        expected_attempt_revision: int = 1,
        now: float | None = None,
    ) -> AttemptEvent:
        timestamp = self._now(now)
        with self._transaction() as connection:
            attempt = self._stored_attempt_for_claim(connection, claim)
            self._require_claim(connection, attempt, timestamp)
            current_flow = self._current_flow_in(connection, attempt.flow_id)
            if (
                current_flow.state is not FlowState.RUNNING
                or current_flow.active_attempt_id != attempt.attempt_id
                or current_flow.cancellation_requested
            ):
                raise ClaimLostError("flow no longer permits dispatch")
            current = self._current_attempt_event_in(connection, attempt.attempt_id)
            if current.revision != expected_attempt_revision:
                raise StaleRevisionError("attempt revision is stale")
            if current.state is not AttemptState.CREATED:
                raise ValidationError("only a created attempt may begin dispatch")
            return self._insert_attempt_event(
                connection,
                attempt_id=attempt.attempt_id,
                revision=current.revision + 1,
                state=AttemptState.DISPATCHING,
                reason_code="dispatch_intent_recorded",
                occurred_at=timestamp,
            )

    def renew_claim(
        self,
        claim: AttemptClaim,
        *,
        ttl_seconds: float,
        now: float | None = None,
    ) -> float:
        timestamp = self._now(now)
        ttl = _positive_duration(ttl_seconds, "ttl_seconds")
        with self._transaction() as connection:
            attempt = self._stored_attempt_for_claim(connection, claim)
            new_expiry = min(timestamp + ttl, attempt.deadline_at)
            if new_expiry <= timestamp:
                raise ClaimLostError("attempt reached its fixed execution deadline")
            current_flow = self._current_flow_in(connection, attempt.flow_id)
            if (
                current_flow.state is not FlowState.RUNNING
                or current_flow.active_attempt_id != attempt.attempt_id
                or current_flow.cancellation_requested
            ):
                raise ClaimLostError("flow no longer permits attempt renewal")
            self._require_claim(connection, attempt, timestamp)
            for key in attempt.lease_keys:
                connection.execute(
                    """
                    UPDATE leases SET renewed_at = ?, expires_at = ?
                    WHERE lease_key = ? AND owner_id = ?
                    """,
                    (timestamp, new_expiry, key, attempt.lease_owner),
                )
        return new_expiry

    def request_cancellation(
        self,
        flow_id: str,
        *,
        requested_by: str,
        reason_code: str,
        now: float | None = None,
    ) -> FlowRevision:
        _validate_text(flow_id, "flow_id")
        _validate_text(requested_by, "requested_by", maximum=256)
        _validate_reason(reason_code)
        timestamp = self._now(now)
        with self._transaction() as connection:
            current = self._current_flow_in(connection, flow_id)
            existing = connection.execute(
                "SELECT * FROM supervisor_cancellation_requests WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if existing is not None:
                return current
            connection.execute(
                """
                INSERT INTO supervisor_cancellation_requests (
                    request_id, flow_id, reason_code, requested_by, requested_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self._new_id("cancellation"), flow_id, reason_code,
                    requested_by, timestamp,
                ),
            )
            if current.state in _FINAL_FLOW_STATES:
                return current
            target = (
                FlowState.RUNNING if current.state is FlowState.RUNNING
                else FlowState.CANCELLED
            )
            updated = self._insert_flow_revision(
                connection,
                flow_id=flow_id,
                revision=current.revision + 1,
                state=target,
                cancellation_requested=True,
                active_attempt_id=current.active_attempt_id,
                reason_code="cancellation_requested",
                occurred_at=timestamp,
            )
            if target is FlowState.CANCELLED:
                self._insert_completion_intent(
                    connection, updated, attempt_id=None, occurred_at=timestamp
                )
            return updated

    def complete_attempt(
        self,
        claim: AttemptClaim,
        *,
        expected_flow_revision: int,
        outcome: FlowState,
        reason_code: str,
        now: float | None = None,
    ) -> tuple[FlowRevision, CompletionIntent]:
        if outcome not in _TERMINAL_ATTEMPT_FOR_FLOW:
            raise ValidationError("attempt outcome is not supported")
        _validate_revision(expected_flow_revision)
        _validate_reason(reason_code)
        timestamp = self._now(now)
        operation_digest = _sha256_text(
            _canonical_json(
                {
                    "attempt_id": claim.attempt.attempt_id,
                    "input_digest": claim.attempt.input_digest,
                    "expected_flow_revision": expected_flow_revision,
                    "requested_outcome": outcome.value,
                    "reason_code": reason_code,
                }
            )
        )
        with self._transaction() as connection:
            attempt = self._stored_attempt_for_claim(connection, claim)
            replay = connection.execute(
                """
                SELECT o.* FROM supervisor_completion_outbox o
                WHERE o.attempt_id = ? ORDER BY o.source_revision DESC LIMIT 1
                """,
                (attempt.attempt_id,),
            ).fetchone()
            current = self._current_flow_in(connection, attempt.flow_id)
            if current.revision != expected_flow_revision:
                if replay is not None:
                    if replay["operation_digest"] == operation_digest:
                        historical = connection.execute(
                            """
                            SELECT * FROM supervisor_flow_revisions
                            WHERE flow_id = ? AND revision = ?
                            """,
                            (replay["flow_id"], replay["source_revision"]),
                        ).fetchone()
                        if historical is None:
                            raise SupervisorError(
                                "completion lineage is missing its source revision"
                            )
                        replayed = _completion_from_row(replay)
                        envelope = replayed.envelope
                        if envelope.get("attempt_id") != attempt.attempt_id:
                            raise SupervisorError(
                                "completion lineage does not match the durable attempt"
                            )
                        return _flow_revision_from_row(historical), replayed
                raise StaleRevisionError("flow revision is stale")
            if (
                current.state is not FlowState.RUNNING
                or current.active_attempt_id != attempt.attempt_id
            ):
                raise ClaimLostError("attempt is not the active flow claim")
            self._require_claim(connection, attempt, timestamp)
            selected_outcome = (
                FlowState.CANCELLED if current.cancellation_requested else outcome
            )
            if selected_outcome not in _FLOW_TRANSITIONS[current.state]:
                raise ValidationError("attempt outcome violates the flow state machine")
            attempt_current = self._current_attempt_event_in(
                connection, attempt.attempt_id
            )
            self._insert_attempt_event(
                connection,
                attempt_id=attempt.attempt_id,
                revision=attempt_current.revision + 1,
                state=_TERMINAL_ATTEMPT_FOR_FLOW[selected_outcome],
                reason_code=reason_code,
                occurred_at=timestamp,
            )
            completed = self._insert_flow_revision(
                connection,
                flow_id=attempt.flow_id,
                revision=current.revision + 1,
                state=selected_outcome,
                cancellation_requested=current.cancellation_requested,
                active_attempt_id=None,
                reason_code=reason_code,
                occurred_at=timestamp,
            )
            outbox = self._insert_completion_intent(
                connection,
                completed,
                attempt_id=attempt.attempt_id,
                operation_digest=operation_digest,
                occurred_at=timestamp,
            )
            for key in attempt.lease_keys:
                connection.execute(
                    "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                    (key, attempt.lease_owner),
                )
        return completed, outbox

    def list_pending_completions(self) -> tuple[CompletionIntent, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT o.* FROM supervisor_completion_outbox o
                LEFT JOIN supervisor_completion_receipts r ON r.outbox_id = o.outbox_id
                WHERE r.outbox_id IS NULL ORDER BY o.created_at, o.outbox_id
                """
            ).fetchall()
        return tuple(_completion_from_row(row) for row in rows)

    def acknowledge_completion(
        self,
        outbox_id: str,
        *,
        consumer_id: str,
        result_digest: str,
        delivery_id: str,
        now: float | None = None,
    ) -> CompletionReceipt:
        for value, name in (
            (outbox_id, "outbox_id"),
            (consumer_id, "consumer_id"),
            (delivery_id, "delivery_id"),
        ):
            _validate_text(value, name, maximum=256)
        _validate_digest(result_digest, "result_digest")
        timestamp = self._now(now)
        with self._transaction() as connection:
            outbox = connection.execute(
                "SELECT * FROM supervisor_completion_outbox WHERE outbox_id = ?",
                (outbox_id,),
            ).fetchone()
            if outbox is None:
                raise SupervisorError("completion intent was not found")
            existing = connection.execute(
                "SELECT * FROM supervisor_completion_receipts WHERE outbox_id = ?",
                (outbox_id,),
            ).fetchone()
            receipt_key = outbox["idempotency_key"]
            if existing is not None:
                receipt = _receipt_from_row(existing)
                if (
                    receipt.consumer_id != consumer_id
                    or receipt.result_digest != result_digest
                    or receipt.idempotency_key != receipt_key
                ):
                    raise AdmissionConflictError(
                        "completion replay conflicts with the existing receipt"
                    )
                return receipt
            connection.execute(
                """
                INSERT INTO supervisor_completion_delivery_events (
                    event_id, outbox_id, delivery_id, event_type, reason_code, occurred_at
                ) VALUES (?, ?, ?, 'delivered', 'local_consumer_acknowledged', ?)
                """,
                (self._new_id("delivery_event"), outbox_id, delivery_id, timestamp),
            )
            receipt = CompletionReceipt(
                receipt_id=self._new_id("receipt"),
                outbox_id=outbox_id,
                idempotency_key=receipt_key,
                consumer_id=consumer_id,
                result_digest=result_digest,
                delivered_at=timestamp,
            )
            connection.execute(
                """
                INSERT INTO supervisor_completion_receipts (
                    receipt_id, outbox_id, idempotency_key, consumer_id,
                    result_digest, delivered_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id, receipt.outbox_id, receipt.idempotency_key,
                    receipt.consumer_id, receipt.result_digest, receipt.delivered_at,
                ),
            )
        return receipt

    def reconciliation_plan(self, *, now: float | None = None) -> ReconciliationPlan:
        timestamp = self._now(now)
        with self._lock:
            findings = _audit_connection(self._connection, timestamp)
        return _make_plan(True, timestamp, findings)

    def apply_reconciliation(
        self,
        *,
        plan_digest: str,
        now: float | None = None,
    ) -> tuple[ReconciliationFinding, ...]:
        _validate_digest(plan_digest, "plan_digest")
        timestamp = self._now(now)
        with self._transaction() as connection:
            findings = _audit_connection(connection, timestamp)
            current_plan = _make_plan(True, timestamp, findings)
            if current_plan.plan_digest != plan_digest:
                raise StaleReconciliationPlanError(
                    "reconciliation plan is stale; inspect again before applying"
                )
            applied: list[ReconciliationFinding] = []
            for finding in findings:
                if finding.action == "mark_queued_timed_out":
                    assert finding.flow_id is not None
                    current = self._current_flow_in(connection, finding.flow_id)
                    if current.revision != finding.expected_revision:
                        raise StaleReconciliationPlanError(
                            "flow changed during reconciliation"
                        )
                    revision = self._insert_flow_revision(
                        connection,
                        flow_id=finding.flow_id,
                        revision=current.revision + 1,
                        state=FlowState.TIMED_OUT,
                        cancellation_requested=current.cancellation_requested,
                        active_attempt_id=None,
                        reason_code=finding.reason_code,
                        occurred_at=timestamp,
                    )
                    self._insert_completion_intent(
                        connection,
                        revision,
                        attempt_id=None,
                        occurred_at=timestamp,
                    )
                    applied.append(finding)
                elif finding.action == "finalize_cancelled_pre_dispatch":
                    self._reconcile_attempt(
                        connection, finding, FlowState.CANCELLED, timestamp
                    )
                    applied.append(finding)
                elif finding.action == "mark_lost_pre_dispatch":
                    self._reconcile_attempt(
                        connection, finding, FlowState.LOST, timestamp
                    )
                    applied.append(finding)
                elif finding.action == "repair_completion_outbox":
                    assert finding.flow_id is not None
                    revision = self._current_flow_in(connection, finding.flow_id)
                    self._insert_completion_intent(
                        connection,
                        revision,
                        attempt_id=revision.active_attempt_id,
                        occurred_at=timestamp,
                    )
                    applied.append(finding)
                elif finding.action == "release_orphan_attempt_leases":
                    assert finding.attempt_id is not None
                    attempt = self._attempt_in(connection, finding.attempt_id)
                    for key in attempt.lease_keys:
                        connection.execute(
                            "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                            (key, attempt.lease_owner),
                        )
                    applied.append(finding)
        return tuple(applied)

    def _reconcile_attempt(
        self,
        connection: sqlite3.Connection,
        finding: ReconciliationFinding,
        outcome: FlowState,
        timestamp: float,
    ) -> None:
        assert finding.flow_id is not None
        assert finding.attempt_id is not None
        current = self._current_flow_in(connection, finding.flow_id)
        if current.revision != finding.expected_revision:
            raise StaleReconciliationPlanError("flow changed during reconciliation")
        attempt = self._attempt_in(connection, finding.attempt_id)
        attempt_event = self._current_attempt_event_in(connection, finding.attempt_id)
        self._insert_attempt_event(
            connection,
            attempt_id=finding.attempt_id,
            revision=attempt_event.revision + 1,
            state=_TERMINAL_ATTEMPT_FOR_FLOW[outcome],
            reason_code=finding.reason_code,
            occurred_at=timestamp,
        )
        revision = self._insert_flow_revision(
            connection,
            flow_id=finding.flow_id,
            revision=current.revision + 1,
            state=outcome,
            cancellation_requested=current.cancellation_requested,
            active_attempt_id=None,
            reason_code=finding.reason_code,
            occurred_at=timestamp,
        )
        self._insert_completion_intent(
            connection, revision, attempt_id=finding.attempt_id, occurred_at=timestamp
        )
        for key in attempt.lease_keys:
            connection.execute(
                "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                (key, attempt.lease_owner),
            )

    def _insert_flow_revision(
        self,
        connection: sqlite3.Connection,
        *,
        flow_id: str,
        revision: int,
        state: FlowState,
        cancellation_requested: bool,
        active_attempt_id: str | None,
        reason_code: str,
        occurred_at: float,
    ) -> FlowRevision:
        event_id = self._new_id("flow_event")
        cursor = connection.execute(
            """
            INSERT INTO supervisor_flow_revisions (
                event_id, flow_id, revision, state, cancellation_requested,
                active_attempt_id, reason_code, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, flow_id, revision, state.value,
                int(cancellation_requested), active_attempt_id, reason_code, occurred_at,
            ),
        )
        return FlowRevision(
            int(cursor.lastrowid), event_id, flow_id, revision, state,
            cancellation_requested, active_attempt_id, reason_code, occurred_at,
        )

    def _insert_attempt_event(
        self,
        connection: sqlite3.Connection,
        *,
        attempt_id: str,
        revision: int,
        state: AttemptState,
        reason_code: str,
        occurred_at: float,
    ) -> AttemptEvent:
        event_id = self._new_id("attempt_event")
        cursor = connection.execute(
            """
            INSERT INTO supervisor_attempt_events (
                event_id, attempt_id, revision, state, reason_code, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_id, attempt_id, revision, state.value, reason_code, occurred_at),
        )
        return AttemptEvent(
            int(cursor.lastrowid), event_id, attempt_id, revision,
            state, reason_code, occurred_at,
        )

    def _insert_completion_intent(
        self,
        connection: sqlite3.Connection,
        revision: FlowRevision,
        *,
        attempt_id: str | None,
        operation_digest: str | None = None,
        occurred_at: float,
    ) -> CompletionIntent:
        existing = connection.execute(
            """
            SELECT * FROM supervisor_completion_outbox
            WHERE flow_id = ? AND source_revision = ?
            """,
            (revision.flow_id, revision.revision),
        ).fetchone()
        if existing is not None:
            if (
                operation_digest is not None
                and existing["operation_digest"] != operation_digest
            ):
                raise AdmissionConflictError(
                    "completion replay conflicts with the existing operation"
                )
            return _completion_from_row(existing)
        envelope_json = _bounded_json(
            {
                "flow_id": revision.flow_id,
                "source_revision": revision.revision,
                "state": revision.state.value,
                "attempt_id": attempt_id,
                "reason_code": revision.reason_code,
            },
            "completion_envelope",
        )
        intent = CompletionIntent(
            outbox_id=self._new_id("outbox"),
            idempotency_key=(
                f"flow:{revision.flow_id}:revision:{revision.revision}"
            ),
            flow_id=revision.flow_id,
            source_revision=revision.revision,
            attempt_id=attempt_id,
            envelope_json=envelope_json,
            intent_digest=_sha256_text(envelope_json),
            operation_digest=(
                _sha256_text(envelope_json)
                if operation_digest is None
                else operation_digest
            ),
            created_at=occurred_at,
        )
        connection.execute(
            """
            INSERT INTO supervisor_completion_outbox (
                outbox_id, idempotency_key, flow_id, source_revision, attempt_id,
                envelope_json, intent_digest, operation_digest, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                intent.outbox_id, intent.idempotency_key, intent.flow_id,
                intent.source_revision, intent.attempt_id, intent.envelope_json,
                intent.intent_digest, intent.operation_digest, intent.created_at,
            ),
        )
        return intent

    def _current_control_in(
        self, connection: sqlite3.Connection
    ) -> SupervisorControlRevision:
        row = connection.execute(
            "SELECT * FROM supervisor_control_events ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return SupervisorControlRevision(
                0, "synthetic:stopped:0", 0, SupervisorMode.STOPPED,
                "system", "initial_state", 0.0,
            )
        return _control_from_row(row)

    @staticmethod
    def _current_flow_in(
        connection: sqlite3.Connection, flow_id: str
    ) -> FlowRevision:
        row = connection.execute(
            """
            SELECT * FROM supervisor_flow_revisions
            WHERE flow_id = ? ORDER BY revision DESC LIMIT 1
            """,
            (flow_id,),
        ).fetchone()
        if row is None:
            raise SupervisorError("flow was not found")
        return _flow_revision_from_row(row)

    @staticmethod
    def _current_attempt_event_in(
        connection: sqlite3.Connection, attempt_id: str
    ) -> AttemptEvent:
        row = connection.execute(
            """
            SELECT * FROM supervisor_attempt_events
            WHERE attempt_id = ? ORDER BY revision DESC LIMIT 1
            """,
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise SupervisorError("attempt event was not found")
        return _attempt_event_from_row(row)

    @staticmethod
    def _attempt_in(
        connection: sqlite3.Connection, attempt_id: str
    ) -> AttemptRecord:
        row = connection.execute(
            "SELECT * FROM supervisor_attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise SupervisorError("attempt was not found")
        return _attempt_from_row(row)

    @classmethod
    def _stored_attempt_for_claim(
        cls,
        connection: sqlite3.Connection,
        claim: AttemptClaim,
    ) -> AttemptRecord:
        if not isinstance(claim, AttemptClaim):
            raise ValidationError("claim must be an AttemptClaim")
        stored = cls._attempt_in(connection, claim.attempt.attempt_id)
        if stored != claim.attempt or stored.flow_id != claim.flow.flow_id:
            raise ClaimLostError("claim does not match its durable fencing record")
        return stored

    @staticmethod
    def _leases_available(
        connection: sqlite3.Connection,
        lease_keys: Sequence[str],
        now: float,
    ) -> bool:
        for key in lease_keys:
            row = connection.execute(
                "SELECT owner_id, expires_at FROM leases WHERE lease_key = ?", (key,)
            ).fetchone()
            if row is not None and row["expires_at"] > now:
                return False
        return True

    @staticmethod
    def _require_foreground(
        connection: sqlite3.Connection,
        instance_owner: str,
        now: float,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM leases WHERE lease_key = ?", (_FOREGROUND_LEASE_KEY,)
        ).fetchone()
        if (
            row is None
            or row["owner_id"] != instance_owner
            or row["expires_at"] <= now
        ):
            raise ClaimLostError("foreground supervisor lease is not active")

    @staticmethod
    def _require_claim(
        connection: sqlite3.Connection,
        attempt: AttemptRecord,
        now: float,
    ) -> None:
        for key in attempt.lease_keys:
            row = connection.execute(
                "SELECT * FROM leases WHERE lease_key = ?", (key,)
            ).fetchone()
            if (
                row is None
                or row["owner_id"] != attempt.lease_owner
                or row["expires_at"] <= now
                or row["renewed_at"] > now
            ):
                raise ClaimLostError("attempt claim is missing, stale, or expired")

    def _new_id(self, field_name: str) -> str:
        value = self._id_factory()
        _validate_text(value, field_name, maximum=256)
        return value

    def _now(self, supplied: float | None) -> float:
        return _timestamp(self._clock() if supplied is None else supplied, "timestamp")


class ForegroundSupervisor:
    """Foreground control loop with worker dispatch intentionally disabled."""

    def __init__(
        self,
        store: SQLiteSupervisorStore,
        *,
        instance_owner: str,
        clock: Callable[[], float] = time.time,
        lease_ttl_seconds: float = 30.0,
    ) -> None:
        _validate_owner(instance_owner, "instance_owner")
        self.store = store
        self.instance_owner = instance_owner
        self.clock = clock
        self.lease_ttl_seconds = _positive_duration(
            lease_ttl_seconds, "lease_ttl_seconds"
        )

    def tick(self) -> dict[str, Any]:
        now = _timestamp(self.clock(), "timestamp")
        renewed = self.store.renew_foreground(
            self.instance_owner, ttl_seconds=self.lease_ttl_seconds, now=now
        )
        if not renewed and not self.store.acquire_foreground(
            self.instance_owner, ttl_seconds=self.lease_ttl_seconds, now=now
        ):
            raise SupervisorError("another foreground supervisor holds the lease")
        control = self.store.current_control()
        if control.mode in {SupervisorMode.DRAINING, SupervisorMode.STOP_REQUESTED}:
            active = self.store.flow_state_counts().get(FlowState.RUNNING.value, 0)
            if active == 0:
                control = self.store.update_control(
                    expected_revision=control.revision,
                    mode=SupervisorMode.STOPPED,
                    actor_id=self.instance_owner,
                    reason_code=(
                        "drain_completed"
                        if control.mode is SupervisorMode.DRAINING
                        else "stop_completed"
                    ),
                    occurred_at=now,
                )
        return {
            "mode": control.mode.value,
            "control_revision": control.revision,
            "dispatch_enabled": False,
            "claimed": False,
            "dispatch_blocker": "runtime_abac_enforcement_not_implemented",
        }

    def close(self) -> None:
        self.store.release_foreground(self.instance_owner)


def inspect_supervisor_status(
    database_path: str | Path,
    *,
    now: float | None = None,
) -> SupervisorStatus:
    """Read status without creating a database, sidecar, or migration."""

    timestamp = _timestamp(time.time() if now is None else now, "timestamp")
    path = Path(database_path)
    if str(database_path) != ":memory:" and not path.is_file():
        return SupervisorStatus(
            False, False, 0, SupervisorMode.STOPPED, {}, 0, False
        )
    try:
        with _read_only_connection(path) as connection:
            tables = _table_names(connection)
            if "supervisor_control_events" not in tables:
                return SupervisorStatus(
                    True, False, 0, SupervisorMode.STOPPED, {}, 0, False
                )
            row = connection.execute(
                "SELECT revision, mode FROM supervisor_control_events "
                "ORDER BY revision DESC LIMIT 1"
            ).fetchone()
            revision = 0 if row is None else int(row["revision"])
            mode = SupervisorMode.STOPPED if row is None else SupervisorMode(row["mode"])
            counts = {
                item["state"]: int(item["count"])
                for item in connection.execute(
                    """
                    WITH heads AS (
                        SELECT r.* FROM supervisor_flow_revisions r
                        JOIN (
                            SELECT flow_id, MAX(revision) AS revision
                            FROM supervisor_flow_revisions GROUP BY flow_id
                        ) h ON h.flow_id = r.flow_id AND h.revision = r.revision
                    )
                    SELECT state, COUNT(*) AS count FROM heads GROUP BY state
                    """
                ).fetchall()
            }
            pending = int(
                connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM supervisor_completion_outbox o
                    LEFT JOIN supervisor_completion_receipts r
                      ON r.outbox_id = o.outbox_id
                    WHERE r.outbox_id IS NULL
                    """
                ).fetchone()["count"]
            )
            lease = connection.execute(
                "SELECT * FROM leases WHERE lease_key = ?",
                (_FOREGROUND_LEASE_KEY,),
            ).fetchone()
            lease_active = lease is not None and lease["expires_at"] > timestamp
            return SupervisorStatus(
                True, True, revision, mode, counts, pending, lease_active
            )
    except sqlite3.Error as error:
        raise ConfigurationError("supervisor state is unreadable or malformed") from error


def inspect_reconciliation(
    database_path: str | Path,
    *,
    now: float | None = None,
) -> ReconciliationPlan:
    """Read-only recovery inspection that never initializes state."""

    timestamp = _timestamp(time.time() if now is None else now, "timestamp")
    path = Path(database_path)
    if not path.is_file():
        return _make_plan(False, timestamp, ())
    try:
        with _read_only_connection(path) as connection:
            if "supervisor_flows" not in _table_names(connection):
                return _make_plan(True, timestamp, ())
            return _make_plan(True, timestamp, _audit_connection(connection, timestamp))
    except sqlite3.Error as error:
        raise ConfigurationError("supervisor state is unreadable or malformed") from error


def inspect_supervisor_authorization(
    database_path: str | Path,
) -> SupervisorAuthorizationAudit:
    """Independently verify supervisor shadow evidence without changing state."""

    path = Path(database_path)
    if not path.is_file():
        return SupervisorAuthorizationAudit(False, False, 0, 0, ())
    try:
        with _read_only_connection(path) as connection:
            return _inspect_supervisor_authorization_connection(connection)
    except Exception as error:
        raise ConfigurationError(
            "supervisor authorization state is unreadable or malformed"
        ) from error


def inspect_supervisor_audit(
    database_path: str | Path,
    *,
    now: float | None = None,
) -> tuple[ReconciliationPlan, SupervisorAuthorizationAudit]:
    """Inspect recovery and authorization through one read-only snapshot."""

    timestamp = _timestamp(time.time() if now is None else now, "timestamp")
    path = Path(database_path)
    if not path.is_file():
        return (
            _make_plan(False, timestamp, ()),
            SupervisorAuthorizationAudit(False, False, 0, 0, ()),
        )
    try:
        with _read_only_connection(path) as connection:
            tables = _table_names(connection)
            plan = (
                _make_plan(True, timestamp, ())
                if "supervisor_flows" not in tables
                else _make_plan(
                    True, timestamp, _audit_connection(connection, timestamp)
                )
            )
            authorization = _inspect_supervisor_authorization_connection(connection)
            return plan, authorization
    except Exception as error:
        raise ConfigurationError("supervisor state is unreadable or malformed") from error


def _inspect_supervisor_authorization_connection(
    connection: sqlite3.Connection,
) -> SupervisorAuthorizationAudit:
    tables = _table_names(connection)
    if "supervisor_flows" not in tables:
        return SupervisorAuthorizationAudit(True, False, 0, 0, ())
    flow_rows = connection.execute(
        "SELECT * FROM supervisor_flows ORDER BY created_at, flow_id"
    ).fetchall()
    attempt_rows = connection.execute(
        """
        SELECT * FROM supervisor_attempts
        ORDER BY flow_id, attempt_number, attempt_id
        """
    ).fetchall()
    baseline = (
        {
            (row["entity_type"], row["entity_id"])
            for row in connection.execute(
                "SELECT entity_type, entity_id FROM "
                "supervisor_authorization_shadow_baseline"
            ).fetchall()
        }
        if "supervisor_authorization_shadow_baseline" in tables
        else set()
    )
    expected_count = sum(
        ("flow", row["flow_id"]) not in baseline for row in flow_rows
    ) + sum(
        ("attempt", row["attempt_id"]) not in baseline for row in attempt_rows
    )
    if "supervisor_authorization_observations" not in tables:
        findings = (
            SupervisorAuthorizationFinding(
                "authorization_schema_missing", None, None, None
            ),
        )
        return SupervisorAuthorizationAudit(True, False, 0, expected_count, findings)
    observation_rows = connection.execute(
        """
        SELECT * FROM supervisor_authorization_observations
        ORDER BY sequence
        """
    ).fetchall()
    findings = list(_authorization_guard_findings(connection))
    attempts_by_flow: dict[str, list[sqlite3.Row]] = {}
    for row in attempt_rows:
        attempts_by_flow.setdefault(row["flow_id"], []).append(row)
    observations_by_flow: dict[str, list[sqlite3.Row]] = {}
    for row in observation_rows:
        observations_by_flow.setdefault(row["flow_id"], []).append(row)
    known_flow_ids = {row["flow_id"] for row in flow_rows}
    for flow_id in sorted(set(observations_by_flow) - known_flow_ids):
        for row in observations_by_flow[flow_id]:
            findings.append(_authorization_finding("observation_without_flow", row=row))
    for flow_row in flow_rows:
        spec = _flow_from_row(flow_row)
        if flow_row["request_digest"] != spec.request_digest:
            findings.append(
                SupervisorAuthorizationFinding(
                    "flow_request_digest_mismatch", spec.flow_id, None, None
                )
            )
        expected = [
            *(
                [("flow_admission", spec.created_at, None)]
                if ("flow", spec.flow_id) not in baseline
                else []
            ),
            *[
                ("attempt_claim", row["created_at"], row["attempt_id"])
                for row in attempts_by_flow.get(spec.flow_id, [])
                if ("attempt", row["attempt_id"]) not in baseline
            ],
        ]
        actual = observations_by_flow.get(spec.flow_id, [])
        expected_with_ids = [
            (
                boundary,
                observed_at,
                attempt_id,
                _supervisor_authorization_request(
                    boundary=boundary,
                    spec=spec,
                    observed_at=observed_at,
                    attempt_id=attempt_id,
                )[0].request_id,
            )
            for boundary, observed_at, attempt_id in expected
        ]
        actual_ids = [_observation_request_id(row) for row in actual]
        expected_ids = [item[3] for item in expected_with_ids]
        if actual_ids != expected_ids:
            findings.append(
                SupervisorAuthorizationFinding(
                    "boundary_coverage_or_order_mismatch", spec.flow_id, None, None
                )
            )
        used: set[int] = set()
        for boundary, observed_at, attempt_id, request_id in expected_with_ids:
            matches = [
                index
                for index, row in enumerate(actual)
                if index not in used
                and row["boundary"] == boundary
                and actual_ids[index] == request_id
            ]
            if len(matches) != 1:
                findings.append(
                    SupervisorAuthorizationFinding(
                        (
                            "observation_missing"
                            if not matches
                            else "observation_duplicated"
                        ),
                        spec.flow_id,
                        boundary,
                        None,
                    )
                )
                continue
            index = matches[0]
            used.add(index)
            findings.extend(
                _verify_authorization_observation(
                    actual[index],
                    spec=spec,
                    boundary=boundary,
                    observed_at=observed_at,
                    attempt_id=attempt_id,
                )
            )
        for index, row in enumerate(actual):
            if index not in used:
                findings.append(
                    _authorization_finding("observation_unexpected", row=row)
                )
    return SupervisorAuthorizationAudit(
        True, True, len(observation_rows), expected_count, tuple(findings)
    )


def inspect_pending_completions(
    database_path: str | Path,
) -> tuple[CompletionIntent, ...]:
    """Read pending local completion intents without initializing state."""

    path = Path(database_path)
    if not path.is_file():
        return ()
    try:
        with _read_only_connection(path) as connection:
            if "supervisor_completion_outbox" not in _table_names(connection):
                return ()
            rows = connection.execute(
                """
                SELECT o.* FROM supervisor_completion_outbox o
                LEFT JOIN supervisor_completion_receipts r ON r.outbox_id = o.outbox_id
                WHERE r.outbox_id IS NULL ORDER BY o.created_at, o.outbox_id
                """
            ).fetchall()
            return tuple(_completion_from_row(row) for row in rows)
    except sqlite3.Error as error:
        raise ConfigurationError("supervisor state is unreadable or malformed") from error


def _authorization_guard_findings(
    connection: sqlite3.Connection,
) -> tuple[SupervisorAuthorizationFinding, ...]:
    findings: list[SupervisorAuthorizationFinding] = []
    expected = {
        name: value
        for name, value in _expected_supervisor_schema().items()
        if name.startswith("supervisor_authorization_")
        or value[1].startswith("supervisor_authorization_")
    }
    objects = _schema_objects(connection)
    actual = {
        name: value
        for name, value in objects.items()
        if name.startswith("supervisor_authorization_")
        or value[1].startswith("supervisor_authorization_")
    }
    if actual != expected:
        findings.append(
            SupervisorAuthorizationFinding(
                "authorization_schema_mismatch", None, None, None
            )
        )
    migration = connection.execute(
        "SELECT name, script_sha256 FROM state_schema_migrations WHERE version = 3"
    ).fetchone()
    if (
        migration is None
        or migration["name"] != "supervisor_authorization_shadow"
        or migration["script_sha256"] != _sha256_text(_SCHEMA_V3)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "authorization_migration_ledger_mismatch", None, None, None
            )
        )
    return tuple(findings)


def _verify_authorization_observation(
    row: sqlite3.Row,
    *,
    spec: FlowSpec,
    boundary: str,
    observed_at: float,
    attempt_id: str | None,
) -> tuple[SupervisorAuthorizationFinding, ...]:
    findings: list[SupervisorAuthorizationFinding] = []

    def add(code: str) -> None:
        findings.append(_authorization_finding(code, row=row))

    try:
        payload_text = row["payload_json"]
        if (
            not isinstance(payload_text, str)
            or len(payload_text.encode("utf-8")) > _MAX_JSON_BYTES
        ):
            raise ValidationError("authorization payload exceeds its bound")
        payload = parse_json_document(payload_text)
    except (RecursionError, TypeError, UnicodeError, ValidationError):
        add("payload_invalid")
        return tuple(findings)
    if not isinstance(payload, dict):
        add("payload_invalid")
        return tuple(findings)
    expected_request, expected_policy = _supervisor_authorization_request(
        boundary=boundary,
        spec=spec,
        observed_at=observed_at,
        attempt_id=attempt_id,
    )
    expected_decision = ShadowAuthorizationEvaluator().evaluate(
        expected_request, expected_policy
    )
    expected_payload = {
        "mode": "shadow",
        "boundary": boundary,
        "request": expected_request.to_canonical(),
        "request_digest": expected_request.digest,
        "decision": expected_decision.to_canonical(),
        "decision_digest": expected_decision.digest,
        "legacy_executable": True,
        "execution_parity": expected_decision.effect.value == "permit",
    }
    if payload != expected_payload:
        add("payload_recomputation_mismatch")
    request_value = payload.get("request")
    decision_value = payload.get("decision")
    try:
        payload_request_digest = canonical_digest(request_value)
    except (TypeError, ValueError):
        payload_request_digest = None
    try:
        payload_decision_digest = canonical_digest(decision_value)
    except (TypeError, ValueError):
        payload_decision_digest = None
    if (
        payload_request_digest is None
        or payload.get("request_digest") != payload_request_digest
        or row["request_digest"] != payload_request_digest
        or row["request_digest"] != expected_request.digest
    ):
        add("request_digest_mismatch")
    if (
        payload_decision_digest is None
        or payload.get("decision_digest") != payload_decision_digest
        or row["decision_digest"] != payload_decision_digest
        or row["decision_digest"] != expected_decision.digest
    ):
        add("decision_digest_mismatch")
    if not isinstance(decision_value, dict) or (
        decision_value.get("request_digest") != row["request_digest"]
    ):
        add("decision_request_lineage_mismatch")
    expected_permit = expected_decision.effect.value == "permit"
    if (
        row["effect"] != expected_decision.effect.value
        or row["derived_permission_class"]
        != int(expected_decision.derived_permission_class)
    ):
        add("decision_projection_mismatch")
    if not bool(row["legacy_executable"]):
        add("legacy_executability_mismatch")
    if bool(row["execution_parity"]) != expected_permit:
        add("execution_parity_mismatch")
    if row["observed_at"] != observed_at:
        add("observation_time_mismatch")
    return tuple(findings)


def _observation_request_id(row: sqlite3.Row) -> str | None:
    try:
        payload_text = row["payload_json"]
        if (
            not isinstance(payload_text, str)
            or len(payload_text.encode("utf-8")) > _MAX_JSON_BYTES
        ):
            return None
        payload = parse_json_document(payload_text)
    except (RecursionError, TypeError, UnicodeError, ValidationError):
        return None
    if not isinstance(payload, dict):
        return None
    request = payload.get("request")
    if not isinstance(request, dict):
        return None
    request_id = request.get("request_id")
    return request_id if isinstance(request_id, str) else None


def _authorization_finding(
    code: str,
    *,
    row: sqlite3.Row,
) -> SupervisorAuthorizationFinding:
    return SupervisorAuthorizationFinding(
        code=code,
        flow_id=row["flow_id"],
        boundary=row["boundary"],
        observation_sequence=int(row["sequence"]),
    )


@contextmanager
def _read_only_connection(path: Path) -> Iterator[sqlite3.Connection]:
    absolute = path.resolve()
    wal_path = Path(f"{absolute}-wal")
    shared_memory_path = Path(f"{absolute}-shm")
    wal_exists = wal_path.exists()
    shared_memory_exists = shared_memory_path.exists()
    if wal_exists != shared_memory_exists:
        raise ConfigurationError(
            "supervisor state has incomplete WAL coordination files; reconcile first"
        )
    # A clean, closed database is opened as an immutable snapshot so inspection
    # cannot create SQLite sidecars.  A live WAL database must use its existing
    # WAL+SHM pair to see committed frames; mode=ro cannot create either name
    # because their presence was verified above.
    immutable = 0 if wal_exists else 1
    uri = (
        f"file:{quote(str(absolute), safe='/')}?mode=ro&immutable={immutable}"
    )
    connection = sqlite3.connect(uri, uri=True, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("BEGIN")
    try:
        yield connection
    finally:
        connection.rollback()
        connection.close()


def _audit_connection(
    connection: sqlite3.Connection,
    now: float,
) -> tuple[ReconciliationFinding, ...]:
    findings: list[ReconciliationFinding] = []
    heads = connection.execute(
        """
        WITH heads AS (
            SELECT r.* FROM supervisor_flow_revisions r
            JOIN (
                SELECT flow_id, MAX(revision) AS revision
                FROM supervisor_flow_revisions GROUP BY flow_id
            ) h ON h.flow_id = r.flow_id AND h.revision = r.revision
        )
        SELECT * FROM heads ORDER BY flow_id
        """
    ).fetchall()
    for row in heads:
        revision = _flow_revision_from_row(row)
        if revision.state is FlowState.QUEUED:
            deadline = connection.execute(
                "SELECT deadline_at FROM supervisor_flows WHERE flow_id = ?",
                (revision.flow_id,),
            ).fetchone()["deadline_at"]
            if deadline is not None and deadline <= now:
                findings.append(
                    _finding(
                        "queued_deadline_elapsed",
                        "flow_deadline_elapsed",
                        revision.flow_id,
                        None,
                        revision.revision,
                        "mark_queued_timed_out",
                    )
                )
        if revision.state is FlowState.RUNNING and revision.active_attempt_id is not None:
            attempt_row = connection.execute(
                "SELECT * FROM supervisor_attempts WHERE attempt_id = ?",
                (revision.active_attempt_id,),
            ).fetchone()
            if attempt_row is None:
                findings.append(
                    _finding(
                        "missing_active_attempt", "active_attempt_missing",
                        revision.flow_id, revision.active_attempt_id,
                        revision.revision, None,
                    )
                )
                continue
            attempt = _attempt_from_row(attempt_row)
            active = True
            for key in attempt.lease_keys:
                lease = connection.execute(
                    "SELECT * FROM leases WHERE lease_key = ?", (key,)
                ).fetchone()
                if (
                    lease is None
                    or lease["owner_id"] != attempt.lease_owner
                    or lease["expires_at"] <= now
                ):
                    active = False
                    break
            if not active:
                attempt_event = connection.execute(
                    """
                    SELECT * FROM supervisor_attempt_events
                    WHERE attempt_id = ? ORDER BY revision DESC LIMIT 1
                    """,
                    (attempt.attempt_id,),
                ).fetchone()
                state = AttemptState(attempt_event["state"])
                if state is AttemptState.CREATED:
                    action = (
                        "finalize_cancelled_pre_dispatch"
                        if revision.cancellation_requested
                        else "mark_lost_pre_dispatch"
                    )
                    findings.append(
                        _finding(
                            "expired_pre_dispatch_claim",
                            "pre_dispatch_claim_expired",
                            revision.flow_id,
                            attempt.attempt_id,
                            revision.revision,
                            action,
                        )
                    )
                else:
                    findings.append(
                        _finding(
                            "ambiguous_expired_attempt",
                            "possible_worker_outcome_unknown",
                            revision.flow_id,
                            attempt.attempt_id,
                            revision.revision,
                            None,
                        )
                    )
        outbox = connection.execute(
            """
            SELECT 1 FROM supervisor_completion_outbox
            WHERE flow_id = ? AND source_revision = ?
            """,
            (revision.flow_id, revision.revision),
        ).fetchone()
        if revision.state in _FINAL_FLOW_STATES and outbox is None:
            findings.append(
                _finding(
                    "terminal_without_completion",
                    "completion_intent_missing",
                    revision.flow_id,
                    revision.active_attempt_id,
                    revision.revision,
                    "repair_completion_outbox",
                )
            )
    attempts = connection.execute(
        "SELECT * FROM supervisor_attempts ORDER BY attempt_id"
    ).fetchall()
    for row in attempts:
        attempt = _attempt_from_row(row)
        head = connection.execute(
            """
            SELECT * FROM supervisor_flow_revisions
            WHERE flow_id = ? ORDER BY revision DESC LIMIT 1
            """,
            (attempt.flow_id,),
        ).fetchone()
        revision = _flow_revision_from_row(head)
        if revision.active_attempt_id == attempt.attempt_id:
            continue
        held = False
        for key in attempt.lease_keys:
            lease = connection.execute(
                "SELECT * FROM leases WHERE lease_key = ?", (key,)
            ).fetchone()
            if lease is not None and lease["owner_id"] == attempt.lease_owner:
                held = True
                break
        if held:
            findings.append(
                _finding(
                    "orphan_attempt_leases",
                    "inactive_attempt_still_holds_lease",
                    attempt.flow_id,
                    attempt.attempt_id,
                    revision.revision,
                    "release_orphan_attempt_leases",
                )
            )
    pending = connection.execute(
        """
        SELECT o.* FROM supervisor_completion_outbox o
        LEFT JOIN supervisor_completion_receipts r ON r.outbox_id = o.outbox_id
        WHERE r.outbox_id IS NULL ORDER BY o.outbox_id
        """
    ).fetchall()
    for row in pending:
        findings.append(
            _finding(
                "undelivered_completion",
                "local_completion_receipt_missing",
                row["flow_id"], row["attempt_id"], row["source_revision"], None,
            )
        )
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def _make_plan(
    database_present: bool,
    observed_at: float,
    findings: Iterable[ReconciliationFinding],
) -> ReconciliationPlan:
    selected = tuple(findings)
    digest = _sha256_text(
        _canonical_json(
            {
                "database_present": database_present,
                "findings": [finding.to_mapping() for finding in selected],
            }
        )
    )
    return ReconciliationPlan(database_present, observed_at, selected, digest)


def _finding(
    kind: str,
    reason_code: str,
    flow_id: str | None,
    attempt_id: str | None,
    expected_revision: int | None,
    action: str | None,
) -> ReconciliationFinding:
    identity = _canonical_json(
        {
            "kind": kind,
            "flow_id": flow_id,
            "attempt_id": attempt_id,
            "expected_revision": expected_revision,
            "action": action,
        }
    )
    return ReconciliationFinding(
        finding_id=_sha256_text(identity),
        kind=kind,
        reason_code=reason_code,
        flow_id=flow_id,
        attempt_id=attempt_id,
        expected_revision=expected_revision,
        action=action,
    )


def _table_names(connection: sqlite3.Connection) -> frozenset[str]:
    return frozenset(
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    )


def _schema_objects(
    connection: sqlite3.Connection,
) -> dict[str, tuple[str, str, str]]:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql FROM sqlite_master
        WHERE sql IS NOT NULL AND type IN ('table', 'index', 'trigger')
        ORDER BY type, name
        """
    ).fetchall()
    return {
        row["name"]: (
            row["type"],
            row["tbl_name"],
            " ".join(row["sql"].split()),
        )
        for row in rows
    }


@cache
def _expected_baseline_schema() -> dict[str, tuple[str, str, str]]:
    with SQLiteStateStore(":memory:") as store:
        return _schema_objects(store._connection)


@cache
def _expected_supervisor_schema() -> dict[str, tuple[str, str, str]]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_SCHEMA_V2 + "\n" + _SCHEMA_V3)
        objects = _schema_objects(connection)
        return {
            name: value
            for name, value in objects.items()
            if name.startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


def _verify_baseline_schema(connection: sqlite3.Connection) -> None:
    actual = _schema_objects(connection)
    expected = _expected_baseline_schema()
    baseline_tables = {
        name for name, value in expected.items() if value[0] == "table"
    }
    actual_owned = {
        name: value
        for name, value in actual.items()
        if name in expected or value[1] in baseline_tables
    }
    if actual_owned != expected:
        raise ConfigurationError("state database baseline schema does not match v1")


def _verify_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        name: value
        for name, value in objects.items()
        if name.startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_supervisor_schema():
        raise ConfigurationError("supervisor schema objects do not match migrations")


@cache
def _expected_migration_schema() -> dict[str, tuple[str, str, str]]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_MIGRATION_SCHEMA)
        objects = _schema_objects(connection)
        return {
            name: value
            for name, value in objects.items()
            if name.startswith("state_schema_migrations")
            or value[1] == "state_schema_migrations"
        }
    finally:
        connection.close()


def _verify_migration_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        name: value
        for name, value in objects.items()
        if name.startswith("state_schema_migrations")
        or value[1] == "state_schema_migrations"
    }
    if actual != _expected_migration_schema():
        raise ConfigurationError("schema migration ledger objects are invalid")


def _validate_flow_spec(spec: FlowSpec) -> None:
    if not isinstance(spec, FlowSpec):
        raise ValidationError("flow specification must be a FlowSpec")
    for field_name in (
        "flow_id",
        "admission_key",
        "task_id",
        "task_version",
        "runner_id",
        "profile_id",
    ):
        _validate_text(getattr(spec, field_name), field_name, maximum=256)
    for field_name in ("task_definition_digest", "context_digest"):
        _validate_digest(getattr(spec, field_name), field_name)
    if spec.runner_id != "mock":
        raise ValidationError("the supervisor tracer admits only deterministic mock flows")
    if spec.permission_class not in {
        PermissionClass.READ_ONLY,
        PermissionClass.LOCAL_DRAFT,
    }:
        raise ValidationError("only permission classes 0 and 1 may be admitted")
    if not isinstance(spec.resource_keys, tuple):
        raise ValidationError("resource_keys must be an immutable tuple")
    if len(spec.resource_keys) > 32 or len(set(spec.resource_keys)) != len(spec.resource_keys):
        raise ValidationError("resource_keys must contain at most 32 unique values")
    for key in spec.resource_keys:
        if not isinstance(key, str) or _RESOURCE_KEY.fullmatch(key) is None:
            raise ValidationError("resource key is invalid")
        if key == _FOREGROUND_LEASE_KEY or key.startswith("flow:"):
            raise ValidationError("resource key uses a controller-reserved namespace")
    _timestamp(spec.available_at, "available_at")
    _timestamp(spec.created_at, "created_at")
    if spec.deadline_at is not None:
        deadline = _timestamp(spec.deadline_at, "deadline_at")
        if deadline <= spec.available_at:
            raise ValidationError("deadline_at must be later than available_at")
    if (
        isinstance(spec.attempt_timeout_seconds, bool)
        or not isinstance(spec.attempt_timeout_seconds, int)
        or not 1 <= spec.attempt_timeout_seconds <= 86_400
    ):
        raise ValidationError(
            "attempt_timeout_seconds must be an integer from 1 through 86400"
        )
    for field_name in ("mandatory_priority", "blocker_priority"):
        if getattr(spec, field_name) not in (0, 1):
            raise ValidationError(f"{field_name} must be 0 or 1")
    for field_name in ("value_priority", "evidence_priority", "capacity_fit_priority"):
        value = getattr(spec, field_name)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
            raise ValidationError(f"{field_name} must be an integer from 0 through 100")
    if isinstance(spec.max_attempts, bool) or not isinstance(spec.max_attempts, int):
        raise ValidationError("max_attempts must be a positive integer")
    if not 1 <= spec.max_attempts <= 10:
        raise ValidationError("max_attempts must be between 1 and 10")
    _validate_digest(spec.request_digest, "request_digest")


def _validate_text(value: str, field_name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValidationError(f"{field_name} must be a bounded non-empty string")
    if "\x00" in value or any(
        ord(character) < 32 and character not in "\t\n\r" for character in value
    ):
        raise ValidationError(f"{field_name} contains control characters")
    # Reuse canonical JSON's central secret scanner without persisting a value.
    _canonical_json({"value": value})
    return value


def _validate_owner(value: str, field_name: str) -> None:
    _validate_text(value, field_name, maximum=256)
    if "/" not in value or len(value.rsplit("/", 1)[-1]) < 12:
        raise ValidationError(f"{field_name} must include a never-reused random suffix")


def _validate_reason(value: str) -> None:
    if not isinstance(value, str) or _REASON_CODE.fullmatch(value) is None:
        raise ValidationError("reason_code must be bounded snake_case")


def _validate_digest(value: str, field_name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValidationError(f"{field_name} must be a lowercase SHA-256 digest")


def _validate_revision(value: int, *, allow_zero: bool = False) -> None:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError("revision is invalid")


def _timestamp(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be a finite non-negative number")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        raise ValidationError(f"{field_name} must be a finite non-negative number")
    return numeric


def _positive_duration(value: float, field_name: str) -> float:
    numeric = _timestamp(value, field_name)
    if numeric <= 0:
        raise ValidationError(f"{field_name} must be positive")
    return numeric


def _bounded_json(value: Any, field_name: str) -> str:
    encoded = _canonical_json(value)
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValidationError(f"{field_name} exceeds the persisted JSON limit")
    return encoded


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _flow_from_row(row: sqlite3.Row) -> FlowSpec:
    return FlowSpec(
        flow_id=row["flow_id"],
        admission_key=row["admission_key"],
        task_id=row["task_id"],
        task_version=row["task_version"],
        task_definition_digest=row["task_definition_digest"],
        context_digest=row["context_digest"],
        runner_id=row["runner_id"],
        profile_id=row["profile_id"],
        permission_class=PermissionClass(row["permission_class"]),
        resource_keys=tuple(json.loads(row["resource_keys_json"])),
        available_at=row["available_at"],
        deadline_at=row["deadline_at"],
        attempt_timeout_seconds=row["attempt_timeout_seconds"],
        mandatory_priority=row["mandatory_priority"],
        blocker_priority=row["blocker_priority"],
        value_priority=row["value_priority"],
        evidence_priority=row["evidence_priority"],
        capacity_fit_priority=row["capacity_fit_priority"],
        max_attempts=row["max_attempts"],
        created_at=row["created_at"],
    )


def _flow_revision_from_row(row: sqlite3.Row) -> FlowRevision:
    return FlowRevision(
        sequence=row["sequence"],
        event_id=row["event_id"],
        flow_id=row["flow_id"],
        revision=row["revision"],
        state=FlowState(row["state"]),
        cancellation_requested=bool(row["cancellation_requested"]),
        active_attempt_id=row["active_attempt_id"],
        reason_code=row["reason_code"],
        occurred_at=row["occurred_at"],
    )


def _supervisor_authorization_request(
    *,
    boundary: str,
    spec: FlowSpec,
    observed_at: float,
    attempt_id: str | None,
) -> tuple[AuthorizationRequest, PolicyBundle]:
    if boundary not in {"flow_admission", "attempt_claim"}:
        raise ValidationError("unsupported supervisor authorization boundary")
    operation = (
        "supervisor.flow_admit"
        if boundary == "flow_admission"
        else "supervisor.attempt_claim"
    )
    verb = ActionVerb.CREATE if boundary == "flow_admission" else ActionVerb.EXECUTE
    flow_state = "admission_proposed" if boundary == "flow_admission" else "claim_proposed"
    request = AuthorizationRequest(
        request_id=f"supervisor:{boundary}:{spec.flow_id}:{attempt_id or 'initial'}",
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="agentops:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest({"profile_id": spec.profile_id}),
            runner_id=spec.runner_id,
            session_id=None,
        ),
        action=ActionAttributes(
            verb=verb,
            operation=operation,
            parameters_digest=canonical_digest(
                {
                    "attempt_id": attempt_id,
                    "flow_request_digest": spec.request_digest,
                    "resource_keys": list(spec.resource_keys),
                }
            ),
            intended_effect="append_local_control_plane_state",
        ),
        resource=ResourceAttributes(
            resource_type="supervisor_flow",
            identifier=canonical_digest({"flow_id": spec.flow_id}),
            version=spec.request_digest,
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(spec.immutable_mapping()),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=observed_at,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.MOCK,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=PaidContinuationProtection.NOT_APPLICABLE,
            circuit_state=CircuitState.CLOSED,
            flow_state=flow_state,
        ),
        consequences=ConsequenceVector(
            confidentiality=ImpactLevel.LOW,
            integrity=ImpactLevel.LOW,
            availability=ImpactLevel.LOW,
            reach=Reach.LOCAL,
            destructive=False,
            reversible=True,
            sensitivity=ImpactLevel.LOW,
            blast_radius=BlastRadius.SINGLE_RESOURCE,
        ),
    )
    sources = {
        "subject": EvidenceSource.CONTROLLER,
        "action": EvidenceSource.CONTROLLER,
        "resource": EvidenceSource.LOCAL_REGISTRY,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.LOCAL_REGISTRY,
    }
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=f"supervisor:{boundary}:{attribute}",
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id=f"agentops:{source.value}",
            observed_at=observed_at,
            expires_at=observed_at + 60.0,
            authenticated=True,
        )
        for attribute, source in sources.items()
    )
    request = AuthorizationRequest(
        request.request_id,
        request.subject,
        request.action,
        request.resource,
        request.environment,
        request.consequences,
        evidence,
    )
    base = PolicyBundle.current_stage(issued_at=observed_at)
    policy = PolicyBundle(
        bundle_id=base.bundle_id,
        version=base.version,
        issued_at=base.issued_at,
        evidence_requirements=base.evidence_requirements,
        enabled_classes=base.enabled_classes,
        allowed_verbs=base.allowed_verbs,
        allowed_roles=tuple(dict.fromkeys((*base.allowed_roles, Role.CONTROLLER))),
        allowed_operations=tuple(dict.fromkeys((*base.allowed_operations, operation))),
        allowed_resource_types=tuple(
            dict.fromkeys((*base.allowed_resource_types, "supervisor_flow"))
        ),
        allowed_trust_boundaries=tuple(
            dict.fromkeys((*base.allowed_trust_boundaries, "local_control_plane"))
        ),
        allowed_flow_states=tuple(
            dict.fromkeys((*base.allowed_flow_states, flow_state))
        ),
        allowed_network_states=base.allowed_network_states,
        allowed_billing_routes=base.allowed_billing_routes,
        approval_requirements=base.approval_requirements,
        decision_ttl_seconds=base.decision_ttl_seconds,
    )
    return request, policy


def _authorization_observation_from_row(
    row: sqlite3.Row,
) -> SupervisorAuthorizationObservation:
    return SupervisorAuthorizationObservation(
        sequence=row["sequence"],
        observation_id=row["observation_id"],
        boundary=row["boundary"],
        flow_id=row["flow_id"],
        request_digest=row["request_digest"],
        decision_digest=row["decision_digest"],
        effect=row["effect"],
        derived_permission_class=PermissionClass(row["derived_permission_class"]),
        legacy_executable=bool(row["legacy_executable"]),
        execution_parity=bool(row["execution_parity"]),
        payload=json.loads(row["payload_json"]),
        observed_at=row["observed_at"],
    )


def _control_from_row(row: sqlite3.Row) -> SupervisorControlRevision:
    return SupervisorControlRevision(
        sequence=row["sequence"],
        event_id=row["event_id"],
        revision=row["revision"],
        mode=SupervisorMode(row["mode"]),
        actor_id=row["actor_id"],
        reason_code=row["reason_code"],
        occurred_at=row["occurred_at"],
    )


def _attempt_from_row(row: sqlite3.Row) -> AttemptRecord:
    return AttemptRecord(
        attempt_id=row["attempt_id"],
        flow_id=row["flow_id"],
        attempt_number=row["attempt_number"],
        run_id=row["run_id"],
        claimed_revision=row["claimed_revision"],
        lease_owner=row["lease_owner"],
        lease_keys=tuple(json.loads(row["lease_keys_json"])),
        input_digest=row["input_digest"],
        deadline_at=row["deadline_at"],
        created_at=row["created_at"],
    )


def _attempt_event_from_row(row: sqlite3.Row) -> AttemptEvent:
    return AttemptEvent(
        sequence=row["sequence"],
        event_id=row["event_id"],
        attempt_id=row["attempt_id"],
        revision=row["revision"],
        state=AttemptState(row["state"]),
        reason_code=row["reason_code"],
        occurred_at=row["occurred_at"],
    )


def _completion_from_row(row: sqlite3.Row) -> CompletionIntent:
    return CompletionIntent(
        outbox_id=row["outbox_id"],
        idempotency_key=row["idempotency_key"],
        flow_id=row["flow_id"],
        source_revision=row["source_revision"],
        attempt_id=row["attempt_id"],
        envelope_json=row["envelope_json"],
        intent_digest=row["intent_digest"],
        operation_digest=row["operation_digest"],
        created_at=row["created_at"],
    )


def _receipt_from_row(row: sqlite3.Row) -> CompletionReceipt:
    return CompletionReceipt(
        receipt_id=row["receipt_id"],
        outbox_id=row["outbox_id"],
        idempotency_key=row["idempotency_key"],
        consumer_id=row["consumer_id"],
        result_digest=row["result_digest"],
        delivered_at=row["delivered_at"],
    )


__all__ = [
    "AdmissionConflictError",
    "AttemptClaim",
    "AttemptRecord",
    "AttemptState",
    "ClaimLostError",
    "CompletionIntent",
    "CompletionReceipt",
    "FlowRevision",
    "FlowSpec",
    "FlowState",
    "ForegroundSupervisor",
    "ReconciliationFinding",
    "ReconciliationPlan",
    "SQLiteSupervisorStore",
    "StaleReconciliationPlanError",
    "StaleRevisionError",
    "SupervisorControlRevision",
    "SupervisorAuthorizationObservation",
    "SupervisorAuthorizationAudit",
    "SupervisorAuthorizationFinding",
    "SupervisorError",
    "SupervisorMode",
    "SupervisorStatus",
    "inspect_reconciliation",
    "inspect_pending_completions",
    "inspect_supervisor_authorization",
    "inspect_supervisor_audit",
    "inspect_supervisor_status",
]
