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

from .errors import (
    AuthorizationBlocked,
    ConfigurationError,
    OrdomataError,
    ValidationError,
)
from .environment import is_sensitive_environment_value
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
from .state import (
    SQLiteStateStore,
    _KNOWN_STATE_MIGRATIONS,
    _canonical_json,
    _expected_migration_schema,
    _state_schema_integrity_issues,
    _verify_baseline_history,
    _verify_baseline_schema,
    _verify_migration_ledger,
    _verify_migration_schema,
)
from .schema import parse_json_document
from .supervisor_attempt_claim_authorization import (
    SupervisorAttemptClaim,
    SupervisorAttemptClaimAuthorization,
    assert_supervisor_attempt_claim_authorized,
    build_supervisor_attempt_claim_action_receipt,
    evaluate_supervisor_attempt_claim_authorization,
)
from .supervisor_control_authorization import (
    SupervisorControlAuthorization,
    SupervisorControlTransition,
    assert_supervisor_control_transition_authorized,
    build_supervisor_control_action_receipt,
    evaluate_supervisor_control_authorization,
)
from .supervisor_flow_admission_authorization import (
    SupervisorFlowAdmission,
    SupervisorFlowAdmissionAuthorization,
    assert_supervisor_flow_admission_authorized,
    build_supervisor_flow_admission_action_receipt,
    evaluate_supervisor_flow_admission_authorization,
)
from .supervisor_pre_dispatch_intent_authorization import (
    SupervisorPreDispatchIntent,
    SupervisorPreDispatchIntentAuthorization,
    SupervisorPreDispatchIntentLease,
    assert_supervisor_pre_dispatch_intent_authorized,
    build_supervisor_pre_dispatch_intent_action_receipt,
    evaluate_supervisor_pre_dispatch_intent_authorization,
)


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
_ATTEMPT_TRANSITIONS: Mapping[AttemptState, frozenset[AttemptState]] = {
    AttemptState.CREATED: frozenset(
        {
            AttemptState.DISPATCHING,
            AttemptState.SUCCEEDED,
            AttemptState.FAILED,
            AttemptState.BLOCKED,
            AttemptState.TIMED_OUT,
            AttemptState.CANCELLED,
            AttemptState.LOST,
        }
    ),
    AttemptState.DISPATCHING: frozenset(
        {
            AttemptState.RUNNING,
            AttemptState.SUCCEEDED,
            AttemptState.FAILED,
            AttemptState.BLOCKED,
            AttemptState.TIMED_OUT,
            AttemptState.CANCELLED,
            AttemptState.LOST,
        }
    ),
    AttemptState.RUNNING: frozenset(
        {
            AttemptState.SUCCEEDED,
            AttemptState.FAILED,
            AttemptState.BLOCKED,
            AttemptState.TIMED_OUT,
            AttemptState.CANCELLED,
            AttemptState.LOST,
        }
    ),
    AttemptState.SUCCEEDED: frozenset(),
    AttemptState.FAILED: frozenset(),
    AttemptState.BLOCKED: frozenset(),
    AttemptState.TIMED_OUT: frozenset(),
    AttemptState.CANCELLED: frozenset(),
    AttemptState.LOST: frozenset(),
}
_REASON_CODE = re.compile(r"[a-z0-9_]{1,100}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_RESOURCE_KEY = re.compile(r"[a-z0-9][a-z0-9._:/-]{0,199}")
_MAX_JSON_BYTES = 262_144
_SCHEMA_VERSION = 11
_FOREGROUND_LEASE_KEY = "supervisor:foreground"
_PRE_DISPATCH_INTENT_BOUNDARY = "attempt_pre_dispatch_intent"
_PRE_DISPATCH_INTENT_ACTION_SCOPE = (
    "supervisor_local_attempt_pre_dispatch_intent_only"
)
_PRE_DISPATCH_INTENT_OPERATION = "supervisor.attempt_pre_dispatch_intent"
# The read-only audit must not inherit a patched first-pass shadow evaluator.
_BUILTIN_PRE_DISPATCH_SHADOW_EVALUATE = ShadowAuthorizationEvaluator.evaluate
_ATTEMPT_COMPLETION_BOUNDARY = "attempt_completion"
_ATTEMPT_COMPLETION_ACTION_SCOPE = "supervisor_local_attempt_completion_only"
_ATTEMPT_COMPLETION_OPERATION = "supervisor.attempt_completion"
# As above, historical completion-shadow replay must use the shipped evaluator.
_BUILTIN_ATTEMPT_COMPLETION_SHADOW_EVALUATE = ShadowAuthorizationEvaluator.evaluate
_PRE_DISPATCH_RECONCILIATION_BOUNDARY = "attempt_pre_dispatch_reconciliation"
_PRE_DISPATCH_RECONCILIATION_ACTION_SCOPE = (
    "supervisor_local_pre_dispatch_reconciliation_only"
)
_PRE_DISPATCH_RECONCILIATION_OPERATION = (
    "supervisor.attempt_pre_dispatch_reconciliation"
)
# As above, historical reconciliation-shadow replay must use the shipped
# evaluator rather than a mutable first-pass seam.
_BUILTIN_PRE_DISPATCH_RECONCILIATION_SHADOW_EVALUATE = (
    ShadowAuthorizationEvaluator.evaluate
)
SUPERVISOR_DISPATCH_BLOCKERS = (
    "runtime_abac_enforcement_not_implemented",
    "repository_worker_containment_not_proven",
)


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
class SupervisorBookkeepingAuthorizationObservation:
    sequence: int
    observation_id: str
    boundary: str
    flow_id: str | None
    control_event_id: str | None
    cancellation_request_id: str | None
    request_digest: str
    decision_digest: str
    effect: str
    derived_permission_class: PermissionClass
    legacy_executable: bool
    execution_parity: bool
    payload: Mapping[str, Any]
    observed_at: float


@dataclass(frozen=True, slots=True)
class SupervisorPreDispatchIntentAuthorizationObservation:
    """One non-authoritative, privacy-bounded local pre-dispatch observation."""

    sequence: int
    observation_id: str
    flow_id: str
    attempt_id: str
    source_flow_event_id: str
    source_flow_revision: int
    source_attempt_event_id: str
    target_attempt_event_id: str
    request_digest: str
    decision_digest: str
    effect: str
    derived_permission_class: PermissionClass
    legacy_executable: bool
    execution_parity: bool
    payload: Mapping[str, Any]
    observed_at: float


@dataclass(frozen=True, slots=True)
class SupervisorAttemptCompletionAuthorizationObservation:
    """One non-authoritative, privacy-bounded local completion observation."""

    sequence: int
    observation_id: str
    flow_id: str
    attempt_id: str
    source_flow_event_id: str
    source_flow_revision: int
    source_attempt_event_id: str
    target_flow_event_id: str
    target_attempt_event_id: str
    outbox_id: str
    request_digest: str
    decision_digest: str
    effect: str
    derived_permission_class: PermissionClass
    legacy_executable: bool
    execution_parity: bool
    payload: Mapping[str, Any]
    observed_at: float


@dataclass(frozen=True, slots=True)
class SupervisorPreDispatchReconciliationAuthorizationObservation:
    """One non-authoritative, privacy-bounded pre-dispatch repair observation."""

    sequence: int
    observation_id: str
    flow_id: str
    attempt_id: str
    source_flow_event_id: str
    source_flow_revision: int
    source_attempt_event_id: str
    target_flow_event_id: str
    target_attempt_event_id: str
    outbox_id: str
    reconciliation_action: str
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
    target_reference: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "flow_id": self.flow_id,
            "boundary": self.boundary,
            "observation_sequence": self.observation_sequence,
            "target_reference": self.target_reference,
        }


@dataclass(frozen=True, slots=True)
class SupervisorAuthorizationAudit:
    database_present: bool
    schema_present: bool
    observation_count: int
    expected_observation_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]
    control_enforcement_record_count: int = 0
    expected_control_enforcement_record_count: int = 0
    flow_admission_enforcement_record_count: int = 0
    expected_flow_admission_enforcement_record_count: int = 0
    attempt_claim_enforcement_record_count: int = 0
    expected_attempt_claim_enforcement_record_count: int = 0
    pre_dispatch_intent_observation_count: int = 0
    expected_pre_dispatch_intent_observation_count: int = 0
    pre_dispatch_intent_enforcement_record_count: int = 0
    expected_pre_dispatch_intent_enforcement_record_count: int = 0
    attempt_completion_observation_count: int = 0
    expected_attempt_completion_observation_count: int = 0
    pre_dispatch_reconciliation_observation_count: int = 0
    expected_pre_dispatch_reconciliation_observation_count: int = 0

    @property
    def clean(self) -> bool:
        return not self.findings

    def to_mapping(self) -> dict[str, Any]:
        return {
            "database_present": self.database_present,
            "schema_present": self.schema_present,
            "observation_count": self.observation_count,
            "expected_observation_count": self.expected_observation_count,
            "control_enforcement_record_count": (
                self.control_enforcement_record_count
            ),
            "expected_control_enforcement_record_count": (
                self.expected_control_enforcement_record_count
            ),
            "flow_admission_enforcement_record_count": (
                self.flow_admission_enforcement_record_count
            ),
            "expected_flow_admission_enforcement_record_count": (
                self.expected_flow_admission_enforcement_record_count
            ),
            "attempt_claim_enforcement_record_count": (
                self.attempt_claim_enforcement_record_count
            ),
            "expected_attempt_claim_enforcement_record_count": (
                self.expected_attempt_claim_enforcement_record_count
            ),
            "pre_dispatch_intent_observation_count": (
                self.pre_dispatch_intent_observation_count
            ),
            "expected_pre_dispatch_intent_observation_count": (
                self.expected_pre_dispatch_intent_observation_count
            ),
            "pre_dispatch_intent_enforcement_record_count": (
                self.pre_dispatch_intent_enforcement_record_count
            ),
            "expected_pre_dispatch_intent_enforcement_record_count": (
                self.expected_pre_dispatch_intent_enforcement_record_count
            ),
            "attempt_completion_observation_count": (
                self.attempt_completion_observation_count
            ),
            "expected_attempt_completion_observation_count": (
                self.expected_attempt_completion_observation_count
            ),
            "pre_dispatch_reconciliation_observation_count": (
                self.pre_dispatch_reconciliation_observation_count
            ),
            "expected_pre_dispatch_reconciliation_observation_count": (
                self.expected_pre_dispatch_reconciliation_observation_count
            ),
            "finding_count": len(self.findings),
            "clean": self.clean,
            "findings": [finding.to_mapping() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class _SupervisorControlEnforcementAudit:
    """Internal read-only replay summary for the control-transition PEP."""

    schema_present: bool
    record_count: int
    expected_record_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]


@dataclass(frozen=True, slots=True)
class _SupervisorFlowAdmissionEnforcementAudit:
    """Internal read-only replay summary for the flow-admission PEP."""

    schema_present: bool
    record_count: int
    expected_record_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]


@dataclass(frozen=True, slots=True)
class _SupervisorAttemptClaimEnforcementAudit:
    """Internal read-only replay summary for the attempt-claim PEP."""

    schema_present: bool
    record_count: int
    expected_record_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]


@dataclass(frozen=True, slots=True)
class _SupervisorPreDispatchIntentShadowAudit:
    """Internal read-only replay summary for the pre-dispatch shadow."""

    schema_present: bool
    record_count: int
    expected_record_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]


@dataclass(frozen=True, slots=True)
class _SupervisorPreDispatchIntentEnforcementAudit:
    """Internal read-only replay summary for the local intent PEP."""

    schema_present: bool
    record_count: int
    expected_record_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]


@dataclass(frozen=True, slots=True)
class _SupervisorAttemptCompletionShadowAudit:
    """Internal read-only replay summary for the completion shadow."""

    schema_present: bool
    record_count: int
    expected_record_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]


@dataclass(frozen=True, slots=True)
class _SupervisorPreDispatchReconciliationShadowAudit:
    """Internal replay summary for pre-dispatch reconciliation shadows."""

    schema_present: bool
    record_count: int
    expected_record_count: int
    findings: tuple[SupervisorAuthorizationFinding, ...]


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
            "dispatch_blocker": SUPERVISOR_DISPATCH_BLOCKERS[0],
            "dispatch_blockers": list(SUPERVISOR_DISPATCH_BLOCKERS),
        }


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


_SCHEMA_V4 = """
CREATE TABLE supervisor_bookkeeping_authorization_baseline (
    entity_type TEXT NOT NULL CHECK (
        entity_type IN ('control_event', 'cancellation_request')
    ),
    entity_id TEXT NOT NULL,
    PRIMARY KEY(entity_type, entity_id)
);
INSERT INTO supervisor_bookkeeping_authorization_baseline (entity_type, entity_id)
    SELECT 'control_event', event_id FROM supervisor_control_events;
INSERT INTO supervisor_bookkeeping_authorization_baseline (entity_type, entity_id)
    SELECT 'cancellation_request', request_id
    FROM supervisor_cancellation_requests requests
    JOIN supervisor_flows flows ON flows.flow_id = requests.flow_id;

CREATE TABLE supervisor_bookkeeping_authorization_sources (
    cancellation_request_id TEXT PRIMARY KEY
        REFERENCES supervisor_cancellation_requests(request_id),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    source_flow_revision INTEGER NOT NULL CHECK (source_flow_revision > 0),
    FOREIGN KEY(flow_id, source_flow_revision)
        REFERENCES supervisor_flow_revisions(flow_id, revision)
);

CREATE TABLE supervisor_bookkeeping_authorization_observations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id TEXT NOT NULL UNIQUE,
    boundary TEXT NOT NULL CHECK (
        boundary IN ('control_transition', 'flow_cancellation')
    ),
    flow_id TEXT NULL REFERENCES supervisor_flows(flow_id),
    control_event_id TEXT NULL REFERENCES supervisor_control_events(event_id),
    cancellation_request_id TEXT NULL
        REFERENCES supervisor_cancellation_requests(request_id),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    effect TEXT NOT NULL CHECK (effect IN ('permit', 'defer', 'deny', 'indeterminate')),
    derived_permission_class INTEGER NOT NULL CHECK (
        derived_permission_class IN (0, 1, 2, 3)
    ),
    legacy_executable INTEGER NOT NULL CHECK (legacy_executable IN (0, 1)),
    execution_parity INTEGER NOT NULL CHECK (execution_parity IN (0, 1)),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    observed_at REAL NOT NULL CHECK (observed_at >= 0),
    CHECK (
        (boundary = 'control_transition' AND flow_id IS NULL
            AND control_event_id IS NOT NULL
            AND cancellation_request_id IS NULL)
        OR
        (boundary = 'flow_cancellation' AND flow_id IS NOT NULL
            AND control_event_id IS NULL
            AND cancellation_request_id IS NOT NULL)
    )
);
CREATE INDEX supervisor_bookkeeping_authorization_control
    ON supervisor_bookkeeping_authorization_observations(control_event_id, sequence);
CREATE INDEX supervisor_bookkeeping_authorization_cancellation
    ON supervisor_bookkeeping_authorization_observations(
        cancellation_request_id, sequence
    );
CREATE TRIGGER supervisor_bookkeeping_authorization_observations_no_update
BEFORE UPDATE ON supervisor_bookkeeping_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor bookkeeping authorization observations are append-only');
END;
CREATE TRIGGER supervisor_bookkeeping_authorization_observations_no_delete
BEFORE DELETE ON supervisor_bookkeeping_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor bookkeeping authorization observations are append-only');
END;
CREATE TRIGGER supervisor_bookkeeping_authorization_sources_no_update
BEFORE UPDATE ON supervisor_bookkeeping_authorization_sources BEGIN
    SELECT RAISE(ABORT, 'supervisor bookkeeping authorization sources are append-only');
END;
CREATE TRIGGER supervisor_bookkeeping_authorization_sources_no_delete
BEFORE DELETE ON supervisor_bookkeeping_authorization_sources BEGIN
    SELECT RAISE(ABORT, 'supervisor bookkeeping authorization sources are append-only');
END;
CREATE TRIGGER supervisor_bookkeeping_authorization_baseline_no_update
BEFORE UPDATE ON supervisor_bookkeeping_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor bookkeeping authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_bookkeeping_authorization_baseline_no_delete
BEFORE DELETE ON supervisor_bookkeeping_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor bookkeeping authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_bookkeeping_authorization_baseline_no_insert
BEFORE INSERT ON supervisor_bookkeeping_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor bookkeeping authorization baseline is frozen');
END;
"""


_SCHEMA_V5 = """
CREATE TABLE supervisor_control_authorization_baseline (
    control_event_id TEXT PRIMARY KEY
        REFERENCES supervisor_control_events(event_id)
);
INSERT INTO supervisor_control_authorization_baseline (control_event_id)
    SELECT event_id FROM supervisor_control_events;

CREATE TABLE supervisor_control_authorization_decisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_event_id TEXT NOT NULL UNIQUE CHECK (length(decision_event_id) = 71),
    control_event_id TEXT NOT NULL UNIQUE,
    previous_control_event_id TEXT NOT NULL,
    previous_revision INTEGER NOT NULL CHECK (previous_revision >= 0),
    target_revision INTEGER NOT NULL CHECK (
        target_revision = previous_revision + 1
    ),
    target_mode TEXT NOT NULL CHECK (
        target_mode IN ('stopped', 'running', 'paused', 'draining', 'stop_requested')
    ),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    evaluated_at REAL NOT NULL CHECK (evaluated_at >= 0)
);
CREATE INDEX supervisor_control_authorization_decisions_control
    ON supervisor_control_authorization_decisions(control_event_id, sequence);

CREATE TABLE supervisor_control_authorization_action_receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_event_id TEXT NOT NULL UNIQUE CHECK (length(receipt_event_id) = 71),
    control_event_id TEXT NOT NULL UNIQUE
        REFERENCES supervisor_control_events(event_id),
    decision_event_id TEXT NOT NULL UNIQUE
        REFERENCES supervisor_control_authorization_decisions(decision_event_id),
    receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    completed_at REAL NOT NULL CHECK (completed_at >= 0)
);
CREATE INDEX supervisor_control_authorization_receipts_control
    ON supervisor_control_authorization_action_receipts(control_event_id, sequence);

CREATE TRIGGER supervisor_control_authorization_baseline_no_update
BEFORE UPDATE ON supervisor_control_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor control authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_control_authorization_baseline_no_delete
BEFORE DELETE ON supervisor_control_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor control authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_control_authorization_baseline_no_insert
BEFORE INSERT ON supervisor_control_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor control authorization baseline is frozen');
END;
CREATE TRIGGER supervisor_control_authorization_decisions_no_update
BEFORE UPDATE ON supervisor_control_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor control authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_control_authorization_decisions_no_delete
BEFORE DELETE ON supervisor_control_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor control authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_control_authorization_action_receipts_no_update
BEFORE UPDATE ON supervisor_control_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor control authorization receipts are append-only');
END;
CREATE TRIGGER supervisor_control_authorization_action_receipts_no_delete
BEFORE DELETE ON supervisor_control_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor control authorization receipts are append-only');
END;
"""


_SCHEMA_V6 = """
CREATE TABLE supervisor_flow_admission_authorization_baseline (
    flow_id TEXT PRIMARY KEY REFERENCES supervisor_flows(flow_id)
);
INSERT INTO supervisor_flow_admission_authorization_baseline (flow_id)
    SELECT flow_id FROM supervisor_flows;

CREATE TABLE supervisor_flow_admission_authorization_decisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_event_id TEXT NOT NULL UNIQUE CHECK (length(decision_event_id) = 71),
    flow_id TEXT NOT NULL UNIQUE,
    admission_key_ref TEXT NOT NULL CHECK (length(admission_key_ref) = 71),
    flow_request_digest TEXT NOT NULL CHECK (length(flow_request_digest) = 64),
    initial_flow_event_id TEXT NOT NULL CHECK (length(initial_flow_event_id) <= 256),
    initial_revision INTEGER NOT NULL CHECK (initial_revision = 1),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    evaluated_at REAL NOT NULL CHECK (evaluated_at >= 0)
);
CREATE INDEX supervisor_flow_admission_authorization_decisions_flow
    ON supervisor_flow_admission_authorization_decisions(flow_id, sequence);

CREATE TABLE supervisor_flow_admission_authorization_action_receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_event_id TEXT NOT NULL UNIQUE CHECK (length(receipt_event_id) = 71),
    flow_id TEXT NOT NULL UNIQUE REFERENCES supervisor_flows(flow_id),
    decision_event_id TEXT NOT NULL UNIQUE
        REFERENCES supervisor_flow_admission_authorization_decisions(decision_event_id),
    receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    completed_at REAL NOT NULL CHECK (completed_at >= 0)
);
CREATE INDEX supervisor_flow_admission_authorization_receipts_flow
    ON supervisor_flow_admission_authorization_action_receipts(flow_id, sequence);

CREATE TRIGGER supervisor_flow_admission_authorization_baseline_no_update
BEFORE UPDATE ON supervisor_flow_admission_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor flow admission authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_flow_admission_authorization_baseline_no_delete
BEFORE DELETE ON supervisor_flow_admission_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor flow admission authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_flow_admission_authorization_baseline_no_insert
BEFORE INSERT ON supervisor_flow_admission_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor flow admission authorization baseline is frozen');
END;
CREATE TRIGGER supervisor_flow_admission_authorization_decisions_no_update
BEFORE UPDATE ON supervisor_flow_admission_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor flow admission authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_flow_admission_authorization_decisions_no_delete
BEFORE DELETE ON supervisor_flow_admission_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor flow admission authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_flow_admission_authorization_action_receipts_no_update
BEFORE UPDATE ON supervisor_flow_admission_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor flow admission authorization receipts are append-only');
END;
CREATE TRIGGER supervisor_flow_admission_authorization_action_receipts_no_delete
BEFORE DELETE ON supervisor_flow_admission_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor flow admission authorization receipts are append-only');
END;
"""


_SCHEMA_V7 = """
CREATE TABLE supervisor_attempt_claim_authorization_baseline (
    attempt_id TEXT PRIMARY KEY REFERENCES supervisor_attempts(attempt_id)
);
INSERT INTO supervisor_attempt_claim_authorization_baseline (attempt_id)
    SELECT attempt_id FROM supervisor_attempts;

CREATE TABLE supervisor_attempt_claim_authorization_decisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_event_id TEXT NOT NULL UNIQUE CHECK (length(decision_event_id) = 71),
    attempt_id TEXT NOT NULL UNIQUE CHECK (length(attempt_id) <= 256),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    flow_request_digest TEXT NOT NULL CHECK (length(flow_request_digest) = 64),
    source_flow_revision INTEGER NOT NULL CHECK (source_flow_revision >= 1),
    target_flow_revision INTEGER NOT NULL CHECK (
        target_flow_revision = source_flow_revision + 1
    ),
    control_revision INTEGER NOT NULL CHECK (control_revision >= 1),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    run_id_ref TEXT NOT NULL CHECK (length(run_id_ref) = 71),
    attempt_event_id TEXT NOT NULL CHECK (length(attempt_event_id) <= 256),
    flow_event_id TEXT NOT NULL CHECK (length(flow_event_id) <= 256),
    instance_owner_ref TEXT NOT NULL CHECK (length(instance_owner_ref) = 71),
    lease_owner_ref TEXT NOT NULL CHECK (length(lease_owner_ref) = 71),
    lease_keys_digest TEXT NOT NULL CHECK (length(lease_keys_digest) = 71),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    deadline_at REAL NOT NULL CHECK (deadline_at >= 0),
    lease_expires_at REAL NOT NULL CHECK (
        lease_expires_at >= 0 AND lease_expires_at <= deadline_at
    ),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    evaluated_at REAL NOT NULL CHECK (evaluated_at >= 0)
);
CREATE INDEX supervisor_attempt_claim_authorization_decisions_attempt
    ON supervisor_attempt_claim_authorization_decisions(attempt_id, sequence);

CREATE TABLE supervisor_attempt_claim_authorization_action_receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_event_id TEXT NOT NULL UNIQUE CHECK (length(receipt_event_id) = 71),
    attempt_id TEXT NOT NULL UNIQUE REFERENCES supervisor_attempts(attempt_id),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    decision_event_id TEXT NOT NULL UNIQUE
        REFERENCES supervisor_attempt_claim_authorization_decisions(decision_event_id),
    receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    completed_at REAL NOT NULL CHECK (completed_at >= 0)
);
CREATE INDEX supervisor_attempt_claim_authorization_receipts_attempt
    ON supervisor_attempt_claim_authorization_action_receipts(attempt_id, sequence);

CREATE TRIGGER supervisor_attempt_claim_authorization_baseline_no_update
BEFORE UPDATE ON supervisor_attempt_claim_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt claim authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_attempt_claim_authorization_baseline_no_delete
BEFORE DELETE ON supervisor_attempt_claim_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt claim authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_attempt_claim_authorization_baseline_no_insert
BEFORE INSERT ON supervisor_attempt_claim_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt claim authorization baseline is frozen');
END;
CREATE TRIGGER supervisor_attempt_claim_authorization_decisions_no_update
BEFORE UPDATE ON supervisor_attempt_claim_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt claim authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_attempt_claim_authorization_decisions_no_delete
BEFORE DELETE ON supervisor_attempt_claim_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt claim authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_attempt_claim_authorization_action_receipts_no_update
BEFORE UPDATE ON supervisor_attempt_claim_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt claim authorization receipts are append-only');
END;
CREATE TRIGGER supervisor_attempt_claim_authorization_action_receipts_no_delete
BEFORE DELETE ON supervisor_attempt_claim_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt claim authorization receipts are append-only');
END;
"""


_SCHEMA_V8 = """
CREATE TABLE supervisor_pre_dispatch_intent_authorization_baseline (
    attempt_event_id TEXT PRIMARY KEY
        REFERENCES supervisor_attempt_events(event_id)
);
INSERT INTO supervisor_pre_dispatch_intent_authorization_baseline (
    attempt_event_id
)
    SELECT event_id FROM supervisor_attempt_events
    WHERE state = 'dispatching';

CREATE TABLE supervisor_pre_dispatch_intent_authorization_observations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id TEXT NOT NULL UNIQUE CHECK (length(observation_id) <= 256),
    target_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(target_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    source_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(source_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    attempt_id TEXT NOT NULL REFERENCES supervisor_attempts(attempt_id),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    source_flow_event_id TEXT NOT NULL CHECK (
        length(source_flow_event_id) <= 256
    ) REFERENCES supervisor_flow_revisions(event_id),
    source_flow_revision INTEGER NOT NULL CHECK (source_flow_revision >= 1),
    flow_request_digest TEXT NOT NULL CHECK (length(flow_request_digest) = 64),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    lease_snapshot_digest TEXT NOT NULL CHECK (
        length(lease_snapshot_digest) = 71
    ),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    effect TEXT NOT NULL CHECK (effect IN ('permit', 'defer', 'deny', 'indeterminate')),
    derived_permission_class INTEGER NOT NULL CHECK (
        derived_permission_class IN (0, 1, 2, 3)
    ),
    legacy_executable INTEGER NOT NULL CHECK (legacy_executable IN (0, 1)),
    execution_parity INTEGER NOT NULL CHECK (execution_parity IN (0, 1)),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    observed_at REAL NOT NULL CHECK (observed_at >= 0),
    CHECK (source_attempt_event_id != target_attempt_event_id)
);
CREATE INDEX supervisor_pre_dispatch_intent_authorization_attempt
    ON supervisor_pre_dispatch_intent_authorization_observations(
        attempt_id, sequence
    );
CREATE INDEX supervisor_pre_dispatch_intent_authorization_target
    ON supervisor_pre_dispatch_intent_authorization_observations(
        target_attempt_event_id, sequence
    );
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_baseline_no_update
BEFORE UPDATE ON supervisor_pre_dispatch_intent_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_baseline_no_delete
BEFORE DELETE ON supervisor_pre_dispatch_intent_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_baseline_no_insert
BEFORE INSERT ON supervisor_pre_dispatch_intent_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization baseline is frozen');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_observations_no_update
BEFORE UPDATE ON supervisor_pre_dispatch_intent_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization observations are append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_observations_no_delete
BEFORE DELETE ON supervisor_pre_dispatch_intent_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization observations are append-only');
END;
"""


_SCHEMA_V9 = """
CREATE TABLE supervisor_pre_dispatch_intent_authorization_enforcement_baseline (
    target_attempt_event_id TEXT PRIMARY KEY
        REFERENCES supervisor_attempt_events(event_id)
);
INSERT INTO supervisor_pre_dispatch_intent_authorization_enforcement_baseline (
    target_attempt_event_id
)
    SELECT event_id FROM supervisor_attempt_events
    WHERE state = 'dispatching';

CREATE TABLE supervisor_pre_dispatch_intent_authorization_decisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_event_id TEXT NOT NULL UNIQUE CHECK (length(decision_event_id) = 71),
    target_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(target_attempt_event_id) <= 256
    ),
    source_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(source_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    attempt_id TEXT NOT NULL REFERENCES supervisor_attempts(attempt_id),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    source_flow_event_id TEXT NOT NULL CHECK (
        length(source_flow_event_id) <= 256
    ) REFERENCES supervisor_flow_revisions(event_id),
    source_flow_revision INTEGER NOT NULL CHECK (source_flow_revision >= 1),
    source_attempt_revision INTEGER NOT NULL CHECK (source_attempt_revision = 1),
    target_attempt_revision INTEGER NOT NULL CHECK (
        target_attempt_revision = source_attempt_revision + 1
    ),
    flow_request_digest TEXT NOT NULL CHECK (length(flow_request_digest) = 64),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    run_id_ref TEXT NOT NULL CHECK (length(run_id_ref) = 71),
    lease_owner_ref TEXT NOT NULL CHECK (length(lease_owner_ref) = 71),
    lease_keys_digest TEXT NOT NULL CHECK (length(lease_keys_digest) = 71),
    lease_snapshot_digest TEXT NOT NULL CHECK (
        length(lease_snapshot_digest) = 71
    ),
    deadline_at REAL NOT NULL CHECK (deadline_at >= 0),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    evaluated_at REAL NOT NULL CHECK (evaluated_at >= 0),
    CHECK (source_attempt_event_id != target_attempt_event_id)
);
CREATE INDEX supervisor_pre_dispatch_intent_authorization_decisions_target
    ON supervisor_pre_dispatch_intent_authorization_decisions(
        target_attempt_event_id, sequence
    );

CREATE TABLE supervisor_pre_dispatch_intent_authorization_action_receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_event_id TEXT NOT NULL UNIQUE CHECK (length(receipt_event_id) = 71),
    target_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(target_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    attempt_id TEXT NOT NULL REFERENCES supervisor_attempts(attempt_id),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    decision_event_id TEXT NOT NULL UNIQUE
        REFERENCES supervisor_pre_dispatch_intent_authorization_decisions(
            decision_event_id
        ),
    receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 71),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    completed_at REAL NOT NULL CHECK (completed_at >= 0)
);
CREATE INDEX supervisor_pre_dispatch_intent_authorization_receipts_target
    ON supervisor_pre_dispatch_intent_authorization_action_receipts(
        target_attempt_event_id, sequence
    );

CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_enforcement_baseline_no_update
BEFORE UPDATE ON supervisor_pre_dispatch_intent_authorization_enforcement_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization enforcement baseline is append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_enforcement_baseline_no_delete
BEFORE DELETE ON supervisor_pre_dispatch_intent_authorization_enforcement_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization enforcement baseline is append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_enforcement_baseline_no_insert
BEFORE INSERT ON supervisor_pre_dispatch_intent_authorization_enforcement_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization enforcement baseline is frozen');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_decisions_no_update
BEFORE UPDATE ON supervisor_pre_dispatch_intent_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_decisions_no_delete
BEFORE DELETE ON supervisor_pre_dispatch_intent_authorization_decisions BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization decisions are append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_action_receipts_no_update
BEFORE UPDATE ON supervisor_pre_dispatch_intent_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization receipts are append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_intent_authorization_action_receipts_no_delete
BEFORE DELETE ON supervisor_pre_dispatch_intent_authorization_action_receipts BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch intent authorization receipts are append-only');
END;
"""


_SCHEMA_V10 = """
CREATE TABLE supervisor_attempt_completion_authorization_baseline (
    outbox_id TEXT PRIMARY KEY
        REFERENCES supervisor_completion_outbox(outbox_id)
);
INSERT INTO supervisor_attempt_completion_authorization_baseline (outbox_id)
    SELECT outbox_id FROM supervisor_completion_outbox
    WHERE attempt_id IS NOT NULL AND operation_digest != intent_digest;

CREATE TABLE supervisor_attempt_completion_authorization_observations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id TEXT NOT NULL UNIQUE CHECK (length(observation_id) <= 256),
    outbox_id TEXT NOT NULL UNIQUE CHECK (length(outbox_id) <= 256)
        REFERENCES supervisor_completion_outbox(outbox_id),
    target_flow_event_id TEXT NOT NULL UNIQUE CHECK (
        length(target_flow_event_id) <= 256
    ) REFERENCES supervisor_flow_revisions(event_id),
    target_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(target_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    source_flow_event_id TEXT NOT NULL UNIQUE CHECK (
        length(source_flow_event_id) <= 256
    ) REFERENCES supervisor_flow_revisions(event_id),
    source_flow_revision INTEGER NOT NULL CHECK (source_flow_revision >= 1),
    source_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(source_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    attempt_id TEXT NOT NULL REFERENCES supervisor_attempts(attempt_id),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    flow_request_digest TEXT NOT NULL CHECK (length(flow_request_digest) = 64),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    lease_snapshot_digest TEXT NOT NULL CHECK (
        length(lease_snapshot_digest) = 71
    ),
    completion_intent_digest TEXT NOT NULL CHECK (
        length(completion_intent_digest) = 64
    ),
    completion_operation_digest TEXT NOT NULL CHECK (
        length(completion_operation_digest) = 64
    ),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    effect TEXT NOT NULL CHECK (effect IN ('permit', 'defer', 'deny', 'indeterminate')),
    derived_permission_class INTEGER NOT NULL CHECK (
        derived_permission_class IN (0, 1, 2, 3)
    ),
    legacy_executable INTEGER NOT NULL CHECK (legacy_executable IN (0, 1)),
    execution_parity INTEGER NOT NULL CHECK (execution_parity IN (0, 1)),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    observed_at REAL NOT NULL CHECK (observed_at >= 0),
    CHECK (source_flow_event_id != target_flow_event_id),
    CHECK (source_attempt_event_id != target_attempt_event_id),
    CHECK (completion_intent_digest != completion_operation_digest)
);
CREATE INDEX supervisor_attempt_completion_authorization_attempt
    ON supervisor_attempt_completion_authorization_observations(
        attempt_id, sequence
    );
CREATE INDEX supervisor_attempt_completion_authorization_target
    ON supervisor_attempt_completion_authorization_observations(
        outbox_id, sequence
    );
CREATE TRIGGER supervisor_attempt_completion_authorization_baseline_no_update
BEFORE UPDATE ON supervisor_attempt_completion_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt completion authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_attempt_completion_authorization_baseline_no_delete
BEFORE DELETE ON supervisor_attempt_completion_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt completion authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_attempt_completion_authorization_baseline_no_insert
BEFORE INSERT ON supervisor_attempt_completion_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt completion authorization baseline is frozen');
END;
CREATE TRIGGER supervisor_attempt_completion_authorization_observations_no_update
BEFORE UPDATE ON supervisor_attempt_completion_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt completion authorization observations are append-only');
END;
CREATE TRIGGER supervisor_attempt_completion_authorization_observations_no_delete
BEFORE DELETE ON supervisor_attempt_completion_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor attempt completion authorization observations are append-only');
END;
"""


_SCHEMA_V11 = """
CREATE TABLE supervisor_pre_dispatch_reconciliation_authorization_baseline (
    outbox_id TEXT PRIMARY KEY
        REFERENCES supervisor_completion_outbox(outbox_id)
);
INSERT INTO supervisor_pre_dispatch_reconciliation_authorization_baseline (
    outbox_id
)
    SELECT outbox_id FROM supervisor_completion_outbox
    WHERE attempt_id IS NOT NULL AND operation_digest = intent_digest;

CREATE TABLE supervisor_pre_dispatch_reconciliation_authorization_observations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id TEXT NOT NULL UNIQUE CHECK (length(observation_id) <= 256),
    outbox_id TEXT NOT NULL UNIQUE CHECK (length(outbox_id) <= 256)
        REFERENCES supervisor_completion_outbox(outbox_id),
    target_flow_event_id TEXT NOT NULL UNIQUE CHECK (
        length(target_flow_event_id) <= 256
    ) REFERENCES supervisor_flow_revisions(event_id),
    target_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(target_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    source_flow_event_id TEXT NOT NULL UNIQUE CHECK (
        length(source_flow_event_id) <= 256
    ) REFERENCES supervisor_flow_revisions(event_id),
    source_flow_revision INTEGER NOT NULL CHECK (source_flow_revision >= 1),
    source_attempt_event_id TEXT NOT NULL UNIQUE CHECK (
        length(source_attempt_event_id) <= 256
    ) REFERENCES supervisor_attempt_events(event_id),
    attempt_id TEXT NOT NULL REFERENCES supervisor_attempts(attempt_id),
    flow_id TEXT NOT NULL REFERENCES supervisor_flows(flow_id),
    flow_request_digest TEXT NOT NULL CHECK (length(flow_request_digest) = 64),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    lease_snapshot_digest TEXT NOT NULL CHECK (
        length(lease_snapshot_digest) = 71
    ),
    completion_intent_digest TEXT NOT NULL CHECK (
        length(completion_intent_digest) = 64
    ),
    completion_operation_digest TEXT NOT NULL CHECK (
        length(completion_operation_digest) = 64
    ),
    reconciliation_action TEXT NOT NULL CHECK (
        reconciliation_action IN (
            'finalize_cancelled_pre_dispatch',
            'mark_lost_pre_dispatch'
        )
    ),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    effect TEXT NOT NULL CHECK (effect IN ('permit', 'defer', 'deny', 'indeterminate')),
    derived_permission_class INTEGER NOT NULL CHECK (
        derived_permission_class IN (0, 1, 2, 3)
    ),
    legacy_executable INTEGER NOT NULL CHECK (legacy_executable IN (0, 1)),
    execution_parity INTEGER NOT NULL CHECK (execution_parity IN (0, 1)),
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 262144),
    observed_at REAL NOT NULL CHECK (observed_at >= 0),
    CHECK (source_flow_event_id != target_flow_event_id),
    CHECK (source_attempt_event_id != target_attempt_event_id),
    CHECK (completion_intent_digest = completion_operation_digest)
);
CREATE INDEX supervisor_pre_dispatch_reconciliation_authorization_attempt
    ON supervisor_pre_dispatch_reconciliation_authorization_observations(
        attempt_id, sequence
    );
CREATE INDEX supervisor_pre_dispatch_reconciliation_authorization_target
    ON supervisor_pre_dispatch_reconciliation_authorization_observations(
        outbox_id, sequence
    );
CREATE TRIGGER supervisor_pre_dispatch_reconciliation_authorization_baseline_no_update
BEFORE UPDATE ON supervisor_pre_dispatch_reconciliation_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch reconciliation authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_reconciliation_authorization_baseline_no_delete
BEFORE DELETE ON supervisor_pre_dispatch_reconciliation_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch reconciliation authorization baseline is append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_reconciliation_authorization_baseline_no_insert
BEFORE INSERT ON supervisor_pre_dispatch_reconciliation_authorization_baseline BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch reconciliation authorization baseline is frozen');
END;
CREATE TRIGGER supervisor_pre_dispatch_reconciliation_authorization_observations_no_update
BEFORE UPDATE ON supervisor_pre_dispatch_reconciliation_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch reconciliation authorization observations are append-only');
END;
CREATE TRIGGER supervisor_pre_dispatch_reconciliation_authorization_observations_no_delete
BEFORE DELETE ON supervisor_pre_dispatch_reconciliation_authorization_observations BEGIN
    SELECT RAISE(ABORT, 'supervisor pre-dispatch reconciliation authorization observations are append-only');
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
                _configure_journal_mode=False,
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
            self._initialise_migrations()
            self._connection.execute("PRAGMA journal_mode = WAL")
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
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                _verify_baseline_schema(self._connection)
                _verify_baseline_history(self._connection)
                _verify_migration_schema(self._connection)
                _verify_migration_ledger(self._connection)
                versions = {
                    int(row["version"]): row
                    for row in self._connection.execute(
                        "SELECT * FROM state_schema_migrations ORDER BY version"
                    ).fetchall()
                }
                migration_scripts = {
                    2: _SCHEMA_V2,
                    3: _SCHEMA_V3,
                    4: _SCHEMA_V4,
                    5: _SCHEMA_V5,
                    6: _SCHEMA_V6,
                    7: _SCHEMA_V7,
                    8: _SCHEMA_V8,
                    9: _SCHEMA_V9,
                    10: _SCHEMA_V10,
                    11: _SCHEMA_V11,
                }
                for version, script in migration_scripts.items():
                    if _sha256_text(script) != _KNOWN_STATE_MIGRATIONS[version][1]:
                        raise ConfigurationError(
                            "frozen supervisor migration script digest mismatch"
                        )
                missing_versions = tuple(
                    version for version in migration_scripts if version not in versions
                )
                applied_at = self._now(None) if missing_versions else None

                for version in missing_versions:
                    if version == 4:
                        _verify_pre_v4_supervisor_schema(self._connection)
                        _verify_pre_v4_bookkeeping_history(self._connection)
                    if version == 5:
                        _verify_pre_v5_supervisor_schema(self._connection)
                        _verify_pre_v5_control_history(self._connection)
                    if version == 6:
                        _verify_pre_v6_supervisor_schema(self._connection)
                        _verify_pre_v6_flow_history(self._connection)
                    if version == 7:
                        _verify_pre_v7_supervisor_schema(self._connection)
                        _verify_pre_v7_attempt_history(self._connection)
                    if version == 8:
                        _verify_pre_v8_supervisor_schema(self._connection)
                        _verify_pre_v8_pre_dispatch_intent_history(
                            self._connection
                        )
                    if version == 9:
                        _verify_pre_v9_supervisor_schema(self._connection)
                        _verify_pre_v9_pre_dispatch_intent_history(
                            self._connection
                        )
                    if version == 10:
                        _verify_pre_v10_supervisor_schema(self._connection)
                        _verify_pre_v10_attempt_completion_history(
                            self._connection
                        )
                    if version == 11:
                        _verify_pre_v11_supervisor_schema(self._connection)
                        _verify_pre_v11_pre_dispatch_reconciliation_history(
                            self._connection
                        )
                    _execute_schema_script(
                        self._connection,
                        migration_scripts[version],
                    )
                    name, digest = _KNOWN_STATE_MIGRATIONS[version]
                    self._connection.execute(
                        """
                        INSERT INTO state_schema_migrations (
                            version, name, script_sha256, applied_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (version, name, digest, applied_at),
                    )

                _verify_migration_schema(self._connection)
                _verify_migration_ledger(self._connection)
                _verify_supervisor_schema(self._connection)
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def current_control(self) -> SupervisorControlRevision:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM supervisor_control_events ORDER BY revision DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return _initial_control_revision()
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
                _initial_control_revision()
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
            transition = SupervisorControlTransition(
                previous_control_event_id=current.event_id,
                previous_revision=current.revision,
                previous_mode=current.mode.value,
                control_event_id=event_id,
                target_revision=revision,
                target_mode=mode.value,
                actor_ref=canonical_digest({"actor_id": actor_id}),
                reason_code=reason_code,
                occurred_at=timestamp,
            )
            authorization = evaluate_supervisor_control_authorization(
                transition=transition,
                legacy_executable=True,
            )
            decision_payload = authorization.to_event_payload()
            persisted_decision_payload = self._append_control_authorization_decision(
                connection,
                authorization=authorization,
                payload=decision_payload,
            )
            assert_supervisor_control_transition_authorized(
                authorization,
                transition=transition,
                action_started_at=timestamp,
                persisted_payload=persisted_decision_payload,
            )
            cursor = connection.execute(
                """
                INSERT INTO supervisor_control_events (
                    event_id, revision, mode, actor_id, reason_code, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_id, revision, mode.value, actor_id, reason_code, timestamp),
            )
            sequence = int(cursor.lastrowid)
            updated = SupervisorControlRevision(
                sequence, event_id, revision, mode, actor_id, reason_code, timestamp
            )
            receipt_payload = build_supervisor_control_action_receipt(
                authorization=authorization,
                action_started_at=timestamp,
                completed_at=timestamp,
            )
            persisted_receipt_payload = self._append_control_authorization_receipt(
                connection,
                authorization=authorization,
                payload=receipt_payload,
                completed_at=timestamp,
            )
            if persisted_receipt_payload != receipt_payload:
                raise SupervisorError(
                    "supervisor control authorization receipt persistence is uncertain"
                )
            try:
                self._append_bookkeeping_authorization_observation(
                    connection,
                    boundary="control_transition",
                    observed_at=timestamp,
                    legacy_executable=True,
                    control=updated,
                    previous_control=current,
                )
            except Exception:
                # Shadow evidence cannot change a valid legacy control transition.
                pass
        return updated

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
            initial_flow_event_id = self._new_id("flow_event")
            admission = SupervisorFlowAdmission(
                flow_id=spec.flow_id,
                admission_key_ref=canonical_digest(
                    {"admission_key": spec.admission_key}
                ),
                flow_request_digest=spec.request_digest,
                initial_flow_event_id=initial_flow_event_id,
                occurred_at=spec.created_at,
            )
            authorization = evaluate_supervisor_flow_admission_authorization(
                admission=admission,
                legacy_executable=True,
            )
            decision_payload = authorization.to_event_payload()
            persisted_decision_payload = (
                self._append_flow_admission_authorization_decision(
                    connection,
                    authorization=authorization,
                    payload=decision_payload,
                )
            )
            assert_supervisor_flow_admission_authorized(
                authorization,
                admission=admission,
                action_started_at=spec.created_at,
                persisted_payload=persisted_decision_payload,
            )
            if (
                admission.flow_id != spec.flow_id
                or admission.admission_key_ref
                != canonical_digest({"admission_key": spec.admission_key})
                or admission.flow_request_digest != spec.request_digest
                or admission.occurred_at != spec.created_at
            ):
                raise AuthorizationBlocked(
                    "supervisor flow admission target does not match its immutable flow"
                )
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
            initial_revision = self._insert_flow_revision(
                connection,
                flow_id=spec.flow_id,
                revision=1,
                state=FlowState.QUEUED,
                cancellation_requested=False,
                active_attempt_id=None,
                reason_code="admitted",
                occurred_at=spec.created_at,
                event_id=initial_flow_event_id,
            )
            if (
                not isinstance(initial_revision, FlowRevision)
                or initial_revision.event_id != admission.initial_flow_event_id
                or initial_revision.flow_id != admission.flow_id
                or initial_revision.revision != 1
                or initial_revision.state is not FlowState.QUEUED
                or initial_revision.cancellation_requested
                or initial_revision.active_attempt_id is not None
                or initial_revision.reason_code != "admitted"
                or initial_revision.occurred_at != admission.occurred_at
            ):
                raise SupervisorError(
                    "supervisor flow admission revision persistence is uncertain"
                )
            receipt_payload = build_supervisor_flow_admission_action_receipt(
                authorization=authorization,
                action_started_at=spec.created_at,
                completed_at=spec.created_at,
            )
            persisted_receipt_payload = (
                self._append_flow_admission_authorization_receipt(
                    connection,
                    authorization=authorization,
                    payload=receipt_payload,
                    completed_at=spec.created_at,
                )
            )
            if persisted_receipt_payload != receipt_payload:
                raise SupervisorError(
                    "supervisor flow admission authorization receipt persistence is uncertain"
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

    def list_bookkeeping_authorization_observations(
        self,
    ) -> tuple[SupervisorBookkeepingAuthorizationObservation, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM supervisor_bookkeeping_authorization_observations
                ORDER BY sequence
                """
            ).fetchall()
        return tuple(
            _bookkeeping_authorization_observation_from_row(row) for row in rows
        )

    def list_pre_dispatch_intent_authorization_observations(
        self,
        attempt_id: str | None = None,
    ) -> tuple[SupervisorPreDispatchIntentAuthorizationObservation, ...]:
        """Return non-authoritative local pre-dispatch shadow records.

        These records describe only the append-only ``dispatching`` intent
        transition. They are not an authorization permit and never dispatch a
        worker, runner, model, subprocess, repository action, or network call.
        """

        if attempt_id is not None:
            _validate_text(attempt_id, "attempt_id", maximum=256)
        with self._lock:
            if attempt_id is None:
                rows = self._connection.execute(
                    """
                    SELECT * FROM supervisor_pre_dispatch_intent_authorization_observations
                    ORDER BY sequence
                    """
                ).fetchall()
            else:
                rows = self._connection.execute(
                    """
                    SELECT * FROM supervisor_pre_dispatch_intent_authorization_observations
                    WHERE attempt_id = ? ORDER BY sequence
                    """,
                    (attempt_id,),
                ).fetchall()
        return tuple(
            _pre_dispatch_intent_authorization_observation_from_row(row)
            for row in rows
        )

    def list_attempt_completion_authorization_observations(
        self,
        attempt_id: str | None = None,
    ) -> tuple[SupervisorAttemptCompletionAuthorizationObservation, ...]:
        """Return non-authoritative local attempt-completion shadow records.

        The observations bind only an already-committed local flow/attempt
        completion and its local outbox intent. They do not authorize, send,
        deliver, dispatch, or execute anything.
        """

        if attempt_id is not None:
            _validate_text(attempt_id, "attempt_id", maximum=256)
        with self._lock:
            if attempt_id is None:
                rows = self._connection.execute(
                    """
                    SELECT * FROM supervisor_attempt_completion_authorization_observations
                    ORDER BY sequence
                    """
                ).fetchall()
            else:
                rows = self._connection.execute(
                    """
                    SELECT * FROM supervisor_attempt_completion_authorization_observations
                    WHERE attempt_id = ? ORDER BY sequence
                    """,
                    (attempt_id,),
                ).fetchall()
        return tuple(
            _attempt_completion_authorization_observation_from_row(row)
            for row in rows
        )

    def list_pre_dispatch_reconciliation_authorization_observations(
        self,
        attempt_id: str | None = None,
    ) -> tuple[SupervisorPreDispatchReconciliationAuthorizationObservation, ...]:
        """Return non-authoritative pre-dispatch repair shadow records.

        These observations bind only a completed local reconciliation of an
        expired pre-dispatch claim. They cannot authorize or invoke a worker,
        delivery, subprocess, task, repository operation, or network action.
        """

        if attempt_id is not None:
            _validate_text(attempt_id, "attempt_id", maximum=256)
        with self._lock:
            if attempt_id is None:
                rows = self._connection.execute(
                    """
                    SELECT *
                    FROM supervisor_pre_dispatch_reconciliation_authorization_observations
                    ORDER BY sequence
                    """
                ).fetchall()
            else:
                rows = self._connection.execute(
                    """
                    SELECT *
                    FROM supervisor_pre_dispatch_reconciliation_authorization_observations
                    WHERE attempt_id = ? ORDER BY sequence
                    """,
                    (attempt_id,),
                ).fetchall()
        return tuple(
            _pre_dispatch_reconciliation_authorization_observation_from_row(row)
            for row in rows
        )

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

        The authoritative PEP here controls only local mock claim bookkeeping.
        The foreground CLI still never calls this method: worker dispatch,
        runner execution, and repository containment remain disabled.
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
                input_digest = _sha256_text(
                    _canonical_json(
                        {
                            "flow_request_digest": spec.request_digest,
                            "attempt_number": attempt_number,
                            "control_revision": control.revision,
                        }
                    )
                )
                attempt_event_id = self._new_id("attempt_event")
                flow_event_id = self._new_id("flow_event")
                claim_target = SupervisorAttemptClaim(
                    flow_id=spec.flow_id,
                    attempt_id=attempt_id,
                    run_id=run_id,
                    source_flow_revision=revision,
                    target_flow_revision=revision + 1,
                    control_revision=control.revision,
                    attempt_number=attempt_number,
                    flow_request_digest=spec.request_digest,
                    input_digest=input_digest,
                    instance_owner_ref=canonical_digest(
                        {"instance_owner": instance_owner}
                    ),
                    lease_owner_ref=canonical_digest(
                        {"lease_owner": lease_owner}
                    ),
                    lease_keys_digest=canonical_digest(
                        {"lease_keys": list(lease_keys)}
                    ),
                    deadline_at=hard_deadline,
                    lease_expires_at=lease_expiry,
                    attempt_event_id=attempt_event_id,
                    flow_event_id=flow_event_id,
                    occurred_at=timestamp,
                )
                authorization = evaluate_supervisor_attempt_claim_authorization(
                    claim=claim_target,
                    legacy_executable=True,
                )
                decision_payload = authorization.to_event_payload()
                persisted_decision_payload = (
                    self._append_attempt_claim_authorization_decision(
                        connection,
                        authorization=authorization,
                        payload=decision_payload,
                    )
                )
                assert_supervisor_attempt_claim_authorized(
                    authorization,
                    claim=claim_target,
                    action_started_at=timestamp,
                    persisted_payload=persisted_decision_payload,
                )
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
                attempt = AttemptRecord(
                    attempt_id, spec.flow_id, attempt_number, run_id, revision,
                    lease_owner, lease_keys, input_digest, hard_deadline, timestamp,
                )
                attempt_row = connection.execute(
                    "SELECT * FROM supervisor_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if attempt_row is None or _attempt_from_row(attempt_row) != attempt:
                    raise SupervisorError(
                        "supervisor attempt claim persistence is uncertain"
                    )
                attempt_event = self._insert_attempt_event(
                    connection,
                    attempt_id=attempt_id,
                    revision=1,
                    state=AttemptState.CREATED,
                    reason_code="claim_created",
                    occurred_at=timestamp,
                    event_id=attempt_event_id,
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
                    event_id=flow_event_id,
                )
                if (
                    not isinstance(attempt_event, AttemptEvent)
                    or attempt_event.event_id != claim_target.attempt_event_id
                    or attempt_event.attempt_id != claim_target.attempt_id
                    or attempt_event.revision != 1
                    or attempt_event.state is not AttemptState.CREATED
                    or attempt_event.reason_code != "claim_created"
                    or attempt_event.occurred_at != claim_target.occurred_at
                    or not isinstance(flow_revision, FlowRevision)
                    or flow_revision.event_id != claim_target.flow_event_id
                    or flow_revision.flow_id != claim_target.flow_id
                    or flow_revision.revision != claim_target.target_flow_revision
                    or flow_revision.state is not FlowState.RUNNING
                    or flow_revision.cancellation_requested
                    or flow_revision.active_attempt_id != claim_target.attempt_id
                    or flow_revision.reason_code != "attempt_claimed"
                    or flow_revision.occurred_at != claim_target.occurred_at
                ):
                    raise SupervisorError(
                        "supervisor attempt claim effect persistence is uncertain"
                    )
                for lease_key in lease_keys:
                    lease = connection.execute(
                        """
                        SELECT owner_id, acquired_at, renewed_at, expires_at
                        FROM leases WHERE lease_key = ?
                        """,
                        (lease_key,),
                    ).fetchone()
                    if lease is None or tuple(lease) != (
                        lease_owner,
                        timestamp,
                        timestamp,
                        lease_expiry,
                    ):
                        raise SupervisorError(
                            "supervisor attempt claim lease persistence is uncertain"
                        )
                receipt_payload = build_supervisor_attempt_claim_action_receipt(
                    authorization=authorization,
                    action_started_at=timestamp,
                    completed_at=timestamp,
                )
                persisted_receipt_payload = (
                    self._append_attempt_claim_authorization_receipt(
                        connection,
                        authorization=authorization,
                        payload=receipt_payload,
                        completed_at=timestamp,
                    )
                )
                if persisted_receipt_payload != receipt_payload:
                    raise SupervisorError(
                        "supervisor attempt claim authorization receipt persistence is uncertain"
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

    def _append_flow_admission_authorization_decision(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorFlowAdmissionAuthorization,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Durably bind an exact PEP decision before a flow admission."""

        if (
            not isinstance(authorization, SupervisorFlowAdmissionAuthorization)
            or dict(payload) != authorization.to_event_payload()
        ):
            raise AuthorizationBlocked(
                "supervisor flow admission authorization decision is inconsistent"
            )
        admission = authorization.admission
        payload_json = _bounded_json(
            dict(payload),
            "supervisor flow admission authorization decision payload",
        )
        values = (
            authorization.decision.digest,
            admission.flow_id,
            admission.admission_key_ref,
            admission.flow_request_digest,
            admission.initial_flow_event_id,
            1,
            authorization.request.digest,
            authorization.decision.digest,
            payload_json,
            admission.occurred_at,
        )
        connection.execute(
            """
            INSERT INTO supervisor_flow_admission_authorization_decisions (
                decision_event_id, flow_id, admission_key_ref, flow_request_digest,
                initial_flow_event_id, initial_revision, request_digest,
                decision_digest, payload_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT decision_event_id, flow_id, admission_key_ref, flow_request_digest,
                   initial_flow_event_id, initial_revision, request_digest,
                   decision_digest, payload_json, evaluated_at
            FROM supervisor_flow_admission_authorization_decisions
            WHERE flow_id = ?
            """,
            (admission.flow_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor flow admission authorization decision persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor flow admission authorization decision persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor flow admission authorization decision persistence is uncertain"
            )
        return persisted_payload

    def _append_flow_admission_authorization_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorFlowAdmissionAuthorization,
        payload: Mapping[str, Any],
        completed_at: float,
    ) -> dict[str, Any]:
        """Append and exactly reread the receipt after a local admission."""

        if (
            not isinstance(authorization, SupervisorFlowAdmissionAuthorization)
            or type(completed_at) not in (int, float)
            or isinstance(completed_at, bool)
            or not math.isfinite(float(completed_at))
            or completed_at < 0
        ):
            raise AuthorizationBlocked(
                "supervisor flow admission authorization receipt is inconsistent"
            )
        expected_payload = build_supervisor_flow_admission_action_receipt(
            authorization=authorization,
            action_started_at=authorization.admission.occurred_at,
            completed_at=float(completed_at),
        )
        if dict(payload) != expected_payload:
            raise AuthorizationBlocked(
                "supervisor flow admission authorization receipt is inconsistent"
            )
        receipt_digest = payload.get("receipt_digest")
        if type(receipt_digest) is not str:
            raise AuthorizationBlocked(
                "supervisor flow admission authorization receipt is inconsistent"
            )
        payload_json = _bounded_json(
            dict(payload),
            "supervisor flow admission authorization receipt payload",
        )
        values = (
            receipt_digest,
            authorization.admission.flow_id,
            authorization.decision.digest,
            receipt_digest,
            payload_json,
            float(completed_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_flow_admission_authorization_action_receipts (
                receipt_event_id, flow_id, decision_event_id, receipt_digest,
                payload_json, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT receipt_event_id, flow_id, decision_event_id, receipt_digest,
                   payload_json, completed_at
            FROM supervisor_flow_admission_authorization_action_receipts
            WHERE flow_id = ?
            """,
            (authorization.admission.flow_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor flow admission authorization receipt persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor flow admission authorization receipt persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor flow admission authorization receipt persistence is uncertain"
            )
        return persisted_payload

    def _append_attempt_claim_authorization_decision(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorAttemptClaimAuthorization,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Durably bind an exact PEP decision before an attempt claim."""

        if (
            not isinstance(authorization, SupervisorAttemptClaimAuthorization)
            or dict(payload) != authorization.to_event_payload()
        ):
            raise AuthorizationBlocked(
                "supervisor attempt claim authorization decision is inconsistent"
            )
        claim = authorization.claim
        payload_json = _bounded_json(
            dict(payload),
            "supervisor attempt claim authorization decision payload",
        )
        values = (
            authorization.decision.digest,
            claim.attempt_id,
            claim.flow_id,
            claim.flow_request_digest,
            claim.source_flow_revision,
            claim.target_flow_revision,
            claim.control_revision,
            claim.attempt_number,
            claim.run_id_ref,
            claim.attempt_event_id,
            claim.flow_event_id,
            claim.instance_owner_ref,
            claim.lease_owner_ref,
            claim.lease_keys_digest,
            claim.input_digest,
            float(claim.deadline_at),
            float(claim.lease_expires_at),
            authorization.request.digest,
            authorization.decision.digest,
            payload_json,
            float(claim.occurred_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_attempt_claim_authorization_decisions (
                decision_event_id, attempt_id, flow_id, flow_request_digest,
                source_flow_revision, target_flow_revision, control_revision,
                attempt_number, run_id_ref, attempt_event_id, flow_event_id,
                instance_owner_ref, lease_owner_ref, lease_keys_digest,
                input_digest, deadline_at, lease_expires_at, request_digest,
                decision_digest, payload_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT decision_event_id, attempt_id, flow_id, flow_request_digest,
                   source_flow_revision, target_flow_revision, control_revision,
                   attempt_number, run_id_ref, attempt_event_id, flow_event_id,
                   instance_owner_ref, lease_owner_ref, lease_keys_digest,
                   input_digest, deadline_at, lease_expires_at, request_digest,
                   decision_digest, payload_json, evaluated_at
            FROM supervisor_attempt_claim_authorization_decisions
            WHERE attempt_id = ?
            """,
            (claim.attempt_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor attempt claim authorization decision persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor attempt claim authorization decision persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor attempt claim authorization decision persistence is uncertain"
            )
        return persisted_payload

    def _append_attempt_claim_authorization_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorAttemptClaimAuthorization,
        payload: Mapping[str, Any],
        completed_at: float,
    ) -> dict[str, Any]:
        """Append and exactly reread the receipt after a local claim."""

        if (
            not isinstance(authorization, SupervisorAttemptClaimAuthorization)
            or type(completed_at) not in (int, float)
            or isinstance(completed_at, bool)
            or not math.isfinite(float(completed_at))
            or completed_at < 0
        ):
            raise AuthorizationBlocked(
                "supervisor attempt claim authorization receipt is inconsistent"
            )
        expected_payload = build_supervisor_attempt_claim_action_receipt(
            authorization=authorization,
            action_started_at=authorization.claim.occurred_at,
            completed_at=float(completed_at),
        )
        if dict(payload) != expected_payload:
            raise AuthorizationBlocked(
                "supervisor attempt claim authorization receipt is inconsistent"
            )
        receipt_digest = payload.get("receipt_digest")
        if type(receipt_digest) is not str:
            raise AuthorizationBlocked(
                "supervisor attempt claim authorization receipt is inconsistent"
            )
        payload_json = _bounded_json(
            dict(payload),
            "supervisor attempt claim authorization receipt payload",
        )
        values = (
            receipt_digest,
            authorization.claim.attempt_id,
            authorization.claim.flow_id,
            authorization.decision.digest,
            receipt_digest,
            payload_json,
            float(completed_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_attempt_claim_authorization_action_receipts (
                receipt_event_id, attempt_id, flow_id, decision_event_id,
                receipt_digest, payload_json, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT receipt_event_id, attempt_id, flow_id, decision_event_id,
                   receipt_digest, payload_json, completed_at
            FROM supervisor_attempt_claim_authorization_action_receipts
            WHERE attempt_id = ?
            """,
            (authorization.claim.attempt_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor attempt claim authorization receipt persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor attempt claim authorization receipt persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor attempt claim authorization receipt persistence is uncertain"
            )
        return persisted_payload

    def _append_control_authorization_decision(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorControlAuthorization,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Durably bind an exact PEP decision before its control mutation."""

        if (
            not isinstance(authorization, SupervisorControlAuthorization)
            or dict(payload) != authorization.to_event_payload()
        ):
            raise AuthorizationBlocked(
                "supervisor control authorization decision is inconsistent"
            )
        transition = authorization.transition
        payload_json = _bounded_json(
            dict(payload),
            "supervisor control authorization decision payload",
        )
        values = (
            authorization.decision.digest,
            transition.control_event_id,
            transition.previous_control_event_id,
            transition.previous_revision,
            transition.target_revision,
            transition.target_mode,
            authorization.request.digest,
            authorization.decision.digest,
            payload_json,
            transition.occurred_at,
        )
        connection.execute(
            """
            INSERT INTO supervisor_control_authorization_decisions (
                decision_event_id, control_event_id, previous_control_event_id,
                previous_revision, target_revision, target_mode, request_digest,
                decision_digest, payload_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT decision_event_id, control_event_id, previous_control_event_id,
                   previous_revision, target_revision, target_mode, request_digest,
                   decision_digest, payload_json, evaluated_at
            FROM supervisor_control_authorization_decisions
            WHERE control_event_id = ?
            """,
            (transition.control_event_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor control authorization decision persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor control authorization decision persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor control authorization decision persistence is uncertain"
            )
        return persisted_payload

    def _append_control_authorization_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorControlAuthorization,
        payload: Mapping[str, Any],
        completed_at: float,
    ) -> dict[str, Any]:
        """Append and exactly reread the receipt after the local state change."""

        if (
            not isinstance(authorization, SupervisorControlAuthorization)
            or type(completed_at) not in (int, float)
            or isinstance(completed_at, bool)
            or not math.isfinite(float(completed_at))
            or completed_at < 0
        ):
            raise AuthorizationBlocked(
                "supervisor control authorization receipt is inconsistent"
            )
        expected_payload = build_supervisor_control_action_receipt(
            authorization=authorization,
            action_started_at=authorization.transition.occurred_at,
            completed_at=float(completed_at),
        )
        if dict(payload) != expected_payload:
            raise AuthorizationBlocked(
                "supervisor control authorization receipt is inconsistent"
            )
        receipt_digest = payload.get("receipt_digest")
        if type(receipt_digest) is not str:
            raise AuthorizationBlocked(
                "supervisor control authorization receipt is inconsistent"
            )
        payload_json = _bounded_json(
            dict(payload),
            "supervisor control authorization receipt payload",
        )
        values = (
            receipt_digest,
            authorization.transition.control_event_id,
            authorization.decision.digest,
            receipt_digest,
            payload_json,
            float(completed_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_control_authorization_action_receipts (
                receipt_event_id, control_event_id, decision_event_id,
                receipt_digest, payload_json, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT receipt_event_id, control_event_id, decision_event_id,
                   receipt_digest, payload_json, completed_at
            FROM supervisor_control_authorization_action_receipts
            WHERE control_event_id = ?
            """,
            (authorization.transition.control_event_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor control authorization receipt persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor control authorization receipt persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor control authorization receipt persistence is uncertain"
            )
        return persisted_payload

    def _append_bookkeeping_authorization_observation(
        self,
        connection: sqlite3.Connection,
        *,
        boundary: str,
        observed_at: float,
        legacy_executable: bool,
        control: SupervisorControlRevision | None = None,
        previous_control: SupervisorControlRevision | None = None,
        spec: FlowSpec | None = None,
        flow_revision: FlowRevision | None = None,
        cancellation_request_id: str | None = None,
        requested_by: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        request, policy = _supervisor_bookkeeping_authorization_request(
            boundary=boundary,
            observed_at=observed_at,
            control=control,
            previous_control=previous_control,
            spec=spec,
            flow_revision=flow_revision,
            cancellation_request_id=cancellation_request_id,
            requested_by=requested_by,
            reason_code=reason_code,
        )
        if boundary == "flow_cancellation":
            if (
                spec is None
                or flow_revision is None
                or cancellation_request_id is None
            ):
                raise ValidationError(
                    "cancellation authorization source is incomplete"
                )
            connection.execute(
                """
                INSERT INTO supervisor_bookkeeping_authorization_sources (
                    cancellation_request_id, flow_id, source_flow_revision
                ) VALUES (?, ?, ?)
                """,
                (
                    cancellation_request_id,
                    spec.flow_id,
                    flow_revision.revision,
                ),
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
            INSERT INTO supervisor_bookkeeping_authorization_observations (
                observation_id, boundary, flow_id, control_event_id,
                cancellation_request_id, request_digest, decision_digest,
                effect, derived_permission_class, legacy_executable,
                execution_parity, payload_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._new_id("bookkeeping_authorization"),
                boundary,
                None if spec is None else spec.flow_id,
                None if control is None else control.event_id,
                cancellation_request_id,
                request.digest,
                decision.digest,
                decision.effect.value,
                int(decision.derived_permission_class),
                int(legacy_executable),
                int(parity),
                _bounded_json(payload, "bookkeeping authorization payload"),
                observed_at,
            ),
        )

    @staticmethod
    def _pre_dispatch_intent_authorization_target(
        *,
        spec: FlowSpec,
        attempt: AttemptRecord,
        source_flow: FlowRevision,
        source_attempt: AttemptEvent,
        target_attempt: AttemptEvent,
        lease_snapshot: object,
        observed_at: float,
    ) -> SupervisorPreDispatchIntent:
        """Build the exact pre-write target from checked local source facts."""

        mapping = _pre_dispatch_intent_mapping(
            spec=spec,
            attempt=attempt,
            source_flow=source_flow,
            source_attempt=source_attempt,
            target_attempt=target_attempt,
            lease_snapshot=lease_snapshot,
            observed_at=observed_at,
        )
        source = mapping["source"]
        snapshot = source["lease_snapshot"]
        if type(snapshot) is not list:
            raise ValidationError("pre-dispatch authorization lease snapshot is invalid")
        leases = tuple(
            SupervisorPreDispatchIntentLease(
                lease_key_ref=item["lease_key_ref"],
                lease_owner_ref=item["lease_owner_ref"],
                acquired_at=item["acquired_at"],
                renewed_at=item["renewed_at"],
                expires_at=item["expires_at"],
            )
            for item in snapshot
        )
        return SupervisorPreDispatchIntent(
            flow_id=attempt.flow_id,
            attempt_id=attempt.attempt_id,
            run_id=attempt.run_id,
            source_flow_event_id=source_flow.event_id,
            source_flow_revision=source_flow.revision,
            source_flow_occurred_at=source_flow.occurred_at,
            source_attempt_event_id=source_attempt.event_id,
            source_attempt_revision=source_attempt.revision,
            source_attempt_occurred_at=source_attempt.occurred_at,
            target_attempt_event_id=target_attempt.event_id,
            target_attempt_revision=target_attempt.revision,
            flow_request_digest=spec.request_digest,
            input_digest=attempt.input_digest,
            lease_owner_ref=canonical_digest({"lease_owner": attempt.lease_owner}),
            lease_keys_digest=canonical_digest(
                {"lease_keys": list(attempt.lease_keys)}
            ),
            lease_snapshot=leases,
            deadline_at=attempt.deadline_at,
            occurred_at=observed_at,
        )

    def _append_pre_dispatch_intent_authorization_decision(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorPreDispatchIntentAuthorization,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist and exactly reread the pre-write local intent permit."""

        if (
            not isinstance(authorization, SupervisorPreDispatchIntentAuthorization)
            or dict(payload) != authorization.to_event_payload()
        ):
            raise AuthorizationBlocked(
                "supervisor pre-dispatch authorization decision is inconsistent"
            )
        intent = authorization.intent
        payload_json = _bounded_json(
            dict(payload),
            "supervisor pre-dispatch authorization decision payload",
        )
        values = (
            authorization.decision.digest,
            intent.target_attempt_event_id,
            intent.source_attempt_event_id,
            intent.attempt_id,
            intent.flow_id,
            intent.source_flow_event_id,
            intent.source_flow_revision,
            intent.source_attempt_revision,
            intent.target_attempt_revision,
            intent.flow_request_digest,
            intent.input_digest,
            intent.run_id_ref,
            intent.lease_owner_ref,
            intent.lease_keys_digest,
            intent.lease_snapshot_digest,
            float(intent.deadline_at),
            authorization.request.digest,
            authorization.decision.digest,
            payload_json,
            float(intent.occurred_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_pre_dispatch_intent_authorization_decisions (
                decision_event_id, target_attempt_event_id, source_attempt_event_id,
                attempt_id, flow_id, source_flow_event_id, source_flow_revision,
                source_attempt_revision, target_attempt_revision,
                flow_request_digest, input_digest, run_id_ref, lease_owner_ref,
                lease_keys_digest, lease_snapshot_digest, deadline_at,
                request_digest, decision_digest, payload_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT decision_event_id, target_attempt_event_id,
                   source_attempt_event_id, attempt_id, flow_id,
                   source_flow_event_id, source_flow_revision,
                   source_attempt_revision, target_attempt_revision,
                   flow_request_digest, input_digest, run_id_ref, lease_owner_ref,
                   lease_keys_digest, lease_snapshot_digest, deadline_at,
                   request_digest, decision_digest, payload_json, evaluated_at
            FROM supervisor_pre_dispatch_intent_authorization_decisions
            WHERE target_attempt_event_id = ?
            """,
            (intent.target_attempt_event_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor pre-dispatch authorization decision persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor pre-dispatch authorization decision persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor pre-dispatch authorization decision persistence is uncertain"
            )
        return persisted_payload

    def _append_pre_dispatch_intent_authorization_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        authorization: SupervisorPreDispatchIntentAuthorization,
        payload: Mapping[str, Any],
        completed_at: float,
    ) -> dict[str, Any]:
        """Persist and exactly reread the receipt after local intent append."""

        if (
            not isinstance(authorization, SupervisorPreDispatchIntentAuthorization)
            or type(completed_at) not in (int, float)
            or isinstance(completed_at, bool)
            or not math.isfinite(float(completed_at))
            or completed_at < 0
        ):
            raise AuthorizationBlocked(
                "supervisor pre-dispatch authorization receipt is inconsistent"
            )
        expected_payload = build_supervisor_pre_dispatch_intent_action_receipt(
            authorization=authorization,
            action_started_at=authorization.intent.occurred_at,
            completed_at=float(completed_at),
        )
        if dict(payload) != expected_payload:
            raise AuthorizationBlocked(
                "supervisor pre-dispatch authorization receipt is inconsistent"
            )
        receipt_digest = payload.get("receipt_digest")
        if type(receipt_digest) is not str:
            raise AuthorizationBlocked(
                "supervisor pre-dispatch authorization receipt is inconsistent"
            )
        payload_json = _bounded_json(
            dict(payload),
            "supervisor pre-dispatch authorization receipt payload",
        )
        intent = authorization.intent
        values = (
            receipt_digest,
            intent.target_attempt_event_id,
            intent.attempt_id,
            intent.flow_id,
            authorization.decision.digest,
            receipt_digest,
            payload_json,
            float(completed_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_pre_dispatch_intent_authorization_action_receipts (
                receipt_event_id, target_attempt_event_id, attempt_id, flow_id,
                decision_event_id, receipt_digest, payload_json, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT receipt_event_id, target_attempt_event_id, attempt_id, flow_id,
                   decision_event_id, receipt_digest, payload_json, completed_at
            FROM supervisor_pre_dispatch_intent_authorization_action_receipts
            WHERE target_attempt_event_id = ?
            """,
            (intent.target_attempt_event_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "supervisor pre-dispatch authorization receipt persistence is uncertain"
            )
        try:
            persisted_payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError(
                "supervisor pre-dispatch authorization receipt persistence is uncertain"
            ) from error
        if type(persisted_payload) is not dict:
            raise SupervisorError(
                "supervisor pre-dispatch authorization receipt persistence is uncertain"
            )
        return persisted_payload

    def _append_pre_dispatch_intent_authorization_observation(
        self,
        connection: sqlite3.Connection,
        *,
        spec: FlowSpec,
        attempt: AttemptRecord,
        source_flow: FlowRevision,
        source_attempt: AttemptEvent,
        target_attempt: AttemptEvent,
        observed_at: float,
        legacy_executable: bool,
    ) -> None:
        """Append a best-effort shadow for a local dispatching-state intent.

        This method is intentionally non-authoritative.  The caller wraps it
        so an evaluator or evidence-persistence failure cannot alter the
        already validated local state transition, and it cannot dispatch work.
        """

        lease_snapshot = _pre_dispatch_intent_lease_snapshot(
            connection,
            attempt=attempt,
            observed_at=observed_at,
        )
        request, policy, intent = (
            _supervisor_pre_dispatch_intent_authorization_request(
                spec=spec,
                attempt=attempt,
                source_flow=source_flow,
                source_attempt=source_attempt,
                target_attempt=target_attempt,
                lease_snapshot=lease_snapshot,
                observed_at=observed_at,
            )
        )
        decision = ShadowAuthorizationEvaluator().evaluate(request, policy)
        parity = (decision.effect.value == "permit") == legacy_executable
        payload = {
            "mode": "shadow",
            "boundary": _PRE_DISPATCH_INTENT_BOUNDARY,
            "action_scope": _PRE_DISPATCH_INTENT_ACTION_SCOPE,
            "pre_dispatch_intent": intent,
            "pre_dispatch_intent_digest": canonical_digest(intent),
            "request": request.to_canonical(),
            "request_digest": request.digest,
            "decision": decision.to_canonical(),
            "decision_digest": decision.digest,
            "legacy_executable": legacy_executable,
            "execution_parity": parity,
        }
        payload_json = _bounded_json(
            payload,
            "pre-dispatch intent authorization payload",
        )
        lease_snapshot_digest = intent["source"]["lease_snapshot_digest"]
        values = (
            self._new_id("pre_dispatch_intent_authorization"),
            target_attempt.event_id,
            source_attempt.event_id,
            attempt.attempt_id,
            attempt.flow_id,
            source_flow.event_id,
            source_flow.revision,
            spec.request_digest,
            attempt.input_digest,
            lease_snapshot_digest,
            request.digest,
            decision.digest,
            decision.effect.value,
            int(decision.derived_permission_class),
            int(legacy_executable),
            int(parity),
            payload_json,
            float(observed_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_pre_dispatch_intent_authorization_observations (
                observation_id, target_attempt_event_id, source_attempt_event_id,
                attempt_id, flow_id, source_flow_event_id, source_flow_revision,
                flow_request_digest, input_digest, lease_snapshot_digest,
                request_digest, decision_digest, effect, derived_permission_class,
                legacy_executable, execution_parity, payload_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT observation_id, target_attempt_event_id, source_attempt_event_id,
                   attempt_id, flow_id, source_flow_event_id, source_flow_revision,
                   flow_request_digest, input_digest, lease_snapshot_digest,
                   request_digest, decision_digest, effect,
                   derived_permission_class, legacy_executable, execution_parity,
                   payload_json, observed_at
            FROM supervisor_pre_dispatch_intent_authorization_observations
            WHERE target_attempt_event_id = ?
            """,
            (target_attempt.event_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "pre-dispatch intent authorization persistence is uncertain"
            )

    def _append_attempt_completion_authorization_observation(
        self,
        connection: sqlite3.Connection,
        *,
        spec: FlowSpec,
        attempt: AttemptRecord,
        source_flow: FlowRevision,
        source_attempt: AttemptEvent,
        target_flow: FlowRevision,
        target_attempt: AttemptEvent,
        completion: CompletionIntent,
        lease_snapshot: object,
        observed_at: float,
        legacy_executable: bool,
    ) -> None:
        """Append a best-effort shadow for an already-written local completion.

        The caller deliberately invokes this only after the terminal flow,
        attempt, outbox, and lease writes have succeeded. A shadow evaluator or
        evidence-persistence failure is therefore unable to change the
        deterministic bookkeeping result, and this method cannot deliver an
        outbox, dispatch a worker, or execute a task.
        """

        request, policy, intent = _supervisor_attempt_completion_authorization_request(
            spec=spec,
            attempt=attempt,
            source_flow=source_flow,
            source_attempt=source_attempt,
            target_flow=target_flow,
            target_attempt=target_attempt,
            completion=completion,
            lease_snapshot=lease_snapshot,
            observed_at=observed_at,
        )
        decision = ShadowAuthorizationEvaluator().evaluate(request, policy)
        parity = (decision.effect.value == "permit") == legacy_executable
        payload = {
            "mode": "shadow",
            "boundary": _ATTEMPT_COMPLETION_BOUNDARY,
            "action_scope": _ATTEMPT_COMPLETION_ACTION_SCOPE,
            "attempt_completion": intent,
            "attempt_completion_digest": canonical_digest(intent),
            "request": request.to_canonical(),
            "request_digest": request.digest,
            "decision": decision.to_canonical(),
            "decision_digest": decision.digest,
            "legacy_executable": legacy_executable,
            "execution_parity": parity,
        }
        payload_json = _bounded_json(
            payload,
            "attempt completion authorization payload",
        )
        values = (
            self._new_id("attempt_completion_authorization"),
            completion.outbox_id,
            target_flow.event_id,
            target_attempt.event_id,
            source_flow.event_id,
            source_flow.revision,
            source_attempt.event_id,
            attempt.attempt_id,
            attempt.flow_id,
            spec.request_digest,
            attempt.input_digest,
            intent["source"]["lease_snapshot_digest"],
            completion.intent_digest,
            completion.operation_digest,
            request.digest,
            decision.digest,
            decision.effect.value,
            int(decision.derived_permission_class),
            int(legacy_executable),
            int(parity),
            payload_json,
            float(observed_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_attempt_completion_authorization_observations (
                observation_id, outbox_id, target_flow_event_id,
                target_attempt_event_id, source_flow_event_id,
                source_flow_revision, source_attempt_event_id, attempt_id,
                flow_id, flow_request_digest, input_digest, lease_snapshot_digest,
                completion_intent_digest, completion_operation_digest,
                request_digest, decision_digest, effect,
                derived_permission_class, legacy_executable, execution_parity,
                payload_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT observation_id, outbox_id, target_flow_event_id,
                   target_attempt_event_id, source_flow_event_id,
                   source_flow_revision, source_attempt_event_id, attempt_id,
                   flow_id, flow_request_digest, input_digest,
                   lease_snapshot_digest, completion_intent_digest,
                   completion_operation_digest, request_digest, decision_digest,
                   effect, derived_permission_class, legacy_executable,
                   execution_parity, payload_json, observed_at
            FROM supervisor_attempt_completion_authorization_observations
            WHERE outbox_id = ?
            """,
            (completion.outbox_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "attempt completion authorization persistence is uncertain"
            )

    def _append_pre_dispatch_reconciliation_authorization_observation(
        self,
        connection: sqlite3.Connection,
        *,
        spec: FlowSpec,
        attempt: AttemptRecord,
        source_flow: FlowRevision,
        source_attempt: AttemptEvent,
        target_flow: FlowRevision,
        target_attempt: AttemptEvent,
        completion: CompletionIntent,
        lease_snapshot: object,
        reconciliation_action: str | None,
        observed_at: float,
        legacy_executable: bool,
    ) -> None:
        """Append best-effort evidence for an already-repaired pre-dispatch claim.

        The caller reaches this method only after the terminal flow, attempt,
        outbox, and lease-release writes have succeeded. The observation is
        therefore compatibility evidence only; it cannot alter the deterministic
        repair or activate delivery, a worker, a subprocess, or a task.
        """

        request, policy, intent = (
            _supervisor_pre_dispatch_reconciliation_authorization_request(
                spec=spec,
                attempt=attempt,
                source_flow=source_flow,
                source_attempt=source_attempt,
                target_flow=target_flow,
                target_attempt=target_attempt,
                completion=completion,
                lease_snapshot=lease_snapshot,
                reconciliation_action=reconciliation_action,
                observed_at=observed_at,
            )
        )
        decision = ShadowAuthorizationEvaluator().evaluate(request, policy)
        parity = (decision.effect.value == "permit") == legacy_executable
        payload = {
            "mode": "shadow",
            "boundary": _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
            "action_scope": _PRE_DISPATCH_RECONCILIATION_ACTION_SCOPE,
            "pre_dispatch_reconciliation": intent,
            "pre_dispatch_reconciliation_digest": canonical_digest(intent),
            "request": request.to_canonical(),
            "request_digest": request.digest,
            "decision": decision.to_canonical(),
            "decision_digest": decision.digest,
            "legacy_executable": legacy_executable,
            "execution_parity": parity,
        }
        payload_json = _bounded_json(
            payload,
            "pre-dispatch reconciliation authorization payload",
        )
        values = (
            self._new_id("pre_dispatch_reconciliation_authorization"),
            completion.outbox_id,
            target_flow.event_id,
            target_attempt.event_id,
            source_flow.event_id,
            source_flow.revision,
            source_attempt.event_id,
            attempt.attempt_id,
            attempt.flow_id,
            spec.request_digest,
            attempt.input_digest,
            intent["source"]["lease_snapshot_digest"],
            completion.intent_digest,
            completion.operation_digest,
            intent["reconciliation"]["action"],
            request.digest,
            decision.digest,
            decision.effect.value,
            int(decision.derived_permission_class),
            int(legacy_executable),
            int(parity),
            payload_json,
            float(observed_at),
        )
        connection.execute(
            """
            INSERT INTO supervisor_pre_dispatch_reconciliation_authorization_observations (
                observation_id, outbox_id, target_flow_event_id,
                target_attempt_event_id, source_flow_event_id,
                source_flow_revision, source_attempt_event_id, attempt_id,
                flow_id, flow_request_digest, input_digest, lease_snapshot_digest,
                completion_intent_digest, completion_operation_digest,
                reconciliation_action, request_digest, decision_digest, effect,
                derived_permission_class, legacy_executable, execution_parity,
                payload_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            """
            SELECT observation_id, outbox_id, target_flow_event_id,
                   target_attempt_event_id, source_flow_event_id,
                   source_flow_revision, source_attempt_event_id, attempt_id,
                   flow_id, flow_request_digest, input_digest,
                   lease_snapshot_digest, completion_intent_digest,
                   completion_operation_digest, reconciliation_action,
                   request_digest, decision_digest, effect,
                   derived_permission_class, legacy_executable,
                   execution_parity, payload_json, observed_at
            FROM supervisor_pre_dispatch_reconciliation_authorization_observations
            WHERE outbox_id = ?
            """,
            (completion.outbox_id,),
        ).fetchone()
        if row is None or tuple(row) != values:
            raise SupervisorError(
                "pre-dispatch reconciliation authorization persistence is uncertain"
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
            target_event_id = self._new_id("attempt_event")
            flow_row = connection.execute(
                "SELECT * FROM supervisor_flows WHERE flow_id = ?",
                (attempt.flow_id,),
            ).fetchone()
            if flow_row is None:
                raise SupervisorError("flow was not found")
            target_candidate = AttemptEvent(
                0,
                target_event_id,
                attempt.attempt_id,
                current.revision + 1,
                AttemptState.DISPATCHING,
                "dispatch_intent_recorded",
                timestamp,
            )
            lease_snapshot = _pre_dispatch_intent_lease_snapshot(
                connection,
                attempt=attempt,
                observed_at=timestamp,
            )
            intent = self._pre_dispatch_intent_authorization_target(
                spec=_flow_from_row(flow_row),
                attempt=attempt,
                source_flow=current_flow,
                source_attempt=current,
                target_attempt=target_candidate,
                lease_snapshot=lease_snapshot,
                observed_at=timestamp,
            )
            authorization = evaluate_supervisor_pre_dispatch_intent_authorization(
                intent=intent,
                legacy_executable=True,
            )
            decision_payload = authorization.to_event_payload()
            persisted_decision_payload = (
                self._append_pre_dispatch_intent_authorization_decision(
                    connection,
                    authorization=authorization,
                    payload=decision_payload,
                )
            )
            assert_supervisor_pre_dispatch_intent_authorized(
                authorization,
                intent=intent,
                action_started_at=timestamp,
                persisted_payload=persisted_decision_payload,
            )
            target = self._insert_attempt_event(
                connection,
                attempt_id=attempt.attempt_id,
                revision=current.revision + 1,
                state=AttemptState.DISPATCHING,
                reason_code="dispatch_intent_recorded",
                occurred_at=timestamp,
                event_id=target_event_id,
            )
            if (
                not isinstance(target, AttemptEvent)
                or target.event_id != intent.target_attempt_event_id
                or target.attempt_id != intent.attempt_id
                or target.revision != intent.target_attempt_revision
                or target.state is not AttemptState.DISPATCHING
                or target.reason_code != "dispatch_intent_recorded"
                or target.occurred_at != intent.occurred_at
            ):
                raise SupervisorError(
                    "supervisor pre-dispatch authorization effect persistence is uncertain"
                )
            receipt_payload = build_supervisor_pre_dispatch_intent_action_receipt(
                authorization=authorization,
                action_started_at=timestamp,
                completed_at=timestamp,
            )
            persisted_receipt_payload = (
                self._append_pre_dispatch_intent_authorization_receipt(
                    connection,
                    authorization=authorization,
                    payload=receipt_payload,
                    completed_at=timestamp,
                )
            )
            if persisted_receipt_payload != receipt_payload:
                raise SupervisorError(
                    "supervisor pre-dispatch authorization receipt persistence is uncertain"
                )
            try:
                self._append_pre_dispatch_intent_authorization_observation(
                    connection,
                    spec=_flow_from_row(flow_row),
                    attempt=attempt,
                    source_flow=current_flow,
                    source_attempt=current,
                    target_attempt=target,
                    observed_at=timestamp,
                    legacy_executable=True,
                )
            except Exception:
                # Shadow evidence is deliberately non-authoritative.  The
                # transition records local intent only; it never starts a
                # worker, and a shadow failure cannot change that outcome.
                pass
            return target

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
            if timestamp < current.occurred_at:
                raise ValidationError(
                    "cancellation timestamp predates the current flow revision"
                )
            flow_row = connection.execute(
                "SELECT * FROM supervisor_flows WHERE flow_id = ?", (flow_id,)
            ).fetchone()
            if flow_row is None:
                raise SupervisorError("flow was not found")
            spec = _flow_from_row(flow_row)
            request_id = self._new_id("cancellation")
            connection.execute(
                """
                INSERT INTO supervisor_cancellation_requests (
                    request_id, flow_id, reason_code, requested_by, requested_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    request_id, flow_id, reason_code,
                    requested_by, timestamp,
                ),
            )
            try:
                self._append_bookkeeping_authorization_observation(
                    connection,
                    boundary="flow_cancellation",
                    observed_at=timestamp,
                    legacy_executable=True,
                    spec=spec,
                    flow_revision=current,
                    cancellation_request_id=request_id,
                    requested_by=requested_by,
                    reason_code=reason_code,
                )
            except Exception:
                # Cancellation remains fail-safe when shadow evidence fails.
                pass
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
            flow_row = connection.execute(
                "SELECT * FROM supervisor_flows WHERE flow_id = ?",
                (attempt.flow_id,),
            ).fetchone()
            if flow_row is None:
                raise SupervisorError("flow was not found")
            lease_snapshot = _attempt_completion_lease_snapshot(
                connection,
                attempt=attempt,
                observed_at=timestamp,
            )
            attempt_current = self._current_attempt_event_in(
                connection, attempt.attempt_id
            )
            completed_attempt = self._insert_attempt_event(
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
            try:
                self._append_attempt_completion_authorization_observation(
                    connection,
                    spec=_flow_from_row(flow_row),
                    attempt=attempt,
                    source_flow=current,
                    source_attempt=attempt_current,
                    target_flow=completed,
                    target_attempt=completed_attempt,
                    completion=outbox,
                    lease_snapshot=lease_snapshot,
                    observed_at=timestamp,
                    legacy_executable=True,
                )
            except Exception:
                # This post-write shadow is compatibility evidence only. The
                # local transition and outbox stay durable even if evidence
                # construction, evaluation, or persistence fails.
                pass
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
        flow_row = connection.execute(
            "SELECT * FROM supervisor_flows WHERE flow_id = ?",
            (finding.flow_id,),
        ).fetchone()
        if flow_row is None:
            raise SupervisorError("flow was not found")
        lease_snapshot = _pre_dispatch_reconciliation_lease_snapshot(
            connection,
            attempt=attempt,
            observed_at=timestamp,
        )
        completed_attempt = self._insert_attempt_event(
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
        outbox = self._insert_completion_intent(
            connection, revision, attempt_id=finding.attempt_id, occurred_at=timestamp
        )
        for key in attempt.lease_keys:
            connection.execute(
                "DELETE FROM leases WHERE lease_key = ? AND owner_id = ?",
                (key, attempt.lease_owner),
            )
        try:
            self._append_pre_dispatch_reconciliation_authorization_observation(
                connection,
                spec=_flow_from_row(flow_row),
                attempt=attempt,
                source_flow=current,
                source_attempt=attempt_event,
                target_flow=revision,
                target_attempt=completed_attempt,
                completion=outbox,
                lease_snapshot=lease_snapshot,
                reconciliation_action=finding.action,
                observed_at=timestamp,
                legacy_executable=True,
            )
        except Exception:
            # Reconciliation remains deterministic and fail-safe. This
            # post-write compatibility shadow cannot alter a terminal local
            # repair, deliver its outbox, or invoke a worker.
            pass

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
        event_id: str | None = None,
    ) -> FlowRevision:
        if event_id is None:
            event_id = self._new_id("flow_event")
        else:
            _validate_text(event_id, "flow_event", maximum=256)
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
        event_id: str | None = None,
    ) -> AttemptEvent:
        if event_id is None:
            event_id = self._new_id("attempt_event")
        else:
            _validate_text(event_id, "attempt_event", maximum=256)
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
            return _initial_control_revision()
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
            "dispatch_blocker": SUPERVISOR_DISPATCH_BLOCKERS[0],
            "dispatch_blockers": list(SUPERVISOR_DISPATCH_BLOCKERS),
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
            authorization = _inspect_supervisor_authorization_connection(
                connection
            )
            plan = (
                _make_plan(True, timestamp, ())
                if (
                    "supervisor_flows" not in tables
                    or not authorization.schema_present
                )
                else _make_plan(
                    True, timestamp, _audit_connection(connection, timestamp)
                )
            )
            return plan, authorization
    except Exception as error:
        raise ConfigurationError("supervisor state is unreadable or malformed") from error


def _inspect_supervisor_authorization_connection(
    connection: sqlite3.Connection,
) -> SupervisorAuthorizationAudit:
    tables = _table_names(connection)
    if "supervisor_flows" not in tables:
        objects = _schema_objects(connection)
        supervisor_state_present = any(
            key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
            for key, value in objects.items()
        )
        migration_objects = {
            key: value
            for key, value in objects.items()
            if key[1].startswith("state_schema_migrations")
            or value[1] == "state_schema_migrations"
        }
        if migration_objects == _expected_migration_schema():
            supervisor_state_present = supervisor_state_present or (
                connection.execute(
                    "SELECT 1 FROM state_schema_migrations WHERE version >= 2 LIMIT 1"
                ).fetchone()
                is not None
            )
        findings = (
            (
                SupervisorAuthorizationFinding(
                    "supervisor_schema_missing", None, None, None
                ),
                *_authorization_guard_findings(connection),
            )
            if supervisor_state_present
            else _shared_state_guard_findings(connection)
        )
        return SupervisorAuthorizationAudit(True, False, 0, 0, findings)
    guard_findings = _authorization_guard_findings(connection)
    guard_codes = {finding.code for finding in guard_findings}
    projection_unsafe = (
        "migration_schema_mismatch" in guard_codes
        or (
            "authorization_schema_mismatch" in guard_codes
            and not _supervisor_table_shapes_safe(connection)
        )
    )
    if projection_unsafe:
        return SupervisorAuthorizationAudit(
            True,
            False,
            0,
            0,
            guard_findings,
        )
    required_sources = {
        "supervisor_attempts",
        "supervisor_cancellation_requests",
        "supervisor_control_events",
        "supervisor_flow_revisions",
        "supervisor_flows",
    }
    if not required_sources.issubset(tables):
        return SupervisorAuthorizationAudit(
            True,
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "supervisor_schema_missing", None, None, None
                ),
                *guard_findings,
            ),
        )
    flow = _inspect_flow_authorization_connection(connection)
    bookkeeping = _inspect_bookkeeping_authorization_connection(connection)
    control_enforcement = _inspect_control_enforcement_connection(connection)
    flow_admission_enforcement = (
        _inspect_flow_admission_enforcement_connection(connection)
    )
    attempt_claim_enforcement = (
        _inspect_attempt_claim_enforcement_connection(connection)
    )
    pre_dispatch_intent = (
        _inspect_pre_dispatch_intent_authorization_connection(connection)
    )
    pre_dispatch_intent_enforcement = (
        _inspect_pre_dispatch_intent_enforcement_connection(connection)
    )
    attempt_completion = _inspect_attempt_completion_authorization_connection(
        connection
    )
    pre_dispatch_reconciliation = (
        _inspect_pre_dispatch_reconciliation_authorization_connection(connection)
    )
    findings = (
        *flow.findings,
        *bookkeeping.findings,
        *control_enforcement.findings,
        *flow_admission_enforcement.findings,
        *attempt_claim_enforcement.findings,
        *pre_dispatch_intent.findings,
        *pre_dispatch_intent_enforcement.findings,
        *attempt_completion.findings,
        *pre_dispatch_reconciliation.findings,
        *guard_findings,
    )
    return SupervisorAuthorizationAudit(
        database_present=True,
        schema_present=(
            flow.schema_present
            and bookkeeping.schema_present
            and control_enforcement.schema_present
            and flow_admission_enforcement.schema_present
            and attempt_claim_enforcement.schema_present
            and pre_dispatch_intent.schema_present
            and pre_dispatch_intent_enforcement.schema_present
            and attempt_completion.schema_present
            and pre_dispatch_reconciliation.schema_present
            and not guard_findings
        ),
        observation_count=(
            flow.observation_count
            + bookkeeping.observation_count
            + pre_dispatch_intent.record_count
            + attempt_completion.record_count
            + pre_dispatch_reconciliation.record_count
        ),
        expected_observation_count=(
            flow.expected_observation_count
            + bookkeeping.expected_observation_count
            + pre_dispatch_intent.expected_record_count
            + attempt_completion.expected_record_count
            + pre_dispatch_reconciliation.expected_record_count
        ),
        findings=findings,
        control_enforcement_record_count=control_enforcement.record_count,
        expected_control_enforcement_record_count=(
            control_enforcement.expected_record_count
        ),
        flow_admission_enforcement_record_count=(
            flow_admission_enforcement.record_count
        ),
        expected_flow_admission_enforcement_record_count=(
            flow_admission_enforcement.expected_record_count
        ),
        attempt_claim_enforcement_record_count=(
            attempt_claim_enforcement.record_count
        ),
        expected_attempt_claim_enforcement_record_count=(
            attempt_claim_enforcement.expected_record_count
        ),
        pre_dispatch_intent_observation_count=pre_dispatch_intent.record_count,
        expected_pre_dispatch_intent_observation_count=(
            pre_dispatch_intent.expected_record_count
        ),
        pre_dispatch_intent_enforcement_record_count=(
            pre_dispatch_intent_enforcement.record_count
        ),
        expected_pre_dispatch_intent_enforcement_record_count=(
            pre_dispatch_intent_enforcement.expected_record_count
        ),
        attempt_completion_observation_count=attempt_completion.record_count,
        expected_attempt_completion_observation_count=(
            attempt_completion.expected_record_count
        ),
        pre_dispatch_reconciliation_observation_count=(
            pre_dispatch_reconciliation.record_count
        ),
        expected_pre_dispatch_reconciliation_observation_count=(
            pre_dispatch_reconciliation.expected_record_count
        ),
    )


def _supervisor_table_shapes_safe(connection: sqlite3.Connection) -> bool:
    expected_tables = {
        key: value
        for key, value in _expected_supervisor_schema().items()
        if key[0] == "table"
    }
    expected_names = {key[1] for key in expected_tables}
    actual_tables = {
        key: value
        for key, value in _schema_objects(connection).items()
        if key[0] == "table" and key[1].startswith("supervisor_")
    }
    return all(
        key[1] in expected_names and expected_tables.get(key) == value
        for key, value in actual_tables.items()
    )


def _inspect_flow_authorization_connection(
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
    findings: list[SupervisorAuthorizationFinding] = []
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
                    "flow_request_digest_mismatch",
                    _audit_flow_reference(spec.flow_id),
                    None,
                    None,
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
                    "boundary_coverage_or_order_mismatch",
                    _audit_flow_reference(spec.flow_id),
                    None,
                    None,
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
                        _audit_flow_reference(spec.flow_id),
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


def _inspect_bookkeeping_authorization_connection(
    connection: sqlite3.Connection,
) -> SupervisorAuthorizationAudit:
    tables = _table_names(connection)
    control_rows = connection.execute(
        "SELECT * FROM supervisor_control_events ORDER BY revision"
    ).fetchall()
    cancellation_rows = connection.execute(
        """
        SELECT * FROM supervisor_cancellation_requests
        ORDER BY requested_at, request_id
        """
    ).fetchall()
    baseline_table = "supervisor_bookkeeping_authorization_baseline"
    source_table = "supervisor_bookkeeping_authorization_sources"
    observation_table = "supervisor_bookkeeping_authorization_observations"
    baseline = (
        {
            (row["entity_type"], row["entity_id"])
            for row in connection.execute(
                f"SELECT entity_type, entity_id FROM {baseline_table}"
            ).fetchall()
        }
        if baseline_table in tables
        else set()
    )
    expected_control_rows = [
        row
        for row in control_rows
        if ("control_event", row["event_id"]) not in baseline
    ]
    expected_cancellation_rows = [
        row
        for row in cancellation_rows
        if ("cancellation_request", row["request_id"]) not in baseline
    ]
    expected_count = len(expected_control_rows) + len(expected_cancellation_rows)
    if (
        observation_table not in tables
        or baseline_table not in tables
        or source_table not in tables
    ):
        return SupervisorAuthorizationAudit(
            True,
            False,
            0,
            expected_count,
            (
                SupervisorAuthorizationFinding(
                    "bookkeeping_authorization_schema_missing",
                    None,
                    None,
                    None,
                ),
            ),
        )
    observation_rows = connection.execute(
        f"SELECT * FROM {observation_table} ORDER BY sequence"
    ).fetchall()
    flow_rows = {
        row["flow_id"]: row
        for row in connection.execute("SELECT * FROM supervisor_flows").fetchall()
    }
    flow_revision_rows = {
        (row["flow_id"], row["revision"]): row
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions"
        ).fetchall()
    }
    source_rows = {
        row["cancellation_request_id"]: row
        for row in connection.execute(f"SELECT * FROM {source_table}").fetchall()
    }
    expected: list[
        tuple[
            str,
            str | None,
            str | None,
            str | None,
            float,
            AuthorizationRequest,
            PolicyBundle,
            str,
        ]
    ] = []
    findings: list[SupervisorAuthorizationFinding] = []
    previous_control = _initial_control_revision()
    for row in control_rows:
        control = _control_from_row(row)
        if ("control_event", control.event_id) not in baseline:
            request, policy = _supervisor_bookkeeping_authorization_request(
                boundary="control_transition",
                observed_at=control.occurred_at,
                control=control,
                previous_control=previous_control,
            )
            expected.append(
                (
                    "control_transition",
                    None,
                    control.event_id,
                    None,
                    control.occurred_at,
                    request,
                    policy,
                    f"control_revision:{control.revision}",
                )
            )
        previous_control = control
    for row in expected_cancellation_rows:
        flow_row = flow_rows.get(row["flow_id"])
        if flow_row is None:
            findings.append(
                SupervisorAuthorizationFinding(
                    "bookkeeping_target_missing",
                    _audit_flow_reference(row["flow_id"]),
                    "flow_cancellation",
                    None,
                )
            )
            continue
        source_row = source_rows.get(row["request_id"])
        if source_row is None:
            findings.append(
                SupervisorAuthorizationFinding(
                    "bookkeeping_source_missing",
                    _audit_flow_reference(row["flow_id"]),
                    "flow_cancellation",
                    None,
                )
            )
            continue
        if source_row["flow_id"] != row["flow_id"]:
            findings.append(
                SupervisorAuthorizationFinding(
                    "bookkeeping_source_lineage_mismatch",
                    _audit_flow_reference(row["flow_id"]),
                    "flow_cancellation",
                    None,
                )
            )
            continue
        flow_revision_row = flow_revision_rows.get(
            (row["flow_id"], source_row["source_flow_revision"])
        )
        if flow_revision_row is None:
            findings.append(
                SupervisorAuthorizationFinding(
                    "bookkeeping_source_revision_missing",
                    _audit_flow_reference(row["flow_id"]),
                    "flow_cancellation",
                    None,
                )
            )
            continue
        spec = _flow_from_row(flow_row)
        flow_revision = _flow_revision_from_row(flow_revision_row)
        request, policy = _supervisor_bookkeeping_authorization_request(
            boundary="flow_cancellation",
            observed_at=row["requested_at"],
            spec=spec,
            flow_revision=flow_revision,
            cancellation_request_id=row["request_id"],
            requested_by=row["requested_by"],
            reason_code=row["reason_code"],
        )
        expected.append(
            (
                "flow_cancellation",
                spec.flow_id,
                None,
                row["request_id"],
                row["requested_at"],
                request,
                policy,
                f"flow:{_audit_flow_reference(spec.flow_id)}",
            )
        )
    expected_source_ids = {row["request_id"] for row in expected_cancellation_rows}
    for request_id, row in source_rows.items():
        if request_id not in expected_source_ids:
            findings.append(
                SupervisorAuthorizationFinding(
                    "bookkeeping_source_unexpected",
                    _audit_flow_reference(row["flow_id"]),
                    "flow_cancellation",
                    None,
                )
            )
    actual_ids = [_observation_request_id(row) for row in observation_rows]
    expected_control_ids = [
        item[5].request_id for item in expected if item[0] == "control_transition"
    ]
    actual_control_ids = [
        actual_ids[index]
        for index, row in enumerate(observation_rows)
        if row["boundary"] == "control_transition"
    ]
    if actual_control_ids != expected_control_ids:
        findings.append(
            SupervisorAuthorizationFinding(
                "bookkeeping_boundary_coverage_or_order_mismatch",
                None,
                "control_transition",
                None,
            )
        )
    used: set[int] = set()
    for (
        boundary,
        flow_id,
        control_event_id,
        cancellation_request_id,
        observed_at,
        request,
        policy,
        target_reference,
    ) in expected:
        matches = [
            index
            for index, row in enumerate(observation_rows)
            if index not in used
            and row["boundary"] == boundary
            and actual_ids[index] == request.request_id
        ]
        if len(matches) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "bookkeeping_observation_missing"
                        if not matches
                        else "bookkeeping_observation_duplicated"
                    ),
                    (
                        None
                        if flow_id is None
                        else _audit_flow_reference(flow_id)
                    ),
                    boundary,
                    None,
                    target_reference,
                )
            )
            continue
        index = matches[0]
        used.add(index)
        row = observation_rows[index]
        if (
            row["flow_id"] != flow_id
            or row["control_event_id"] != control_event_id
            or row["cancellation_request_id"] != cancellation_request_id
        ):
            findings.append(
                _authorization_finding(
                    "bookkeeping_target_lineage_mismatch", row=row
                )
            )
        findings.extend(
            _verify_expected_authorization_observation(
                row,
                boundary=boundary,
                observed_at=observed_at,
                expected_request=request,
                expected_policy=policy,
            )
        )
    for index, row in enumerate(observation_rows):
        if index not in used:
            findings.append(
                _authorization_finding(
                    "bookkeeping_observation_unexpected", row=row
                )
            )
    return SupervisorAuthorizationAudit(
        True,
        True,
        len(observation_rows),
        expected_count,
        tuple(findings),
    )


def _inspect_control_enforcement_connection(
    connection: sqlite3.Connection,
) -> _SupervisorControlEnforcementAudit:
    """Replay only post-v5 reversible control transitions without repairing."""

    tables = _table_names(connection)
    required = {
        "supervisor_control_events",
        "supervisor_control_authorization_baseline",
        "supervisor_control_authorization_decisions",
        "supervisor_control_authorization_action_receipts",
    }
    if not required.issubset(tables):
        return _SupervisorControlEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "control_authorization_schema_missing",
                    None,
                    "control_transition",
                    None,
                ),
            ),
        )
    try:
        control_rows = connection.execute(
            "SELECT * FROM supervisor_control_events ORDER BY revision"
        ).fetchall()
        control_ids = {row["event_id"] for row in control_rows}
        baseline = {
            row["control_event_id"]
            for row in connection.execute(
                """
                SELECT control_event_id
                FROM supervisor_control_authorization_baseline
                """
            ).fetchall()
        }
        decision_rows = connection.execute(
            """
            SELECT * FROM supervisor_control_authorization_decisions
            ORDER BY sequence
            """
        ).fetchall()
        receipt_rows = connection.execute(
            """
            SELECT * FROM supervisor_control_authorization_action_receipts
            ORDER BY sequence
            """
        ).fetchall()
    except sqlite3.Error:
        return _SupervisorControlEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "control_authorization_schema_unreadable",
                    None,
                    "control_transition",
                    None,
                ),
            ),
        )

    findings: list[SupervisorAuthorizationFinding] = []
    if not baseline.issubset(control_ids):
        findings.append(
            SupervisorAuthorizationFinding(
                "control_authorization_baseline_invalid",
                None,
                "control_transition",
                None,
            )
        )
    expected_ids = tuple(
        row["event_id"] for row in control_rows if row["event_id"] not in baseline
    )
    expected_set = set(expected_ids)
    decision_by_control: dict[str, list[sqlite3.Row]] = {}
    for row in decision_rows:
        decision_by_control.setdefault(row["control_event_id"], []).append(row)
    receipt_by_control: dict[str, list[sqlite3.Row]] = {}
    for row in receipt_rows:
        receipt_by_control.setdefault(row["control_event_id"], []).append(row)

    previous = _initial_control_revision()
    for control_row in control_rows:
        try:
            control = _control_from_row(control_row)
        except (KeyError, TypeError, ValueError):
            findings.append(
                SupervisorAuthorizationFinding(
                    "control_authorization_control_history_invalid",
                    None,
                    "control_transition",
                    None,
                )
            )
            continue
        if control.event_id in baseline:
            previous = control
            continue
        target_ref = canonical_digest({"control_event_id": control.event_id})
        decisions = decision_by_control.get(control.event_id, [])
        receipts = receipt_by_control.get(control.event_id, [])
        if len(decisions) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "control_authorization_decision_missing"
                        if not decisions
                        else "control_authorization_decision_duplicated"
                    ),
                    None,
                    "control_transition",
                    None,
                    target_ref,
                )
            )
        if len(receipts) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "control_authorization_receipt_missing"
                        if not receipts
                        else "control_authorization_receipt_duplicated"
                    ),
                    None,
                    "control_transition",
                    None,
                    target_ref,
                )
            )
        try:
            transition = SupervisorControlTransition(
                previous_control_event_id=previous.event_id,
                previous_revision=previous.revision,
                previous_mode=previous.mode.value,
                control_event_id=control.event_id,
                target_revision=control.revision,
                target_mode=control.mode.value,
                actor_ref=canonical_digest({"actor_id": control.actor_id}),
                reason_code=control.reason_code,
                occurred_at=control.occurred_at,
            )
            authorization = evaluate_supervisor_control_authorization(
                transition=transition,
                legacy_executable=True,
            )
            decision_payload = authorization.to_event_payload()
            decision_values = (
                authorization.decision.digest,
                transition.control_event_id,
                transition.previous_control_event_id,
                transition.previous_revision,
                transition.target_revision,
                transition.target_mode,
                authorization.request.digest,
                authorization.decision.digest,
                _bounded_json(
                    decision_payload,
                    "supervisor control authorization audit decision payload",
                ),
                transition.occurred_at,
            )
            receipt_payload = build_supervisor_control_action_receipt(
                authorization=authorization,
                action_started_at=transition.occurred_at,
                completed_at=transition.occurred_at,
            )
            receipt_digest = receipt_payload["receipt_digest"]
            receipt_values = (
                receipt_digest,
                transition.control_event_id,
                authorization.decision.digest,
                receipt_digest,
                _bounded_json(
                    receipt_payload,
                    "supervisor control authorization audit receipt payload",
                ),
                transition.occurred_at,
            )
        except Exception:
            decision_values = None
            receipt_values = None
        if (
            len(decisions) == 1
            and (
                decision_values is None
                or tuple(
                    decisions[0][
                        field
                    ]
                    for field in (
                        "decision_event_id",
                        "control_event_id",
                        "previous_control_event_id",
                        "previous_revision",
                        "target_revision",
                        "target_mode",
                        "request_digest",
                        "decision_digest",
                        "payload_json",
                        "evaluated_at",
                    )
                )
                != decision_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "control_authorization_decision_invalid",
                    None,
                    "control_transition",
                    None,
                    target_ref,
                )
            )
        if (
            len(receipts) == 1
            and (
                receipt_values is None
                or tuple(
                    receipts[0][field]
                    for field in (
                        "receipt_event_id",
                        "control_event_id",
                        "decision_event_id",
                        "receipt_digest",
                        "payload_json",
                        "completed_at",
                    )
                )
                != receipt_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "control_authorization_receipt_invalid",
                    None,
                    "control_transition",
                    None,
                    target_ref,
                )
            )
        previous = control

    for control_event_id in decision_by_control:
        if control_event_id not in expected_set:
            findings.append(
                SupervisorAuthorizationFinding(
                    "control_authorization_decision_unexpected",
                    None,
                    "control_transition",
                    None,
                    canonical_digest({"control_event_id": control_event_id}),
                )
            )
    for control_event_id in receipt_by_control:
        if control_event_id not in expected_set:
            findings.append(
                SupervisorAuthorizationFinding(
                    "control_authorization_receipt_unexpected",
                    None,
                    "control_transition",
                    None,
                    canonical_digest({"control_event_id": control_event_id}),
                )
            )
    return _SupervisorControlEnforcementAudit(
        True,
        len(decision_rows) + len(receipt_rows),
        len(expected_ids) * 2,
        tuple(findings),
    )


def _inspect_flow_admission_enforcement_connection(
    connection: sqlite3.Connection,
) -> _SupervisorFlowAdmissionEnforcementAudit:
    """Replay only post-v6 mock-flow admissions without repairing state."""

    tables = _table_names(connection)
    required = {
        "supervisor_flows",
        "supervisor_flow_revisions",
        "supervisor_attempts",
        "supervisor_flow_admission_authorization_baseline",
        "supervisor_flow_admission_authorization_decisions",
        "supervisor_flow_admission_authorization_action_receipts",
    }
    if not required.issubset(tables):
        return _SupervisorFlowAdmissionEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "flow_admission_authorization_schema_missing",
                    None,
                    "flow_admission",
                    None,
                ),
            ),
        )
    try:
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY created_at, flow_id"
        ).fetchall()
        revisions_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revisions_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"]
            for row in connection.execute(
                "SELECT attempt_id, flow_id FROM supervisor_attempts"
            ).fetchall()
        }
        baseline = {
            row["flow_id"]
            for row in connection.execute(
                "SELECT flow_id FROM supervisor_flow_admission_authorization_baseline"
            ).fetchall()
        }
        decision_rows = connection.execute(
            """
            SELECT * FROM supervisor_flow_admission_authorization_decisions
            ORDER BY sequence
            """
        ).fetchall()
        receipt_rows = connection.execute(
            """
            SELECT * FROM supervisor_flow_admission_authorization_action_receipts
            ORDER BY sequence
            """
        ).fetchall()
    except sqlite3.Error:
        return _SupervisorFlowAdmissionEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "flow_admission_authorization_schema_unreadable",
                    None,
                    "flow_admission",
                    None,
                ),
            ),
        )

    findings: list[SupervisorAuthorizationFinding] = []
    flow_ids = {row["flow_id"] for row in flow_rows}
    if not baseline.issubset(flow_ids):
        findings.append(
            SupervisorAuthorizationFinding(
                "flow_admission_authorization_baseline_invalid",
                None,
                "flow_admission",
                None,
            )
        )
    expected_ids = tuple(
        row["flow_id"] for row in flow_rows if row["flow_id"] not in baseline
    )
    expected_set = set(expected_ids)
    decision_by_flow: dict[str, list[sqlite3.Row]] = {}
    for row in decision_rows:
        decision_by_flow.setdefault(row["flow_id"], []).append(row)
    receipt_by_flow: dict[str, list[sqlite3.Row]] = {}
    for row in receipt_rows:
        receipt_by_flow.setdefault(row["flow_id"], []).append(row)

    for flow_row in flow_rows:
        flow_id = flow_row["flow_id"]
        if flow_id in baseline:
            continue
        target_ref = canonical_digest({"flow_id": flow_id})
        decisions = decision_by_flow.get(flow_id, [])
        receipts = receipt_by_flow.get(flow_id, [])
        if len(decisions) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "flow_admission_authorization_decision_missing"
                        if not decisions
                        else "flow_admission_authorization_decision_duplicated"
                    ),
                    _audit_flow_reference(flow_id),
                    "flow_admission",
                    None,
                    target_ref,
                )
            )
        if len(receipts) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "flow_admission_authorization_receipt_missing"
                        if not receipts
                        else "flow_admission_authorization_receipt_duplicated"
                    ),
                    _audit_flow_reference(flow_id),
                    "flow_admission",
                    None,
                    target_ref,
                )
            )
        try:
            spec = _flow_from_row(flow_row)
            _validate_flow_spec(spec)
            if flow_row["request_digest"] != spec.request_digest:
                raise ValidationError("flow request digest is invalid")
            revisions = revisions_by_flow.get(spec.flow_id, [])
            _verify_flow_revision_lineage(
                spec.flow_id,
                revisions,
                attempt_flow_ids,
            )
            initial = revisions[0]
            if initial["occurred_at"] != spec.created_at:
                raise ValidationError("flow admission source time is invalid")
            admission = SupervisorFlowAdmission(
                flow_id=spec.flow_id,
                admission_key_ref=canonical_digest(
                    {"admission_key": spec.admission_key}
                ),
                flow_request_digest=spec.request_digest,
                initial_flow_event_id=initial["event_id"],
                occurred_at=spec.created_at,
            )
            authorization = evaluate_supervisor_flow_admission_authorization(
                admission=admission,
                legacy_executable=True,
            )
            decision_payload = authorization.to_event_payload()
            decision_values = (
                authorization.decision.digest,
                admission.flow_id,
                admission.admission_key_ref,
                admission.flow_request_digest,
                admission.initial_flow_event_id,
                1,
                authorization.request.digest,
                authorization.decision.digest,
                _bounded_json(
                    decision_payload,
                    "supervisor flow admission authorization audit decision payload",
                ),
                admission.occurred_at,
            )
            receipt_payload = build_supervisor_flow_admission_action_receipt(
                authorization=authorization,
                action_started_at=admission.occurred_at,
                completed_at=admission.occurred_at,
            )
            receipt_digest = receipt_payload["receipt_digest"]
            receipt_values = (
                receipt_digest,
                admission.flow_id,
                authorization.decision.digest,
                receipt_digest,
                _bounded_json(
                    receipt_payload,
                    "supervisor flow admission authorization audit receipt payload",
                ),
                admission.occurred_at,
            )
        except Exception:
            decision_values = None
            receipt_values = None
            findings.append(
                SupervisorAuthorizationFinding(
                    "flow_admission_authorization_source_invalid",
                    _audit_flow_reference(flow_id),
                    "flow_admission",
                    None,
                    target_ref,
                )
            )
        if (
            len(decisions) == 1
            and (
                decision_values is None
                or tuple(
                    decisions[0][field]
                    for field in (
                        "decision_event_id",
                        "flow_id",
                        "admission_key_ref",
                        "flow_request_digest",
                        "initial_flow_event_id",
                        "initial_revision",
                        "request_digest",
                        "decision_digest",
                        "payload_json",
                        "evaluated_at",
                    )
                )
                != decision_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "flow_admission_authorization_decision_invalid",
                    _audit_flow_reference(flow_id),
                    "flow_admission",
                    None,
                    target_ref,
                )
            )
        if (
            len(receipts) == 1
            and (
                receipt_values is None
                or tuple(
                    receipts[0][field]
                    for field in (
                        "receipt_event_id",
                        "flow_id",
                        "decision_event_id",
                        "receipt_digest",
                        "payload_json",
                        "completed_at",
                    )
                )
                != receipt_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "flow_admission_authorization_receipt_invalid",
                    _audit_flow_reference(flow_id),
                    "flow_admission",
                    None,
                    target_ref,
                )
            )

    for flow_id in decision_by_flow:
        if flow_id not in expected_set:
            findings.append(
                SupervisorAuthorizationFinding(
                    "flow_admission_authorization_decision_unexpected",
                    _audit_flow_reference(flow_id),
                    "flow_admission",
                    None,
                    canonical_digest({"flow_id": flow_id}),
                )
            )
    for flow_id in receipt_by_flow:
        if flow_id not in expected_set:
            findings.append(
                SupervisorAuthorizationFinding(
                    "flow_admission_authorization_receipt_unexpected",
                    _audit_flow_reference(flow_id),
                    "flow_admission",
                    None,
                    canonical_digest({"flow_id": flow_id}),
                )
            )
    return _SupervisorFlowAdmissionEnforcementAudit(
        True,
        len(decision_rows) + len(receipt_rows),
        len(expected_ids) * 2,
        tuple(findings),
    )


def _inspect_attempt_claim_enforcement_connection(
    connection: sqlite3.Connection,
) -> _SupervisorAttemptClaimEnforcementAudit:
    """Replay only post-v7 local mock attempt claims without repairing state."""

    tables = _table_names(connection)
    required = {
        "supervisor_control_events",
        "supervisor_flows",
        "supervisor_flow_revisions",
        "supervisor_attempts",
        "supervisor_attempt_events",
        "supervisor_attempt_claim_authorization_baseline",
        "supervisor_attempt_claim_authorization_decisions",
        "supervisor_attempt_claim_authorization_action_receipts",
    }
    if not required.issubset(tables):
        return _SupervisorAttemptClaimEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "attempt_claim_authorization_schema_missing",
                    None,
                    "attempt_claim",
                    None,
                ),
            ),
        )
    try:
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        flow_rows_by_id = {row["flow_id"]: row for row in flow_rows}
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        attempt_rows_by_id = {row["attempt_id"]: row for row in attempt_rows}
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
        control_rows = connection.execute(
            "SELECT * FROM supervisor_control_events ORDER BY revision"
        ).fetchall()
        baseline = {
            row["attempt_id"]
            for row in connection.execute(
                "SELECT attempt_id FROM supervisor_attempt_claim_authorization_baseline"
            ).fetchall()
        }
        decision_rows = connection.execute(
            """
            SELECT * FROM supervisor_attempt_claim_authorization_decisions
            ORDER BY sequence
            """
        ).fetchall()
        receipt_rows = connection.execute(
            """
            SELECT * FROM supervisor_attempt_claim_authorization_action_receipts
            ORDER BY sequence
            """
        ).fetchall()
    except sqlite3.Error:
        return _SupervisorAttemptClaimEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "attempt_claim_authorization_schema_unreadable",
                    None,
                    "attempt_claim",
                    None,
                ),
            ),
        )

    findings: list[SupervisorAuthorizationFinding] = []
    attempt_ids = set(attempt_rows_by_id)
    if not baseline.issubset(attempt_ids):
        findings.append(
            SupervisorAuthorizationFinding(
                "attempt_claim_authorization_baseline_invalid",
                None,
                "attempt_claim",
                None,
            )
        )
    expected_ids = tuple(
        row["attempt_id"]
        for row in attempt_rows
        if row["attempt_id"] not in baseline
    )
    expected_set = set(expected_ids)
    decision_by_attempt: dict[str, list[sqlite3.Row]] = {}
    for row in decision_rows:
        decision_by_attempt.setdefault(row["attempt_id"], []).append(row)
    receipt_by_attempt: dict[str, list[sqlite3.Row]] = {}
    for row in receipt_rows:
        receipt_by_attempt.setdefault(row["attempt_id"], []).append(row)

    controls_by_revision: dict[int, SupervisorControlRevision] = {}
    controls_valid = True
    previous_control = _initial_control_revision()
    try:
        for expected_revision, row in enumerate(control_rows, start=1):
            control = _control_from_row(row)
            _validate_text(control.event_id, "control event identifier", maximum=256)
            _validate_text(control.actor_id, "control actor identifier", maximum=256)
            _validate_reason(control.reason_code)
            _timestamp(control.occurred_at, "control event timestamp")
            if (
                control.revision != expected_revision
                or control.mode not in _CONTROL_TRANSITIONS[previous_control.mode]
            ):
                raise ValidationError("control history is not contiguous and valid")
            controls_by_revision[control.revision] = control
            previous_control = control
    except (KeyError, TypeError, ValueError, ValidationError):
        controls_valid = False

    for attempt_row in attempt_rows:
        attempt_id = attempt_row["attempt_id"]
        if attempt_id in baseline:
            continue
        target_ref = canonical_digest({"attempt_id": attempt_id})
        flow_ref = _audit_flow_reference(attempt_row["flow_id"])
        decisions = decision_by_attempt.get(attempt_id, [])
        receipts = receipt_by_attempt.get(attempt_id, [])
        if len(decisions) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "attempt_claim_authorization_decision_missing"
                        if not decisions
                        else "attempt_claim_authorization_decision_duplicated"
                    ),
                    flow_ref,
                    "attempt_claim",
                    None,
                    target_ref,
                )
            )
        if len(receipts) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "attempt_claim_authorization_receipt_missing"
                        if not receipts
                        else "attempt_claim_authorization_receipt_duplicated"
                    ),
                    flow_ref,
                    "attempt_claim",
                    None,
                    target_ref,
                )
            )
        try:
            if not controls_valid:
                raise ValidationError("control history is invalid")
            attempt = _attempt_from_row(attempt_row)
            flow_row = flow_rows_by_id.get(attempt.flow_id)
            if flow_row is None:
                raise ValidationError("attempt flow is missing")
            spec = _flow_from_row(flow_row)
            _validate_flow_spec(spec)
            if flow_row["request_digest"] != spec.request_digest:
                raise ValidationError("flow request digest is invalid")
            revisions = revision_rows_by_flow.get(attempt.flow_id, [])
            _verify_flow_revision_lineage(
                attempt.flow_id,
                revisions,
                attempt_flow_ids,
            )
            events = _verify_attempt_claim_history(
                attempt=attempt,
                spec=spec,
                revision_rows=revisions,
                event_rows=event_rows_by_attempt.get(attempt.attempt_id, []),
            )
            control_revision = (
                decisions[0]["control_revision"] if len(decisions) == 1 else None
            )
            control = controls_by_revision.get(control_revision)
            if (
                control is None
                or control.mode is not SupervisorMode.RUNNING
                or control.occurred_at > attempt.created_at
            ):
                raise ValidationError("attempt control source is invalid")
            expected_input_digest = _sha256_text(
                _canonical_json(
                    {
                        "flow_request_digest": spec.request_digest,
                        "attempt_number": attempt.attempt_number,
                        "control_revision": control.revision,
                    }
                )
            )
            if attempt.input_digest != expected_input_digest:
                raise ValidationError("attempt input digest is invalid")
            initial_event = events[0]
            target_revision = _flow_revision_from_row(
                revisions[attempt.claimed_revision]
            )
            claim = SupervisorAttemptClaim(
                flow_id=attempt.flow_id,
                attempt_id=attempt.attempt_id,
                run_id=attempt.run_id,
                source_flow_revision=attempt.claimed_revision,
                target_flow_revision=target_revision.revision,
                control_revision=control.revision,
                attempt_number=attempt.attempt_number,
                flow_request_digest=spec.request_digest,
                input_digest=attempt.input_digest,
                instance_owner_ref=decisions[0]["instance_owner_ref"],
                lease_owner_ref=canonical_digest(
                    {"lease_owner": attempt.lease_owner}
                ),
                lease_keys_digest=canonical_digest(
                    {"lease_keys": list(attempt.lease_keys)}
                ),
                deadline_at=attempt.deadline_at,
                lease_expires_at=decisions[0]["lease_expires_at"],
                attempt_event_id=initial_event.event_id,
                flow_event_id=target_revision.event_id,
                occurred_at=attempt.created_at,
            )
            authorization = evaluate_supervisor_attempt_claim_authorization(
                claim=claim,
                legacy_executable=True,
            )
            decision_payload = authorization.to_event_payload()
            decision_values = (
                authorization.decision.digest,
                claim.attempt_id,
                claim.flow_id,
                claim.flow_request_digest,
                claim.source_flow_revision,
                claim.target_flow_revision,
                claim.control_revision,
                claim.attempt_number,
                claim.run_id_ref,
                claim.attempt_event_id,
                claim.flow_event_id,
                claim.instance_owner_ref,
                claim.lease_owner_ref,
                claim.lease_keys_digest,
                claim.input_digest,
                float(claim.deadline_at),
                float(claim.lease_expires_at),
                authorization.request.digest,
                authorization.decision.digest,
                _bounded_json(
                    decision_payload,
                    "supervisor attempt claim authorization audit decision payload",
                ),
                float(claim.occurred_at),
            )
            receipt_payload = build_supervisor_attempt_claim_action_receipt(
                authorization=authorization,
                action_started_at=claim.occurred_at,
                completed_at=claim.occurred_at,
            )
            receipt_digest = receipt_payload["receipt_digest"]
            receipt_values = (
                receipt_digest,
                claim.attempt_id,
                claim.flow_id,
                authorization.decision.digest,
                receipt_digest,
                _bounded_json(
                    receipt_payload,
                    "supervisor attempt claim authorization audit receipt payload",
                ),
                float(claim.occurred_at),
            )
        except Exception:
            decision_values = None
            receipt_values = None
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_claim_authorization_source_invalid",
                    flow_ref,
                    "attempt_claim",
                    None,
                    target_ref,
                )
            )
        if (
            len(decisions) == 1
            and (
                decision_values is None
                or tuple(
                    decisions[0][field]
                    for field in (
                        "decision_event_id",
                        "attempt_id",
                        "flow_id",
                        "flow_request_digest",
                        "source_flow_revision",
                        "target_flow_revision",
                        "control_revision",
                        "attempt_number",
                        "run_id_ref",
                        "attempt_event_id",
                        "flow_event_id",
                        "instance_owner_ref",
                        "lease_owner_ref",
                        "lease_keys_digest",
                        "input_digest",
                        "deadline_at",
                        "lease_expires_at",
                        "request_digest",
                        "decision_digest",
                        "payload_json",
                        "evaluated_at",
                    )
                )
                != decision_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_claim_authorization_decision_invalid",
                    flow_ref,
                    "attempt_claim",
                    None,
                    target_ref,
                )
            )
        if (
            len(receipts) == 1
            and (
                receipt_values is None
                or tuple(
                    receipts[0][field]
                    for field in (
                        "receipt_event_id",
                        "attempt_id",
                        "flow_id",
                        "decision_event_id",
                        "receipt_digest",
                        "payload_json",
                        "completed_at",
                    )
                )
                != receipt_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_claim_authorization_receipt_invalid",
                    flow_ref,
                    "attempt_claim",
                    None,
                    target_ref,
                )
            )

    for attempt_id in decision_by_attempt:
        if attempt_id not in expected_set:
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_claim_authorization_decision_unexpected",
                    _audit_flow_reference(
                        decision_by_attempt[attempt_id][0]["flow_id"]
                    ),
                    "attempt_claim",
                    None,
                    canonical_digest({"attempt_id": attempt_id}),
                )
            )
    for attempt_id in receipt_by_attempt:
        if attempt_id not in expected_set:
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_claim_authorization_receipt_unexpected",
                    _audit_flow_reference(
                        receipt_by_attempt[attempt_id][0]["flow_id"]
                    ),
                    "attempt_claim",
                    None,
                    canonical_digest({"attempt_id": attempt_id}),
                )
            )
    return _SupervisorAttemptClaimEnforcementAudit(
        True,
        len(decision_rows) + len(receipt_rows),
        len(expected_ids) * 2,
        tuple(findings),
    )


def _inspect_pre_dispatch_intent_authorization_connection(
    connection: sqlite3.Connection,
) -> _SupervisorPreDispatchIntentShadowAudit:
    """Replay only post-v8 local ``dispatching`` intent shadows without repair."""

    tables = _table_names(connection)
    required = {
        "supervisor_flows",
        "supervisor_flow_revisions",
        "supervisor_attempts",
        "supervisor_attempt_events",
        "supervisor_pre_dispatch_intent_authorization_baseline",
        "supervisor_pre_dispatch_intent_authorization_observations",
    }
    if not required.issubset(tables):
        return _SupervisorPreDispatchIntentShadowAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_authorization_schema_missing",
                    None,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                ),
            ),
        )
    try:
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        flow_rows_by_id = {row["flow_id"]: row for row in flow_rows}
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_rows_by_id = {row["attempt_id"]: row for row in attempt_rows}
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        event_rows_by_id: dict[str, sqlite3.Row] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
            event_rows_by_id[row["event_id"]] = row
        baseline = {
            row["attempt_event_id"]
            for row in connection.execute(
                """
                SELECT attempt_event_id
                FROM supervisor_pre_dispatch_intent_authorization_baseline
                """
            ).fetchall()
        }
        observation_rows = connection.execute(
            """
            SELECT * FROM supervisor_pre_dispatch_intent_authorization_observations
            ORDER BY sequence
            """
        ).fetchall()
    except sqlite3.Error:
        return _SupervisorPreDispatchIntentShadowAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_authorization_schema_unreadable",
                    None,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                ),
            ),
        )

    findings: list[SupervisorAuthorizationFinding] = []
    for event_id in sorted(baseline):
        row = event_rows_by_id.get(event_id)
        if (
            row is None
            or row["state"] != AttemptState.DISPATCHING.value
            or row["reason_code"] != "dispatch_intent_recorded"
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_authorization_baseline_invalid",
                    None,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    _audit_attempt_event_reference(event_id),
                )
            )

    dispatch_rows = [
        row
        for rows in event_rows_by_attempt.values()
        for row in rows
        if row["state"] == AttemptState.DISPATCHING.value
    ]
    dispatch_rows.sort(key=lambda row: (row["attempt_id"], row["revision"]))
    expected_rows = [
        row for row in dispatch_rows if row["event_id"] not in baseline
    ]
    expected_ids = {row["event_id"] for row in expected_rows}
    observations_by_target: dict[str, list[sqlite3.Row]] = {}
    for row in observation_rows:
        observations_by_target.setdefault(row["target_attempt_event_id"], []).append(
            row
        )

    for target_row in expected_rows:
        target_id = target_row["event_id"]
        target_reference = _audit_attempt_event_reference(target_id)
        attempt_row = attempt_rows_by_id.get(target_row["attempt_id"])
        flow_reference = (
            None
            if attempt_row is None
            else _audit_flow_reference(attempt_row["flow_id"])
        )
        matches = observations_by_target.get(target_id, [])
        if len(matches) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "pre_dispatch_intent_authorization_observation_missing"
                        if not matches
                        else "pre_dispatch_intent_authorization_observation_duplicated"
                    ),
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    target_reference,
                )
            )
            continue
        source: tuple[
            FlowSpec,
            AttemptRecord,
            FlowRevision,
            AttemptEvent,
            AttemptEvent,
        ] | None = None
        try:
            if attempt_row is None:
                raise ValidationError("attempt source is missing")
            attempt = _attempt_from_row(attempt_row)
            flow_row = flow_rows_by_id.get(attempt.flow_id)
            if flow_row is None:
                raise ValidationError("flow source is missing")
            spec = _flow_from_row(flow_row)
            _validate_flow_spec(spec)
            if flow_row["request_digest"] != spec.request_digest:
                raise ValidationError("flow request digest is invalid")
            revisions = revision_rows_by_flow.get(attempt.flow_id, [])
            _verify_flow_revision_lineage(
                attempt.flow_id,
                revisions,
                attempt_flow_ids,
            )
            events = _verify_attempt_claim_history(
                attempt=attempt,
                spec=spec,
                revision_rows=revisions,
                event_rows=event_rows_by_attempt.get(attempt.attempt_id, []),
            )
            dispatch_events = _verify_pre_dispatch_intent_history(
                attempt=attempt,
                revision_rows=revisions,
                events=events,
            )
            target = next(
                event for event in dispatch_events if event.event_id == target_id
            )
            source_attempt = events[target.revision - 2]
            source_flow = _flow_revision_from_row(
                revisions[attempt.claimed_revision]
            )
            source = (spec, attempt, source_flow, source_attempt, target)
        except Exception:
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_authorization_source_invalid",
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    target_reference,
                )
            )

        if source is None:
            continue
        spec, attempt, source_flow, source_attempt, target = source
        try:
            expected_values = _expected_pre_dispatch_intent_observation_values(
                matches[0],
                spec=spec,
                attempt=attempt,
                source_flow=source_flow,
                source_attempt=source_attempt,
                target_attempt=target,
            )
        except Exception:
            expected_values = None
        if (
            expected_values is None
            or tuple(
                matches[0][field]
                for field in (
                    "target_attempt_event_id",
                    "source_attempt_event_id",
                    "attempt_id",
                    "flow_id",
                    "source_flow_event_id",
                    "source_flow_revision",
                    "flow_request_digest",
                    "input_digest",
                    "lease_snapshot_digest",
                    "request_digest",
                    "decision_digest",
                    "effect",
                    "derived_permission_class",
                    "legacy_executable",
                    "execution_parity",
                    "payload_json",
                    "observed_at",
                )
            )
            != expected_values
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_authorization_observation_invalid",
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    int(matches[0]["sequence"]),
                    target_reference,
                )
            )

    for target_id, rows in observations_by_target.items():
        if target_id not in expected_ids:
            for row in rows:
                findings.append(
                    SupervisorAuthorizationFinding(
                        "pre_dispatch_intent_authorization_observation_unexpected",
                        _audit_flow_reference(row["flow_id"]),
                        _PRE_DISPATCH_INTENT_BOUNDARY,
                        int(row["sequence"]),
                        _audit_attempt_event_reference(target_id),
                    )
                )
    return _SupervisorPreDispatchIntentShadowAudit(
        True,
        len(observation_rows),
        len(expected_rows),
        tuple(findings),
    )


def _inspect_pre_dispatch_intent_enforcement_connection(
    connection: sqlite3.Connection,
) -> _SupervisorPreDispatchIntentEnforcementAudit:
    """Replay only post-v9 local pre-dispatch PEP records without repair."""

    tables = _table_names(connection)
    required = {
        "supervisor_flows",
        "supervisor_flow_revisions",
        "supervisor_attempts",
        "supervisor_attempt_events",
        "supervisor_pre_dispatch_intent_authorization_enforcement_baseline",
        "supervisor_pre_dispatch_intent_authorization_decisions",
        "supervisor_pre_dispatch_intent_authorization_action_receipts",
    }
    if not required.issubset(tables):
        return _SupervisorPreDispatchIntentEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_enforcement_schema_missing",
                    None,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                ),
            ),
        )
    try:
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        flow_rows_by_id = {row["flow_id"]: row for row in flow_rows}
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_rows_by_id = {row["attempt_id"]: row for row in attempt_rows}
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        event_rows_by_id: dict[str, sqlite3.Row] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
            event_rows_by_id[row["event_id"]] = row
        baseline = {
            row["target_attempt_event_id"]
            for row in connection.execute(
                """
                SELECT target_attempt_event_id
                FROM supervisor_pre_dispatch_intent_authorization_enforcement_baseline
                """
            ).fetchall()
        }
        decision_rows = connection.execute(
            """
            SELECT * FROM supervisor_pre_dispatch_intent_authorization_decisions
            ORDER BY sequence
            """
        ).fetchall()
        receipt_rows = connection.execute(
            """
            SELECT * FROM supervisor_pre_dispatch_intent_authorization_action_receipts
            ORDER BY sequence
            """
        ).fetchall()
    except sqlite3.Error:
        return _SupervisorPreDispatchIntentEnforcementAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_enforcement_schema_unreadable",
                    None,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                ),
            ),
        )

    findings: list[SupervisorAuthorizationFinding] = []
    for event_id in sorted(baseline):
        row = event_rows_by_id.get(event_id)
        if (
            row is None
            or row["state"] != AttemptState.DISPATCHING.value
            or row["reason_code"] != "dispatch_intent_recorded"
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_enforcement_baseline_invalid",
                    None,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    _audit_attempt_event_reference(event_id),
                )
            )

    dispatch_rows = [
        row
        for rows in event_rows_by_attempt.values()
        for row in rows
        if row["state"] == AttemptState.DISPATCHING.value
    ]
    dispatch_rows.sort(key=lambda row: (row["attempt_id"], row["revision"]))
    expected_rows = [
        row for row in dispatch_rows if row["event_id"] not in baseline
    ]
    expected_ids = {row["event_id"] for row in expected_rows}
    decisions_by_target: dict[str, list[sqlite3.Row]] = {}
    for row in decision_rows:
        decisions_by_target.setdefault(row["target_attempt_event_id"], []).append(row)
    receipts_by_target: dict[str, list[sqlite3.Row]] = {}
    for row in receipt_rows:
        receipts_by_target.setdefault(row["target_attempt_event_id"], []).append(row)

    for target_row in expected_rows:
        target_id = target_row["event_id"]
        target_reference = _audit_attempt_event_reference(target_id)
        attempt_row = attempt_rows_by_id.get(target_row["attempt_id"])
        flow_reference = (
            None
            if attempt_row is None
            else _audit_flow_reference(attempt_row["flow_id"])
        )
        decisions = decisions_by_target.get(target_id, [])
        receipts = receipts_by_target.get(target_id, [])
        if len(decisions) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "pre_dispatch_intent_enforcement_decision_missing"
                        if not decisions
                        else "pre_dispatch_intent_enforcement_decision_duplicated"
                    ),
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    target_reference,
                )
            )
        if len(receipts) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "pre_dispatch_intent_enforcement_receipt_missing"
                        if not receipts
                        else "pre_dispatch_intent_enforcement_receipt_duplicated"
                    ),
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    target_reference,
                )
            )
        try:
            if attempt_row is None or len(decisions) != 1:
                raise ValidationError("pre-dispatch source is missing")
            attempt = _attempt_from_row(attempt_row)
            flow_row = flow_rows_by_id.get(attempt.flow_id)
            if flow_row is None:
                raise ValidationError("pre-dispatch flow source is missing")
            spec = _flow_from_row(flow_row)
            _validate_flow_spec(spec)
            if flow_row["request_digest"] != spec.request_digest:
                raise ValidationError("flow request digest is invalid")
            revisions = revision_rows_by_flow.get(attempt.flow_id, [])
            _verify_flow_revision_lineage(
                attempt.flow_id,
                revisions,
                attempt_flow_ids,
            )
            events = _verify_attempt_claim_history(
                attempt=attempt,
                spec=spec,
                revision_rows=revisions,
                event_rows=event_rows_by_attempt.get(attempt.attempt_id, []),
            )
            dispatch_events = _verify_pre_dispatch_intent_history(
                attempt=attempt,
                revision_rows=revisions,
                events=events,
            )
            target = next(
                event for event in dispatch_events if event.event_id == target_id
            )
            source_attempt = events[target.revision - 2]
            source_flow = _flow_revision_from_row(
                revisions[attempt.claimed_revision]
            )
            payload_text = decisions[0]["payload_json"]
            if (
                not isinstance(payload_text, str)
                or len(payload_text.encode("utf-8")) > _MAX_JSON_BYTES
            ):
                raise ValidationError("pre-dispatch decision payload is invalid")
            decision_payload = parse_json_document(payload_text)
            if type(decision_payload) is not dict:
                raise ValidationError("pre-dispatch decision payload is invalid")
            intent_payload = decision_payload.get("pre_dispatch_intent")
            if type(intent_payload) is not dict:
                raise ValidationError("pre-dispatch intent payload is invalid")
            source_payload = intent_payload.get("source")
            if type(source_payload) is not dict:
                raise ValidationError("pre-dispatch source payload is invalid")
            lease_snapshot = source_payload.get("lease_snapshot")
            intent = SQLiteSupervisorStore._pre_dispatch_intent_authorization_target(
                spec=spec,
                attempt=attempt,
                source_flow=source_flow,
                source_attempt=source_attempt,
                target_attempt=target,
                lease_snapshot=lease_snapshot,
                observed_at=target.occurred_at,
            )
            authorization = evaluate_supervisor_pre_dispatch_intent_authorization(
                intent=intent,
                legacy_executable=True,
            )
            assert_supervisor_pre_dispatch_intent_authorized(
                authorization,
                intent=intent,
                action_started_at=target.occurred_at,
                persisted_payload=decision_payload,
            )
            expected_decision_payload = authorization.to_event_payload()
            decision_values = (
                authorization.decision.digest,
                intent.target_attempt_event_id,
                intent.source_attempt_event_id,
                intent.attempt_id,
                intent.flow_id,
                intent.source_flow_event_id,
                intent.source_flow_revision,
                intent.source_attempt_revision,
                intent.target_attempt_revision,
                intent.flow_request_digest,
                intent.input_digest,
                intent.run_id_ref,
                intent.lease_owner_ref,
                intent.lease_keys_digest,
                intent.lease_snapshot_digest,
                float(intent.deadline_at),
                authorization.request.digest,
                authorization.decision.digest,
                _bounded_json(
                    expected_decision_payload,
                    "supervisor pre-dispatch authorization audit decision payload",
                ),
                float(intent.occurred_at),
            )
            receipt_payload = build_supervisor_pre_dispatch_intent_action_receipt(
                authorization=authorization,
                action_started_at=target.occurred_at,
                completed_at=target.occurred_at,
            )
            receipt_digest = receipt_payload["receipt_digest"]
            receipt_values = (
                receipt_digest,
                intent.target_attempt_event_id,
                intent.attempt_id,
                intent.flow_id,
                authorization.decision.digest,
                receipt_digest,
                _bounded_json(
                    receipt_payload,
                    "supervisor pre-dispatch authorization audit receipt payload",
                ),
                float(target.occurred_at),
            )
        except Exception:
            decision_values = None
            receipt_values = None
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_enforcement_source_invalid",
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    target_reference,
                )
            )
        if (
            len(decisions) == 1
            and (
                decision_values is None
                or tuple(
                    decisions[0][field]
                    for field in (
                        "decision_event_id",
                        "target_attempt_event_id",
                        "source_attempt_event_id",
                        "attempt_id",
                        "flow_id",
                        "source_flow_event_id",
                        "source_flow_revision",
                        "source_attempt_revision",
                        "target_attempt_revision",
                        "flow_request_digest",
                        "input_digest",
                        "run_id_ref",
                        "lease_owner_ref",
                        "lease_keys_digest",
                        "lease_snapshot_digest",
                        "deadline_at",
                        "request_digest",
                        "decision_digest",
                        "payload_json",
                        "evaluated_at",
                    )
                )
                != decision_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_enforcement_decision_invalid",
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    target_reference,
                )
            )
        if (
            len(receipts) == 1
            and (
                receipt_values is None
                or tuple(
                    receipts[0][field]
                    for field in (
                        "receipt_event_id",
                        "target_attempt_event_id",
                        "attempt_id",
                        "flow_id",
                        "decision_event_id",
                        "receipt_digest",
                        "payload_json",
                        "completed_at",
                    )
                )
                != receipt_values
            )
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_intent_enforcement_receipt_invalid",
                    flow_reference,
                    _PRE_DISPATCH_INTENT_BOUNDARY,
                    None,
                    target_reference,
                )
            )

    for target_id, rows in decisions_by_target.items():
        if target_id not in expected_ids:
            for row in rows:
                findings.append(
                    SupervisorAuthorizationFinding(
                        "pre_dispatch_intent_enforcement_decision_unexpected",
                        _audit_flow_reference(row["flow_id"]),
                        _PRE_DISPATCH_INTENT_BOUNDARY,
                        None,
                        _audit_attempt_event_reference(target_id),
                    )
                )
    for target_id, rows in receipts_by_target.items():
        if target_id not in expected_ids:
            for row in rows:
                findings.append(
                    SupervisorAuthorizationFinding(
                        "pre_dispatch_intent_enforcement_receipt_unexpected",
                        _audit_flow_reference(row["flow_id"]),
                        _PRE_DISPATCH_INTENT_BOUNDARY,
                        None,
                        _audit_attempt_event_reference(target_id),
                    )
                )
    return _SupervisorPreDispatchIntentEnforcementAudit(
        True,
        len(decision_rows) + len(receipt_rows),
        len(expected_ids) * 2,
        tuple(findings),
    )


def _is_attempt_completion_outbox_row(row: sqlite3.Row) -> bool:
    """Return whether an outbox row came from ``complete_attempt`` semantics."""

    try:
        return (
            row["attempt_id"] is not None
            and row["operation_digest"] != row["intent_digest"]
        )
    except (IndexError, KeyError):
        return False


def _structural_attempt_completion_lease_snapshot(
    attempt: AttemptRecord,
) -> tuple[dict[str, Any], ...]:
    """Make a non-persisted shape solely for legacy lineage validation.

    Historical completion rows retain no active lease records because a valid
    completion releases them. This placeholder proves only that the durable
    flow/attempt/outbox lineage can fit the frozen redacted shape; it is never
    evidence for an observation and is never persisted.
    """

    return tuple(
        {
            "lease_key_ref": canonical_digest({"lease_key": lease_key}),
            "lease_owner_ref": canonical_digest(
                {"lease_owner": attempt.lease_owner}
            ),
            "acquired_at": float(attempt.created_at),
            "renewed_at": float(attempt.created_at),
            "expires_at": float(attempt.deadline_at),
        }
        for lease_key in attempt.lease_keys
    )


def _attempt_completion_source_from_outbox(
    *,
    outbox_row: sqlite3.Row,
    flow_rows_by_id: Mapping[str, sqlite3.Row],
    revision_rows_by_flow: Mapping[str, Sequence[sqlite3.Row]],
    attempt_rows_by_id: Mapping[str, sqlite3.Row],
    event_rows_by_attempt: Mapping[str, Sequence[sqlite3.Row]],
    attempt_flow_ids: Mapping[str, str],
) -> tuple[
    FlowSpec,
    AttemptRecord,
    FlowRevision,
    AttemptEvent,
    FlowRevision,
    AttemptEvent,
    CompletionIntent,
]:
    """Rebuild one local completion source from immutable durable records."""

    completion = _completion_from_row(outbox_row)
    if (
        type(completion.flow_id) is not str
        or type(completion.attempt_id) is not str
    ):
        raise ValidationError("attempt completion outbox source is invalid")
    _validate_revision(completion.source_revision)
    if completion.source_revision < 2:
        raise ValidationError("attempt completion source revision is invalid")
    attempt_row = attempt_rows_by_id.get(completion.attempt_id)
    flow_row = flow_rows_by_id.get(completion.flow_id)
    if attempt_row is None or flow_row is None:
        raise ValidationError("attempt completion source is missing")
    attempt = _attempt_from_row(attempt_row)
    spec = _flow_from_row(flow_row)
    _validate_flow_spec(spec)
    if flow_row["request_digest"] != spec.request_digest:
        raise ValidationError("attempt completion flow request digest is invalid")
    if attempt.flow_id != spec.flow_id:
        raise ValidationError("attempt completion attempt flow is invalid")
    revisions = revision_rows_by_flow.get(spec.flow_id, ())
    _verify_flow_revision_lineage(spec.flow_id, revisions, attempt_flow_ids)
    if completion.source_revision > len(revisions):
        raise ValidationError("attempt completion target flow is missing")
    events = _verify_attempt_claim_history(
        attempt=attempt,
        spec=spec,
        revision_rows=revisions,
        event_rows=event_rows_by_attempt.get(attempt.attempt_id, ()),
    )
    if len(events) < 2:
        raise ValidationError("attempt completion target event is missing")
    source_flow = _flow_revision_from_row(
        revisions[completion.source_revision - 2]
    )
    target_flow = _flow_revision_from_row(
        revisions[completion.source_revision - 1]
    )
    source_attempt = events[-2]
    target_attempt = events[-1]
    _attempt_completion_mapping(
        spec=spec,
        attempt=attempt,
        source_flow=source_flow,
        source_attempt=source_attempt,
        target_flow=target_flow,
        target_attempt=target_attempt,
        completion=completion,
        lease_snapshot=_structural_attempt_completion_lease_snapshot(attempt),
        observed_at=target_flow.occurred_at,
    )
    return (
        spec,
        attempt,
        source_flow,
        source_attempt,
        target_flow,
        target_attempt,
        completion,
    )


def _inspect_attempt_completion_authorization_connection(
    connection: sqlite3.Connection,
) -> _SupervisorAttemptCompletionShadowAudit:
    """Replay only post-v10 local completion shadows without repair."""

    tables = _table_names(connection)
    required = {
        "supervisor_flows",
        "supervisor_flow_revisions",
        "supervisor_attempts",
        "supervisor_attempt_events",
        "supervisor_completion_outbox",
        "supervisor_attempt_completion_authorization_baseline",
        "supervisor_attempt_completion_authorization_observations",
    }
    if not required.issubset(tables):
        return _SupervisorAttemptCompletionShadowAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "attempt_completion_authorization_schema_missing",
                    None,
                    _ATTEMPT_COMPLETION_BOUNDARY,
                    None,
                ),
            ),
        )
    try:
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        flow_rows_by_id = {row["flow_id"]: row for row in flow_rows}
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_rows_by_id = {row["attempt_id"]: row for row in attempt_rows}
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
        outbox_rows = connection.execute(
            """
            SELECT * FROM supervisor_completion_outbox
            ORDER BY flow_id, source_revision, outbox_id
            """
        ).fetchall()
        outbox_rows_by_id = {row["outbox_id"]: row for row in outbox_rows}
        baseline = {
            row["outbox_id"]
            for row in connection.execute(
                """
                SELECT outbox_id
                FROM supervisor_attempt_completion_authorization_baseline
                """
            ).fetchall()
        }
        observation_rows = connection.execute(
            """
            SELECT * FROM supervisor_attempt_completion_authorization_observations
            ORDER BY sequence
            """
        ).fetchall()
    except sqlite3.Error:
        return _SupervisorAttemptCompletionShadowAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "attempt_completion_authorization_schema_unreadable",
                    None,
                    _ATTEMPT_COMPLETION_BOUNDARY,
                    None,
                ),
            ),
        )

    findings: list[SupervisorAuthorizationFinding] = []
    for outbox_id in sorted(baseline):
        row = outbox_rows_by_id.get(outbox_id)
        try:
            if row is None or not _is_attempt_completion_outbox_row(row):
                raise ValidationError("attempt completion baseline is invalid")
            _attempt_completion_source_from_outbox(
                outbox_row=row,
                flow_rows_by_id=flow_rows_by_id,
                revision_rows_by_flow=revision_rows_by_flow,
                attempt_rows_by_id=attempt_rows_by_id,
                event_rows_by_attempt=event_rows_by_attempt,
                attempt_flow_ids=attempt_flow_ids,
            )
        except Exception:
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_completion_authorization_baseline_invalid",
                    None if row is None else _audit_flow_reference(row["flow_id"]),
                    _ATTEMPT_COMPLETION_BOUNDARY,
                    None,
                    _audit_completion_outbox_reference(outbox_id),
                )
            )

    expected_rows = [
        row
        for row in outbox_rows
        if _is_attempt_completion_outbox_row(row)
        and row["outbox_id"] not in baseline
    ]
    expected_ids = {row["outbox_id"] for row in expected_rows}
    observations_by_outbox: dict[str, list[sqlite3.Row]] = {}
    for row in observation_rows:
        observations_by_outbox.setdefault(row["outbox_id"], []).append(row)

    for outbox_row in expected_rows:
        outbox_id = outbox_row["outbox_id"]
        target_reference = _audit_completion_outbox_reference(outbox_id)
        flow_reference = _audit_flow_reference(outbox_row["flow_id"])
        matches = observations_by_outbox.get(outbox_id, [])
        if len(matches) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "attempt_completion_authorization_observation_missing"
                        if not matches
                        else "attempt_completion_authorization_observation_duplicated"
                    ),
                    flow_reference,
                    _ATTEMPT_COMPLETION_BOUNDARY,
                    None,
                    target_reference,
                )
            )
            continue
        source: tuple[
            FlowSpec,
            AttemptRecord,
            FlowRevision,
            AttemptEvent,
            FlowRevision,
            AttemptEvent,
            CompletionIntent,
        ] | None = None
        try:
            source = _attempt_completion_source_from_outbox(
                outbox_row=outbox_row,
                flow_rows_by_id=flow_rows_by_id,
                revision_rows_by_flow=revision_rows_by_flow,
                attempt_rows_by_id=attempt_rows_by_id,
                event_rows_by_attempt=event_rows_by_attempt,
                attempt_flow_ids=attempt_flow_ids,
            )
        except Exception:
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_completion_authorization_source_invalid",
                    flow_reference,
                    _ATTEMPT_COMPLETION_BOUNDARY,
                    None,
                    target_reference,
                )
            )
        if source is None:
            continue
        (
            spec,
            attempt,
            source_flow,
            source_attempt,
            target_flow,
            target_attempt,
            completion,
        ) = source
        try:
            expected_values = _expected_attempt_completion_observation_values(
                matches[0],
                spec=spec,
                attempt=attempt,
                source_flow=source_flow,
                source_attempt=source_attempt,
                target_flow=target_flow,
                target_attempt=target_attempt,
                completion=completion,
            )
        except Exception:
            expected_values = None
        if (
            expected_values is None
            or tuple(
                matches[0][field]
                for field in (
                    "outbox_id",
                    "target_flow_event_id",
                    "target_attempt_event_id",
                    "source_flow_event_id",
                    "source_flow_revision",
                    "source_attempt_event_id",
                    "attempt_id",
                    "flow_id",
                    "flow_request_digest",
                    "input_digest",
                    "lease_snapshot_digest",
                    "completion_intent_digest",
                    "completion_operation_digest",
                    "request_digest",
                    "decision_digest",
                    "effect",
                    "derived_permission_class",
                    "legacy_executable",
                    "execution_parity",
                    "payload_json",
                    "observed_at",
                )
            )
            != expected_values
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "attempt_completion_authorization_observation_invalid",
                    flow_reference,
                    _ATTEMPT_COMPLETION_BOUNDARY,
                    int(matches[0]["sequence"]),
                    target_reference,
                )
            )

    for outbox_id, rows in observations_by_outbox.items():
        if outbox_id not in expected_ids:
            for row in rows:
                findings.append(
                    SupervisorAuthorizationFinding(
                        "attempt_completion_authorization_observation_unexpected",
                        _audit_flow_reference(row["flow_id"]),
                        _ATTEMPT_COMPLETION_BOUNDARY,
                        int(row["sequence"]),
                        _audit_completion_outbox_reference(outbox_id),
                    )
                )
    return _SupervisorAttemptCompletionShadowAudit(
        True,
        len(observation_rows),
        len(expected_rows),
        tuple(findings),
    )


def _is_pre_dispatch_reconciliation_outbox_row(row: sqlite3.Row) -> bool:
    """Return whether an outbox row closes an expired pre-dispatch claim."""

    try:
        return (
            row["attempt_id"] is not None
            and row["operation_digest"] == row["intent_digest"]
        )
    except (IndexError, KeyError):
        return False


def _structural_pre_dispatch_reconciliation_lease_snapshot(
    attempt: AttemptRecord,
    *,
    observed_at: float,
) -> tuple[dict[str, Any], ...]:
    """Make a never-persisted expired shape for legacy lineage validation."""

    timestamp = _timestamp(
        observed_at,
        "pre-dispatch reconciliation observation timestamp",
    )
    expiry = min(float(attempt.deadline_at), timestamp)
    return tuple(
        {
            "lease_key_ref": canonical_digest({"lease_key": lease_key}),
            "lease_state": "owned_expired",
            "lease_owner_ref": canonical_digest(
                {"lease_owner": attempt.lease_owner}
            ),
            "acquired_at": float(attempt.created_at),
            "renewed_at": float(attempt.created_at),
            "expires_at": expiry,
        }
        for lease_key in attempt.lease_keys
    )


def _pre_dispatch_reconciliation_source_from_outbox(
    *,
    outbox_row: sqlite3.Row,
    flow_rows_by_id: Mapping[str, sqlite3.Row],
    revision_rows_by_flow: Mapping[str, Sequence[sqlite3.Row]],
    attempt_rows_by_id: Mapping[str, sqlite3.Row],
    event_rows_by_attempt: Mapping[str, Sequence[sqlite3.Row]],
    attempt_flow_ids: Mapping[str, str],
) -> tuple[
    FlowSpec,
    AttemptRecord,
    FlowRevision,
    AttemptEvent,
    FlowRevision,
    AttemptEvent,
    CompletionIntent,
    str,
]:
    """Rebuild one expired pre-dispatch repair from immutable records."""

    completion = _completion_from_row(outbox_row)
    if (
        type(completion.flow_id) is not str
        or type(completion.attempt_id) is not str
    ):
        raise ValidationError("pre-dispatch reconciliation outbox source is invalid")
    _validate_revision(completion.source_revision)
    if completion.source_revision < 2:
        raise ValidationError("pre-dispatch reconciliation source revision is invalid")
    attempt_row = attempt_rows_by_id.get(completion.attempt_id)
    flow_row = flow_rows_by_id.get(completion.flow_id)
    if attempt_row is None or flow_row is None:
        raise ValidationError("pre-dispatch reconciliation source is missing")
    attempt = _attempt_from_row(attempt_row)
    spec = _flow_from_row(flow_row)
    _validate_flow_spec(spec)
    if flow_row["request_digest"] != spec.request_digest:
        raise ValidationError(
            "pre-dispatch reconciliation flow request digest is invalid"
        )
    if attempt.flow_id != spec.flow_id:
        raise ValidationError("pre-dispatch reconciliation attempt flow is invalid")
    revisions = revision_rows_by_flow.get(spec.flow_id, ())
    _verify_flow_revision_lineage(spec.flow_id, revisions, attempt_flow_ids)
    if completion.source_revision > len(revisions):
        raise ValidationError("pre-dispatch reconciliation target flow is missing")
    events = _verify_attempt_claim_history(
        attempt=attempt,
        spec=spec,
        revision_rows=revisions,
        event_rows=event_rows_by_attempt.get(attempt.attempt_id, ()),
    )
    if len(events) < 2:
        raise ValidationError("pre-dispatch reconciliation target event is missing")
    source_flow = _flow_revision_from_row(
        revisions[completion.source_revision - 2]
    )
    target_flow = _flow_revision_from_row(
        revisions[completion.source_revision - 1]
    )
    source_attempt = events[-2]
    target_attempt = events[-1]
    action = (
        "finalize_cancelled_pre_dispatch"
        if source_flow.cancellation_requested
        else "mark_lost_pre_dispatch"
    )
    _pre_dispatch_reconciliation_mapping(
        spec=spec,
        attempt=attempt,
        source_flow=source_flow,
        source_attempt=source_attempt,
        target_flow=target_flow,
        target_attempt=target_attempt,
        completion=completion,
        lease_snapshot=_structural_pre_dispatch_reconciliation_lease_snapshot(
            attempt,
            observed_at=target_flow.occurred_at,
        ),
        reconciliation_action=action,
        observed_at=target_flow.occurred_at,
    )
    return (
        spec,
        attempt,
        source_flow,
        source_attempt,
        target_flow,
        target_attempt,
        completion,
        action,
    )


def _inspect_pre_dispatch_reconciliation_authorization_connection(
    connection: sqlite3.Connection,
) -> _SupervisorPreDispatchReconciliationShadowAudit:
    """Replay post-v11 expired-claim repair shadows without repair."""

    tables = _table_names(connection)
    required = {
        "supervisor_flows",
        "supervisor_flow_revisions",
        "supervisor_attempts",
        "supervisor_attempt_events",
        "supervisor_completion_outbox",
        "supervisor_pre_dispatch_reconciliation_authorization_baseline",
        "supervisor_pre_dispatch_reconciliation_authorization_observations",
    }
    if not required.issubset(tables):
        return _SupervisorPreDispatchReconciliationShadowAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "pre_dispatch_reconciliation_authorization_schema_missing",
                    None,
                    _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
                    None,
                ),
            ),
        )
    try:
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        flow_rows_by_id = {row["flow_id"]: row for row in flow_rows}
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_rows_by_id = {row["attempt_id"]: row for row in attempt_rows}
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
        outbox_rows = connection.execute(
            """
            SELECT * FROM supervisor_completion_outbox
            ORDER BY flow_id, source_revision, outbox_id
            """
        ).fetchall()
        outbox_rows_by_id = {row["outbox_id"]: row for row in outbox_rows}
        baseline = {
            row["outbox_id"]
            for row in connection.execute(
                """
                SELECT outbox_id
                FROM supervisor_pre_dispatch_reconciliation_authorization_baseline
                """
            ).fetchall()
        }
        observation_rows = connection.execute(
            """
            SELECT *
            FROM supervisor_pre_dispatch_reconciliation_authorization_observations
            ORDER BY sequence
            """
        ).fetchall()
    except sqlite3.Error:
        return _SupervisorPreDispatchReconciliationShadowAudit(
            False,
            0,
            0,
            (
                SupervisorAuthorizationFinding(
                    "pre_dispatch_reconciliation_authorization_schema_unreadable",
                    None,
                    _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
                    None,
                ),
            ),
        )

    findings: list[SupervisorAuthorizationFinding] = []
    for outbox_id in sorted(baseline):
        row = outbox_rows_by_id.get(outbox_id)
        try:
            if row is None or not _is_pre_dispatch_reconciliation_outbox_row(row):
                raise ValidationError(
                    "pre-dispatch reconciliation baseline is invalid"
                )
            _pre_dispatch_reconciliation_source_from_outbox(
                outbox_row=row,
                flow_rows_by_id=flow_rows_by_id,
                revision_rows_by_flow=revision_rows_by_flow,
                attempt_rows_by_id=attempt_rows_by_id,
                event_rows_by_attempt=event_rows_by_attempt,
                attempt_flow_ids=attempt_flow_ids,
            )
        except Exception:
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_reconciliation_authorization_baseline_invalid",
                    None if row is None else _audit_flow_reference(row["flow_id"]),
                    _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
                    None,
                    _audit_completion_outbox_reference(outbox_id),
                )
            )

    expected_rows = [
        row
        for row in outbox_rows
        if _is_pre_dispatch_reconciliation_outbox_row(row)
        and row["outbox_id"] not in baseline
    ]
    expected_ids = {row["outbox_id"] for row in expected_rows}
    observations_by_outbox: dict[str, list[sqlite3.Row]] = {}
    for row in observation_rows:
        observations_by_outbox.setdefault(row["outbox_id"], []).append(row)

    for outbox_row in expected_rows:
        outbox_id = outbox_row["outbox_id"]
        target_reference = _audit_completion_outbox_reference(outbox_id)
        flow_reference = _audit_flow_reference(outbox_row["flow_id"])
        matches = observations_by_outbox.get(outbox_id, [])
        if len(matches) != 1:
            findings.append(
                SupervisorAuthorizationFinding(
                    (
                        "pre_dispatch_reconciliation_authorization_observation_missing"
                        if not matches
                        else "pre_dispatch_reconciliation_authorization_observation_duplicated"
                    ),
                    flow_reference,
                    _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
                    None,
                    target_reference,
                )
            )
            continue
        source: tuple[
            FlowSpec,
            AttemptRecord,
            FlowRevision,
            AttemptEvent,
            FlowRevision,
            AttemptEvent,
            CompletionIntent,
            str,
        ] | None = None
        try:
            source = _pre_dispatch_reconciliation_source_from_outbox(
                outbox_row=outbox_row,
                flow_rows_by_id=flow_rows_by_id,
                revision_rows_by_flow=revision_rows_by_flow,
                attempt_rows_by_id=attempt_rows_by_id,
                event_rows_by_attempt=event_rows_by_attempt,
                attempt_flow_ids=attempt_flow_ids,
            )
        except Exception:
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_reconciliation_authorization_source_invalid",
                    flow_reference,
                    _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
                    None,
                    target_reference,
                )
            )
        if source is None:
            continue
        (
            spec,
            attempt,
            source_flow,
            source_attempt,
            target_flow,
            target_attempt,
            completion,
            action,
        ) = source
        try:
            expected_values = _expected_pre_dispatch_reconciliation_observation_values(
                matches[0],
                spec=spec,
                attempt=attempt,
                source_flow=source_flow,
                source_attempt=source_attempt,
                target_flow=target_flow,
                target_attempt=target_attempt,
                completion=completion,
            )
        except Exception:
            expected_values = None
        if (
            expected_values is None
            or tuple(
                matches[0][field]
                for field in (
                    "outbox_id",
                    "target_flow_event_id",
                    "target_attempt_event_id",
                    "source_flow_event_id",
                    "source_flow_revision",
                    "source_attempt_event_id",
                    "attempt_id",
                    "flow_id",
                    "flow_request_digest",
                    "input_digest",
                    "lease_snapshot_digest",
                    "completion_intent_digest",
                    "completion_operation_digest",
                    "reconciliation_action",
                    "request_digest",
                    "decision_digest",
                    "effect",
                    "derived_permission_class",
                    "legacy_executable",
                    "execution_parity",
                    "payload_json",
                    "observed_at",
                )
            )
            != expected_values
        ):
            findings.append(
                SupervisorAuthorizationFinding(
                    "pre_dispatch_reconciliation_authorization_observation_invalid",
                    flow_reference,
                    _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
                    int(matches[0]["sequence"]),
                    target_reference,
                )
            )

    for outbox_id, rows in observations_by_outbox.items():
        if outbox_id not in expected_ids:
            for row in rows:
                findings.append(
                    SupervisorAuthorizationFinding(
                        "pre_dispatch_reconciliation_authorization_observation_unexpected",
                        _audit_flow_reference(row["flow_id"]),
                        _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
                        int(row["sequence"]),
                        _audit_completion_outbox_reference(outbox_id),
                    )
                )
    return _SupervisorPreDispatchReconciliationShadowAudit(
        True,
        len(observation_rows),
        len(expected_rows),
        tuple(findings),
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
    findings = list(_shared_state_guard_findings(connection))
    expected = _expected_supervisor_schema()
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != expected:
        findings.append(
            SupervisorAuthorizationFinding(
                "authorization_schema_mismatch", None, None, None
            )
        )
    expected_migration = _expected_migration_schema()
    actual_migration = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("state_schema_migrations")
        or value[1] == "state_schema_migrations"
    }
    migration_schema_matches = actual_migration == expected_migration
    if not migration_schema_matches:
        findings.append(
            SupervisorAuthorizationFinding(
                "migration_schema_mismatch", None, None, None
            )
        )
    tables = _table_names(connection)
    if "state_schema_migrations" not in tables:
        for code in (
            "supervisor_migration_ledger_mismatch",
            "authorization_migration_ledger_mismatch",
            "bookkeeping_authorization_migration_ledger_mismatch",
            "control_authorization_migration_ledger_mismatch",
            "flow_admission_authorization_migration_ledger_mismatch",
            "attempt_claim_authorization_migration_ledger_mismatch",
            "pre_dispatch_intent_authorization_migration_ledger_mismatch",
            "pre_dispatch_intent_enforcement_migration_ledger_mismatch",
            "attempt_completion_authorization_migration_ledger_mismatch",
            "pre_dispatch_reconciliation_authorization_migration_ledger_mismatch",
        ):
            findings.append(
                SupervisorAuthorizationFinding(code, None, None, None)
            )
        return tuple(dict.fromkeys(findings))
    if not migration_schema_matches:
        return tuple(dict.fromkeys(findings))
    ledger = {
        int(row["version"]): row
        for row in connection.execute(
            "SELECT version, name, script_sha256 FROM state_schema_migrations"
        ).fetchall()
    }
    if tuple(sorted(ledger)) != tuple(range(1, _SCHEMA_VERSION + 1)):
        findings.append(
            SupervisorAuthorizationFinding(
                "migration_version_set_mismatch", None, None, None
            )
        )
    baseline_migration = ledger.get(1)
    if (
        baseline_migration is None
        or baseline_migration["name"] != "baseline_state"
        or baseline_migration["script_sha256"]
        != _sha256_text("agentops-baseline-schema-v1")
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "baseline_migration_ledger_mismatch", None, None, None
            )
        )
    supervisor_migration = ledger.get(2)
    if (
        supervisor_migration is None
        or supervisor_migration["name"] != "supervisor_control_plane"
        or supervisor_migration["script_sha256"] != _sha256_text(_SCHEMA_V2)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "supervisor_migration_ledger_mismatch", None, None, None
            )
        )
    migration = ledger.get(3)
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
    bookkeeping_migration = ledger.get(4)
    if (
        bookkeeping_migration is None
        or bookkeeping_migration["name"]
        != "supervisor_bookkeeping_authorization_shadow"
        or bookkeeping_migration["script_sha256"] != _sha256_text(_SCHEMA_V4)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "bookkeeping_authorization_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    control_migration = ledger.get(5)
    if (
        control_migration is None
        or control_migration["name"]
        != "supervisor_control_authorization_enforcement"
        or control_migration["script_sha256"] != _sha256_text(_SCHEMA_V5)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "control_authorization_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    flow_admission_migration = ledger.get(6)
    if (
        flow_admission_migration is None
        or flow_admission_migration["name"]
        != "supervisor_flow_admission_authorization_enforcement"
        or flow_admission_migration["script_sha256"] != _sha256_text(_SCHEMA_V6)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "flow_admission_authorization_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    attempt_claim_migration = ledger.get(7)
    if (
        attempt_claim_migration is None
        or attempt_claim_migration["name"]
        != "supervisor_attempt_claim_authorization_enforcement"
        or attempt_claim_migration["script_sha256"] != _sha256_text(_SCHEMA_V7)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "attempt_claim_authorization_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    pre_dispatch_intent_migration = ledger.get(8)
    if (
        pre_dispatch_intent_migration is None
        or pre_dispatch_intent_migration["name"]
        != "supervisor_pre_dispatch_intent_authorization_shadow"
        or pre_dispatch_intent_migration["script_sha256"]
        != _sha256_text(_SCHEMA_V8)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "pre_dispatch_intent_authorization_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    pre_dispatch_intent_enforcement_migration = ledger.get(9)
    if (
        pre_dispatch_intent_enforcement_migration is None
        or pre_dispatch_intent_enforcement_migration["name"]
        != "supervisor_pre_dispatch_intent_authorization_enforcement"
        or pre_dispatch_intent_enforcement_migration["script_sha256"]
        != _sha256_text(_SCHEMA_V9)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "pre_dispatch_intent_enforcement_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    attempt_completion_migration = ledger.get(10)
    if (
        attempt_completion_migration is None
        or attempt_completion_migration["name"]
        != "supervisor_attempt_completion_authorization_shadow"
        or attempt_completion_migration["script_sha256"]
        != _sha256_text(_SCHEMA_V10)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "attempt_completion_authorization_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    pre_dispatch_reconciliation_migration = ledger.get(11)
    if (
        pre_dispatch_reconciliation_migration is None
        or pre_dispatch_reconciliation_migration["name"]
        != "supervisor_pre_dispatch_reconciliation_authorization_shadow"
        or pre_dispatch_reconciliation_migration["script_sha256"]
        != _sha256_text(_SCHEMA_V11)
    ):
        findings.append(
            SupervisorAuthorizationFinding(
                "pre_dispatch_reconciliation_authorization_migration_ledger_mismatch",
                None,
                None,
                None,
            )
        )
    return tuple(dict.fromkeys(findings))


def _shared_state_guard_findings(
    connection: sqlite3.Connection,
) -> tuple[SupervisorAuthorizationFinding, ...]:
    return tuple(
        SupervisorAuthorizationFinding(code, None, None, None)
        for code in _state_schema_integrity_issues(connection)
    )


def _verify_authorization_observation(
    row: sqlite3.Row,
    *,
    spec: FlowSpec,
    boundary: str,
    observed_at: float,
    attempt_id: str | None,
) -> tuple[SupervisorAuthorizationFinding, ...]:
    expected_request, expected_policy = _supervisor_authorization_request(
        boundary=boundary,
        spec=spec,
        observed_at=observed_at,
        attempt_id=attempt_id,
    )
    return _verify_expected_authorization_observation(
        row,
        boundary=boundary,
        observed_at=observed_at,
        expected_request=expected_request,
        expected_policy=expected_policy,
    )


def _verify_expected_authorization_observation(
    row: sqlite3.Row,
    *,
    boundary: str,
    observed_at: float,
    expected_request: AuthorizationRequest,
    expected_policy: PolicyBundle,
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
    if not expected_permit:
        add("legacy_authorization_parity_mismatch")
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
        flow_id=(
            None
            if row["flow_id"] is None
            else _audit_flow_reference(row["flow_id"])
        ),
        boundary=_audit_boundary_reference(row["boundary"]),
        observation_sequence=int(row["sequence"]),
    )


def _audit_flow_reference(value: Any) -> str:
    if (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and not is_sensitive_environment_value(value)
    ):
        return value
    if isinstance(value, str):
        return canonical_digest({"flow_id": value})
    if isinstance(value, bytes):
        return f"sha256:{hashlib.sha256(value).hexdigest()}"
    return canonical_digest({"flow_id_type": type(value).__name__})


def _audit_attempt_event_reference(value: Any) -> str:
    """Return a deterministic redacted target reference even for bad rows."""

    if isinstance(value, str):
        return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"
    if isinstance(value, bytes):
        return f"sha256:{hashlib.sha256(value).hexdigest()}"
    return canonical_digest({"attempt_event_id_type": type(value).__name__})


def _audit_completion_outbox_reference(value: Any) -> str:
    """Return a deterministic redacted completion target reference."""

    if isinstance(value, str):
        return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"
    if isinstance(value, bytes):
        return f"sha256:{hashlib.sha256(value).hexdigest()}"
    return canonical_digest({"completion_outbox_id_type": type(value).__name__})


def _audit_boundary_reference(value: Any) -> str | None:
    if value in {
        "flow_admission",
        "attempt_claim",
        _PRE_DISPATCH_INTENT_BOUNDARY,
        _ATTEMPT_COMPLETION_BOUNDARY,
        "control_transition",
        "flow_cancellation",
    }:
        return value
    if isinstance(value, str):
        return "invalid:" + canonical_digest({"boundary": value})
    return None


@contextmanager
def _read_only_connection(path: Path) -> Iterator[sqlite3.Connection]:
    try:
        if path.is_symlink() or path.parent.is_symlink():
            raise ConfigurationError(
                "supervisor state database must not be a symlink"
            )
        absolute = path.resolve(strict=True)
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "supervisor state is unreadable or malformed"
        ) from error
    wal_path = Path(f"{absolute}-wal")
    shared_memory_path = Path(f"{absolute}-shm")
    main_signature = _supervisor_file_signature(absolute, required=True)
    wal_signature = _supervisor_file_signature(wal_path, required=False)
    shared_memory_signature = _supervisor_file_signature(
        shared_memory_path,
        required=False,
    )
    wal_exists = wal_signature is not None
    shared_memory_exists = shared_memory_signature is not None
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
        if not wal_exists:
            after = (
                _supervisor_file_signature(absolute, required=True),
                _supervisor_file_signature(wal_path, required=False),
                _supervisor_file_signature(
                    shared_memory_path,
                    required=False,
                ),
            )
            if after != (main_signature, None, None):
                raise ConfigurationError(
                    "supervisor state changed during inspection"
                )


def _supervisor_file_signature(
    path: Path,
    *,
    required: bool,
) -> tuple[int, int, int, int] | None:
    try:
        if path.is_symlink():
            raise ConfigurationError(
                "supervisor state database must not use symlinks"
            )
        metadata = path.stat()
    except FileNotFoundError:
        if not required:
            return None
        raise ConfigurationError(
            "supervisor state is unreadable or malformed"
        ) from None
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "supervisor state is unreadable or malformed"
        ) from error
    if not path.is_file():
        raise ConfigurationError(
            "supervisor state is unreadable or malformed"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


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
) -> dict[tuple[str, str], tuple[str, str, str]]:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql FROM sqlite_master
        WHERE sql IS NOT NULL AND type IN ('table', 'index', 'trigger', 'view')
        ORDER BY type, name
        """
    ).fetchall()
    return {
        (row["type"], row["name"]): (
            row["type"],
            row["tbl_name"],
            " ".join(row["sql"].split()),
        )
        for row in rows
    }


def _execute_schema_script(connection: sqlite3.Connection, script: str) -> None:
    statement = ""
    for line in script.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            if sql:
                connection.execute(sql)
            statement = ""
    if statement.strip():
        raise ConfigurationError("schema migration script is incomplete")


def _verify_pre_v5_control_history(connection: sqlite3.Connection) -> None:
    try:
        foreign_key_errors = tuple(
            row
            for table in (
                "supervisor_control_events",
                "supervisor_flows",
                "supervisor_flow_revisions",
                "supervisor_cancellation_requests",
                "supervisor_attempts",
                "supervisor_attempt_events",
                "supervisor_completion_outbox",
                "supervisor_completion_delivery_events",
                "supervisor_completion_receipts",
                "supervisor_authorization_observations",
                "supervisor_bookkeeping_authorization_sources",
                "supervisor_bookkeeping_authorization_observations",
            )
            for row in connection.execute(f'PRAGMA foreign_key_check("{table}")')
        )
        if foreign_key_errors:
            raise ValidationError("supervisor history has invalid references")
        previous = _initial_control_revision()
        rows = connection.execute(
            "SELECT * FROM supervisor_control_events ORDER BY revision"
        ).fetchall()
        for expected_revision, row in enumerate(rows, start=1):
            control = _control_from_row(row)
            _validate_text(
                control.event_id,
                "control event identifier",
                maximum=256,
            )
            _validate_text(
                control.actor_id,
                "control actor identifier",
                maximum=256,
            )
            _validate_reason(control.reason_code)
            _timestamp(control.occurred_at, "control event timestamp")
            if (
                control.revision != expected_revision
                or control.mode not in _CONTROL_TRANSITIONS[previous.mode]
            ):
                raise ValidationError("control history is not contiguous and valid")
            previous = control
    except (KeyError, TypeError, ValueError, ValidationError, sqlite3.Error) as error:
        raise ConfigurationError(
            "pre-v5 supervisor control history is invalid"
        ) from error


def _verify_pre_v6_flow_history(connection: sqlite3.Connection) -> None:
    """Refuse to baseline malformed legacy flows into the enforcing PEP."""

    try:
        foreign_key_errors = tuple(
            row
            for table in (
                "supervisor_control_events",
                "supervisor_flows",
                "supervisor_flow_revisions",
                "supervisor_cancellation_requests",
                "supervisor_attempts",
                "supervisor_attempt_events",
                "supervisor_completion_outbox",
                "supervisor_completion_delivery_events",
                "supervisor_completion_receipts",
                "supervisor_authorization_observations",
                "supervisor_bookkeeping_authorization_sources",
                "supervisor_bookkeeping_authorization_observations",
                "supervisor_control_authorization_baseline",
                "supervisor_control_authorization_decisions",
                "supervisor_control_authorization_action_receipts",
            )
            for row in connection.execute(f'PRAGMA foreign_key_check("{table}")')
        )
        if foreign_key_errors:
            raise ValidationError("supervisor history has invalid references")
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"]
            for row in connection.execute(
                "SELECT attempt_id, flow_id FROM supervisor_attempts"
            ).fetchall()
        }
        for row in flow_rows:
            spec = _flow_from_row(row)
            _validate_flow_spec(spec)
            if row["request_digest"] != spec.request_digest:
                raise ValidationError("flow request digest is invalid")
            head = _verify_flow_revision_lineage(
                spec.flow_id,
                revision_rows_by_flow.get(spec.flow_id, []),
                attempt_flow_ids,
            )
            initial = revision_rows_by_flow[spec.flow_id][0]
            if initial["occurred_at"] != spec.created_at or head.flow_id != spec.flow_id:
                raise ValidationError("flow admission source history is invalid")
    except (KeyError, TypeError, ValueError, ValidationError, sqlite3.Error) as error:
        raise ConfigurationError(
            "pre-v6 supervisor flow history is invalid"
        ) from error


def _verify_pre_v7_attempt_history(connection: sqlite3.Connection) -> None:
    """Refuse to baseline malformed legacy claims into the enforcing PEP."""

    try:
        foreign_key_errors = tuple(
            row
            for table in (
                "supervisor_control_events",
                "supervisor_flows",
                "supervisor_flow_revisions",
                "supervisor_cancellation_requests",
                "supervisor_attempts",
                "supervisor_attempt_events",
                "supervisor_completion_outbox",
                "supervisor_completion_delivery_events",
                "supervisor_completion_receipts",
                "supervisor_authorization_observations",
                "supervisor_bookkeeping_authorization_sources",
                "supervisor_bookkeeping_authorization_observations",
                "supervisor_control_authorization_baseline",
                "supervisor_control_authorization_decisions",
                "supervisor_control_authorization_action_receipts",
                "supervisor_flow_admission_authorization_baseline",
                "supervisor_flow_admission_authorization_decisions",
                "supervisor_flow_admission_authorization_action_receipts",
            )
            for row in connection.execute(f'PRAGMA foreign_key_check("{table}")')
        )
        if foreign_key_errors:
            raise ValidationError("supervisor history has invalid references")
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        specs_by_flow: dict[str, FlowSpec] = {}
        for row in flow_rows:
            spec = _flow_from_row(row)
            _validate_flow_spec(spec)
            if row["request_digest"] != spec.request_digest:
                raise ValidationError("flow request digest is invalid")
            specs_by_flow[spec.flow_id] = spec
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        for row in attempt_rows:
            attempt_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)

        for flow_id, spec in specs_by_flow.items():
            _verify_flow_revision_lineage(
                flow_id,
                revision_rows_by_flow.get(flow_id, []),
                attempt_flow_ids,
            )
            for expected_number, attempt_row in enumerate(
                attempt_rows_by_flow.get(flow_id, []),
                start=1,
            ):
                attempt = _attempt_from_row(attempt_row)
                if attempt.attempt_number != expected_number:
                    raise ValidationError("attempt numbering is not contiguous")
                _verify_attempt_claim_history(
                    attempt=attempt,
                    spec=spec,
                    revision_rows=revision_rows_by_flow[flow_id],
                    event_rows=event_rows_by_attempt.get(attempt.attempt_id, []),
                )
        if set(event_rows_by_attempt) != set(attempt_flow_ids):
            raise ValidationError("attempt event history has an unknown attempt")
    except (KeyError, TypeError, ValueError, ValidationError, sqlite3.Error) as error:
        raise ConfigurationError(
            "pre-v7 supervisor attempt history is invalid"
        ) from error


def _verify_pre_v8_pre_dispatch_intent_history(
    connection: sqlite3.Connection,
) -> None:
    """Refuse to baseline malformed local dispatch-intent history."""

    try:
        _verify_pre_v7_attempt_history(connection)
        foreign_key_errors = tuple(
            row
            for table in (
                "supervisor_control_events",
                "supervisor_flows",
                "supervisor_flow_revisions",
                "supervisor_cancellation_requests",
                "supervisor_attempts",
                "supervisor_attempt_events",
                "supervisor_completion_outbox",
                "supervisor_completion_delivery_events",
                "supervisor_completion_receipts",
                "supervisor_authorization_observations",
                "supervisor_bookkeeping_authorization_sources",
                "supervisor_bookkeeping_authorization_observations",
                "supervisor_control_authorization_baseline",
                "supervisor_control_authorization_decisions",
                "supervisor_control_authorization_action_receipts",
                "supervisor_flow_admission_authorization_baseline",
                "supervisor_flow_admission_authorization_decisions",
                "supervisor_flow_admission_authorization_action_receipts",
                "supervisor_attempt_claim_authorization_baseline",
                "supervisor_attempt_claim_authorization_decisions",
                "supervisor_attempt_claim_authorization_action_receipts",
            )
            for row in connection.execute(f'PRAGMA foreign_key_check("{table}")')
        )
        if foreign_key_errors:
            raise ValidationError("supervisor history has invalid references")
        specs_by_flow: dict[str, FlowSpec] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall():
            spec = _flow_from_row(row)
            _validate_flow_spec(spec)
            if row["request_digest"] != spec.request_digest:
                raise ValidationError("flow request digest is invalid")
            specs_by_flow[spec.flow_id] = spec
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
        for attempt_row in attempt_rows:
            attempt = _attempt_from_row(attempt_row)
            spec = specs_by_flow.get(attempt.flow_id)
            if spec is None:
                raise ValidationError("attempt flow is missing")
            events = _verify_attempt_claim_history(
                attempt=attempt,
                spec=spec,
                revision_rows=revision_rows_by_flow.get(attempt.flow_id, []),
                event_rows=event_rows_by_attempt.get(attempt.attempt_id, []),
            )
            _verify_pre_dispatch_intent_history(
                attempt=attempt,
                revision_rows=revision_rows_by_flow[attempt.flow_id],
                events=events,
            )
    except (
        ConfigurationError,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
        sqlite3.Error,
    ) as error:
        raise ConfigurationError(
            "pre-v8 supervisor pre-dispatch intent history is invalid"
        ) from error


def _verify_pre_v9_pre_dispatch_intent_history(
    connection: sqlite3.Connection,
) -> None:
    """Refuse to baseline malformed v8 pre-dispatch source references."""

    try:
        _verify_pre_v8_pre_dispatch_intent_history(connection)
        foreign_key_errors = tuple(
            row
            for table in (
                "supervisor_pre_dispatch_intent_authorization_baseline",
                "supervisor_pre_dispatch_intent_authorization_observations",
            )
            for row in connection.execute(f'PRAGMA foreign_key_check("{table}")')
        )
        if foreign_key_errors:
            raise ValidationError(
                "supervisor pre-dispatch shadow has invalid references"
            )
    except (ConfigurationError, ValidationError, sqlite3.Error) as error:
        raise ConfigurationError(
            "pre-v9 supervisor pre-dispatch intent history is invalid"
        ) from error


def _verify_pre_v10_attempt_completion_history(
    connection: sqlite3.Connection,
) -> None:
    """Refuse to baseline malformed durable local completion history."""

    try:
        _verify_pre_v9_pre_dispatch_intent_history(connection)
        foreign_key_errors = tuple(
            row
            for table in (
                "supervisor_pre_dispatch_intent_authorization_enforcement_baseline",
                "supervisor_pre_dispatch_intent_authorization_decisions",
                "supervisor_pre_dispatch_intent_authorization_action_receipts",
            )
            for row in connection.execute(f'PRAGMA foreign_key_check("{table}")')
        )
        if foreign_key_errors:
            raise ValidationError(
                "supervisor pre-dispatch enforcement has invalid references"
            )
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        flow_rows_by_id = {row["flow_id"]: row for row in flow_rows}
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_rows_by_id = {row["attempt_id"]: row for row in attempt_rows}
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
        for outbox_row in connection.execute(
            """
            SELECT * FROM supervisor_completion_outbox
            WHERE attempt_id IS NOT NULL AND operation_digest != intent_digest
            ORDER BY flow_id, source_revision, outbox_id
            """
        ).fetchall():
            _attempt_completion_source_from_outbox(
                outbox_row=outbox_row,
                flow_rows_by_id=flow_rows_by_id,
                revision_rows_by_flow=revision_rows_by_flow,
                attempt_rows_by_id=attempt_rows_by_id,
                event_rows_by_attempt=event_rows_by_attempt,
                attempt_flow_ids=attempt_flow_ids,
            )
    except (
        ConfigurationError,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
        sqlite3.Error,
    ) as error:
        raise ConfigurationError(
            "pre-v10 supervisor attempt completion history is invalid"
        ) from error


def _verify_pre_v11_pre_dispatch_reconciliation_history(
    connection: sqlite3.Connection,
) -> None:
    """Refuse to baseline malformed expired pre-dispatch repair history."""

    try:
        _verify_pre_v10_attempt_completion_history(connection)
        foreign_key_errors = tuple(
            row
            for table in (
                "supervisor_attempt_completion_authorization_baseline",
                "supervisor_attempt_completion_authorization_observations",
            )
            for row in connection.execute(f'PRAGMA foreign_key_check("{table}")')
        )
        if foreign_key_errors:
            raise ValidationError(
                "supervisor attempt completion shadow has invalid references"
            )
        flow_rows = connection.execute(
            "SELECT * FROM supervisor_flows ORDER BY flow_id"
        ).fetchall()
        flow_rows_by_id = {row["flow_id"]: row for row in flow_rows}
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_rows = connection.execute(
            "SELECT * FROM supervisor_attempts ORDER BY flow_id, attempt_number"
        ).fetchall()
        attempt_rows_by_id = {row["attempt_id"]: row for row in attempt_rows}
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"] for row in attempt_rows
        }
        event_rows_by_attempt: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_attempt_events ORDER BY attempt_id, revision"
        ).fetchall():
            event_rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
        for outbox_row in connection.execute(
            """
            SELECT * FROM supervisor_completion_outbox
            WHERE attempt_id IS NOT NULL AND operation_digest = intent_digest
            ORDER BY flow_id, source_revision, outbox_id
            """
        ).fetchall():
            _pre_dispatch_reconciliation_source_from_outbox(
                outbox_row=outbox_row,
                flow_rows_by_id=flow_rows_by_id,
                revision_rows_by_flow=revision_rows_by_flow,
                attempt_rows_by_id=attempt_rows_by_id,
                event_rows_by_attempt=event_rows_by_attempt,
                attempt_flow_ids=attempt_flow_ids,
            )
    except (
        ConfigurationError,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
        sqlite3.Error,
    ) as error:
        raise ConfigurationError(
            "pre-v11 supervisor pre-dispatch reconciliation history is invalid"
        ) from error


def _verify_attempt_claim_history(
    *,
    attempt: AttemptRecord,
    spec: FlowSpec,
    revision_rows: Sequence[sqlite3.Row],
    event_rows: Sequence[sqlite3.Row],
) -> tuple[AttemptEvent, ...]:
    """Validate one durable claim against its local flow and event lineage."""

    for name in ("attempt_id", "flow_id", "run_id", "lease_owner"):
        _validate_text(getattr(attempt, name), name, maximum=256)
    _validate_revision(attempt.attempt_number)
    if attempt.attempt_number > spec.max_attempts:
        raise ValidationError("attempt number exceeds its flow budget")
    _validate_revision(attempt.claimed_revision)
    _validate_digest(attempt.input_digest, "attempt input digest")
    _timestamp(attempt.deadline_at, "attempt deadline")
    _timestamp(attempt.created_at, "attempt claim timestamp")
    if attempt.flow_id != spec.flow_id or attempt.created_at < spec.available_at:
        raise ValidationError("attempt does not match its flow")
    expected_lease_keys = tuple(
        sorted({f"flow:{spec.flow_id}", *spec.resource_keys})
    )
    if attempt.lease_keys != expected_lease_keys:
        raise ValidationError("attempt lease keys do not match its flow")
    expected_deadline = min(
        attempt.created_at + spec.attempt_timeout_seconds,
        (
            spec.deadline_at
            if spec.deadline_at is not None
            else attempt.created_at + spec.attempt_timeout_seconds
        ),
    )
    if attempt.deadline_at != expected_deadline or attempt.deadline_at <= attempt.created_at:
        raise ValidationError("attempt deadline does not match its flow")
    if attempt.claimed_revision >= len(revision_rows):
        raise ValidationError("attempt claim has no resulting flow revision")
    source = _flow_revision_from_row(revision_rows[attempt.claimed_revision - 1])
    target = _flow_revision_from_row(revision_rows[attempt.claimed_revision])
    if (
        source.revision != attempt.claimed_revision
        or source.state is not FlowState.QUEUED
        or source.cancellation_requested
        or source.active_attempt_id is not None
        or target.revision != attempt.claimed_revision + 1
        or target.state is not FlowState.RUNNING
        or target.cancellation_requested
        or target.active_attempt_id != attempt.attempt_id
        or target.reason_code != "attempt_claimed"
        or target.occurred_at != attempt.created_at
    ):
        raise ValidationError("attempt claim flow transition is invalid")
    events: list[AttemptEvent] = []
    previous: AttemptEvent | None = None
    for expected_revision, row in enumerate(event_rows, start=1):
        event = _attempt_event_from_row(row)
        _validate_text(event.event_id, "attempt event identifier", maximum=256)
        _validate_reason(event.reason_code)
        _timestamp(event.occurred_at, "attempt event timestamp")
        if (
            event.attempt_id != attempt.attempt_id
            or event.revision != expected_revision
            or (previous is None and event.state is not AttemptState.CREATED)
            or (
                previous is not None
                and event.state not in _ATTEMPT_TRANSITIONS[previous.state]
            )
        ):
            raise ValidationError("attempt event history is invalid")
        if (
            previous is None
            and (
                event.reason_code != "claim_created"
                or event.occurred_at != attempt.created_at
            )
        ):
            raise ValidationError("attempt initial event is invalid")
        events.append(event)
        previous = event
    if not events:
        raise ValidationError("attempt event history is missing")
    return tuple(events)


def _verify_pre_dispatch_intent_history(
    *,
    attempt: AttemptRecord,
    revision_rows: Sequence[sqlite3.Row],
    events: Sequence[AttemptEvent],
) -> tuple[AttemptEvent, ...]:
    """Validate the narrow durable history that can yield a dispatch intent.

    The check establishes only a local ``dispatching`` state transition. It
    does not infer a worker launch, process invocation, or external effect.
    """

    if attempt.claimed_revision >= len(revision_rows):
        raise ValidationError("pre-dispatch source flow is missing")
    source_flow = _flow_revision_from_row(revision_rows[attempt.claimed_revision])
    if (
        source_flow.flow_id != attempt.flow_id
        or source_flow.revision != attempt.claimed_revision + 1
        or source_flow.state is not FlowState.RUNNING
        or source_flow.cancellation_requested
        or source_flow.active_attempt_id != attempt.attempt_id
        or source_flow.reason_code != "attempt_claimed"
        or source_flow.occurred_at != attempt.created_at
    ):
        raise ValidationError("pre-dispatch source flow is invalid")
    targets: list[AttemptEvent] = []
    for index, event in enumerate(events):
        if event.state is not AttemptState.DISPATCHING:
            continue
        source = events[index - 1] if index else None
        if (
            source is None
            or event.revision != 2
            or source.revision != 1
            or source.state is not AttemptState.CREATED
            or source.reason_code != "claim_created"
            or source.occurred_at != attempt.created_at
            or event.reason_code != "dispatch_intent_recorded"
            or event.occurred_at < source.occurred_at
            or event.occurred_at >= attempt.deadline_at
        ):
            raise ValidationError("pre-dispatch intent transition is invalid")
        targets.append(event)
    if len(targets) > 1:
        raise ValidationError("attempt has multiple pre-dispatch intents")
    return tuple(targets)


def _verify_pre_v4_bookkeeping_history(connection: sqlite3.Connection) -> None:
    foreign_key_tables = (
        "supervisor_attempt_events",
        "supervisor_attempts",
        "supervisor_authorization_observations",
        "supervisor_cancellation_requests",
        "supervisor_completion_delivery_events",
        "supervisor_completion_outbox",
        "supervisor_completion_receipts",
        "supervisor_flow_revisions",
    )
    try:
        foreign_key_errors = tuple(
            row
            for table in foreign_key_tables
            for row in connection.execute(
                f'PRAGMA foreign_key_check("{table}")'
            ).fetchall()
        )
    except sqlite3.Error as error:
        raise ConfigurationError(
            "pre-v4 supervisor bookkeeping history has invalid references"
        ) from error
    if foreign_key_errors:
        raise ConfigurationError(
            "pre-v4 supervisor bookkeeping history has invalid references"
        )
    previous = _initial_control_revision()
    try:
        control_rows = connection.execute(
            "SELECT * FROM supervisor_control_events ORDER BY revision"
        ).fetchall()
        for expected_revision, row in enumerate(control_rows, start=1):
            control = _control_from_row(row)
            _validate_text(control.event_id, "control event identifier", maximum=256)
            _validate_text(control.actor_id, "control actor identifier", maximum=256)
            _validate_reason(control.reason_code)
            _timestamp(control.occurred_at, "control event timestamp")
            if (
                control.revision != expected_revision
                or control.mode not in _CONTROL_TRANSITIONS[previous.mode]
            ):
                raise ValidationError("control history is not contiguous and valid")
            previous = control
        cancellation_rows = connection.execute(
            "SELECT * FROM supervisor_cancellation_requests"
        ).fetchall()
        revision_rows_by_flow: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM supervisor_flow_revisions ORDER BY flow_id, revision"
        ).fetchall():
            revision_rows_by_flow.setdefault(row["flow_id"], []).append(row)
        attempt_flow_ids = {
            row["attempt_id"]: row["flow_id"]
            for row in connection.execute(
                "SELECT attempt_id, flow_id FROM supervisor_attempts"
            ).fetchall()
        }
        for row in cancellation_rows:
            _validate_text(row["request_id"], "cancellation request identifier")
            _validate_text(row["flow_id"], "flow identifier", maximum=256)
            _validate_reason(row["reason_code"])
            _validate_text(row["requested_by"], "requested_by", maximum=256)
            _timestamp(row["requested_at"], "cancellation request timestamp")
            head = _verify_flow_revision_lineage(
                row["flow_id"],
                revision_rows_by_flow.get(row["flow_id"], []),
                attempt_flow_ids,
            )
            if head.cancellation_requested:
                if head.state not in {FlowState.RUNNING, FlowState.CANCELLED}:
                    raise ValidationError(
                        "cancelled flow has an invalid current state"
                    )
            elif (
                head.state not in _FINAL_FLOW_STATES
                or row["requested_at"] < head.occurred_at
            ):
                raise ValidationError(
                    "cancellation request is not reflected in flow state"
                )
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        raise ConfigurationError(
            "pre-v4 supervisor bookkeeping history is invalid"
        ) from error


def _verify_flow_revision_lineage(
    flow_id: str,
    rows: Sequence[sqlite3.Row],
    attempt_flow_ids: Mapping[str, str],
) -> FlowRevision:
    if not rows:
        raise ValidationError("flow revision history is missing")
    previous: FlowRevision | None = None
    for expected_revision, row in enumerate(rows, start=1):
        revision = _flow_revision_from_row(row)
        _validate_text(revision.event_id, "flow event identifier", maximum=256)
        _validate_reason(revision.reason_code)
        _timestamp(revision.occurred_at, "flow event timestamp")
        if revision.flow_id != flow_id or revision.revision != expected_revision:
            raise ValidationError("flow revision history is not contiguous")
        if revision.active_attempt_id is not None:
            _validate_text(
                revision.active_attempt_id,
                "active attempt identifier",
                maximum=256,
            )
            if attempt_flow_ids.get(revision.active_attempt_id) != flow_id:
                raise ValidationError("active attempt does not belong to the flow")
        if previous is None:
            if (
                revision.state is not FlowState.QUEUED
                or revision.cancellation_requested
                or revision.active_attempt_id is not None
            ):
                raise ValidationError("initial flow revision is invalid")
        else:
            regular_transition = revision.state in _FLOW_TRANSITIONS[previous.state]
            running_cancellation = (
                previous.state is FlowState.RUNNING
                and revision.state is FlowState.RUNNING
                and not previous.cancellation_requested
                and revision.cancellation_requested
                and revision.active_attempt_id == previous.active_attempt_id
            )
            if not regular_transition and not running_cancellation:
                raise ValidationError("flow revision transition is invalid")
            if previous.cancellation_requested and not revision.cancellation_requested:
                raise ValidationError("flow cancellation is not sticky")
            cancellation_became_requested = (
                not previous.cancellation_requested
                and revision.cancellation_requested
            )
            valid_terminal_cancellation = (
                revision.state is FlowState.CANCELLED
                and previous.state is not FlowState.RUNNING
            )
            if (
                cancellation_became_requested
                and not running_cancellation
                and not valid_terminal_cancellation
            ):
                raise ValidationError("flow cancellation transition is invalid")
        if (revision.state is FlowState.RUNNING) != (
            revision.active_attempt_id is not None
        ):
            raise ValidationError("flow active-attempt shape is invalid")
        previous = revision
    if previous is None:
        raise ValidationError("flow revision history is missing")
    return previous


@cache
def _expected_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            _SCHEMA_V2
            + "\n"
            + _SCHEMA_V3
            + "\n"
            + _SCHEMA_V4
            + "\n"
            + _SCHEMA_V5
            + "\n"
            + _SCHEMA_V6
            + "\n"
            + _SCHEMA_V7
            + "\n"
            + _SCHEMA_V8
            + "\n"
            + _SCHEMA_V9
            + "\n"
            + _SCHEMA_V10
            + "\n"
            + _SCHEMA_V11
        )
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v4_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_SCHEMA_V2 + "\n" + _SCHEMA_V3)
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v5_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_SCHEMA_V2 + "\n" + _SCHEMA_V3 + "\n" + _SCHEMA_V4)
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v6_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            _SCHEMA_V2 + "\n" + _SCHEMA_V3 + "\n" + _SCHEMA_V4 + "\n" + _SCHEMA_V5
        )
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v7_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            _SCHEMA_V2
            + "\n"
            + _SCHEMA_V3
            + "\n"
            + _SCHEMA_V4
            + "\n"
            + _SCHEMA_V5
            + "\n"
            + _SCHEMA_V6
        )
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v8_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            _SCHEMA_V2
            + "\n"
            + _SCHEMA_V3
            + "\n"
            + _SCHEMA_V4
            + "\n"
            + _SCHEMA_V5
            + "\n"
            + _SCHEMA_V6
            + "\n"
            + _SCHEMA_V7
        )
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v9_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            _SCHEMA_V2
            + "\n"
            + _SCHEMA_V3
            + "\n"
            + _SCHEMA_V4
            + "\n"
            + _SCHEMA_V5
            + "\n"
            + _SCHEMA_V6
            + "\n"
            + _SCHEMA_V7
            + "\n"
            + _SCHEMA_V8
        )
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v10_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            _SCHEMA_V2
            + "\n"
            + _SCHEMA_V3
            + "\n"
            + _SCHEMA_V4
            + "\n"
            + _SCHEMA_V5
            + "\n"
            + _SCHEMA_V6
            + "\n"
            + _SCHEMA_V7
            + "\n"
            + _SCHEMA_V8
            + "\n"
            + _SCHEMA_V9
        )
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


@cache
def _expected_pre_v11_supervisor_schema() -> dict[
    tuple[str, str], tuple[str, str, str]
]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            _SCHEMA_V2
            + "\n"
            + _SCHEMA_V3
            + "\n"
            + _SCHEMA_V4
            + "\n"
            + _SCHEMA_V5
            + "\n"
            + _SCHEMA_V6
            + "\n"
            + _SCHEMA_V7
            + "\n"
            + _SCHEMA_V8
            + "\n"
            + _SCHEMA_V9
            + "\n"
            + _SCHEMA_V10
        )
        objects = _schema_objects(connection)
        return {
            key: value
            for key, value in objects.items()
            if key[1].startswith("supervisor_")
            or value[1].startswith("supervisor_")
        }
    finally:
        connection.close()


def _verify_pre_v4_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v4_supervisor_schema():
        raise ConfigurationError("pre-v4 supervisor schema is invalid")


def _verify_pre_v5_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v5_supervisor_schema():
        raise ConfigurationError("pre-v5 supervisor schema is invalid")


def _verify_pre_v6_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v6_supervisor_schema():
        raise ConfigurationError("pre-v6 supervisor schema is invalid")


def _verify_pre_v7_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v7_supervisor_schema():
        raise ConfigurationError("pre-v7 supervisor schema is invalid")


def _verify_pre_v8_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v8_supervisor_schema():
        raise ConfigurationError("pre-v8 supervisor schema is invalid")


def _verify_pre_v9_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v9_supervisor_schema():
        raise ConfigurationError("pre-v9 supervisor schema is invalid")


def _verify_pre_v10_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v10_supervisor_schema():
        raise ConfigurationError("pre-v10 supervisor schema is invalid")


def _verify_pre_v11_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_pre_v11_supervisor_schema():
        raise ConfigurationError("pre-v11 supervisor schema is invalid")


def _verify_supervisor_schema(connection: sqlite3.Connection) -> None:
    objects = _schema_objects(connection)
    actual = {
        key: value
        for key, value in objects.items()
        if key[1].startswith("supervisor_")
        or value[1].startswith("supervisor_")
    }
    if actual != _expected_supervisor_schema():
        raise ConfigurationError("supervisor schema objects do not match migrations")


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


def _control_authorization_mapping(
    control: SupervisorControlRevision,
) -> dict[str, Any]:
    return {
        "event_id": control.event_id,
        "revision": control.revision,
        "mode": control.mode.value,
        "actor_ref": canonical_digest({"actor_id": control.actor_id}),
        "reason_code": control.reason_code,
        "occurred_at": control.occurred_at,
    }


def _flow_revision_authorization_mapping(
    revision: FlowRevision,
) -> dict[str, Any]:
    return {
        "event_id": revision.event_id,
        "flow_id_ref": canonical_digest({"flow_id": revision.flow_id}),
        "revision": revision.revision,
        "state": revision.state.value,
        "cancellation_requested": revision.cancellation_requested,
        "active_attempt_ref": (
            None
            if revision.active_attempt_id is None
            else canonical_digest({"attempt_id": revision.active_attempt_id})
        ),
        "reason_code": revision.reason_code,
        "occurred_at": revision.occurred_at,
    }


def _cancellation_effect_mapping(revision: FlowRevision) -> dict[str, Any]:
    is_final = revision.state in _FINAL_FLOW_STATES
    target_state = (
        revision.state
        if is_final or revision.state is FlowState.RUNNING
        else FlowState.CANCELLED
    )
    return {
        "cancellation_request_appended": True,
        "flow_revision_appended": not is_final,
        "target_revision": revision.revision if is_final else revision.revision + 1,
        "target_state": target_state.value,
        "target_cancellation_requested": (
            revision.cancellation_requested if is_final else True
        ),
        "completion_intent_appended": (
            not is_final and revision.state is not FlowState.RUNNING
        ),
    }


def _pre_dispatch_intent_lease_snapshot(
    connection: sqlite3.Connection,
    *,
    attempt: AttemptRecord,
    observed_at: float,
) -> tuple[dict[str, Any], ...]:
    """Capture only digest-bound lease facts needed for a shadow replay."""

    snapshot: list[dict[str, Any]] = []
    for lease_key in attempt.lease_keys:
        row = connection.execute(
            """
            SELECT owner_id, acquired_at, renewed_at, expires_at
            FROM leases WHERE lease_key = ?
            """,
            (lease_key,),
        ).fetchone()
        if row is None:
            raise ValidationError("pre-dispatch lease source is missing")
        snapshot.append(
            {
                "lease_key_ref": canonical_digest({"lease_key": lease_key}),
                "lease_owner_ref": canonical_digest(
                    {"lease_owner": row["owner_id"]}
                ),
                "acquired_at": float(row["acquired_at"]),
                "renewed_at": float(row["renewed_at"]),
                "expires_at": float(row["expires_at"]),
            }
        )
    return _validate_pre_dispatch_intent_lease_snapshot(
        snapshot,
        attempt=attempt,
        observed_at=observed_at,
    )


def _validate_pre_dispatch_intent_lease_snapshot(
    snapshot: object,
    *,
    attempt: AttemptRecord,
    observed_at: float,
) -> tuple[dict[str, Any], ...]:
    """Validate a privacy-safe snapshot against immutable claim inputs."""

    timestamp = _timestamp(observed_at, "pre-dispatch observation timestamp")
    if type(snapshot) not in {list, tuple}:
        raise ValidationError("pre-dispatch lease snapshot is invalid")
    expected_keys = tuple(attempt.lease_keys)
    if len(snapshot) != len(expected_keys):
        raise ValidationError("pre-dispatch lease snapshot is incomplete")
    expected_owner_ref = canonical_digest({"lease_owner": attempt.lease_owner})
    normalized: list[dict[str, Any]] = []
    for lease_key, item in zip(expected_keys, snapshot, strict=True):
        if type(item) is not dict or set(item) != {
            "lease_key_ref",
            "lease_owner_ref",
            "acquired_at",
            "renewed_at",
            "expires_at",
        }:
            raise ValidationError("pre-dispatch lease snapshot is invalid")
        if (
            item["lease_key_ref"]
            != canonical_digest({"lease_key": lease_key})
            or item["lease_owner_ref"] != expected_owner_ref
        ):
            raise ValidationError("pre-dispatch lease snapshot does not match claim")
        acquired_at = _timestamp(
            item["acquired_at"], "pre-dispatch lease acquisition timestamp"
        )
        renewed_at = _timestamp(
            item["renewed_at"], "pre-dispatch lease renewal timestamp"
        )
        expires_at = _timestamp(
            item["expires_at"], "pre-dispatch lease expiry timestamp"
        )
        if not (
            acquired_at <= renewed_at <= timestamp < expires_at <= attempt.deadline_at
        ):
            raise ValidationError("pre-dispatch lease snapshot is not active")
        normalized.append(
            {
                "lease_key_ref": item["lease_key_ref"],
                "lease_owner_ref": item["lease_owner_ref"],
                "acquired_at": acquired_at,
                "renewed_at": renewed_at,
                "expires_at": expires_at,
            }
        )
    return tuple(normalized)


def _pre_dispatch_reconciliation_lease_snapshot(
    connection: sqlite3.Connection,
    *,
    attempt: AttemptRecord,
    observed_at: float,
) -> tuple[dict[str, Any], ...]:
    """Capture redacted evidence explaining why a pre-dispatch claim expired."""

    timestamp = _timestamp(
        observed_at,
        "pre-dispatch reconciliation observation timestamp",
    )
    snapshot: list[dict[str, Any]] = []
    expected_owner_ref = canonical_digest({"lease_owner": attempt.lease_owner})
    for lease_key in attempt.lease_keys:
        row = connection.execute(
            """
            SELECT owner_id, acquired_at, renewed_at, expires_at
            FROM leases WHERE lease_key = ?
            """,
            (lease_key,),
        ).fetchone()
        item: dict[str, Any] = {
            "lease_key_ref": canonical_digest({"lease_key": lease_key}),
        }
        if row is None:
            item["lease_state"] = "missing"
        else:
            owner_ref = canonical_digest({"lease_owner": row["owner_id"]})
            item.update(
                {
                    "lease_state": (
                        "owned_active"
                        if owner_ref == expected_owner_ref
                        and float(row["expires_at"]) > timestamp
                        else (
                            "owned_expired"
                            if owner_ref == expected_owner_ref
                            else "foreign"
                        )
                    ),
                    "lease_owner_ref": owner_ref,
                    "acquired_at": float(row["acquired_at"]),
                    "renewed_at": float(row["renewed_at"]),
                    "expires_at": float(row["expires_at"]),
                }
            )
        snapshot.append(item)
    return _validate_pre_dispatch_reconciliation_lease_snapshot(
        snapshot,
        attempt=attempt,
        observed_at=timestamp,
    )


def _validate_pre_dispatch_reconciliation_lease_snapshot(
    snapshot: object,
    *,
    attempt: AttemptRecord,
    observed_at: float,
) -> tuple[dict[str, Any], ...]:
    """Validate redacted, possibly expired pre-dispatch lease evidence."""

    timestamp = _timestamp(
        observed_at,
        "pre-dispatch reconciliation observation timestamp",
    )
    if type(snapshot) not in {list, tuple}:
        raise ValidationError("pre-dispatch reconciliation lease snapshot is invalid")
    expected_keys = tuple(attempt.lease_keys)
    if len(snapshot) != len(expected_keys):
        raise ValidationError(
            "pre-dispatch reconciliation lease snapshot is incomplete"
        )
    expected_owner_ref = canonical_digest({"lease_owner": attempt.lease_owner})
    normalized: list[dict[str, Any]] = []
    inactive_seen = False
    for lease_key, item in zip(expected_keys, snapshot, strict=True):
        if type(item) is not dict:
            raise ValidationError("pre-dispatch reconciliation lease snapshot is invalid")
        if item.get("lease_key_ref") != canonical_digest({"lease_key": lease_key}):
            raise ValidationError(
                "pre-dispatch reconciliation lease snapshot does not match claim"
            )
        state = item.get("lease_state")
        if state == "missing":
            if set(item) != {"lease_key_ref", "lease_state"}:
                raise ValidationError(
                    "pre-dispatch reconciliation lease snapshot is invalid"
                )
            inactive_seen = True
            normalized.append(
                {
                    "lease_key_ref": item["lease_key_ref"],
                    "lease_state": state,
                }
            )
            continue
        if state not in {"owned_active", "owned_expired", "foreign"} or set(
            item
        ) != {
            "lease_key_ref",
            "lease_state",
            "lease_owner_ref",
            "acquired_at",
            "renewed_at",
            "expires_at",
        }:
            raise ValidationError("pre-dispatch reconciliation lease snapshot is invalid")
        owner_ref = item["lease_owner_ref"]
        if not isinstance(owner_ref, str) or len(owner_ref) != 71:
            raise ValidationError("pre-dispatch reconciliation lease owner is invalid")
        acquired_at = _timestamp(
            item["acquired_at"],
            "pre-dispatch reconciliation lease acquisition timestamp",
        )
        renewed_at = _timestamp(
            item["renewed_at"],
            "pre-dispatch reconciliation lease renewal timestamp",
        )
        expires_at = _timestamp(
            item["expires_at"],
            "pre-dispatch reconciliation lease expiry timestamp",
        )
        if not acquired_at <= renewed_at <= expires_at:
            raise ValidationError("pre-dispatch reconciliation lease timing is invalid")
        if state == "foreign":
            if owner_ref == expected_owner_ref:
                raise ValidationError(
                    "pre-dispatch reconciliation foreign lease is invalid"
                )
            inactive_seen = True
        else:
            if owner_ref != expected_owner_ref:
                raise ValidationError(
                    "pre-dispatch reconciliation lease owner is invalid"
                )
            if expires_at > attempt.deadline_at:
                raise ValidationError(
                    "pre-dispatch reconciliation lease exceeds claim deadline"
                )
            if state == "owned_active":
                if timestamp >= expires_at:
                    raise ValidationError(
                        "pre-dispatch reconciliation lease state is invalid"
                    )
            else:
                if timestamp < expires_at:
                    raise ValidationError(
                        "pre-dispatch reconciliation lease state is invalid"
                    )
                inactive_seen = True
        normalized.append(
            {
                "lease_key_ref": item["lease_key_ref"],
                "lease_state": state,
                "lease_owner_ref": owner_ref,
                "acquired_at": acquired_at,
                "renewed_at": renewed_at,
                "expires_at": expires_at,
            }
        )
    if not inactive_seen:
        raise ValidationError("pre-dispatch reconciliation claim is still active")
    return tuple(normalized)


def _pre_dispatch_intent_mapping(
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_attempt: AttemptEvent,
    lease_snapshot: object,
    observed_at: float,
) -> dict[str, Any]:
    """Build the exact redacted source/target mapping for one local intent."""

    _validate_flow_spec(spec)
    for field_name in ("attempt_id", "flow_id", "run_id", "lease_owner"):
        _validate_text(getattr(attempt, field_name), field_name, maximum=256)
    _validate_revision(attempt.attempt_number)
    _validate_revision(attempt.claimed_revision)
    _validate_digest(attempt.input_digest, "attempt input digest")
    attempt_created_at = _timestamp(attempt.created_at, "attempt claim timestamp")
    deadline_at = _timestamp(attempt.deadline_at, "attempt deadline")
    if (
        attempt.flow_id != spec.flow_id
        or not 1 <= attempt.attempt_number <= spec.max_attempts
        or attempt.lease_keys
        != tuple(sorted({f"flow:{spec.flow_id}", *spec.resource_keys}))
    ):
        raise ValidationError("pre-dispatch attempt source is invalid")
    expected_deadline = min(
        attempt_created_at + spec.attempt_timeout_seconds,
        (
            spec.deadline_at
            if spec.deadline_at is not None
            else attempt_created_at + spec.attempt_timeout_seconds
        ),
    )
    if deadline_at != expected_deadline or deadline_at <= attempt_created_at:
        raise ValidationError("pre-dispatch attempt deadline is invalid")
    for event in (source_attempt, target_attempt):
        _validate_text(event.event_id, "attempt event identifier", maximum=256)
        _validate_text(event.attempt_id, "attempt identifier", maximum=256)
        _validate_revision(event.revision)
        _validate_reason(event.reason_code)
        _timestamp(event.occurred_at, "attempt event timestamp")
    for field_name in ("event_id", "flow_id"):
        _validate_text(
            getattr(source_flow, field_name),
            f"source flow {field_name}",
            maximum=256,
        )
    _validate_revision(source_flow.revision)
    _validate_reason(source_flow.reason_code)
    source_flow_time = _timestamp(
        source_flow.occurred_at, "source flow timestamp"
    )
    timestamp = _timestamp(observed_at, "pre-dispatch observation timestamp")
    if (
        source_flow.flow_id != attempt.flow_id
        or source_flow.revision != attempt.claimed_revision + 1
        or source_flow.state is not FlowState.RUNNING
        or source_flow.cancellation_requested
        or source_flow.active_attempt_id != attempt.attempt_id
        or source_flow.reason_code != "attempt_claimed"
        or source_flow_time != attempt_created_at
        or source_attempt.attempt_id != attempt.attempt_id
        or source_attempt.revision != 1
        or source_attempt.state is not AttemptState.CREATED
        or source_attempt.reason_code != "claim_created"
        or source_attempt.occurred_at != attempt_created_at
        or target_attempt.attempt_id != attempt.attempt_id
        or target_attempt.revision != source_attempt.revision + 1
        or target_attempt.state is not AttemptState.DISPATCHING
        or target_attempt.reason_code != "dispatch_intent_recorded"
        or target_attempt.occurred_at != timestamp
        or target_attempt.occurred_at < source_attempt.occurred_at
        or target_attempt.occurred_at >= deadline_at
    ):
        raise ValidationError("pre-dispatch intent source or target is invalid")
    leases = _validate_pre_dispatch_intent_lease_snapshot(
        lease_snapshot,
        attempt=attempt,
        observed_at=timestamp,
    )
    attempt_id_ref = canonical_digest({"attempt_id": attempt.attempt_id})
    return {
        "source": {
            "flow_id_ref": canonical_digest({"flow_id": attempt.flow_id}),
            "flow_event_ref": canonical_digest(
                {"flow_event_id": source_flow.event_id}
            ),
            "flow_revision": source_flow.revision,
            "flow_state": source_flow.state.value,
            "cancellation_requested": False,
            "active_attempt_ref": attempt_id_ref,
            "attempt_id_ref": attempt_id_ref,
            "run_id_ref": canonical_digest({"run_id": attempt.run_id}),
            "attempt_event_ref": canonical_digest(
                {"attempt_event_id": source_attempt.event_id}
            ),
            "attempt_revision": source_attempt.revision,
            "attempt_state": source_attempt.state.value,
            "attempt_reason_code": source_attempt.reason_code,
            "attempt_occurred_at": float(source_attempt.occurred_at),
            "flow_request_digest": spec.request_digest,
            "input_digest": attempt.input_digest,
            "lease_owner_ref": canonical_digest(
                {"lease_owner": attempt.lease_owner}
            ),
            "lease_keys_digest": canonical_digest(
                {"lease_keys": list(attempt.lease_keys)}
            ),
            "lease_snapshot": [dict(item) for item in leases],
            "lease_snapshot_digest": canonical_digest({"leases": list(leases)}),
            "deadline_at": float(deadline_at),
        },
        "target": {
            "attempt_id_ref": attempt_id_ref,
            "attempt_event_ref": canonical_digest(
                {"attempt_event_id": target_attempt.event_id}
            ),
            "attempt_revision": target_attempt.revision,
            "attempt_state": target_attempt.state.value,
            "attempt_reason_code": target_attempt.reason_code,
            "attempt_occurred_at": float(target_attempt.occurred_at),
        },
    }


def _supervisor_pre_dispatch_intent_authorization_request(
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_attempt: AttemptEvent,
    lease_snapshot: object,
    observed_at: float,
) -> tuple[AuthorizationRequest, PolicyBundle, dict[str, Any]]:
    """Build a fixed shadow-only ABAC request for local intent bookkeeping."""

    intent = _pre_dispatch_intent_mapping(
        spec=spec,
        attempt=attempt,
        source_flow=source_flow,
        source_attempt=source_attempt,
        target_attempt=target_attempt,
        lease_snapshot=lease_snapshot,
        observed_at=observed_at,
    )
    timestamp = _timestamp(observed_at, "pre-dispatch observation timestamp")
    request = AuthorizationRequest(
        request_id=(
            f"supervisor:{_PRE_DISPATCH_INTENT_BOUNDARY}:"
            f"{canonical_digest({'attempt_event_id': target_attempt.event_id})}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="agentops:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest({"profile_id": "controller_bookkeeping"}),
            runner_id="local_non_ai",
            session_id=None,
        ),
        action=ActionAttributes(
            verb=ActionVerb.MODIFY,
            operation=_PRE_DISPATCH_INTENT_OPERATION,
            parameters_digest=canonical_digest(intent),
            intended_effect="append_local_attempt_dispatch_intent_only",
        ),
        resource=ResourceAttributes(
            resource_type="supervisor_attempt",
            identifier=canonical_digest({"attempt_id": attempt.attempt_id}),
            version=canonical_digest(
                {
                    "source_attempt_event_id": source_attempt.event_id,
                    "source_attempt_revision": source_attempt.revision,
                    "source_flow_event_id": source_flow.event_id,
                    "source_flow_revision": source_flow.revision,
                }
            ),
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(
                {
                    "flow_request_digest": spec.request_digest,
                    "source": intent["source"],
                }
            ),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=timestamp,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.LOCAL_NON_AI,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=PaidContinuationProtection.NOT_APPLICABLE,
            circuit_state=CircuitState.CLOSED,
            flow_state=source_flow.state.value,
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
        "resource": EvidenceSource.CONTROLLER,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.CONTROLLER,
    }
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=(
                f"supervisor:{_PRE_DISPATCH_INTENT_BOUNDARY}:{attribute}"
            ),
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id="agentops:controller",
            observed_at=timestamp,
            expires_at=timestamp + 60.0,
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
    base = PolicyBundle.current_stage(issued_at=timestamp)
    policy = PolicyBundle(
        bundle_id=base.bundle_id,
        version=base.version,
        issued_at=base.issued_at,
        evidence_requirements=base.evidence_requirements,
        enabled_classes=base.enabled_classes,
        allowed_verbs=base.allowed_verbs,
        allowed_roles=tuple(dict.fromkeys((*base.allowed_roles, Role.CONTROLLER))),
        allowed_operations=tuple(
            dict.fromkeys((*base.allowed_operations, _PRE_DISPATCH_INTENT_OPERATION))
        ),
        allowed_resource_types=tuple(
            dict.fromkeys((*base.allowed_resource_types, "supervisor_attempt"))
        ),
        allowed_trust_boundaries=tuple(
            dict.fromkeys((*base.allowed_trust_boundaries, "local_control_plane"))
        ),
        allowed_flow_states=tuple(
            dict.fromkeys((*base.allowed_flow_states, source_flow.state.value))
        ),
        allowed_network_states=base.allowed_network_states,
        allowed_billing_routes=base.allowed_billing_routes,
        approval_requirements=base.approval_requirements,
        decision_ttl_seconds=base.decision_ttl_seconds,
    )
    return request, policy, intent


def _expected_pre_dispatch_intent_observation_values(
    row: sqlite3.Row,
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_attempt: AttemptEvent,
) -> tuple[Any, ...]:
    """Independently rebuild one durable shadow observation from its sources."""

    _validate_text(
        row["observation_id"],
        "pre-dispatch authorization observation identifier",
        maximum=256,
    )
    payload_text = row["payload_json"]
    if (
        not isinstance(payload_text, str)
        or len(payload_text.encode("utf-8")) > _MAX_JSON_BYTES
    ):
        raise ValidationError("pre-dispatch authorization payload is invalid")
    payload = parse_json_document(payload_text)
    if type(payload) is not dict:
        raise ValidationError("pre-dispatch authorization payload is invalid")
    supplied_intent = payload.get("pre_dispatch_intent")
    if type(supplied_intent) is not dict:
        raise ValidationError("pre-dispatch authorization intent is invalid")
    supplied_source = supplied_intent.get("source")
    if type(supplied_source) is not dict:
        raise ValidationError("pre-dispatch authorization source is invalid")
    lease_snapshot = supplied_source.get("lease_snapshot")
    request, policy, intent = _supervisor_pre_dispatch_intent_authorization_request(
        spec=spec,
        attempt=attempt,
        source_flow=source_flow,
        source_attempt=source_attempt,
        target_attempt=target_attempt,
        lease_snapshot=lease_snapshot,
        observed_at=target_attempt.occurred_at,
    )
    decision = _BUILTIN_PRE_DISPATCH_SHADOW_EVALUATE(
        ShadowAuthorizationEvaluator(),
        request,
        policy,
    )
    parity = decision.effect.value == "permit"
    expected_payload = {
        "mode": "shadow",
        "boundary": _PRE_DISPATCH_INTENT_BOUNDARY,
        "action_scope": _PRE_DISPATCH_INTENT_ACTION_SCOPE,
        "pre_dispatch_intent": intent,
        "pre_dispatch_intent_digest": canonical_digest(intent),
        "request": request.to_canonical(),
        "request_digest": request.digest,
        "decision": decision.to_canonical(),
        "decision_digest": decision.digest,
        "legacy_executable": True,
        "execution_parity": parity,
    }
    if payload != expected_payload:
        raise ValidationError("pre-dispatch authorization payload is inconsistent")
    return (
        target_attempt.event_id,
        source_attempt.event_id,
        attempt.attempt_id,
        attempt.flow_id,
        source_flow.event_id,
        source_flow.revision,
        spec.request_digest,
        attempt.input_digest,
        intent["source"]["lease_snapshot_digest"],
        request.digest,
        decision.digest,
        decision.effect.value,
        int(decision.derived_permission_class),
        1,
        int(parity),
        _bounded_json(
            expected_payload,
            "pre-dispatch intent authorization audit payload",
        ),
        float(target_attempt.occurred_at),
    )


def _attempt_completion_lease_snapshot(
    connection: sqlite3.Connection,
    *,
    attempt: AttemptRecord,
    observed_at: float,
) -> tuple[dict[str, Any], ...]:
    """Capture the active claim facts before a completion releases its leases."""

    # The frozen v8 lease shape is already the minimal digest-only active-lease
    # representation. Reusing it prevents this parallel shadow from widening
    # what completion evidence retains.
    return _pre_dispatch_intent_lease_snapshot(
        connection,
        attempt=attempt,
        observed_at=observed_at,
    )


def _attempt_completion_mapping(
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_flow: FlowRevision,
    target_attempt: AttemptEvent,
    completion: CompletionIntent,
    lease_snapshot: object,
    observed_at: float,
) -> dict[str, Any]:
    """Build the exact redacted mapping for one local completion append.

    This is deliberately an effect record, not a reconstruction of the
    caller's requested outcome. Sticky cancellation may replace that requested
    outcome before it is persisted, so the durable selected state and opaque
    operation digest are the only authoritative completion facts.
    """

    _validate_flow_spec(spec)
    for field_name in ("attempt_id", "flow_id", "run_id", "lease_owner"):
        _validate_text(getattr(attempt, field_name), field_name, maximum=256)
    _validate_revision(attempt.attempt_number)
    _validate_revision(attempt.claimed_revision)
    _validate_digest(attempt.input_digest, "attempt input digest")
    attempt_created_at = _timestamp(attempt.created_at, "attempt claim timestamp")
    deadline_at = _timestamp(attempt.deadline_at, "attempt deadline")
    if (
        attempt.flow_id != spec.flow_id
        or not 1 <= attempt.attempt_number <= spec.max_attempts
        or attempt.lease_keys
        != tuple(sorted({f"flow:{spec.flow_id}", *spec.resource_keys}))
    ):
        raise ValidationError("attempt completion source is invalid")
    expected_deadline = min(
        attempt_created_at + spec.attempt_timeout_seconds,
        (
            spec.deadline_at
            if spec.deadline_at is not None
            else attempt_created_at + spec.attempt_timeout_seconds
        ),
    )
    if deadline_at != expected_deadline or deadline_at <= attempt_created_at:
        raise ValidationError("attempt completion deadline is invalid")

    for event in (source_attempt, target_attempt):
        _validate_text(event.event_id, "attempt event identifier", maximum=256)
        _validate_text(event.attempt_id, "attempt identifier", maximum=256)
        _validate_revision(event.revision)
        _validate_reason(event.reason_code)
        _timestamp(event.occurred_at, "attempt event timestamp")
    for flow, description in (
        (source_flow, "source"),
        (target_flow, "target"),
    ):
        for field_name in ("event_id", "flow_id"):
            _validate_text(
                getattr(flow, field_name),
                f"{description} flow {field_name}",
                maximum=256,
            )
        _validate_revision(flow.revision)
        _validate_reason(flow.reason_code)
        _timestamp(flow.occurred_at, f"{description} flow timestamp")
        if type(flow.cancellation_requested) is not bool:
            raise ValidationError("attempt completion cancellation source is invalid")
    timestamp = _timestamp(observed_at, "attempt completion observation timestamp")

    for field_name in ("outbox_id", "idempotency_key", "flow_id"):
        _validate_text(
            getattr(completion, field_name),
            f"completion {field_name}",
            maximum=256,
        )
    _validate_revision(completion.source_revision)
    if completion.attempt_id is None:
        raise ValidationError("attempt completion outbox is missing its attempt")
    _validate_text(completion.attempt_id, "completion attempt identifier", maximum=256)
    for field_name in ("intent_digest", "operation_digest"):
        _validate_digest(
            getattr(completion, field_name),
            f"completion {field_name}",
        )
    completion_created_at = _timestamp(
        completion.created_at,
        "completion outbox timestamp",
    )
    expected_envelope_json = _bounded_json(
        {
            "flow_id": target_flow.flow_id,
            "source_revision": target_flow.revision,
            "state": target_flow.state.value,
            "attempt_id": attempt.attempt_id,
            "reason_code": target_flow.reason_code,
        },
        "attempt completion envelope",
    )
    if (
        source_flow.flow_id != attempt.flow_id
        or source_flow.state is not FlowState.RUNNING
        or source_flow.active_attempt_id != attempt.attempt_id
        or target_flow.flow_id != attempt.flow_id
        or target_flow.revision != source_flow.revision + 1
        or target_flow.state not in _TERMINAL_ATTEMPT_FOR_FLOW
        or target_flow.cancellation_requested
        != source_flow.cancellation_requested
        or target_flow.active_attempt_id is not None
        or target_flow.reason_code != target_attempt.reason_code
        or source_attempt.attempt_id != attempt.attempt_id
        or source_attempt.state
        not in {AttemptState.CREATED, AttemptState.DISPATCHING, AttemptState.RUNNING}
        or target_attempt.attempt_id != attempt.attempt_id
        or target_attempt.revision != source_attempt.revision + 1
        or target_attempt.state
        is not _TERMINAL_ATTEMPT_FOR_FLOW[target_flow.state]
        or target_attempt.state not in _ATTEMPT_TRANSITIONS[source_attempt.state]
        or target_attempt.occurred_at != timestamp
        or target_flow.occurred_at != timestamp
        or completion_created_at != timestamp
        or timestamp < source_flow.occurred_at
        or timestamp < source_attempt.occurred_at
        or timestamp >= deadline_at
        or (
            source_flow.cancellation_requested
            and target_flow.state is not FlowState.CANCELLED
        )
        or completion.flow_id != target_flow.flow_id
        or completion.source_revision != target_flow.revision
        or completion.attempt_id != attempt.attempt_id
        or completion.idempotency_key
        != f"flow:{target_flow.flow_id}:revision:{target_flow.revision}"
        or completion.envelope_json != expected_envelope_json
        or completion.intent_digest != _sha256_text(expected_envelope_json)
        or completion.operation_digest == completion.intent_digest
    ):
        raise ValidationError("attempt completion source or target is invalid")
    leases = _validate_pre_dispatch_intent_lease_snapshot(
        lease_snapshot,
        attempt=attempt,
        observed_at=timestamp,
    )
    attempt_id_ref = canonical_digest({"attempt_id": attempt.attempt_id})
    return {
        "source": {
            "flow_id_ref": canonical_digest({"flow_id": attempt.flow_id}),
            "flow_event_ref": canonical_digest(
                {"flow_event_id": source_flow.event_id}
            ),
            "flow_revision": source_flow.revision,
            "flow_state": source_flow.state.value,
            "flow_reason_code": source_flow.reason_code,
            "cancellation_requested": source_flow.cancellation_requested,
            "active_attempt_ref": attempt_id_ref,
            "attempt_id_ref": attempt_id_ref,
            "run_id_ref": canonical_digest({"run_id": attempt.run_id}),
            "attempt_event_ref": canonical_digest(
                {"attempt_event_id": source_attempt.event_id}
            ),
            "attempt_revision": source_attempt.revision,
            "attempt_state": source_attempt.state.value,
            "attempt_reason_code": source_attempt.reason_code,
            "attempt_occurred_at": float(source_attempt.occurred_at),
            "flow_request_digest": spec.request_digest,
            "input_digest": attempt.input_digest,
            "lease_owner_ref": canonical_digest(
                {"lease_owner": attempt.lease_owner}
            ),
            "lease_keys_digest": canonical_digest(
                {"lease_keys": list(attempt.lease_keys)}
            ),
            "lease_snapshot": [dict(item) for item in leases],
            "lease_snapshot_digest": canonical_digest({"leases": list(leases)}),
            "deadline_at": float(deadline_at),
        },
        "target": {
            "flow_id_ref": canonical_digest({"flow_id": target_flow.flow_id}),
            "flow_event_ref": canonical_digest(
                {"flow_event_id": target_flow.event_id}
            ),
            "flow_revision": target_flow.revision,
            "flow_state": target_flow.state.value,
            "flow_reason_code": target_flow.reason_code,
            "cancellation_requested": target_flow.cancellation_requested,
            "active_attempt_absent": True,
            "attempt_id_ref": attempt_id_ref,
            "attempt_event_ref": canonical_digest(
                {"attempt_event_id": target_attempt.event_id}
            ),
            "attempt_revision": target_attempt.revision,
            "attempt_state": target_attempt.state.value,
            "attempt_reason_code": target_attempt.reason_code,
            "attempt_occurred_at": float(target_attempt.occurred_at),
        },
        "completion": {
            "outbox_ref": canonical_digest({"outbox_id": completion.outbox_id}),
            "idempotency_key_ref": canonical_digest(
                {"idempotency_key": completion.idempotency_key}
            ),
            "source_revision": completion.source_revision,
            "state": target_flow.state.value,
            "attempt_id_ref": attempt_id_ref,
            "intent_digest": completion.intent_digest,
            "operation_digest": completion.operation_digest,
            "created_at": float(completion_created_at),
        },
    }


def _supervisor_attempt_completion_authorization_request(
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_flow: FlowRevision,
    target_attempt: AttemptEvent,
    completion: CompletionIntent,
    lease_snapshot: object,
    observed_at: float,
) -> tuple[AuthorizationRequest, PolicyBundle, dict[str, Any]]:
    """Build a fixed shadow-only request for local completion bookkeeping."""

    intent = _attempt_completion_mapping(
        spec=spec,
        attempt=attempt,
        source_flow=source_flow,
        source_attempt=source_attempt,
        target_flow=target_flow,
        target_attempt=target_attempt,
        completion=completion,
        lease_snapshot=lease_snapshot,
        observed_at=observed_at,
    )
    timestamp = _timestamp(observed_at, "attempt completion observation timestamp")
    request = AuthorizationRequest(
        request_id=(
            f"supervisor:{_ATTEMPT_COMPLETION_BOUNDARY}:"
            f"{canonical_digest({'outbox_id': completion.outbox_id})}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="agentops:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest({"profile_id": "controller_bookkeeping"}),
            runner_id="local_non_ai",
            session_id=None,
        ),
        action=ActionAttributes(
            verb=ActionVerb.MODIFY,
            operation=_ATTEMPT_COMPLETION_OPERATION,
            parameters_digest=canonical_digest(intent),
            intended_effect="append_local_attempt_completion_and_outbox_only",
        ),
        resource=ResourceAttributes(
            resource_type="supervisor_attempt",
            identifier=canonical_digest({"attempt_id": attempt.attempt_id}),
            version=canonical_digest(
                {
                    "source_attempt_event_id": source_attempt.event_id,
                    "source_attempt_revision": source_attempt.revision,
                    "source_flow_event_id": source_flow.event_id,
                    "source_flow_revision": source_flow.revision,
                    "target_attempt_event_id": target_attempt.event_id,
                    "target_flow_event_id": target_flow.event_id,
                    "outbox_id": completion.outbox_id,
                }
            ),
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(
                {
                    "flow_request_digest": spec.request_digest,
                    "source": intent["source"],
                    "target": intent["target"],
                    "completion": intent["completion"],
                }
            ),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=timestamp,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.LOCAL_NON_AI,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=PaidContinuationProtection.NOT_APPLICABLE,
            circuit_state=CircuitState.CLOSED,
            flow_state=source_flow.state.value,
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
        "resource": EvidenceSource.CONTROLLER,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.CONTROLLER,
    }
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=f"supervisor:{_ATTEMPT_COMPLETION_BOUNDARY}:{attribute}",
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id="agentops:controller",
            observed_at=timestamp,
            expires_at=timestamp + 60.0,
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
    base = PolicyBundle.current_stage(issued_at=timestamp)
    policy = PolicyBundle(
        bundle_id=base.bundle_id,
        version=base.version,
        issued_at=base.issued_at,
        evidence_requirements=base.evidence_requirements,
        enabled_classes=base.enabled_classes,
        allowed_verbs=base.allowed_verbs,
        allowed_roles=tuple(dict.fromkeys((*base.allowed_roles, Role.CONTROLLER))),
        allowed_operations=tuple(
            dict.fromkeys((*base.allowed_operations, _ATTEMPT_COMPLETION_OPERATION))
        ),
        allowed_resource_types=tuple(
            dict.fromkeys((*base.allowed_resource_types, "supervisor_attempt"))
        ),
        allowed_trust_boundaries=tuple(
            dict.fromkeys((*base.allowed_trust_boundaries, "local_control_plane"))
        ),
        allowed_flow_states=tuple(
            dict.fromkeys((*base.allowed_flow_states, source_flow.state.value))
        ),
        allowed_network_states=base.allowed_network_states,
        allowed_billing_routes=base.allowed_billing_routes,
        approval_requirements=base.approval_requirements,
        decision_ttl_seconds=base.decision_ttl_seconds,
    )
    return request, policy, intent


def _expected_attempt_completion_observation_values(
    row: sqlite3.Row,
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_flow: FlowRevision,
    target_attempt: AttemptEvent,
    completion: CompletionIntent,
) -> tuple[Any, ...]:
    """Independently rebuild a durable completion shadow from its sources."""

    _validate_text(
        row["observation_id"],
        "attempt completion authorization observation identifier",
        maximum=256,
    )
    payload_text = row["payload_json"]
    if (
        not isinstance(payload_text, str)
        or len(payload_text.encode("utf-8")) > _MAX_JSON_BYTES
    ):
        raise ValidationError("attempt completion authorization payload is invalid")
    payload = parse_json_document(payload_text)
    if type(payload) is not dict:
        raise ValidationError("attempt completion authorization payload is invalid")
    supplied_intent = payload.get("attempt_completion")
    if type(supplied_intent) is not dict:
        raise ValidationError("attempt completion authorization intent is invalid")
    supplied_source = supplied_intent.get("source")
    if type(supplied_source) is not dict:
        raise ValidationError("attempt completion authorization source is invalid")
    lease_snapshot = supplied_source.get("lease_snapshot")
    request, policy, intent = _supervisor_attempt_completion_authorization_request(
        spec=spec,
        attempt=attempt,
        source_flow=source_flow,
        source_attempt=source_attempt,
        target_flow=target_flow,
        target_attempt=target_attempt,
        completion=completion,
        lease_snapshot=lease_snapshot,
        observed_at=target_flow.occurred_at,
    )
    decision = _BUILTIN_ATTEMPT_COMPLETION_SHADOW_EVALUATE(
        ShadowAuthorizationEvaluator(),
        request,
        policy,
    )
    parity = decision.effect.value == "permit"
    expected_payload = {
        "mode": "shadow",
        "boundary": _ATTEMPT_COMPLETION_BOUNDARY,
        "action_scope": _ATTEMPT_COMPLETION_ACTION_SCOPE,
        "attempt_completion": intent,
        "attempt_completion_digest": canonical_digest(intent),
        "request": request.to_canonical(),
        "request_digest": request.digest,
        "decision": decision.to_canonical(),
        "decision_digest": decision.digest,
        "legacy_executable": True,
        "execution_parity": parity,
    }
    if payload != expected_payload:
        raise ValidationError("attempt completion authorization payload is inconsistent")
    return (
        completion.outbox_id,
        target_flow.event_id,
        target_attempt.event_id,
        source_flow.event_id,
        source_flow.revision,
        source_attempt.event_id,
        attempt.attempt_id,
        attempt.flow_id,
        spec.request_digest,
        attempt.input_digest,
        intent["source"]["lease_snapshot_digest"],
        completion.intent_digest,
        completion.operation_digest,
        request.digest,
        decision.digest,
        decision.effect.value,
        int(decision.derived_permission_class),
        1,
        int(parity),
        _bounded_json(
            expected_payload,
            "attempt completion authorization audit payload",
        ),
        float(target_flow.occurred_at),
    )


def _pre_dispatch_reconciliation_mapping(
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_flow: FlowRevision,
    target_attempt: AttemptEvent,
    completion: CompletionIntent,
    lease_snapshot: object,
    reconciliation_action: str | None,
    observed_at: float,
) -> dict[str, Any]:
    """Build redacted evidence for one expired pre-dispatch claim repair."""

    _validate_flow_spec(spec)
    for field_name in ("attempt_id", "flow_id", "run_id", "lease_owner"):
        _validate_text(getattr(attempt, field_name), field_name, maximum=256)
    _validate_revision(attempt.attempt_number)
    _validate_revision(attempt.claimed_revision)
    _validate_digest(attempt.input_digest, "attempt input digest")
    attempt_created_at = _timestamp(attempt.created_at, "attempt claim timestamp")
    deadline_at = _timestamp(attempt.deadline_at, "attempt deadline")
    if (
        attempt.flow_id != spec.flow_id
        or not 1 <= attempt.attempt_number <= spec.max_attempts
        or attempt.lease_keys
        != tuple(sorted({f"flow:{spec.flow_id}", *spec.resource_keys}))
    ):
        raise ValidationError("pre-dispatch reconciliation source is invalid")
    expected_deadline = min(
        attempt_created_at + spec.attempt_timeout_seconds,
        (
            spec.deadline_at
            if spec.deadline_at is not None
            else attempt_created_at + spec.attempt_timeout_seconds
        ),
    )
    if deadline_at != expected_deadline or deadline_at <= attempt_created_at:
        raise ValidationError("pre-dispatch reconciliation deadline is invalid")

    for event in (source_attempt, target_attempt):
        _validate_text(event.event_id, "attempt event identifier", maximum=256)
        _validate_text(event.attempt_id, "attempt identifier", maximum=256)
        _validate_revision(event.revision)
        _validate_reason(event.reason_code)
        _timestamp(event.occurred_at, "attempt event timestamp")
    for flow, description in (
        (source_flow, "source"),
        (target_flow, "target"),
    ):
        for field_name in ("event_id", "flow_id"):
            _validate_text(
                getattr(flow, field_name),
                f"{description} flow {field_name}",
                maximum=256,
            )
        _validate_revision(flow.revision)
        _validate_reason(flow.reason_code)
        _timestamp(flow.occurred_at, f"{description} flow timestamp")
        if type(flow.cancellation_requested) is not bool:
            raise ValidationError(
                "pre-dispatch reconciliation cancellation source is invalid"
            )
    timestamp = _timestamp(
        observed_at,
        "pre-dispatch reconciliation observation timestamp",
    )

    for field_name in ("outbox_id", "idempotency_key", "flow_id"):
        _validate_text(
            getattr(completion, field_name),
            f"completion {field_name}",
            maximum=256,
        )
    _validate_revision(completion.source_revision)
    if completion.attempt_id is None:
        raise ValidationError("pre-dispatch reconciliation outbox is missing attempt")
    _validate_text(completion.attempt_id, "completion attempt identifier", maximum=256)
    for field_name in ("intent_digest", "operation_digest"):
        _validate_digest(
            getattr(completion, field_name),
            f"completion {field_name}",
        )
    completion_created_at = _timestamp(
        completion.created_at,
        "completion outbox timestamp",
    )
    expected_action = (
        "finalize_cancelled_pre_dispatch"
        if source_flow.cancellation_requested
        else "mark_lost_pre_dispatch"
    )
    expected_state = (
        FlowState.CANCELLED
        if source_flow.cancellation_requested
        else FlowState.LOST
    )
    if reconciliation_action != expected_action:
        raise ValidationError("pre-dispatch reconciliation action is invalid")
    expected_envelope_json = _bounded_json(
        {
            "flow_id": target_flow.flow_id,
            "source_revision": target_flow.revision,
            "state": target_flow.state.value,
            "attempt_id": attempt.attempt_id,
            "reason_code": target_flow.reason_code,
        },
        "pre-dispatch reconciliation envelope",
    )
    if (
        source_flow.flow_id != attempt.flow_id
        or source_flow.state is not FlowState.RUNNING
        or source_flow.active_attempt_id != attempt.attempt_id
        or target_flow.flow_id != attempt.flow_id
        or target_flow.revision != source_flow.revision + 1
        or target_flow.state is not expected_state
        or target_flow.cancellation_requested
        != source_flow.cancellation_requested
        or target_flow.active_attempt_id is not None
        or target_flow.reason_code != "pre_dispatch_claim_expired"
        or target_flow.reason_code != target_attempt.reason_code
        or source_attempt.attempt_id != attempt.attempt_id
        or source_attempt.state is not AttemptState.CREATED
        or target_attempt.attempt_id != attempt.attempt_id
        or target_attempt.revision != source_attempt.revision + 1
        or target_attempt.state
        is not _TERMINAL_ATTEMPT_FOR_FLOW[target_flow.state]
        or target_attempt.state not in _ATTEMPT_TRANSITIONS[source_attempt.state]
        or target_attempt.occurred_at != timestamp
        or target_flow.occurred_at != timestamp
        or completion_created_at != timestamp
        or timestamp < attempt_created_at
        or timestamp < source_flow.occurred_at
        or timestamp < source_attempt.occurred_at
        or completion.flow_id != target_flow.flow_id
        or completion.source_revision != target_flow.revision
        or completion.attempt_id != attempt.attempt_id
        or completion.idempotency_key
        != f"flow:{target_flow.flow_id}:revision:{target_flow.revision}"
        or completion.envelope_json != expected_envelope_json
        or completion.intent_digest != _sha256_text(expected_envelope_json)
        or completion.operation_digest != completion.intent_digest
    ):
        raise ValidationError("pre-dispatch reconciliation source or target is invalid")
    leases = _validate_pre_dispatch_reconciliation_lease_snapshot(
        lease_snapshot,
        attempt=attempt,
        observed_at=timestamp,
    )
    finding = _finding(
        "expired_pre_dispatch_claim",
        "pre_dispatch_claim_expired",
        attempt.flow_id,
        attempt.attempt_id,
        source_flow.revision,
        expected_action,
    )
    attempt_id_ref = canonical_digest({"attempt_id": attempt.attempt_id})
    return {
        "source": {
            "flow_id_ref": canonical_digest({"flow_id": attempt.flow_id}),
            "flow_event_ref": canonical_digest(
                {"flow_event_id": source_flow.event_id}
            ),
            "flow_revision": source_flow.revision,
            "flow_state": source_flow.state.value,
            "flow_reason_code": source_flow.reason_code,
            "cancellation_requested": source_flow.cancellation_requested,
            "active_attempt_ref": attempt_id_ref,
            "attempt_id_ref": attempt_id_ref,
            "run_id_ref": canonical_digest({"run_id": attempt.run_id}),
            "attempt_event_ref": canonical_digest(
                {"attempt_event_id": source_attempt.event_id}
            ),
            "attempt_revision": source_attempt.revision,
            "attempt_state": source_attempt.state.value,
            "attempt_reason_code": source_attempt.reason_code,
            "attempt_occurred_at": float(source_attempt.occurred_at),
            "flow_request_digest": spec.request_digest,
            "input_digest": attempt.input_digest,
            "lease_owner_ref": canonical_digest(
                {"lease_owner": attempt.lease_owner}
            ),
            "lease_keys_digest": canonical_digest(
                {"lease_keys": list(attempt.lease_keys)}
            ),
            "lease_snapshot": [dict(item) for item in leases],
            "lease_snapshot_digest": canonical_digest({"leases": list(leases)}),
            "deadline_at": float(deadline_at),
        },
        "target": {
            "flow_id_ref": canonical_digest({"flow_id": target_flow.flow_id}),
            "flow_event_ref": canonical_digest(
                {"flow_event_id": target_flow.event_id}
            ),
            "flow_revision": target_flow.revision,
            "flow_state": target_flow.state.value,
            "flow_reason_code": target_flow.reason_code,
            "cancellation_requested": target_flow.cancellation_requested,
            "active_attempt_absent": True,
            "attempt_id_ref": attempt_id_ref,
            "attempt_event_ref": canonical_digest(
                {"attempt_event_id": target_attempt.event_id}
            ),
            "attempt_revision": target_attempt.revision,
            "attempt_state": target_attempt.state.value,
            "attempt_reason_code": target_attempt.reason_code,
            "attempt_occurred_at": float(target_attempt.occurred_at),
        },
        "completion": {
            "outbox_ref": canonical_digest({"outbox_id": completion.outbox_id}),
            "idempotency_key_ref": canonical_digest(
                {"idempotency_key": completion.idempotency_key}
            ),
            "source_revision": completion.source_revision,
            "state": target_flow.state.value,
            "attempt_id_ref": attempt_id_ref,
            "intent_digest": completion.intent_digest,
            "operation_digest": completion.operation_digest,
            "created_at": float(completion_created_at),
        },
        "reconciliation": {
            "finding_ref": canonical_digest({"finding_id": finding.finding_id}),
            "kind": finding.kind,
            "reason_code": finding.reason_code,
            "action": expected_action,
            "expected_flow_revision": source_flow.revision,
        },
    }


def _supervisor_pre_dispatch_reconciliation_authorization_request(
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_flow: FlowRevision,
    target_attempt: AttemptEvent,
    completion: CompletionIntent,
    lease_snapshot: object,
    reconciliation_action: str | None,
    observed_at: float,
) -> tuple[AuthorizationRequest, PolicyBundle, dict[str, Any]]:
    """Build a fixed shadow-only request for local expired-claim repair."""

    intent = _pre_dispatch_reconciliation_mapping(
        spec=spec,
        attempt=attempt,
        source_flow=source_flow,
        source_attempt=source_attempt,
        target_flow=target_flow,
        target_attempt=target_attempt,
        completion=completion,
        lease_snapshot=lease_snapshot,
        reconciliation_action=reconciliation_action,
        observed_at=observed_at,
    )
    timestamp = _timestamp(
        observed_at,
        "pre-dispatch reconciliation observation timestamp",
    )
    request = AuthorizationRequest(
        request_id=(
            f"supervisor:{_PRE_DISPATCH_RECONCILIATION_BOUNDARY}:"
            f"{canonical_digest({'outbox_id': completion.outbox_id})}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="agentops:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest({"profile_id": "controller_bookkeeping"}),
            runner_id="local_non_ai",
            session_id=None,
        ),
        action=ActionAttributes(
            verb=ActionVerb.MODIFY,
            operation=_PRE_DISPATCH_RECONCILIATION_OPERATION,
            parameters_digest=canonical_digest(intent),
            intended_effect=(
                "append_local_pre_dispatch_reconciliation_and_outbox_only"
            ),
        ),
        resource=ResourceAttributes(
            resource_type="supervisor_attempt",
            identifier=canonical_digest({"attempt_id": attempt.attempt_id}),
            version=canonical_digest(
                {
                    "source_attempt_event_id": source_attempt.event_id,
                    "source_attempt_revision": source_attempt.revision,
                    "source_flow_event_id": source_flow.event_id,
                    "source_flow_revision": source_flow.revision,
                    "target_attempt_event_id": target_attempt.event_id,
                    "target_flow_event_id": target_flow.event_id,
                    "outbox_id": completion.outbox_id,
                    "reconciliation_action": intent["reconciliation"]["action"],
                }
            ),
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(
                {
                    "flow_request_digest": spec.request_digest,
                    "source": intent["source"],
                    "target": intent["target"],
                    "completion": intent["completion"],
                    "reconciliation": intent["reconciliation"],
                }
            ),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=timestamp,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.LOCAL_NON_AI,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=PaidContinuationProtection.NOT_APPLICABLE,
            circuit_state=CircuitState.CLOSED,
            flow_state=source_flow.state.value,
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
        "resource": EvidenceSource.CONTROLLER,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.CONTROLLER,
    }
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=(
                f"supervisor:{_PRE_DISPATCH_RECONCILIATION_BOUNDARY}:{attribute}"
            ),
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id="agentops:controller",
            observed_at=timestamp,
            expires_at=timestamp + 60.0,
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
    base = PolicyBundle.current_stage(issued_at=timestamp)
    policy = PolicyBundle(
        bundle_id=base.bundle_id,
        version=base.version,
        issued_at=base.issued_at,
        evidence_requirements=base.evidence_requirements,
        enabled_classes=base.enabled_classes,
        allowed_verbs=base.allowed_verbs,
        allowed_roles=tuple(dict.fromkeys((*base.allowed_roles, Role.CONTROLLER))),
        allowed_operations=tuple(
            dict.fromkeys(
                (*base.allowed_operations, _PRE_DISPATCH_RECONCILIATION_OPERATION)
            )
        ),
        allowed_resource_types=tuple(
            dict.fromkeys((*base.allowed_resource_types, "supervisor_attempt"))
        ),
        allowed_trust_boundaries=tuple(
            dict.fromkeys((*base.allowed_trust_boundaries, "local_control_plane"))
        ),
        allowed_flow_states=tuple(
            dict.fromkeys((*base.allowed_flow_states, source_flow.state.value))
        ),
        allowed_network_states=base.allowed_network_states,
        allowed_billing_routes=base.allowed_billing_routes,
        approval_requirements=base.approval_requirements,
        decision_ttl_seconds=base.decision_ttl_seconds,
    )
    return request, policy, intent


def _expected_pre_dispatch_reconciliation_observation_values(
    row: sqlite3.Row,
    *,
    spec: FlowSpec,
    attempt: AttemptRecord,
    source_flow: FlowRevision,
    source_attempt: AttemptEvent,
    target_flow: FlowRevision,
    target_attempt: AttemptEvent,
    completion: CompletionIntent,
) -> tuple[Any, ...]:
    """Independently rebuild one durable pre-dispatch repair shadow."""

    _validate_text(
        row["observation_id"],
        "pre-dispatch reconciliation authorization observation identifier",
        maximum=256,
    )
    payload_text = row["payload_json"]
    if (
        not isinstance(payload_text, str)
        or len(payload_text.encode("utf-8")) > _MAX_JSON_BYTES
    ):
        raise ValidationError(
            "pre-dispatch reconciliation authorization payload is invalid"
        )
    payload = parse_json_document(payload_text)
    if type(payload) is not dict:
        raise ValidationError(
            "pre-dispatch reconciliation authorization payload is invalid"
        )
    supplied_intent = payload.get("pre_dispatch_reconciliation")
    if type(supplied_intent) is not dict:
        raise ValidationError(
            "pre-dispatch reconciliation authorization intent is invalid"
        )
    supplied_source = supplied_intent.get("source")
    supplied_reconciliation = supplied_intent.get("reconciliation")
    if type(supplied_source) is not dict or type(supplied_reconciliation) is not dict:
        raise ValidationError(
            "pre-dispatch reconciliation authorization source is invalid"
        )
    lease_snapshot = supplied_source.get("lease_snapshot")
    reconciliation_action = supplied_reconciliation.get("action")
    request, policy, intent = (
        _supervisor_pre_dispatch_reconciliation_authorization_request(
            spec=spec,
            attempt=attempt,
            source_flow=source_flow,
            source_attempt=source_attempt,
            target_flow=target_flow,
            target_attempt=target_attempt,
            completion=completion,
            lease_snapshot=lease_snapshot,
            reconciliation_action=reconciliation_action,
            observed_at=target_flow.occurred_at,
        )
    )
    decision = _BUILTIN_PRE_DISPATCH_RECONCILIATION_SHADOW_EVALUATE(
        ShadowAuthorizationEvaluator(),
        request,
        policy,
    )
    parity = decision.effect.value == "permit"
    expected_payload = {
        "mode": "shadow",
        "boundary": _PRE_DISPATCH_RECONCILIATION_BOUNDARY,
        "action_scope": _PRE_DISPATCH_RECONCILIATION_ACTION_SCOPE,
        "pre_dispatch_reconciliation": intent,
        "pre_dispatch_reconciliation_digest": canonical_digest(intent),
        "request": request.to_canonical(),
        "request_digest": request.digest,
        "decision": decision.to_canonical(),
        "decision_digest": decision.digest,
        "legacy_executable": True,
        "execution_parity": parity,
    }
    if payload != expected_payload:
        raise ValidationError(
            "pre-dispatch reconciliation authorization payload is inconsistent"
        )
    return (
        completion.outbox_id,
        target_flow.event_id,
        target_attempt.event_id,
        source_flow.event_id,
        source_flow.revision,
        source_attempt.event_id,
        attempt.attempt_id,
        attempt.flow_id,
        spec.request_digest,
        attempt.input_digest,
        intent["source"]["lease_snapshot_digest"],
        completion.intent_digest,
        completion.operation_digest,
        intent["reconciliation"]["action"],
        request.digest,
        decision.digest,
        decision.effect.value,
        int(decision.derived_permission_class),
        1,
        int(parity),
        _bounded_json(
            expected_payload,
            "pre-dispatch reconciliation authorization audit payload",
        ),
        float(target_flow.occurred_at),
    )


def _supervisor_bookkeeping_authorization_request(
    *,
    boundary: str,
    observed_at: float,
    control: SupervisorControlRevision | None = None,
    previous_control: SupervisorControlRevision | None = None,
    spec: FlowSpec | None = None,
    flow_revision: FlowRevision | None = None,
    cancellation_request_id: str | None = None,
    requested_by: str | None = None,
    reason_code: str | None = None,
) -> tuple[AuthorizationRequest, PolicyBundle]:
    if boundary == "control_transition":
        if (
            control is None
            or previous_control is None
            or spec is not None
            or flow_revision is not None
            or cancellation_request_id is not None
            or requested_by is not None
            or reason_code is not None
            or control.revision != previous_control.revision + 1
            or control.mode not in _CONTROL_TRANSITIONS[previous_control.mode]
        ):
            raise ValidationError("control authorization inputs are invalid")
        operation = "supervisor.control_transition"
        request_id = f"supervisor:control_transition:{control.event_id}"
        resource_type = "supervisor_control_state"
        identifier = canonical_digest({"resource": "supervisor_control_state"})
        version = canonical_digest(
            {
                "event_id": previous_control.event_id,
                "revision": previous_control.revision,
            }
        )
        parameters = {
            "source": _control_authorization_mapping(previous_control),
            "target": _control_authorization_mapping(control),
        }
        content = _control_authorization_mapping(previous_control)
        flow_state = f"control_{previous_control.mode.value}"
        intended_effect = "apply_local_supervisor_control_transition"
        reversible = True
    elif boundary == "flow_cancellation":
        if (
            control is not None
            or previous_control is not None
            or spec is None
            or flow_revision is None
            or cancellation_request_id is None
            or requested_by is None
            or reason_code is None
            or flow_revision.flow_id != spec.flow_id
        ):
            raise ValidationError("cancellation authorization inputs are invalid")
        operation = "supervisor.flow_cancel"
        request_id = f"supervisor:flow_cancellation:{cancellation_request_id}"
        resource_type = "supervisor_flow"
        identifier = canonical_digest({"flow_id": spec.flow_id})
        version = canonical_digest(
            {
                "event_id": flow_revision.event_id,
                "revision": flow_revision.revision,
            }
        )
        source = _flow_revision_authorization_mapping(flow_revision)
        parameters = {
            "flow_request_digest": spec.request_digest,
            "reason_code": reason_code,
            "requested_by_ref": canonical_digest({"requested_by": requested_by}),
            "source": source,
            "effect": _cancellation_effect_mapping(flow_revision),
        }
        content = {
            "flow_request_digest": spec.request_digest,
            "source": source,
        }
        flow_state = flow_revision.state.value
        intended_effect = "record_and_apply_local_flow_cancellation"
        reversible = False
    else:
        raise ValidationError("unsupported bookkeeping authorization boundary")
    request = AuthorizationRequest(
        request_id=request_id,
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="agentops:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest({"profile_id": "controller_bookkeeping"}),
            runner_id="local_non_ai",
            session_id=None,
        ),
        action=ActionAttributes(
            verb=ActionVerb.MODIFY,
            operation=operation,
            parameters_digest=canonical_digest(parameters),
            intended_effect=intended_effect,
        ),
        resource=ResourceAttributes(
            resource_type=resource_type,
            identifier=identifier,
            version=version,
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(content),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=observed_at,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.LOCAL_NON_AI,
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
            reversible=reversible,
            sensitivity=ImpactLevel.LOW,
            blast_radius=BlastRadius.SINGLE_RESOURCE,
        ),
    )
    sources = {
        "subject": EvidenceSource.CONTROLLER,
        "action": EvidenceSource.CONTROLLER,
        "resource": EvidenceSource.CONTROLLER,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.CONTROLLER,
    }
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=f"supervisor:{boundary}:{attribute}",
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id="agentops:controller",
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
            dict.fromkeys((*base.allowed_resource_types, resource_type))
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


def _bookkeeping_authorization_observation_from_row(
    row: sqlite3.Row,
) -> SupervisorBookkeepingAuthorizationObservation:
    return SupervisorBookkeepingAuthorizationObservation(
        sequence=row["sequence"],
        observation_id=row["observation_id"],
        boundary=row["boundary"],
        flow_id=row["flow_id"],
        control_event_id=row["control_event_id"],
        cancellation_request_id=row["cancellation_request_id"],
        request_digest=row["request_digest"],
        decision_digest=row["decision_digest"],
        effect=row["effect"],
        derived_permission_class=PermissionClass(row["derived_permission_class"]),
        legacy_executable=bool(row["legacy_executable"]),
        execution_parity=bool(row["execution_parity"]),
        payload=json.loads(row["payload_json"]),
        observed_at=row["observed_at"],
    )


def _pre_dispatch_intent_authorization_observation_from_row(
    row: sqlite3.Row,
) -> SupervisorPreDispatchIntentAuthorizationObservation:
    return SupervisorPreDispatchIntentAuthorizationObservation(
        sequence=row["sequence"],
        observation_id=row["observation_id"],
        flow_id=row["flow_id"],
        attempt_id=row["attempt_id"],
        source_flow_event_id=row["source_flow_event_id"],
        source_flow_revision=row["source_flow_revision"],
        source_attempt_event_id=row["source_attempt_event_id"],
        target_attempt_event_id=row["target_attempt_event_id"],
        request_digest=row["request_digest"],
        decision_digest=row["decision_digest"],
        effect=row["effect"],
        derived_permission_class=PermissionClass(row["derived_permission_class"]),
        legacy_executable=bool(row["legacy_executable"]),
        execution_parity=bool(row["execution_parity"]),
        payload=json.loads(row["payload_json"]),
        observed_at=row["observed_at"],
    )


def _attempt_completion_authorization_observation_from_row(
    row: sqlite3.Row,
) -> SupervisorAttemptCompletionAuthorizationObservation:
    return SupervisorAttemptCompletionAuthorizationObservation(
        sequence=row["sequence"],
        observation_id=row["observation_id"],
        flow_id=row["flow_id"],
        attempt_id=row["attempt_id"],
        source_flow_event_id=row["source_flow_event_id"],
        source_flow_revision=row["source_flow_revision"],
        source_attempt_event_id=row["source_attempt_event_id"],
        target_flow_event_id=row["target_flow_event_id"],
        target_attempt_event_id=row["target_attempt_event_id"],
        outbox_id=row["outbox_id"],
        request_digest=row["request_digest"],
        decision_digest=row["decision_digest"],
        effect=row["effect"],
        derived_permission_class=PermissionClass(row["derived_permission_class"]),
        legacy_executable=bool(row["legacy_executable"]),
        execution_parity=bool(row["execution_parity"]),
        payload=json.loads(row["payload_json"]),
        observed_at=row["observed_at"],
    )


def _pre_dispatch_reconciliation_authorization_observation_from_row(
    row: sqlite3.Row,
) -> SupervisorPreDispatchReconciliationAuthorizationObservation:
    return SupervisorPreDispatchReconciliationAuthorizationObservation(
        sequence=row["sequence"],
        observation_id=row["observation_id"],
        flow_id=row["flow_id"],
        attempt_id=row["attempt_id"],
        source_flow_event_id=row["source_flow_event_id"],
        source_flow_revision=row["source_flow_revision"],
        source_attempt_event_id=row["source_attempt_event_id"],
        target_flow_event_id=row["target_flow_event_id"],
        target_attempt_event_id=row["target_attempt_event_id"],
        outbox_id=row["outbox_id"],
        reconciliation_action=row["reconciliation_action"],
        request_digest=row["request_digest"],
        decision_digest=row["decision_digest"],
        effect=row["effect"],
        derived_permission_class=PermissionClass(row["derived_permission_class"]),
        legacy_executable=bool(row["legacy_executable"]),
        execution_parity=bool(row["execution_parity"]),
        payload=json.loads(row["payload_json"]),
        observed_at=row["observed_at"],
    )


def _initial_control_revision() -> SupervisorControlRevision:
    return SupervisorControlRevision(
        sequence=0,
        event_id="synthetic:stopped:0",
        revision=0,
        mode=SupervisorMode.STOPPED,
        actor_id="system",
        reason_code="initial_state",
        occurred_at=0.0,
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
    "SupervisorBookkeepingAuthorizationObservation",
    "SupervisorAttemptCompletionAuthorizationObservation",
    "SupervisorPreDispatchReconciliationAuthorizationObservation",
    "SupervisorPreDispatchIntentAuthorizationObservation",
    "SUPERVISOR_DISPATCH_BLOCKERS",
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
