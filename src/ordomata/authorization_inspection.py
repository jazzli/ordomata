"""Read-only inspection of authorization shadow and enforcement evidence.

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
from dataclasses import dataclass, replace
import json
import math
import os
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
    ApprovalRequirement,
    AttributeEvidence,
    AuthorizationEffect,
    AuthorizationRequest,
    BlastRadius,
    CircuitState,
    ConsequenceVector,
    EnvironmentAttributes,
    EvidenceRequirement,
    EvidenceSource,
    ImpactLevel,
    IsolationState,
    NetworkState,
    ObligationKind,
    PolicyBundle,
    Reach,
    ReceiptOutcome,
    ResourceAttributes,
    Role,
    ShadowAuthorizationEvaluator,
    SubjectAttributes,
    canonical_digest,
    derive_permission_class_from_attributes,
)
from .admission_authorization import (
    TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
    TASK_ADMISSION_ACTION_SCOPE,
    TASK_ADMISSION_DECISION_EVENT_TYPE,
    TASK_ADMISSION_ENFORCEMENT_COVERAGE,
    TASK_ADMISSION_EVENT_SCHEMA_VERSION,
    TASK_ADMISSION_EXECUTOR_ID,
    TASK_ADMISSION_OPERATION,
    TASK_ADMISSION_POLICY_ID,
    TASK_ADMISSION_POLICY_VERSION,
    TASK_ADMISSION_RESOURCE_TYPE,
)
from .dispatch_authorization import (
    MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
    MOCK_DISPATCH_ACTION_SCOPE,
    MOCK_DISPATCH_DECISION_EVENT_TYPE,
    MOCK_DISPATCH_EVENT_SCHEMA_VERSION,
    MOCK_DISPATCH_EXECUTOR_ID,
    MOCK_DISPATCH_OPERATION,
    MOCK_DISPATCH_POLICY_ID,
    MOCK_DISPATCH_POLICY_VERSION,
    MOCK_DISPATCH_RESOURCE_TYPE,
)
from .errors import ConfigurationError, ValidationError
from .execution_selection import (
    EXECUTION_SELECTION_KIND,
    EXECUTION_SELECTION_MODES,
    MAX_EXECUTION_SELECTION_CANDIDATES,
    TASK_EXECUTION_SELECTION_EVENT_TYPE,
    routing_policy_digest,
    validate_execution_selection_payload,
)
from .models import (
    AssessmentConfidence,
    BillingRoute,
    CapacityState,
    IncrementalAICharge,
    PaidContinuationProtection,
    PaidCapacityConsumed,
    PaidCreditBalance,
    PermissionClass,
    RunStatus,
    UsageObservation,
)
from .publication_authorization import (
    LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE,
    LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
    LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
    LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION,
    LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID,
    LOCAL_CANDIDATE_PUBLICATION_OPERATION,
    LOCAL_CANDIDATE_PUBLICATION_POLICY_ID,
    LOCAL_CANDIDATE_PUBLICATION_POLICY_VERSION,
    LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE,
)
from .routing import (
    ROUTING_POLICY_ID,
    ROUTING_POLICY_VERSION,
    ROUTING_REJECTION_CODES,
)
from .state import (
    RecordNotFoundError,
    _BASELINE_TABLE_NAMES,
    _state_schema_integrity_issues,
)


AUTHORIZATION_SHADOW_EVENT_TYPE = "authorization_shadow_decision"
COMPARISON_TRIAL_BINDING_EVENT_TYPE = "comparison_trial_binding"
COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE = (
    "comparison_review_artifact_intent"
)
COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE = (
    "comparison_review_artifact_observed"
)
COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE = (
    "comparison_review_artifact_action_receipt"
)
COMPARISON_RUN_KIND = "controlled_comparison_trial"
COMPARISON_SHADOW_COVERAGE = "partial_admission_dispatch_shadow"
COMPARISON_FULL_SHADOW_COVERAGE = (
    "comparison_admission_dispatch_publication_shadow"
)
COMPARISON_ACTION_RECEIPT_COVERAGE = (
    "comparison_private_review_artifact_pre_effect_action_receipt"
)
TASK_ATTEMPT_RUN_KIND = "task_attempt"
TASK_ATTEMPT_BINDING_EVENT_TYPE = "task_attempt_authorization_binding"
TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE = (
    "task_attempt_candidate_artifact_intent"
)
TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE = (
    "task_attempt_candidate_artifact_action_receipt"
)
TASK_ATTEMPT_SHADOW_COVERAGE = (
    "task_attempt_admission_dispatch_publication_shadow"
)
TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE = (
    "task_attempt_candidate_artifact_pre_effect_action_receipt"
)
TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE = (
    "task_attempt_mock_dispatch_decision_action_receipt"
)
TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE = (
    LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
)
TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE = (
    TASK_ADMISSION_ENFORCEMENT_COVERAGE
)
ADMISSION_SCOPE = "task_attempt_admission_only"
DISPATCH_SCOPE = "runner_model_dispatch_only"
PUBLICATION_SCOPE = "local_candidate_publication_only"
KNOWN_ACTION_SCOPES = frozenset(
    {ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE}
)
SUPPORTED_SHADOW_SCHEMA_VERSIONS = frozenset({1, 2, 3, 4, 5})

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
_BARE_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
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
_MAX_COMPARISON_BINDING_EVENTS_PER_RUN = 2
_MAX_COMPARISON_BILLING_EVENTS_PER_RUN = 2
_MAX_COMPARISON_ACCOUNTING_EVENTS_PER_RUN = 2
_MAX_COMPARISON_ARTIFACT_EVENTS_PER_TYPE_PER_RUN = 2
_MAX_TASK_BINDING_EVENTS_PER_RUN = 2
_MAX_TASK_EXECUTION_SELECTION_EVENTS_PER_RUN = 2
_MAX_TASK_ADMISSION_EVENTS_PER_TYPE_PER_RUN = 2
_MAX_MOCK_DISPATCH_EVENTS_PER_TYPE_PER_RUN = 2
_MAX_LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENTS_PER_RUN = 2
_MAX_TASK_ARTIFACT_EVENTS_PER_TYPE_PER_RUN = 2
_MAX_TASK_ARTIFACT_METADATA_PER_RUN = 32
_MAX_RUNNER_EVENTS_PER_RUN = 4096
_MAX_TERMINAL_EVENTS_PER_RUN = 2
_MAX_EVIDENCE_RECORDS = 32
_MAX_OBLIGATION_RESULTS = 32
_MAX_PAYLOAD_BYTES = 512 * 1024
_SHADOW_EVIDENCE_LIFETIME_SECONDS = 120.0
_MISSING = object()

_SELECTED_TASK_BINDING_SCHEMA_VERSIONS = frozenset({2, 3, 4, 5})
_DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS = frozenset({3, 4, 5})
_PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS = frozenset({4, 5})
_ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS = frozenset({5})

_COMPARISON_ACCOUNTING_KEYS = frozenset(
    {
        "billing_circuit_breaker_required",
        "billing_disposition_digest",
        "billing_disposition_reason_codes",
        "billing_matches",
        "billing_quarantine_required",
        "capacity_state",
        "failure_code",
        "harness_process_started",
        "identity_matches",
        "incremental_ai_charge",
        "live_model_execution_occurred",
        "paid_capacity_consumed",
        "result_observed",
        "result_status",
        "runner_event_count",
        "schema_version",
        "subscription_capacity_consumed",
        "usage_observation",
        "wall_seconds",
    }
)
_TASK_ACCOUNTING_KEYS = _COMPARISON_ACCOUNTING_KEYS | frozenset(
    {
        "execution_mode",
        "incremental_api_charge",
        "runner_version",
    }
)
_TASK_EXECUTION_MODES = frozenset(
    {
        "in_memory_mock",
        "codex_exec_jsonl_read_only_ephemeral",
        "claude_print_stream_json_safe_no_tools",
        "local_non_ai",
    }
)
_TASK_SUCCESS_TERMINAL_KEYS = frozenset(
    {
        "accepted",
        "artifact_credential_scan_passed",
        "artifact_observed",
        "artifact_recorded",
        "billing_assessment_matched_preflight",
        "billing_circuit_breaker_required",
        "billing_quarantine_required",
        "runner_status",
    }
)
_EXECUTION_SELECTION_TASK_KEYS = frozenset(
    {
        "allowed_billing_routes",
        "allowed_roles",
        "context_bytes",
        "permission_class",
        "required_capabilities",
        "risk",
        "task_kind",
    }
)
_EXECUTION_SELECTION_CANDIDATE_KEYS = frozenset(
    {
        "allowed_billing_routes",
        "billing",
        "billing_projection_digest",
        "candidate_order",
        "capabilities",
        "disposition",
        "latency_prior_seconds",
        "max_context_bytes",
        "max_permission_class",
        "model_ref",
        "profile_id",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "quality_prior",
        "rank",
        "rejection_codes",
        "role",
        "runner_id",
        "runner_overrides_digest",
        "runtime",
        "score_vector",
        "settings_digest",
        "task_kinds",
    }
)
_EXECUTION_SELECTION_SELECTED_KEYS = frozenset(
    {
        "model_ref",
        "profile_id",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "rank",
        "runner_id",
        "runner_overrides_digest",
        "settings_digest",
    }
)
_EXECUTION_SELECTION_SELECTED_CANDIDATE_KEYS = (
    _EXECUTION_SELECTION_SELECTED_KEYS.difference({"rank"})
)


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
class MockDispatchEnforcementInspection:
    """Sanitized findings for the first authoritative mock dispatch PEP."""

    required: bool
    decision_observed: bool
    decision_sequence: int | None
    effect: str | None
    authorization_eligible: bool | None
    decision_current_at_evaluation: bool | None
    action_receipt_observed: bool
    action_receipt_sequence: int | None
    action_receipt_outcome: str | None
    permit_current_at_action_start: bool | None
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return bool(self.integrity_issues)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "decision_observed": self.decision_observed,
            "decision_sequence": self.decision_sequence,
            "effect": self.effect,
            "authorization_eligible": self.authorization_eligible,
            "decision_current_at_evaluation": (
                self.decision_current_at_evaluation
            ),
            "action_receipt_observed": self.action_receipt_observed,
            "action_receipt_sequence": self.action_receipt_sequence,
            "action_receipt_outcome": self.action_receipt_outcome,
            "permit_current_at_action_start": (
                self.permit_current_at_action_start
            ),
            "integrity_issues": list(self.integrity_issues),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True, slots=True)
class TaskAdmissionEnforcementInspection:
    """Sanitized findings for exact profile-backed mock admission."""

    required: bool
    decision_observed: bool
    decision_sequence: int | None
    effect: str | None
    authorization_eligible: bool | None
    decision_current_at_evaluation: bool | None
    action_receipt_observed: bool
    action_receipt_sequence: int | None
    action_receipt_outcome: str | None
    permit_current_at_action_start: bool | None
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return bool(self.integrity_issues)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "decision_observed": self.decision_observed,
            "decision_sequence": self.decision_sequence,
            "effect": self.effect,
            "authorization_eligible": self.authorization_eligible,
            "decision_current_at_evaluation": (
                self.decision_current_at_evaluation
            ),
            "action_receipt_observed": self.action_receipt_observed,
            "action_receipt_sequence": self.action_receipt_sequence,
            "action_receipt_outcome": self.action_receipt_outcome,
            "permit_current_at_action_start": (
                self.permit_current_at_action_start
            ),
            "integrity_issues": list(self.integrity_issues),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True, slots=True)
class LocalCandidatePublicationEnforcementInspection:
    """Sanitized findings for exact local-candidate publication enforcement."""

    required: bool
    boundary_observed: bool
    decision_observed: bool
    decision_sequence: int | None
    effect: str | None
    authorization_eligible: bool | None
    decision_current_at_evaluation: bool | None
    pre_effect_observed: bool
    pre_effect_sequence: int | None
    action_receipt_observed: bool
    action_receipt_sequence: int | None
    action_receipt_outcome: str | None
    permit_current_at_effect_start: bool | None
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return bool(self.integrity_issues)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "boundary_observed": self.boundary_observed,
            "decision_observed": self.decision_observed,
            "decision_sequence": self.decision_sequence,
            "effect": self.effect,
            "authorization_eligible": self.authorization_eligible,
            "decision_current_at_evaluation": (
                self.decision_current_at_evaluation
            ),
            "pre_effect_observed": self.pre_effect_observed,
            "pre_effect_sequence": self.pre_effect_sequence,
            "action_receipt_observed": self.action_receipt_observed,
            "action_receipt_sequence": self.action_receipt_sequence,
            "action_receipt_outcome": self.action_receipt_outcome,
            "permit_current_at_effect_start": (
                self.permit_current_at_effect_start
            ),
            "integrity_issues": list(self.integrity_issues),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True, slots=True)
class RunAuthorizationInspection:
    """Coverage and shadow-decision findings for one immutable run."""

    run_id: str | None
    run_ref: str
    run_kind: str
    authorization_shadow_coverage: str
    authorization_action_receipt_coverage: str | None
    admission_authorization_enforcement_coverage: str | None
    authorization_enforcement_coverage: str | None
    publication_authorization_enforcement_coverage: str | None
    permission_class: int | None
    attempt: int | None
    latest_status: str | None
    expected_scopes: tuple[str, ...]
    observed_scopes: tuple[str, ...]
    missing_scopes: tuple[str, ...]
    events: tuple[ShadowDecisionInspection, ...]
    task_admission_enforcement: TaskAdmissionEnforcementInspection
    mock_dispatch_enforcement: MockDispatchEnforcementInspection
    local_candidate_publication_enforcement: (
        LocalCandidatePublicationEnforcementInspection
    )
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return (
            bool(self.missing_scopes)
            or bool(self.integrity_issues)
            or any(event.attention_required for event in self.events)
            or self.task_admission_enforcement.attention_required
            or self.mock_dispatch_enforcement.attention_required
            or self.local_candidate_publication_enforcement.attention_required
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "run_ref": self.run_ref,
            "run_kind": self.run_kind,
            "authorization_shadow_coverage": (
                self.authorization_shadow_coverage
            ),
            "authorization_action_receipt_coverage": (
                self.authorization_action_receipt_coverage
            ),
            "admission_authorization_enforcement_coverage": (
                self.admission_authorization_enforcement_coverage
            ),
            "authorization_enforcement_coverage": (
                self.authorization_enforcement_coverage
            ),
            "publication_authorization_enforcement_coverage": (
                self.publication_authorization_enforcement_coverage
            ),
            "permission_class": self.permission_class,
            "attempt": self.attempt,
            "latest_status": self.latest_status,
            "expected_scopes": list(self.expected_scopes),
            "observed_scopes": list(self.observed_scopes),
            "missing_scopes": list(self.missing_scopes),
            "events": [event.to_mapping() for event in self.events],
            "task_admission_enforcement": (
                self.task_admission_enforcement.to_mapping()
            ),
            "mock_dispatch_enforcement": (
                self.mock_dispatch_enforcement.to_mapping()
            ),
            "local_candidate_publication_enforcement": (
                self.local_candidate_publication_enforcement.to_mapping()
            ),
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
    integrity_issues: tuple[str, ...]
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
            "integrity_issues": list(self.integrity_issues),
            "runs": [run.to_mapping() for run in self.runs],
        }


@dataclass(frozen=True, slots=True)
class _RunFacts:
    raw_run_id: str
    raw_task_id: Any
    raw_task_version: Any
    raw_runner_id: Any
    raw_run_directory: Any
    raw_context_digest: Any
    timeout_seconds: int | None
    run_id: str | None
    run_ref: str
    permission_class: int | None
    attempt: int | None
    latest_status: str | None
    terminal_artifact_observed: bool | None
    running_observed: bool
    succeeded_observed: bool
    artifact_observed: bool
    shadow_event_count: int
    comparison_binding_event_count: int
    comparison_billing_event_count: int
    comparison_accounting_event_count: int
    comparison_artifact_intent_event_count: int
    comparison_artifact_observed_event_count: int
    comparison_artifact_action_receipt_event_count: int
    task_binding_event_count: int
    task_execution_selection_event_count: int
    task_artifact_intent_event_count: int
    task_artifact_action_receipt_event_count: int
    task_artifact_metadata_count: int
    created_sequence: int | None
    billing_sequence: int | None
    running_sequence: int | None
    accounting_sequence: int | None
    runner_event_count: int
    runner_event_sequence: int | None
    runner_event_last_sequence: int | None
    terminal_sequence: int | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ComparisonBindingFacts:
    """Validated, private comparison binding used only during inspection."""

    observed: bool
    sequence: int | None
    binding: Mapping[str, Any] | None
    binding_digest: str | None
    issues: tuple[str, ...]
    schema_version: int | None = None
    authorization_shadow_coverage: str = COMPARISON_SHADOW_COVERAGE
    authorization_action_receipt_coverage: str | None = None


@dataclass(frozen=True, slots=True)
class _ComparisonBillingFacts:
    """Validated, private billing evidence used only during inspection."""

    payload: Mapping[str, Any] | None
    assessment_digest: str | None
    evidence_window: tuple[float, float] | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ComparisonAccountingFacts:
    """Validated durable execution accounting used only during inspection."""

    sequence: int | None
    payload: Mapping[str, Any] | None
    billing_disposition_digest: str | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ComparisonArtifactReceiptFacts:
    """Validated private publication receipts retained only for inspection."""

    pre_effect_sequence: int | None
    pre_effect: Mapping[str, Any] | None
    pre_effect_receipt_digest: str | None
    action_sequence: int | None
    action: Mapping[str, Any] | None
    action_receipt_digest: str | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TaskAttemptBindingFacts:
    """Validated, private task-attempt binding used only during inspection."""

    observed: bool
    sequence: int | None
    binding: Mapping[str, Any] | None
    binding_digest: str | None
    issues: tuple[str, ...]
    authorization_shadow_coverage: str = TASK_ATTEMPT_SHADOW_COVERAGE
    authorization_action_receipt_coverage: str = (
        TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE
    )
    admission_authorization_enforcement_coverage: str | None = None
    authorization_enforcement_coverage: str | None = None
    publication_authorization_enforcement_coverage: str | None = None
    schema_version: int | None = None


@dataclass(frozen=True, slots=True)
class _TaskExecutionSelectionFacts:
    """Validated profile-selection evidence retained only for inspection."""

    observed: bool
    sequence: int | None
    selection: Mapping[str, Any] | None
    selection_digest: str | None
    selected: Mapping[str, Any] | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TaskAdmissionDecisionFacts:
    """Validated admission decision retained only inside the inspector."""

    observed: bool
    sequence: int | None
    occurred_at: float | None
    payload: Mapping[str, Any] | None
    request: Mapping[str, Any] | None
    policy: Mapping[str, Any] | None
    decision: Mapping[str, Any] | None
    request_digest: str | None
    policy_digest: str | None
    decision_digest: str | None
    effect: str | None
    authorization_eligible: bool | None
    decision_current_at_evaluation: bool | None
    issued_at: float | None
    expires_at: float | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TaskAdmissionReceiptFacts:
    """Validated admission action receipt retained only internally."""

    observed: bool
    sequence: int | None
    occurred_at: float | None
    payload: Mapping[str, Any] | None
    receipt: Mapping[str, Any] | None
    outcome: str | None
    started_at: float | None
    completed_at: float | None
    permit_current_at_action_start: bool | None
    pre_effect_stop_valid: bool
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _MockDispatchDecisionFacts:
    """Validated enforcing decision retained only inside the inspector."""

    observed: bool
    sequence: int | None
    occurred_at: float | None
    payload: Mapping[str, Any] | None
    request: Mapping[str, Any] | None
    policy: Mapping[str, Any] | None
    decision: Mapping[str, Any] | None
    request_digest: str | None
    policy_digest: str | None
    decision_digest: str | None
    effect: str | None
    authorization_eligible: bool | None
    decision_current_at_evaluation: bool | None
    issued_at: float | None
    expires_at: float | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _MockDispatchReceiptFacts:
    """Validated enforcing action receipt retained only internally."""

    observed: bool
    sequence: int | None
    occurred_at: float | None
    payload: Mapping[str, Any] | None
    receipt: Mapping[str, Any] | None
    outcome: str | None
    started_at: float | None
    completed_at: float | None
    permit_current_at_action_start: bool | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _LocalCandidatePublicationDecisionFacts:
    """Validated publication decision retained only inside the inspector."""

    observed: bool
    sequence: int | None
    occurred_at: float | None
    event_id: str | None
    payload: Mapping[str, Any] | None
    request: Mapping[str, Any] | None
    policy: Mapping[str, Any] | None
    decision: Mapping[str, Any] | None
    request_digest: str | None
    policy_digest: str | None
    decision_digest: str | None
    effect: str | None
    authorization_eligible: bool | None
    decision_current_at_evaluation: bool | None
    issued_at: float | None
    expires_at: float | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TaskAccountingFacts:
    """Validated ordinary task execution accounting used only internally."""

    sequence: int | None
    payload: Mapping[str, Any] | None
    billing_disposition_digest: str | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TaskBillingFacts:
    """Validated ordinary pre-dispatch billing evidence."""

    payload: Mapping[str, Any] | None
    assessment_digest: str | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TaskArtifactReceiptFacts:
    """Validated local-candidate receipt chain retained only for inspection."""

    pre_effect_sequence: int | None
    pre_effect: Mapping[str, Any] | None
    pre_effect_receipt_digest: str | None
    action_sequence: int | None
    action: Mapping[str, Any] | None
    action_receipt_digest: str | None
    artifact_observed: bool
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
                connection.execute("BEGIN")
                schema_issues = _state_schema_integrity_issues(connection)
                tables = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                baseline_projection_safe = not {
                    "baseline_schema_missing",
                    "baseline_schema_mismatch",
                }.intersection(schema_issues)
                if (
                    baseline_projection_safe
                    and _BASELINE_TABLE_NAMES.issubset(tables)
                ):
                    facts, run_truncated = _read_run_facts(
                        connection,
                        requested_run_id=requested_run_id,
                    )
                    if requested_run_id is not None and not facts:
                        raise RecordNotFoundError(
                            "requested authorization run was not found"
                        )
                    event_rows = _read_shadow_events(connection, facts)
                    comparison_binding_rows = _read_comparison_binding_events(
                        connection,
                        facts,
                    )
                    comparison_billing_rows = _read_comparison_billing_events(
                        connection,
                        facts,
                    )
                    comparison_accounting_rows = (
                        _read_comparison_accounting_events(
                            connection,
                            facts,
                        )
                    )
                    comparison_artifact_rows = (
                        _read_comparison_artifact_receipt_events(
                            connection,
                            facts,
                        )
                    )
                    task_binding_rows = _read_task_binding_events(
                        connection,
                        facts,
                    )
                    task_execution_selection_rows = (
                        _read_task_execution_selection_events(
                            connection,
                            facts,
                        )
                    )
                    task_admission_decision_rows = (
                        _read_task_admission_events(
                            connection,
                            facts,
                            event_type=TASK_ADMISSION_DECISION_EVENT_TYPE,
                        )
                    )
                    task_admission_receipt_rows = (
                        _read_task_admission_events(
                            connection,
                            facts,
                            event_type=(
                                TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                            ),
                        )
                    )
                    mock_dispatch_decision_rows = (
                        _read_mock_dispatch_events(
                            connection,
                            facts,
                            event_type=MOCK_DISPATCH_DECISION_EVENT_TYPE,
                        )
                    )
                    mock_dispatch_receipt_rows = (
                        _read_mock_dispatch_events(
                            connection,
                            facts,
                            event_type=(
                                MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                            ),
                        )
                    )
                    local_candidate_publication_decision_rows = (
                        _read_local_candidate_publication_decision_events(
                            connection,
                            facts,
                        )
                    )
                    task_artifact_rows = _read_task_artifact_receipt_events(
                        connection,
                        facts,
                    )
                    task_artifact_metadata_rows = _read_task_artifact_metadata(
                        connection,
                        facts,
                    )
                    runner_event_rows = _read_runner_events(
                        connection,
                        facts,
                    )
                    terminal_event_rows = _read_terminal_events(
                        connection,
                        facts,
                    )
                else:
                    facts = ()
                    event_rows = ()
                    comparison_binding_rows = ()
                    comparison_billing_rows = ()
                    comparison_accounting_rows = ()
                    comparison_artifact_rows = ()
                    task_binding_rows = ()
                    task_execution_selection_rows = ()
                    task_admission_decision_rows = ()
                    task_admission_receipt_rows = ()
                    mock_dispatch_decision_rows = ()
                    mock_dispatch_receipt_rows = ()
                    local_candidate_publication_decision_rows = ()
                    task_artifact_rows = ()
                    task_artifact_metadata_rows = ()
                    runner_event_rows = ()
                    terminal_event_rows = ()
                    run_truncated = False
                connection.rollback()
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

    binding_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_binding_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in binding_rows_by_run
        ):
            binding_rows_by_run[raw_event_run_id].append(row)

    billing_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_billing_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in billing_rows_by_run
        ):
            billing_rows_by_run[raw_event_run_id].append(row)

    accounting_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_accounting_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in accounting_rows_by_run
        ):
            accounting_rows_by_run[raw_event_run_id].append(row)

    artifact_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_artifact_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in artifact_rows_by_run
        ):
            artifact_rows_by_run[raw_event_run_id].append(row)

    task_binding_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in task_binding_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in task_binding_rows_by_run
        ):
            task_binding_rows_by_run[raw_event_run_id].append(row)

    task_execution_selection_rows_by_run: dict[
        str, list[sqlite3.Row]
    ] = {fact.raw_run_id: [] for fact in facts}
    for row in task_execution_selection_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id
            in task_execution_selection_rows_by_run
        ):
            task_execution_selection_rows_by_run[raw_event_run_id].append(
                row
            )

    task_admission_decision_rows_by_run: dict[
        str, list[sqlite3.Row]
    ] = {fact.raw_run_id: [] for fact in facts}
    for row in task_admission_decision_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in task_admission_decision_rows_by_run
        ):
            task_admission_decision_rows_by_run[raw_event_run_id].append(row)

    task_admission_receipt_rows_by_run: dict[
        str, list[sqlite3.Row]
    ] = {fact.raw_run_id: [] for fact in facts}
    for row in task_admission_receipt_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in task_admission_receipt_rows_by_run
        ):
            task_admission_receipt_rows_by_run[raw_event_run_id].append(row)

    mock_dispatch_decision_rows_by_run: dict[
        str, list[sqlite3.Row]
    ] = {fact.raw_run_id: [] for fact in facts}
    for row in mock_dispatch_decision_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in mock_dispatch_decision_rows_by_run
        ):
            mock_dispatch_decision_rows_by_run[raw_event_run_id].append(row)

    mock_dispatch_receipt_rows_by_run: dict[
        str, list[sqlite3.Row]
    ] = {fact.raw_run_id: [] for fact in facts}
    for row in mock_dispatch_receipt_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in mock_dispatch_receipt_rows_by_run
        ):
            mock_dispatch_receipt_rows_by_run[raw_event_run_id].append(row)

    local_candidate_publication_decision_rows_by_run: dict[
        str, list[sqlite3.Row]
    ] = {fact.raw_run_id: [] for fact in facts}
    for row in local_candidate_publication_decision_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id
            in local_candidate_publication_decision_rows_by_run
        ):
            local_candidate_publication_decision_rows_by_run[
                raw_event_run_id
            ].append(row)

    task_artifact_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in task_artifact_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in task_artifact_rows_by_run
        ):
            task_artifact_rows_by_run[raw_event_run_id].append(row)

    task_artifact_metadata_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in task_artifact_metadata_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in task_artifact_metadata_rows_by_run
        ):
            task_artifact_metadata_rows_by_run[raw_event_run_id].append(row)

    runner_event_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in runner_event_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in runner_event_rows_by_run
        ):
            runner_event_rows_by_run[raw_event_run_id].append(row)

    terminal_event_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in terminal_event_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in terminal_event_rows_by_run
        ):
            terminal_event_rows_by_run[raw_event_run_id].append(row)

    all_runs: list[RunAuthorizationInspection] = []
    event_truncated = False
    for fact in facts:
        event_rows_for_run = rows_by_run[fact.raw_run_id]
        task_publication_requires_receipts = any(
            _task_publication_shadow_requires_receipts(row)
            for row in event_rows_for_run
        )
        task_binding = _inspect_task_attempt_binding(
            fact,
            task_binding_rows_by_run[fact.raw_run_id],
        )
        task_execution_selection = _inspect_task_execution_selection(
            fact,
            task_binding,
            task_execution_selection_rows_by_run[fact.raw_run_id],
        )
        task_admission_decision = _inspect_task_admission_decision(
            fact,
            task_binding,
            task_execution_selection,
            task_admission_decision_rows_by_run[fact.raw_run_id],
            terminal_event_rows_by_run[fact.raw_run_id],
            shadow_rows=event_rows_for_run,
            receipt_rows=(
                task_admission_receipt_rows_by_run[fact.raw_run_id]
            ),
        )
        task_admission_receipt = _inspect_task_admission_receipt(
            fact,
            task_binding,
            task_execution_selection,
            task_admission_decision,
            task_admission_receipt_rows_by_run[fact.raw_run_id],
            terminal_event_rows_by_run[fact.raw_run_id],
            shadow_rows=event_rows_for_run,
        )
        task_admission_enforcement = _project_task_admission_enforcement(
            task_binding,
            task_admission_decision,
            task_admission_receipt,
        )
        valid_task_binding = (
            task_binding.binding is not None and not task_binding.issues
        )
        comparison_binding = _inspect_comparison_binding(
            fact,
            binding_rows_by_run[fact.raw_run_id],
        )
        valid_comparison_binding = (
            comparison_binding.binding is not None
            and not comparison_binding.issues
        )
        task_billing = _inspect_task_billing(
            fact,
            task_binding,
            billing_rows_by_run[fact.raw_run_id],
        )
        mock_dispatch_decision = _inspect_mock_dispatch_decision(
            fact,
            task_binding,
            task_execution_selection,
            task_billing,
            task_admission_decision,
            task_admission_receipt,
            event_rows_for_run,
            mock_dispatch_decision_rows_by_run[fact.raw_run_id],
        )
        if valid_comparison_binding:
            comparison_billing = _inspect_comparison_billing(
                fact,
                comparison_binding,
                billing_rows_by_run[fact.raw_run_id],
            )
        else:
            comparison_billing = _ComparisonBillingFacts(
                None,
                None,
                None,
                (),
            )
        comparison_accounting = _inspect_comparison_accounting(
            fact,
            comparison_binding,
            accounting_rows_by_run[fact.raw_run_id],
        )
        comparison_artifact_receipts = _inspect_comparison_artifact_receipts(
            fact,
            comparison_binding,
            comparison_accounting,
            artifact_rows_by_run[fact.raw_run_id],
        )
        task_accounting = _inspect_task_accounting(
            fact,
            task_binding,
            accounting_rows_by_run[fact.raw_run_id],
            required=(
                fact.succeeded_observed
                or task_publication_requires_receipts
                or fact.task_artifact_intent_event_count > 0
                or fact.task_artifact_action_receipt_event_count > 0
            ),
        )
        mock_dispatch_receipt = _inspect_mock_dispatch_receipt(
            fact,
            task_binding,
            task_execution_selection,
            mock_dispatch_decision,
            task_accounting,
            mock_dispatch_receipt_rows_by_run[fact.raw_run_id],
            terminal_event_rows_by_run[fact.raw_run_id],
        )
        mock_dispatch_enforcement = _project_mock_dispatch_enforcement(
            task_binding,
            mock_dispatch_decision,
            mock_dispatch_receipt,
        )
        local_candidate_publication_decision = (
            _inspect_local_candidate_publication_decision(
                fact,
                task_binding,
                task_execution_selection,
                mock_dispatch_decision,
                mock_dispatch_receipt,
                task_accounting,
                event_rows_for_run,
                task_artifact_rows_by_run[fact.raw_run_id],
                local_candidate_publication_decision_rows_by_run[
                    fact.raw_run_id
                ],
            )
        )
        task_artifact_receipts = _inspect_task_artifact_receipts(
            fact,
            task_binding,
            task_billing,
            task_accounting,
            task_artifact_rows_by_run[fact.raw_run_id],
            task_artifact_metadata_rows_by_run[fact.raw_run_id],
            publication_shadow_observed=task_publication_requires_receipts,
            publication_decision=local_candidate_publication_decision,
            terminal_rows=terminal_event_rows_by_run[fact.raw_run_id],
        )
        local_candidate_publication_enforcement = (
            _project_local_candidate_publication_enforcement(
                task_binding,
                local_candidate_publication_decision,
                task_artifact_receipts,
            )
        )
        runner_event_issues = _inspect_runner_events(
            fact,
            runner_event_rows_by_run[fact.raw_run_id],
        )
        task_terminal_issues = _inspect_task_terminal_evidence(
            fact,
            task_binding,
            task_accounting,
            task_artifact_receipts,
            terminal_event_rows_by_run[fact.raw_run_id],
        )
        events = tuple(
            _inspect_event(
                row,
                now=evaluated_now,
                expected_run_id=fact.raw_run_id,
                expected_task_id=fact.raw_task_id,
                expected_task_version=fact.raw_task_version,
                expected_permission_class=fact.permission_class,
                comparison_binding=comparison_binding,
                comparison_billing=comparison_billing,
                comparison_accounting=comparison_accounting,
                comparison_artifact_receipts=comparison_artifact_receipts,
                task_binding=task_binding,
                task_execution_selection=task_execution_selection,
                task_billing=task_billing,
                task_accounting=task_accounting,
                task_artifact_receipts=task_artifact_receipts,
            )
            for row in event_rows_for_run
        )
        expected = (
            set()
            if (
                task_binding.schema_version
                in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
                and task_admission_receipt.pre_effect_stop_valid
            )
            else {ADMISSION_SCOPE}
        )
        if fact.running_observed:
            expected.add(DISPATCH_SCOPE)
        task_publication_evidence_observed = (
            any(
                event.action_scope == PUBLICATION_SCOPE
                and _shadow_row_schema(row) == 5
                for event, row in zip(events, event_rows_for_run, strict=True)
            )
            or fact.task_artifact_intent_event_count > 0
            or fact.task_artifact_action_receipt_event_count > 0
        )
        publication_shadow_observed = any(
            event.action_scope == PUBLICATION_SCOPE
            for event in events
        )
        if (
            valid_task_binding
            and task_binding.schema_version
            in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            and publication_shadow_observed
        ) or (
            task_binding.schema_version
            not in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            and (
                fact.succeeded_observed
                or (fact.artifact_observed and not valid_task_binding)
                or (
                    valid_task_binding
                    and task_publication_evidence_observed
                )
            )
        ):
            expected.add(PUBLICATION_SCOPE)
        observed_counts: dict[str, int] = {}
        for event in events:
            if event.action_scope is not None:
                observed_counts[event.action_scope] = (
                    observed_counts.get(event.action_scope, 0) + 1
                )
        run_issues = [
            *fact.issues,
            *task_binding.issues,
            *task_execution_selection.issues,
            *task_admission_enforcement.integrity_issues,
            *task_billing.issues,
            *mock_dispatch_decision.issues,
            *mock_dispatch_receipt.issues,
            *local_candidate_publication_decision.issues,
            *local_candidate_publication_enforcement.integrity_issues,
            *comparison_binding.issues,
            *comparison_billing.issues,
            *comparison_accounting.issues,
            *comparison_artifact_receipts.issues,
            *task_accounting.issues,
            *task_artifact_receipts.issues,
            *runner_event_issues,
            *task_terminal_issues,
            *_inspect_comparison_action_terminal_linkage(
                fact,
                comparison_artifact_receipts,
            ),
            *_inspect_task_action_terminal_linkage(
                fact,
                task_artifact_receipts,
            ),
        ]
        if task_binding.observed and comparison_binding.observed:
            run_issues.append("authorization_binding_conflict")
        if (
            (task_binding.observed or comparison_binding.observed)
            and (
                fact.billing_sequence is not None
                or fact.accounting_sequence is not None
            )
            and (
                fact.terminal_sequence is None
                or (
                    fact.billing_sequence is not None
                    and fact.billing_sequence >= fact.terminal_sequence
                )
                or (
                    fact.accounting_sequence is not None
                    and fact.accounting_sequence >= fact.terminal_sequence
                )
            )
        ):
            # Once execution-cost evidence exists, an inspector cannot safely
            # distinguish an active attempt from one abandoned before its
            # controller-owned terminal record.  Treat that durable history as
            # attention-required without applying a fallible age heuristic.
            run_issues.append("bound_run_history_incomplete")
        if (
            not comparison_binding.observed
            and any(
                "comparison_shadow_binding_digest_mismatch"
                in event.integrity_issues
                for event in events
            )
        ):
            run_issues.append("comparison_binding_missing")
        if (
            not task_binding.observed
            and (
                task_publication_evidence_observed
                or fact.task_artifact_intent_event_count > 0
                or fact.task_artifact_action_receipt_event_count > 0
            )
        ):
            run_issues.append("task_binding_missing")
        if any(count > 1 for count in observed_counts.values()):
            run_issues.append("duplicate_boundary_event")
        pre_effect_payload = comparison_artifact_receipts.pre_effect
        if isinstance(pre_effect_payload, Mapping):
            publication_shadow_persisted = pre_effect_payload.get(
                "publication_shadow_persisted"
            )
            if publication_shadow_persisted != (
                observed_counts.get(PUBLICATION_SCOPE, 0) == 1
            ):
                run_issues.append(
                    "comparison_publication_shadow_persistence_mismatch"
                )
        task_pre_effect_payload = task_artifact_receipts.pre_effect
        if isinstance(task_pre_effect_payload, Mapping):
            if task_pre_effect_payload.get(
                "publication_shadow_persisted"
            ) != (observed_counts.get(PUBLICATION_SCOPE, 0) == 1):
                run_issues.append(
                    "task_publication_shadow_persistence_mismatch"
                )
        if fact.shadow_event_count > _MAX_SHADOW_EVENTS_PER_RUN:
            run_issues.append("shadow_event_limit_exceeded")
            event_truncated = True
        sequences_by_scope = {
            event.action_scope: event.sequence
            for event in events
            if event.action_scope is not None
        }
        admission_sequence = sequences_by_scope.get(ADMISSION_SCOPE)
        admission_decision_sequence = task_admission_decision.sequence
        admission_receipt_sequence = task_admission_receipt.sequence
        if admission_decision_sequence is not None:
            if (
                task_binding.sequence is None
                or admission_decision_sequence <= task_binding.sequence
                or (
                    task_execution_selection.sequence is not None
                    and admission_decision_sequence
                    <= task_execution_selection.sequence
                )
                or (
                    admission_receipt_sequence is not None
                    and admission_decision_sequence
                    >= admission_receipt_sequence
                )
                or (
                    admission_sequence is not None
                    and admission_decision_sequence >= admission_sequence
                )
                or (
                    fact.billing_sequence is not None
                    and admission_decision_sequence >= fact.billing_sequence
                )
                or (
                    fact.running_sequence is not None
                    and admission_decision_sequence >= fact.running_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and admission_decision_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("task_admission_decision_order_invalid")
        if admission_receipt_sequence is not None:
            if (
                admission_decision_sequence is None
                or admission_receipt_sequence <= admission_decision_sequence
                or (
                    admission_sequence is not None
                    and admission_receipt_sequence >= admission_sequence
                )
                or (
                    fact.billing_sequence is not None
                    and admission_receipt_sequence >= fact.billing_sequence
                )
                or (
                    fact.running_sequence is not None
                    and admission_receipt_sequence >= fact.running_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and admission_receipt_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("task_admission_receipt_order_invalid")
        if mock_dispatch_decision.sequence is not None:
            if (
                admission_sequence is None
                or mock_dispatch_decision.sequence <= admission_sequence
                or (
                    fact.billing_sequence is not None
                    and mock_dispatch_decision.sequence
                    <= fact.billing_sequence
                )
                or (
                    fact.running_sequence is not None
                    and mock_dispatch_decision.sequence
                    >= fact.running_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and mock_dispatch_decision.sequence
                    >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "mock_dispatch_decision_order_invalid"
                )
        if (
            task_execution_selection.observed
            and task_execution_selection.sequence is not None
        ):
            selection_sequence = task_execution_selection.sequence
            if (
                (
                    fact.created_sequence is not None
                    and selection_sequence <= fact.created_sequence
                )
                or (
                    task_binding.sequence is not None
                    and selection_sequence >= task_binding.sequence
                )
                or (
                    admission_sequence is not None
                    and selection_sequence >= admission_sequence
                )
                or (
                    fact.billing_sequence is not None
                    and selection_sequence >= fact.billing_sequence
                )
                or (
                    fact.running_sequence is not None
                    and selection_sequence >= fact.running_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and selection_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("execution_selection_order_invalid")
        if task_binding.observed and task_binding.sequence is not None:
            if (
                (
                    fact.created_sequence is not None
                    and task_binding.sequence <= fact.created_sequence
                )
                or (
                    admission_sequence is not None
                    and task_binding.sequence >= admission_sequence
                )
                or (
                    fact.billing_sequence is not None
                    and task_binding.sequence >= fact.billing_sequence
                )
                or (
                    fact.running_sequence is not None
                    and task_binding.sequence >= fact.running_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and task_binding.sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("task_binding_order_invalid")
        if (
            comparison_binding.observed
            and comparison_binding.sequence is not None
        ):
            if (
                (
                    fact.created_sequence is not None
                    and comparison_binding.sequence <= fact.created_sequence
                )
                or (
                    admission_sequence is not None
                    and comparison_binding.sequence >= admission_sequence
                )
                or (
                    fact.billing_sequence is not None
                    and comparison_binding.sequence >= fact.billing_sequence
                )
                or (
                    fact.running_sequence is not None
                    and comparison_binding.sequence >= fact.running_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and comparison_binding.sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("comparison_binding_order_invalid")
        if admission_sequence is not None:
            if (
                fact.billing_sequence is not None
                and admission_sequence >= fact.billing_sequence
            ) or (
                fact.running_sequence is not None
                and admission_sequence >= fact.running_sequence
            ) or (
                fact.terminal_sequence is not None
                and admission_sequence >= fact.terminal_sequence
            ):
                run_issues.append("admission_boundary_order_invalid")
        if valid_task_binding and fact.running_sequence is not None:
            if fact.billing_sequence is None:
                run_issues.append("task_billing_missing")
            elif fact.billing_sequence >= fact.running_sequence:
                run_issues.append("task_billing_order_invalid")
        if (
            valid_task_binding
            and fact.billing_sequence is not None
            and fact.terminal_sequence is not None
            and fact.billing_sequence >= fact.terminal_sequence
        ):
            run_issues.append("task_billing_order_invalid")
        dispatch_sequence = sequences_by_scope.get(DISPATCH_SCOPE)
        if (
            mock_dispatch_decision.sequence is not None
            and dispatch_sequence is not None
            and mock_dispatch_decision.sequence >= dispatch_sequence
        ):
            run_issues.append("mock_dispatch_decision_order_invalid")
        if (
            mock_dispatch_receipt.sequence is not None
            and dispatch_sequence is not None
            and mock_dispatch_receipt.sequence <= dispatch_sequence
        ):
            run_issues.append("mock_dispatch_receipt_order_invalid")
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
                or (
                    fact.terminal_sequence is not None
                    and dispatch_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("dispatch_boundary_order_invalid")
        if fact.runner_event_count > 0:
            if (
                fact.running_sequence is None
                or dispatch_sequence is None
                or fact.runner_event_sequence is None
                or fact.runner_event_sequence <= dispatch_sequence
                or (
                    fact.accounting_sequence is not None
                    and fact.runner_event_last_sequence is not None
                    and fact.runner_event_last_sequence
                    >= fact.accounting_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and fact.runner_event_last_sequence is not None
                    and fact.runner_event_last_sequence
                    >= fact.terminal_sequence
                )
            ):
                run_issues.append("runner_event_order_invalid")
        publication_sequence = sequences_by_scope.get(PUBLICATION_SCOPE)
        publication_receipts_expected = (
            task_binding.schema_version
            not in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            or _local_candidate_publication_receipts_expected(
                fact,
                local_candidate_publication_decision,
                terminal_event_rows_by_run[fact.raw_run_id],
            )
        )
        if publication_sequence is not None:
            if (
                comparison_binding.schema_version == 2
                and comparison_artifact_receipts.pre_effect is None
            ):
                run_issues.append(
                    "comparison_publication_pre_effect_receipt_missing"
                )
            if (
                comparison_binding.schema_version == 2
                and comparison_artifact_receipts.action is None
            ):
                run_issues.append(
                    "comparison_publication_action_receipt_missing"
                )
            if (
                fact.accounting_sequence is None
                or publication_sequence <= fact.accounting_sequence
                or (
                    fact.terminal_sequence is not None
                    and publication_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("publication_boundary_order_invalid")
            if valid_task_binding and publication_receipts_expected:
                if task_artifact_receipts.pre_effect is None:
                    run_issues.append(
                        "task_publication_pre_effect_receipt_missing"
                    )
                if task_artifact_receipts.action is None:
                    run_issues.append(
                        "task_publication_action_receipt_missing"
                    )
        pre_effect_sequence = comparison_artifact_receipts.pre_effect_sequence
        action_receipt_sequence = comparison_artifact_receipts.action_sequence
        if pre_effect_sequence is not None:
            if (
                fact.accounting_sequence is None
                or pre_effect_sequence <= fact.accounting_sequence
                or publication_sequence is None
                or pre_effect_sequence <= publication_sequence
                or (
                    fact.terminal_sequence is not None
                    and pre_effect_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "comparison_publication_pre_effect_order_invalid"
                )
        if action_receipt_sequence is not None:
            if (
                pre_effect_sequence is None
                or action_receipt_sequence <= pre_effect_sequence
                or (
                    fact.terminal_sequence is not None
                    and action_receipt_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "comparison_publication_action_receipt_order_invalid"
                )
        task_pre_effect_sequence = task_artifact_receipts.pre_effect_sequence
        task_action_receipt_sequence = task_artifact_receipts.action_sequence
        publication_decision_sequence = (
            local_candidate_publication_decision.sequence
        )
        if publication_decision_sequence is not None:
            if (
                fact.accounting_sequence is None
                or publication_decision_sequence <= fact.accounting_sequence
                or mock_dispatch_receipt.sequence is None
                or publication_decision_sequence
                <= mock_dispatch_receipt.sequence
                or (
                    publication_sequence is not None
                    and publication_decision_sequence
                    <= publication_sequence
                )
                or (
                    task_pre_effect_sequence is not None
                    and publication_decision_sequence
                    >= task_pre_effect_sequence
                )
                or (
                    fact.terminal_sequence is not None
                    and publication_decision_sequence
                    >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "local_candidate_publication_decision_order_invalid"
                )
        if task_pre_effect_sequence is not None:
            if (
                fact.accounting_sequence is None
                or task_pre_effect_sequence <= fact.accounting_sequence
                or (
                    task_binding.schema_version
                    not in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
                    and publication_sequence is None
                )
                or (
                    publication_sequence is not None
                    and task_pre_effect_sequence <= publication_sequence
                )
                or (
                    task_binding.schema_version
                    in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
                    and (
                        publication_decision_sequence is None
                        or task_pre_effect_sequence
                        <= publication_decision_sequence
                    )
                )
                or (
                    fact.terminal_sequence is not None
                    and task_pre_effect_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "task_publication_pre_effect_order_invalid"
                )
        if task_action_receipt_sequence is not None:
            if (
                task_pre_effect_sequence is None
                or task_action_receipt_sequence <= task_pre_effect_sequence
                or (
                    fact.terminal_sequence is not None
                    and task_action_receipt_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "task_publication_action_receipt_order_invalid"
                )
        if valid_task_binding and fact.accounting_sequence is not None:
            if (
                dispatch_sequence is None
                or fact.accounting_sequence <= dispatch_sequence
            ) or (
                fact.terminal_sequence is not None
                and fact.accounting_sequence >= fact.terminal_sequence
            ):
                run_issues.append("task_execution_accounting_order_invalid")
        observed = tuple(sorted(observed_counts))
        missing = tuple(sorted(expected.difference(observed_counts)))
        all_runs.append(
            RunAuthorizationInspection(
                run_id=fact.run_id,
                run_ref=fact.run_ref,
                run_kind=(
                    COMPARISON_RUN_KIND
                    if valid_comparison_binding
                    else TASK_ATTEMPT_RUN_KIND
                ),
                authorization_shadow_coverage=(
                    comparison_binding.authorization_shadow_coverage
                    if valid_comparison_binding
                    else task_binding.authorization_shadow_coverage
                    if valid_task_binding
                    else TASK_ATTEMPT_SHADOW_COVERAGE
                ),
                authorization_action_receipt_coverage=(
                    comparison_binding.authorization_action_receipt_coverage
                    if valid_comparison_binding
                    else task_binding.authorization_action_receipt_coverage
                    if valid_task_binding
                    else None
                ),
                admission_authorization_enforcement_coverage=(
                    task_binding
                    .admission_authorization_enforcement_coverage
                    if valid_task_binding
                    else None
                ),
                authorization_enforcement_coverage=(
                    task_binding.authorization_enforcement_coverage
                    if valid_task_binding
                    else None
                ),
                publication_authorization_enforcement_coverage=(
                    task_binding
                    .publication_authorization_enforcement_coverage
                    if valid_task_binding
                    else None
                ),
                permission_class=fact.permission_class,
                attempt=fact.attempt,
                latest_status=fact.latest_status,
                expected_scopes=tuple(sorted(expected)),
                observed_scopes=observed,
                missing_scopes=missing,
                events=events,
                task_admission_enforcement=task_admission_enforcement,
                mock_dispatch_enforcement=mock_dispatch_enforcement,
                local_candidate_publication_enforcement=(
                    local_candidate_publication_enforcement
                ),
                integrity_issues=tuple(sorted(set(run_issues))),
            )
        )

    inspected_event_count = (
        len(event_rows)
        + len(task_admission_decision_rows)
        + len(task_admission_receipt_rows)
        + len(mock_dispatch_decision_rows)
        + len(mock_dispatch_receipt_rows)
        + len(local_candidate_publication_decision_rows)
    )
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
    integrity_issue_count = len(schema_issues) + sum(
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
        integrity_issues=schema_issues,
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
        integrity_issues=(),
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

    with tempfile.TemporaryDirectory(prefix="ordomata-auth-inspect-") as temporary:
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
            r.task_id,
            r.task_version,
            r.runner_id,
            r.run_directory,
            r.context_digest,
            r.permission_class,
            r.timeout_seconds,
            r.attempt,
            EXISTS (
                SELECT 1 FROM run_events running
                WHERE running.run_id = r.run_id AND running.status = 'running'
            ) AS running_observed,
            EXISTS (
                SELECT 1 FROM run_events succeeded
                WHERE succeeded.run_id = r.run_id AND succeeded.status = 'succeeded'
            ) AS succeeded_observed,
            (
                EXISTS (
                    SELECT 1 FROM run_artifacts artifact
                    WHERE artifact.run_id = r.run_id
                )
                OR EXISTS (
                    SELECT 1 FROM run_events comparison_artifact
                    WHERE comparison_artifact.run_id = r.run_id
                      AND comparison_artifact.event_type IN (?, ?, ?)
                )
            ) AS artifact_observed,
            (
                SELECT latest.status FROM run_events latest
                WHERE latest.run_id = r.run_id AND latest.status IS NOT NULL
                ORDER BY latest.sequence DESC LIMIT 1
            ) AS latest_status,
            (
                SELECT CASE
                    WHEN json_valid(terminal.payload_json) THEN
                        CASE json_type(
                            terminal.payload_json,
                            '$.artifact_observed'
                        )
                            WHEN 'true' THEN 1
                            WHEN 'false' THEN 0
                            ELSE NULL
                        END
                    ELSE NULL
                END
                FROM run_events terminal
                WHERE terminal.run_id = r.run_id
                  AND terminal.status IN (
                      'succeeded', 'failed', 'blocked',
                      'quarantined', 'cancelled'
                  )
                ORDER BY terminal.sequence DESC LIMIT 1
            ) AS terminal_artifact_observed,
            (
                SELECT COUNT(*) FROM run_events shadow
                WHERE shadow.run_id = r.run_id
                  AND shadow.event_type = ?
            ) AS shadow_event_count
            ,(
                SELECT COUNT(*) FROM run_events binding
                WHERE binding.run_id = r.run_id
                  AND binding.event_type = ?
            ) AS comparison_binding_event_count
            ,(
                SELECT COUNT(*) FROM run_events comparison_billing
                WHERE comparison_billing.run_id = r.run_id
                  AND comparison_billing.event_type = 'billing_assessment'
            ) AS comparison_billing_event_count
            ,(
                SELECT COUNT(*) FROM run_events comparison_accounting
                WHERE comparison_accounting.run_id = r.run_id
                  AND comparison_accounting.event_type = 'execution_accounting'
            ) AS comparison_accounting_event_count
            ,(
                SELECT COUNT(*) FROM run_events artifact_intent
                WHERE artifact_intent.run_id = r.run_id
                  AND artifact_intent.event_type = ?
            ) AS comparison_artifact_intent_event_count
            ,(
                SELECT COUNT(*) FROM run_events artifact_observed
                WHERE artifact_observed.run_id = r.run_id
                  AND artifact_observed.event_type = ?
            ) AS comparison_artifact_observed_event_count
            ,(
                SELECT COUNT(*) FROM run_events artifact_receipt
                WHERE artifact_receipt.run_id = r.run_id
                  AND artifact_receipt.event_type = ?
            ) AS comparison_artifact_action_receipt_event_count
            ,(
                SELECT COUNT(*) FROM run_events task_binding
                WHERE task_binding.run_id = r.run_id
                  AND task_binding.event_type = ?
            ) AS task_binding_event_count
            ,(
                SELECT COUNT(*) FROM run_events execution_selection
                WHERE execution_selection.run_id = r.run_id
                  AND execution_selection.event_type = ?
            ) AS task_execution_selection_event_count
            ,(
                SELECT COUNT(*) FROM run_events task_artifact_intent
                WHERE task_artifact_intent.run_id = r.run_id
                  AND task_artifact_intent.event_type = ?
            ) AS task_artifact_intent_event_count
            ,(
                SELECT COUNT(*) FROM run_events task_artifact_receipt
                WHERE task_artifact_receipt.run_id = r.run_id
                  AND task_artifact_receipt.event_type = ?
            ) AS task_artifact_action_receipt_event_count
            ,(
                SELECT COUNT(*) FROM run_artifacts task_artifact
                WHERE task_artifact.run_id = r.run_id
            ) AS task_artifact_metadata_count
            ,(
                SELECT MIN(created.sequence) FROM run_events created
                WHERE created.run_id = r.run_id
                  AND created.status = 'created'
            ) AS created_sequence
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
                SELECT COUNT(*) FROM run_events observed
                WHERE observed.run_id = r.run_id
                  AND observed.event_type = 'runner_event_observed'
            ) AS runner_event_count
            ,(
                SELECT MAX(observed.sequence) FROM run_events observed
                WHERE observed.run_id = r.run_id
                  AND observed.event_type = 'runner_event_observed'
            ) AS runner_event_last_sequence
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
        (
            COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            AUTHORIZATION_SHADOW_EVENT_TYPE,
            COMPARISON_TRIAL_BINDING_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            TASK_ATTEMPT_BINDING_EVENT_TYPE,
            TASK_EXECUTION_SELECTION_EVENT_TYPE,
            TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
            TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            *parameters,
        ),
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
        timeout_seconds = row["timeout_seconds"]
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds <= 0
        ):
            timeout_seconds = None
            issues.append("run_timeout_invalid")
        attempt = row["attempt"]
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0:
            attempt = None
            issues.append("run_attempt_invalid")
        latest_status = row["latest_status"]
        if latest_status is not None and latest_status not in _KNOWN_STATUSES:
            latest_status = None
            issues.append("run_status_invalid")
        raw_terminal_artifact_observed = row[
            "terminal_artifact_observed"
        ]
        terminal_artifact_observed = (
            bool(raw_terminal_artifact_observed)
            if raw_terminal_artifact_observed in {0, 1}
            and not isinstance(raw_terminal_artifact_observed, bool)
            else None
        )
        shadow_event_count = row["shadow_event_count"]
        if (
            isinstance(shadow_event_count, bool)
            or not isinstance(shadow_event_count, int)
            or shadow_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid shadow event count")
        comparison_binding_event_count = row["comparison_binding_event_count"]
        if (
            isinstance(comparison_binding_event_count, bool)
            or not isinstance(comparison_binding_event_count, int)
            or comparison_binding_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid comparison binding event count")
        comparison_billing_event_count = row["comparison_billing_event_count"]
        if (
            isinstance(comparison_billing_event_count, bool)
            or not isinstance(comparison_billing_event_count, int)
            or comparison_billing_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid comparison billing event count")
        comparison_accounting_event_count = row[
            "comparison_accounting_event_count"
        ]
        if (
            isinstance(comparison_accounting_event_count, bool)
            or not isinstance(comparison_accounting_event_count, int)
            or comparison_accounting_event_count < 0
        ):
            raise sqlite3.DatabaseError(
                "invalid comparison accounting event count"
            )
        comparison_artifact_intent_event_count = row[
            "comparison_artifact_intent_event_count"
        ]
        comparison_artifact_observed_event_count = row[
            "comparison_artifact_observed_event_count"
        ]
        comparison_artifact_action_receipt_event_count = row[
            "comparison_artifact_action_receipt_event_count"
        ]
        for value in (
            comparison_artifact_intent_event_count,
            comparison_artifact_observed_event_count,
            comparison_artifact_action_receipt_event_count,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise sqlite3.DatabaseError(
                    "invalid comparison artifact event count"
                )
        task_binding_event_count = row["task_binding_event_count"]
        task_execution_selection_event_count = row[
            "task_execution_selection_event_count"
        ]
        task_artifact_intent_event_count = row[
            "task_artifact_intent_event_count"
        ]
        task_artifact_action_receipt_event_count = row[
            "task_artifact_action_receipt_event_count"
        ]
        task_artifact_metadata_count = row["task_artifact_metadata_count"]
        for value in (
            task_binding_event_count,
            task_execution_selection_event_count,
            task_artifact_intent_event_count,
            task_artifact_action_receipt_event_count,
            task_artifact_metadata_count,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise sqlite3.DatabaseError("invalid task evidence count")
        created_sequence = _optional_sequence(row["created_sequence"])
        billing_sequence = _optional_sequence(row["billing_sequence"])
        running_sequence = _optional_sequence(row["running_sequence"])
        accounting_sequence = _optional_sequence(row["accounting_sequence"])
        runner_event_count = row["runner_event_count"]
        if (
            isinstance(runner_event_count, bool)
            or not isinstance(runner_event_count, int)
            or runner_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid runner event count")
        runner_event_sequence = _optional_sequence(row["runner_event_sequence"])
        runner_event_last_sequence = _optional_sequence(
            row["runner_event_last_sequence"]
        )
        terminal_sequence = _optional_sequence(row["terminal_sequence"])
        facts.append(
            _RunFacts(
                raw_run_id=raw_run_id,
                raw_task_id=row["task_id"],
                raw_task_version=row["task_version"],
                raw_runner_id=row["runner_id"],
                raw_run_directory=row["run_directory"],
                raw_context_digest=row["context_digest"],
                timeout_seconds=timeout_seconds,
                run_id=safe_run_id,
                run_ref=canonical_digest({"run_id": raw_run_id}),
                permission_class=permission_class,
                attempt=attempt,
                latest_status=latest_status,
                terminal_artifact_observed=terminal_artifact_observed,
                running_observed=bool(row["running_observed"]),
                succeeded_observed=bool(row["succeeded_observed"]),
                artifact_observed=bool(row["artifact_observed"]),
                shadow_event_count=shadow_event_count,
                comparison_binding_event_count=comparison_binding_event_count,
                comparison_billing_event_count=comparison_billing_event_count,
                comparison_accounting_event_count=(
                    comparison_accounting_event_count
                ),
                comparison_artifact_intent_event_count=(
                    comparison_artifact_intent_event_count
                ),
                comparison_artifact_observed_event_count=(
                    comparison_artifact_observed_event_count
                ),
                comparison_artifact_action_receipt_event_count=(
                    comparison_artifact_action_receipt_event_count
                ),
                task_binding_event_count=task_binding_event_count,
                task_execution_selection_event_count=(
                    task_execution_selection_event_count
                ),
                task_artifact_intent_event_count=(
                    task_artifact_intent_event_count
                ),
                task_artifact_action_receipt_event_count=(
                    task_artifact_action_receipt_event_count
                ),
                task_artifact_metadata_count=task_artifact_metadata_count,
                created_sequence=created_sequence,
                billing_sequence=billing_sequence,
                running_sequence=running_sequence,
                accounting_sequence=accounting_sequence,
                runner_event_count=runner_event_count,
                runner_event_sequence=runner_event_sequence,
                runner_event_last_sequence=runner_event_last_sequence,
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
                event_id,
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
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_shadow_events
        WHERE boundary_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_mock_dispatch_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
    *,
    event_type: str,
) -> tuple[sqlite3.Row, ...]:
    """Read at most two enforcing events per type so duplicates are visible."""

    if not facts:
        return ()
    if event_type not in {
        MOCK_DISPATCH_DECISION_EVENT_TYPE,
        MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
    }:
        raise ValueError("unsupported mock dispatch event type")
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        event_type,
        *(fact.raw_run_id for fact in facts),
        _MAX_MOCK_DISPATCH_EVENTS_PER_TYPE_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_mock_dispatch_events AS (
            SELECT
                event_id,
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS event_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_mock_dispatch_events
        WHERE event_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_local_candidate_publication_decision_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read two decisions per run so duplicate publication gates are visible."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
        *(fact.raw_run_id for fact in facts),
        _MAX_LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_publication_decisions AS (
            SELECT
                event_id,
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS event_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_publication_decisions
        WHERE event_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_binding_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two bindings per run so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        COMPARISON_TRIAL_BINDING_EVENT_TYPE,
        *(fact.raw_run_id for fact in facts),
        _MAX_COMPARISON_BINDING_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_comparison_bindings AS (
            SELECT
                run_id,
                sequence,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS binding_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT run_id, sequence, payload_json
        FROM ranked_comparison_bindings
        WHERE binding_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_billing_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two billing assessments so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        "billing_assessment",
        _MAX_COMPARISON_BILLING_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_billing_events AS (
            SELECT
                event_id,
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS billing_rank
            FROM run_events
            WHERE run_id IN ({placeholders}) AND event_type = ?
        )
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_billing_events
        WHERE billing_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_accounting_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two accounting records so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        _MAX_COMPARISON_ACCOUNTING_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_accounting_events AS (
            SELECT
                event_id,
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS accounting_rank
            FROM run_events
            WHERE run_id IN ({placeholders})
              AND event_type = 'execution_accounting'
        )
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_accounting_events
        WHERE accounting_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_artifact_receipt_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read two events of each receipt kind so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    event_types = (
        COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE,
        COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE,
        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    )
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        *event_types,
        _MAX_COMPARISON_ARTIFACT_EVENTS_PER_TYPE_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_artifact_events AS (
            SELECT
                run_id,
                event_type,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id, event_type ORDER BY sequence
                ) AS artifact_event_rank
            FROM run_events
            WHERE run_id IN ({placeholders})
              AND event_type IN (?, ?, ?)
        )
        SELECT run_id, event_type, sequence, occurred_at, payload_json
        FROM ranked_artifact_events
        WHERE artifact_event_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_task_binding_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two task bindings so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        TASK_ATTEMPT_BINDING_EVENT_TYPE,
        *(fact.raw_run_id for fact in facts),
        _MAX_TASK_BINDING_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_task_bindings AS (
            SELECT
                event_id,
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS binding_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_task_bindings
        WHERE binding_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_task_execution_selection_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two selections so duplicate evidence remains detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        TASK_EXECUTION_SELECTION_EVENT_TYPE,
        *(fact.raw_run_id for fact in facts),
        _MAX_TASK_EXECUTION_SELECTION_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_task_execution_selections AS (
            SELECT
                event_id,
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS selection_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_task_execution_selections
        WHERE selection_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_task_admission_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
    *,
    event_type: str,
) -> tuple[sqlite3.Row, ...]:
    """Read two admission events per type so duplicates stay observable."""

    if not facts:
        return ()
    if event_type not in {
        TASK_ADMISSION_DECISION_EVENT_TYPE,
        TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
    }:
        raise ValueError("unsupported task admission event type")
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        event_type,
        *(fact.raw_run_id for fact in facts),
        _MAX_TASK_ADMISSION_EVENTS_PER_TYPE_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_task_admission_events AS (
            SELECT
                event_id,
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS event_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT event_id, run_id, sequence, occurred_at, payload_json
        FROM ranked_task_admission_events
        WHERE event_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_task_artifact_receipt_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read two events of each task receipt kind per run."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    event_types = (
        TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
        TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    )
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        *event_types,
        _MAX_TASK_ARTIFACT_EVENTS_PER_TYPE_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_task_artifact_events AS (
            SELECT
                event_id,
                run_id,
                event_type,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id, event_type ORDER BY sequence
                ) AS artifact_event_rank
            FROM run_events
            WHERE run_id IN ({placeholders})
              AND event_type IN (?, ?)
        )
        SELECT
            event_id,
            run_id,
            event_type,
            sequence,
            occurred_at,
            payload_json
        FROM ranked_task_artifact_events
        WHERE artifact_event_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_task_artifact_metadata(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read bounded private metadata used only to recompute safe digests."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        _MAX_TASK_ARTIFACT_METADATA_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_task_artifacts AS (
            SELECT
                artifact_id,
                run_id,
                kind,
                path,
                sha256,
                media_type,
                size_bytes,
                created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY created_at, artifact_id
                ) AS artifact_rank
            FROM run_artifacts
            WHERE run_id IN ({placeholders})
        )
        SELECT
            artifact_id,
            run_id,
            kind,
            path,
            sha256,
            media_type,
            size_bytes,
            created_at
        FROM ranked_task_artifacts
        WHERE artifact_rank <= ?
        ORDER BY run_id, artifact_rank
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_runner_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read a bounded ordinal-only runner-event projection per run."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        _MAX_RUNNER_EVENTS_PER_RUN + 1,
    )
    rows = connection.execute(
        f"""
        WITH ranked_runner_events AS (
            SELECT
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS runner_event_rank
            FROM run_events
            WHERE run_id IN ({placeholders})
              AND event_type = 'runner_event_observed'
        )
        SELECT
            run_id,
            sequence,
            occurred_at,
            payload_json,
            runner_event_rank
        FROM ranked_runner_events
        WHERE runner_event_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_terminal_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read two terminal rows so duplicate bound-task terminals are visible."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        _MAX_TERMINAL_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_terminal_events AS (
            SELECT
                event_id,
                run_id,
                event_type,
                status,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS terminal_rank
            FROM run_events
            WHERE run_id IN ({placeholders})
              AND status IN (
                  'succeeded', 'failed', 'blocked',
                  'quarantined', 'cancelled'
              )
        )
        SELECT
            event_id,
            run_id,
            event_type,
            status,
            sequence,
            occurred_at,
            payload_json
        FROM ranked_terminal_events
        WHERE terminal_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _inspect_runner_events(
    fact: _RunFacts,
    rows: list[sqlite3.Row],
) -> tuple[str, ...]:
    """Require bounded, finite, ordinal-only runner observations."""

    if fact.runner_event_count == 0:
        return () if not rows else ("runner_event_record_mismatch",)
    if (
        fact.runner_event_count > _MAX_RUNNER_EVENTS_PER_RUN
        or len(rows) != fact.runner_event_count
    ):
        return ("runner_event_limit_exceeded",)

    issues: list[str] = []
    previous_sequence: int | None = None
    for expected_ordinal, row in enumerate(rows, start=1):
        sequence = _optional_sequence(row["sequence"])
        if (
            sequence is None
            or (
                previous_sequence is not None
                and sequence <= previous_sequence
            )
        ):
            issues.append("runner_event_order_invalid")
        previous_sequence = sequence
        if _optional_timestamp(row["occurred_at"]) is None:
            issues.append("runner_event_timestamp_invalid")
        payload = _bounded_json_mapping(row["payload_json"])
        ordinal = (
            payload.get("ordinal")
            if isinstance(payload, Mapping)
            else None
        )
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {"ordinal"}
            or isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal != expected_ordinal
        ):
            issues.append("runner_event_payload_invalid")
    return tuple(sorted(set(issues)))


def _inspect_task_attempt_binding(
    fact: _RunFacts,
    rows: list[sqlite3.Row],
) -> _TaskAttemptBindingFacts:
    """Validate one digest-only ordinary task-attempt binding."""

    if fact.task_binding_event_count == 0:
        return _TaskAttemptBindingFacts(False, None, None, None, ())
    if fact.task_binding_event_count != 1 or len(rows) != 1:
        return _TaskAttemptBindingFacts(
            True,
            None,
            None,
            None,
            ("task_binding_duplicate",),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    payload = _bounded_json_mapping(row["payload_json"])
    schema_version = payload.get("schema_version") if payload is not None else None
    expected_outer_keys = {
        "authorization_action_receipt_coverage",
        "authorization_shadow_coverage",
        "binding",
        "binding_digest",
        "schema_version",
    }
    if schema_version in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS:
        expected_outer_keys.add("authorization_enforcement_coverage")
    if schema_version in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS:
        expected_outer_keys.add(
            "publication_authorization_enforcement_coverage"
        )
    if schema_version in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS:
        expected_outer_keys.add(
            "admission_authorization_enforcement_coverage"
        )
    if payload is None or set(payload) != expected_outer_keys:
        return _invalid_task_binding(
            sequence,
            "task_binding_payload_invalid",
            schema_version=(
                schema_version if schema_version in {3, 4, 5} else None
            ),
        )
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version not in {1, 2, 3, 4, 5}
        or payload.get("authorization_shadow_coverage")
        != TASK_ATTEMPT_SHADOW_COVERAGE
        or payload.get("authorization_action_receipt_coverage")
        != TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE
        or (
            schema_version
            in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            and payload.get("authorization_enforcement_coverage")
            != TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
        )
        or (
            schema_version
            in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            and payload.get(
                "publication_authorization_enforcement_coverage"
            )
            != TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
        )
        or (
            schema_version
            in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            and payload.get(
                "admission_authorization_enforcement_coverage"
            )
            != TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE
        )
    ):
        return _invalid_task_binding(
            sequence,
            "task_binding_payload_invalid",
            schema_version=(
                schema_version if schema_version in {3, 4, 5} else None
            ),
        )
    binding = payload.get("binding")
    if not _is_task_attempt_binding_shape(
        binding,
        schema_version=schema_version,
    ):
        return _invalid_task_binding(
            sequence,
            "task_binding_payload_invalid",
            schema_version=(
                schema_version if schema_version in {3, 4, 5} else None
            ),
        )
    assert isinstance(binding, Mapping)
    binding_digest = payload.get("binding_digest")
    if not _digest_matches(binding_digest, binding):
        return _TaskAttemptBindingFacts(
            True,
            sequence,
            None,
            None,
            ("task_binding_digest_mismatch",),
            admission_authorization_enforcement_coverage=(
                TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE
                if schema_version
                in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
                else None
            ),
            authorization_enforcement_coverage=(
                TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
                if schema_version
                in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
                else None
            ),
            publication_authorization_enforcement_coverage=(
                TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
                if schema_version
                in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
                else None
            ),
            schema_version=schema_version,
        )

    issues: list[str] = []
    if _optional_timestamp(row["occurred_at"]) is None:
        issues.append("task_binding_timestamp_invalid")
    if row["event_id"] != binding_digest:
        issues.append("task_binding_event_identifier_mismatch")
    if (
        binding.get("run_ref") != fact.run_ref
        or binding.get("task_id") != fact.raw_task_id
        or binding.get("task_version") != fact.raw_task_version
        or binding.get("runner_id") != fact.raw_runner_id
        or _normalize_sha256_digest(binding.get("context_digest"))
        != _normalize_sha256_digest(fact.raw_context_digest)
        or binding.get("timeout_seconds") != fact.timeout_seconds
        or binding.get("attempt") != fact.attempt
        or binding.get("permission_class") != fact.permission_class
    ):
        issues.append("task_binding_record_mismatch")
    return _TaskAttemptBindingFacts(
        True,
        sequence,
        binding,
        binding_digest,
        tuple(issues),
        admission_authorization_enforcement_coverage=(
            TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE
            if schema_version
            in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            else None
        ),
        authorization_enforcement_coverage=(
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
            if schema_version
            in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            else None
        ),
        publication_authorization_enforcement_coverage=(
            TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
            if schema_version
            in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            else None
        ),
        schema_version=schema_version,
    )


def _invalid_task_binding(
    sequence: int | None,
    issue: str,
    *,
    schema_version: int | None = None,
) -> _TaskAttemptBindingFacts:
    return _TaskAttemptBindingFacts(
        True,
        sequence,
        None,
        None,
        (issue,),
        admission_authorization_enforcement_coverage=(
            TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE
            if schema_version
            in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            else None
        ),
        authorization_enforcement_coverage=(
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
            if schema_version
            in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            else None
        ),
        publication_authorization_enforcement_coverage=(
            TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
            if schema_version
            in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            else None
        ),
        schema_version=schema_version,
    )


def _inspect_task_execution_selection(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    rows: list[sqlite3.Row],
) -> _TaskExecutionSelectionFacts:
    """Validate one bounded, controller-authored profile-selection record."""

    required = (
        task_binding.schema_version
        in _SELECTED_TASK_BINDING_SCHEMA_VERSIONS
    )
    if fact.task_execution_selection_event_count == 0:
        return _TaskExecutionSelectionFacts(
            False,
            None,
            None,
            None,
            None,
            ("execution_selection_missing",) if required else (),
        )
    if (
        fact.task_execution_selection_event_count != 1
        or len(rows) != 1
    ):
        return _TaskExecutionSelectionFacts(
            True,
            None,
            None,
            None,
            None,
            ("execution_selection_duplicate",),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    payload = _bounded_json_mapping(row["payload_json"])
    if (
        payload is None
        or set(payload) != {"schema_version", "selection", "selection_digest"}
        or payload.get("schema_version") != 1
    ):
        return _invalid_task_execution_selection(
            sequence,
            "execution_selection_payload_invalid",
        )
    selection = payload.get("selection")
    if not isinstance(selection, Mapping) or set(selection) != {
        "authorization_intent_digest",
        "candidate_set_digest",
        "candidates",
        "context_digest",
        "evaluated_at",
        "kind",
        "routing_policy_digest",
        "routing_policy_id",
        "routing_policy_version",
        "required_valid_until",
        "run_ref",
        "selected",
        "selection_mode",
        "task",
        "task_definition_digest",
        "task_features_digest",
    }:
        return _invalid_task_execution_selection(
            sequence,
            "execution_selection_payload_invalid",
        )
    selection_digest = payload.get("selection_digest")
    issues: list[str] = []
    if not _digest_matches(selection_digest, selection):
        issues.append("execution_selection_digest_mismatch")
        selection_digest = None
    if _optional_timestamp(row["occurred_at"]) is None:
        issues.append("execution_selection_timestamp_invalid")
    if row["event_id"] != payload.get("selection_digest"):
        issues.append("execution_selection_event_identifier_mismatch")
    issues.extend(_inspect_execution_selection_projection(selection))
    try:
        validate_execution_selection_payload(payload)
    except (ValidationError, TypeError, ValueError, RecursionError):
        issues.append("execution_selection_payload_invalid")

    selected = selection.get("selected")
    if selected is not None and not isinstance(selected, Mapping):
        issues.append("execution_selection_payload_invalid")
        selected = None
    binding = task_binding.binding
    if (
        task_binding.schema_version
        not in _SELECTED_TASK_BINDING_SCHEMA_VERSIONS
    ):
        issues.append("execution_selection_unbound")
    elif not isinstance(binding, Mapping) or task_binding.issues:
        issues.append("execution_selection_binding_mismatch")
    elif (
        selection_digest is None
        or binding.get("execution_selection_digest") != selection_digest
        or selection.get("run_ref") != fact.run_ref
        or selection.get("task_definition_digest")
        != binding.get("task_definition_digest")
        or _normalize_sha256_digest(selection.get("context_digest"))
        != _normalize_sha256_digest(binding.get("context_digest"))
        or selection.get("authorization_intent_digest")
        != binding.get("authorization_intent_digest")
        or not isinstance(selected, Mapping)
        or selected.get("profile_ref") != binding.get("profile_ref")
        or selected.get("profile_version_ref")
        != binding.get("profile_version_ref")
        or selected.get("profile_configuration_digest")
        != binding.get("profile_configuration_digest")
        or selected.get("runner_id") != binding.get("runner_id")
        or selected.get("runner_overrides_digest")
        != binding.get("runner_overrides_digest")
    ):
        issues.append("execution_selection_binding_mismatch")

    task = selection.get("task")
    if (
        not isinstance(task, Mapping)
        or selection.get("run_ref") != fact.run_ref
        or selection.get("task_definition_digest")
        != (
            binding.get("task_definition_digest")
            if isinstance(binding, Mapping)
            else None
        )
        or _normalize_sha256_digest(selection.get("context_digest"))
        != _normalize_sha256_digest(fact.raw_context_digest)
        or task.get("permission_class") != fact.permission_class
        or (
            isinstance(selected, Mapping)
            and selected.get("runner_id") != fact.raw_runner_id
        )
    ):
        issues.append("execution_selection_record_mismatch")

    return _TaskExecutionSelectionFacts(
        True,
        sequence,
        selection,
        selection_digest,
        selected if isinstance(selected, Mapping) else None,
        tuple(sorted(set(issues))),
    )


def _invalid_task_execution_selection(
    sequence: int | None,
    issue: str,
) -> _TaskExecutionSelectionFacts:
    return _TaskExecutionSelectionFacts(
        True,
        sequence,
        None,
        None,
        None,
        (issue,),
    )


def _inspect_execution_selection_projection(
    selection: Mapping[str, Any],
) -> tuple[str, ...]:
    """Recompute safe internal links without projecting candidate details."""

    issues: list[str] = []
    task = selection.get("task")
    if not isinstance(task, Mapping) or set(task) != _EXECUTION_SELECTION_TASK_KEYS:
        issues.append("execution_selection_payload_invalid")
    elif not _digest_matches(selection.get("task_features_digest"), task):
        issues.append("execution_selection_task_features_digest_mismatch")

    if (
        selection.get("routing_policy_id") != ROUTING_POLICY_ID
        or selection.get("routing_policy_version") != ROUTING_POLICY_VERSION
        or selection.get("routing_policy_digest") != routing_policy_digest()
    ):
        issues.append("execution_selection_policy_digest_mismatch")
    evaluated_at = _optional_timestamp(selection.get("evaluated_at"))
    required_valid_until = _optional_timestamp(
        selection.get("required_valid_until")
    )
    if (
        selection.get("kind") != EXECUTION_SELECTION_KIND
        or selection.get("selection_mode") not in EXECUTION_SELECTION_MODES
        or not _is_digest(selection.get("run_ref"))
        or not _is_digest(selection.get("task_definition_digest"))
        or not _is_digest(selection.get("context_digest"))
        or not _is_digest(selection.get("authorization_intent_digest"))
        or evaluated_at is None
        or required_valid_until is None
        or required_valid_until < evaluated_at
    ):
        issues.append("execution_selection_payload_invalid")

    candidates = selection.get("candidates")
    if not isinstance(candidates, list):
        issues.append("execution_selection_payload_invalid")
        return tuple(sorted(set(issues)))
    if (
        len(candidates) == 0
        or len(candidates) > MAX_EXECUTION_SELECTION_CANDIDATES
    ):
        issues.append("execution_selection_candidate_limit_exceeded")
    if not _digest_matches_sequence(
        selection.get("candidate_set_digest"),
        candidates,
    ):
        issues.append("execution_selection_candidate_set_digest_mismatch")

    candidate_mappings: list[Mapping[str, Any]] = []
    candidate_profile_ids: set[str] = set()
    ordered_candidate_profile_ids: list[str] = []
    candidate_refs: set[str] = set()
    eligible_ranks: list[int] = []
    for expected_order, candidate in enumerate(candidates):
        if (
            not isinstance(candidate, Mapping)
            or set(candidate) != _EXECUTION_SELECTION_CANDIDATE_KEYS
        ):
            issues.append("execution_selection_payload_invalid")
            continue
        candidate_mappings.append(candidate)
        profile_id = candidate.get("profile_id")
        profile_ref = candidate.get("profile_ref")
        if not _is_execution_selection_profile_id(profile_id):
            issues.append("execution_selection_payload_invalid")
        else:
            assert isinstance(profile_id, str)
            ordered_candidate_profile_ids.append(profile_id)
            if profile_id in candidate_profile_ids:
                issues.append("execution_selection_candidate_order_invalid")
            candidate_profile_ids.add(profile_id)
            if profile_ref != canonical_digest({"profile_id": profile_id}):
                issues.append("execution_selection_profile_reference_mismatch")
        if (
            candidate.get("candidate_order") != expected_order
            or not _is_digest(profile_ref)
            or profile_ref in candidate_refs
        ):
            issues.append("execution_selection_candidate_order_invalid")
        elif isinstance(profile_ref, str):
            candidate_refs.add(profile_ref)
        if not _digest_matches(
            candidate.get("billing_projection_digest"),
            candidate.get("billing"),
        ):
            issues.append("execution_selection_billing_digest_mismatch")
        billing = candidate.get("billing")
        if isinstance(billing, Mapping):
            policy_allowed = billing.get("policy_allowed")
            policy_blockers = billing.get("policy_blocker_codes")
            if (
                not isinstance(policy_allowed, bool)
                or not isinstance(policy_blockers, list)
                or policy_allowed != (len(policy_blockers) == 0)
            ):
                issues.append("execution_selection_policy_evidence_mismatch")
        rejection_codes = candidate.get("rejection_codes")
        if (
            not isinstance(rejection_codes, list)
            or any(code not in ROUTING_REJECTION_CODES for code in rejection_codes)
            or len(rejection_codes) != len(set(rejection_codes))
            or rejection_codes
            != sorted(
                rejection_codes,
                key=ROUTING_REJECTION_CODES.index,
            )
        ):
            issues.append("execution_selection_rejection_codes_mismatch")
        recomputed_rejection_codes = (
            _recompute_execution_selection_rejection_codes(task, candidate)
            if isinstance(task, Mapping)
            else None
        )
        if (
            recomputed_rejection_codes is None
            or rejection_codes != list(recomputed_rejection_codes)
        ):
            issues.append("execution_selection_rejection_codes_mismatch")
        disposition = candidate.get("disposition")
        rank = candidate.get("rank")
        score_vector = candidate.get("score_vector")
        if disposition == "eligible":
            if rejection_codes != [] or not _is_execution_selection_score_vector(
                score_vector
            ) or isinstance(rank, bool) or not isinstance(rank, int) or rank < 0:
                issues.append("execution_selection_ranking_mismatch")
            else:
                eligible_ranks.append(rank)
                recomputed_score = _recompute_execution_selection_score(
                    task,
                    candidate,
                )
                if (
                    recomputed_score is None
                    or score_vector != list(recomputed_score)
                ):
                    issues.append("execution_selection_score_vector_mismatch")
        elif disposition == "rejected":
            if not rejection_codes or score_vector is not None or rank is not None:
                issues.append("execution_selection_ranking_mismatch")
        else:
            issues.append("execution_selection_payload_invalid")

    if ordered_candidate_profile_ids != sorted(ordered_candidate_profile_ids):
        issues.append("execution_selection_candidate_order_invalid")

    if eligible_ranks and tuple(sorted(eligible_ranks)) != tuple(
        range(len(eligible_ranks))
    ):
        issues.append("execution_selection_ranking_mismatch")
    try:
        recomputed_ranking = _recompute_execution_selection_ranking(
            task,
            candidate_mappings,
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        recomputed_ranking = None
    if recomputed_ranking is None:
        issues.append("execution_selection_ranking_mismatch")
    else:
        eligible_candidates = tuple(
            item
            for item in candidate_mappings
            if item.get("disposition") == "eligible"
        )
        if any(
            isinstance(item.get("rank"), bool)
            or not isinstance(item.get("rank"), int)
            for item in eligible_candidates
        ):
            observed_ranking = ()
        else:
            observed_ranking = tuple(
                candidate.get("profile_ref")
                for candidate in sorted(
                    eligible_candidates,
                    key=lambda item: item["rank"],
                )
            )
        if observed_ranking != recomputed_ranking:
            issues.append("execution_selection_ranking_mismatch")
    selected = selection.get("selected")
    if not isinstance(selected, Mapping) or set(selected) != _EXECUTION_SELECTION_SELECTED_KEYS:
        issues.append("execution_selection_selected_candidate_mismatch")
    else:
        selected_profile_id = selected.get("profile_id")
        if not _is_execution_selection_profile_id(selected_profile_id):
            issues.append("execution_selection_payload_invalid")
        elif selected.get("profile_ref") != canonical_digest(
            {"profile_id": selected_profile_id}
        ):
            issues.append("execution_selection_profile_reference_mismatch")
        if not any(
            candidate.get("disposition") == "eligible"
            and all(
                candidate.get(key) == selected.get(key)
                for key in _EXECUTION_SELECTION_SELECTED_CANDIDATE_KEYS
            )
            and candidate.get("rank") == selected.get("rank")
            for candidate in candidate_mappings
        ):
            issues.append("execution_selection_selected_candidate_mismatch")
    return tuple(sorted(set(issues)))


def _digest_matches_sequence(reported: Any, value: list[Any]) -> bool:
    if not _is_digest(reported):
        return False
    try:
        return reported == canonical_digest(value)
    except (TypeError, ValueError, RecursionError):
        return False


def _is_execution_selection_profile_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _SAFE_IDENTIFIER_PATTERN.fullmatch(value) is not None
    )


def _is_execution_selection_score_vector(value: Any) -> bool:
    if not isinstance(value, list) or len(value) != 6:
        return False
    return all(
        item is None
        or (
            not isinstance(item, bool)
            and isinstance(item, (int, float))
            and math.isfinite(float(item))
        )
        for item in value
    )


def _recompute_execution_selection_rejection_codes(
    task: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[str, ...] | None:
    billing = candidate.get("billing")
    runtime = candidate.get("runtime")
    if not isinstance(billing, Mapping) or not isinstance(runtime, Mapping):
        return None
    try:
        codes: list[str] = []
        route = billing["route"]
        if billing["runner_id"] != candidate["runner_id"]:
            codes.append("billing_runner_identity_mismatch")
        if billing["confidence"] != AssessmentConfidence.HIGH.value:
            codes.append("billing_confidence_not_high")
        if billing["policy_allowed"] is not True:
            codes.append("billing_route_prohibited")
        profile_routes = candidate["allowed_billing_routes"]
        if not profile_routes:
            codes.append("profile_billing_route_allowlist_missing")
        elif route not in profile_routes:
            codes.append("profile_billing_route_not_allowed")
        if runtime["available"] is not True:
            codes.append("profile_unavailable")
        if runtime["cooldown_active"] is True:
            codes.append("profile_cooldown_active")
        if runtime["subscription_capacity_available"] is not True:
            codes.append("subscription_capacity_unavailable")
        if task["permission_class"] > candidate["max_permission_class"]:
            codes.append("permission_class_exceeds_profile_limit")
        task_kinds = candidate["task_kinds"]
        if task_kinds and task["task_kind"] not in task_kinds:
            codes.append("task_kind_unsupported")
        allowed_roles = task["allowed_roles"]
        if allowed_roles and candidate["role"] not in allowed_roles:
            codes.append("profile_role_not_enabled")
        lane_routes = task["allowed_billing_routes"]
        if lane_routes and route not in lane_routes:
            codes.append("lane_billing_route_not_enabled")
        if set(task["required_capabilities"]).difference(
            candidate["capabilities"]
        ):
            codes.append("required_capability_missing")
        max_context_bytes = candidate["max_context_bytes"]
        if (
            max_context_bytes is not None
            and task["context_bytes"] > max_context_bytes
        ):
            codes.append("context_exceeds_profile_limit")
    except (KeyError, OverflowError, TypeError, ValueError):
        return None
    return tuple(codes)


def _recompute_execution_selection_score(
    task: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[float | None, ...] | None:
    runtime = candidate.get("runtime")
    if not isinstance(runtime, Mapping):
        return None
    try:
        success = float(runtime["verified_success_rate"]["value"])
        accepted = float(runtime["accepted_result_rate"]["value"])
        recent_failure_rate = float(runtime["recent_failure_rate"])
        evidence_count = int(runtime["evidence_count"])
        permission_headroom = float(
            candidate["max_permission_class"] - task["permission_class"]
        )
        risk = float(task["risk"])
        latency = float(runtime["median_latency_seconds"]["value"])
        efficiency_projection = runtime["subscription_efficiency"]
        efficiency = (
            None
            if efficiency_projection["source"] == "unavailable"
            else round(float(efficiency_projection["value"]), 6)
        )
        values: tuple[float | None, ...] = (
            round(success * (1.0 - recent_failure_rate), 6),
            round(accepted, 6),
            round(min(evidence_count / 20.0, 1.0), 6),
            -risk - permission_headroom,
            efficiency,
            -round(latency, 6),
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if any(
        value is not None and not math.isfinite(float(value))
        for value in values
    ):
        return None
    return values


def _recompute_execution_selection_ranking(
    task: Any,
    candidates: list[Mapping[str, Any]],
) -> tuple[str, ...] | None:
    if not isinstance(task, Mapping):
        return None
    scored: list[tuple[Mapping[str, Any], tuple[float | None, ...]]] = []
    for candidate in candidates:
        if not _is_execution_selection_profile_id(candidate.get("profile_id")):
            return None
        if candidate.get("disposition") != "eligible":
            continue
        score = _recompute_execution_selection_score(task, candidate)
        if score is None:
            return None
        scored.append((candidate, score))

    quality_groups: dict[
        tuple[float | None, ...],
        list[tuple[Mapping[str, Any], tuple[float | None, ...]]],
    ] = {}
    for item in scored:
        quality_groups.setdefault(item[1][:4], []).append(item)

    ranked: list[str] = []
    for quality_key in sorted(quality_groups, reverse=True):
        buckets: dict[
            tuple[Any, ...],
            list[tuple[Mapping[str, Any], tuple[float | None, ...]]],
        ] = {}
        for item in sorted(
            quality_groups[quality_key],
            key=lambda item: item[0].get("profile_id"),
        ):
            candidate, score = item
            runtime = candidate.get("runtime")
            if not isinstance(runtime, Mapping):
                return None
            efficiency = runtime.get("subscription_efficiency")
            if not isinstance(efficiency, Mapping):
                return None
            if efficiency.get("source") == "unavailable":
                key = ("unavailable", candidate.get("profile_id"))
            else:
                key = (
                    "comparable",
                    candidate.get("runner_id"),
                    efficiency.get("pool_ref"),
                    efficiency.get("unit_ref"),
                )
            buckets.setdefault(key, []).append(item)
        for key, bucket in buckets.items():
            if key[0] == "comparable":
                bucket.sort(
                    key=lambda item: (
                        -float(item[1][4]),
                        -float(item[1][5]),
                        item[0].get("profile_id"),
                    )
                )
        while buckets:
            selected_key = min(
                buckets,
                key=lambda key: (
                    -float(buckets[key][0][1][5]),
                    buckets[key][0][0].get("profile_id"),
                ),
            )
            selected = buckets[selected_key].pop(0)
            profile_ref = selected[0].get("profile_ref")
            if not isinstance(profile_ref, str):
                return None
            ranked.append(profile_ref)
            if not buckets[selected_key]:
                del buckets[selected_key]
    return tuple(ranked)


def _inspect_comparison_binding(
    fact: _RunFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonBindingFacts:
    """Validate one digest-only controller binding without projecting it."""

    if fact.comparison_binding_event_count == 0:
        return _ComparisonBindingFacts(False, None, None, None, ())
    if fact.comparison_binding_event_count != 1 or len(rows) != 1:
        return _ComparisonBindingFacts(
            True,
            None,
            None,
            None,
            ("comparison_binding_duplicate",),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    if len(payload_json.encode("utf-8", errors="replace")) > _MAX_PAYLOAD_BYTES:
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    if not isinstance(payload, Mapping):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    schema_version = payload.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version not in {1, 2}
    ):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    expected_outer_keys = (
        {
            "authorization_shadow_coverage",
            "binding",
            "binding_digest",
            "schema_version",
        }
        if schema_version == 1
        else {
            "authorization_action_receipt_coverage",
            "authorization_shadow_coverage",
            "binding",
            "binding_digest",
            "schema_version",
        }
        if schema_version == 2
        else set()
    )
    if set(payload) != expected_outer_keys:
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    if schema_version == 1:
        authorization_shadow_coverage = payload.get(
            "authorization_shadow_coverage"
        )
        authorization_action_receipt_coverage = None
        if authorization_shadow_coverage != COMPARISON_SHADOW_COVERAGE:
            return _invalid_comparison_binding(
                sequence,
                "comparison_binding_payload_invalid",
            )
    else:
        authorization_shadow_coverage = payload.get(
            "authorization_shadow_coverage"
        )
        authorization_action_receipt_coverage = payload.get(
            "authorization_action_receipt_coverage"
        )
        if (
            authorization_shadow_coverage != COMPARISON_FULL_SHADOW_COVERAGE
            or authorization_action_receipt_coverage
            != COMPARISON_ACTION_RECEIPT_COVERAGE
        ):
            return _invalid_comparison_binding(
                sequence,
                "comparison_binding_payload_invalid",
            )

    binding = payload.get("binding")
    if not _is_comparison_binding_shape(binding):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    assert isinstance(binding, Mapping)
    binding_digest = payload.get("binding_digest")
    if not _digest_matches(binding_digest, binding):
        return _ComparisonBindingFacts(
            True,
            sequence,
            None,
            None,
            ("comparison_binding_digest_mismatch",),
        )

    issues: list[str] = []
    if (
        binding.get("runner_id") != fact.raw_runner_id
        or binding.get("permission_class") != fact.permission_class
        or binding.get("timeout_seconds") != fact.timeout_seconds
        or binding.get("attempt") != fact.attempt
        or _normalize_sha256_digest(binding.get("context_digest"))
        != _normalize_sha256_digest(fact.raw_context_digest)
    ):
        issues.append("comparison_binding_record_mismatch")
    return _ComparisonBindingFacts(
        True,
        sequence,
        binding,
        binding_digest,
        tuple(issues),
        schema_version=schema_version,
        authorization_shadow_coverage=authorization_shadow_coverage,
        authorization_action_receipt_coverage=(
            authorization_action_receipt_coverage
        ),
    )


def _invalid_comparison_binding(
    sequence: int | None,
    issue: str,
) -> _ComparisonBindingFacts:
    return _ComparisonBindingFacts(True, sequence, None, None, (issue,))


def _inspect_comparison_billing(
    fact: _RunFacts,
    comparison_binding: _ComparisonBindingFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonBillingFacts:
    """Validate the persisted billing assessment bound to a comparison."""

    if fact.comparison_billing_event_count == 0:
        return _ComparisonBillingFacts(
            None,
            None,
            None,
            ("comparison_billing_payload_missing",),
        )
    if fact.comparison_billing_event_count != 1 or len(rows) != 1:
        return _ComparisonBillingFacts(
            None,
            None,
            None,
            ("comparison_billing_duplicate",),
        )
    payload_json = rows[0]["payload_json"]
    if not isinstance(payload_json, str) or len(
        payload_json.encode("utf-8", errors="replace")
    ) > _MAX_PAYLOAD_BYTES:
        return _invalid_comparison_billing("comparison_billing_payload_invalid")
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_comparison_billing("comparison_billing_payload_invalid")
    if not _is_comparison_billing_shape(payload):
        return _invalid_comparison_billing("comparison_billing_payload_invalid")
    assert isinstance(payload, Mapping)

    assessment_digest = payload["assessment_digest"]
    assessment_body = dict(payload)
    del assessment_body["assessment_digest"]
    issues: list[str] = []
    if not _event_identifier_matches(
        rows[0],
        event_type="billing_assessment",
        payload=payload,
        run_id=fact.raw_run_id,
    ):
        issues.append("comparison_billing_event_identifier_mismatch")
    if not _digest_matches(assessment_digest, assessment_body):
        issues.append("comparison_billing_digest_mismatch")
        return _ComparisonBillingFacts(
            payload,
            None,
            None,
            tuple(issues),
        )

    binding = comparison_binding.binding
    assert isinstance(binding, Mapping)
    if (
        binding["billing_assessment_digest"] != assessment_digest
        or payload["runner_id"] != binding["runner_id"]
        or payload["runner_id"] != fact.raw_runner_id
    ):
        issues.append("comparison_billing_binding_mismatch")
    return _ComparisonBillingFacts(
        payload,
        assessment_digest,
        _comparison_billing_evidence_window(payload),
        tuple(issues),
    )


def _invalid_comparison_billing(issue: str) -> _ComparisonBillingFacts:
    return _ComparisonBillingFacts(None, None, None, (issue,))


def _inspect_task_billing(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    rows: list[sqlite3.Row],
) -> _TaskBillingFacts:
    """Validate ordinary billing evidence used by the dispatch shadow."""

    if task_binding.binding is None or task_binding.issues:
        return _TaskBillingFacts(None, None, ())
    if fact.comparison_billing_event_count == 0:
        return _TaskBillingFacts(None, None, ())
    if fact.comparison_billing_event_count != 1 or len(rows) != 1:
        return _TaskBillingFacts(
            None,
            None,
            ("task_billing_duplicate",),
        )
    payload = _bounded_json_mapping(rows[0]["payload_json"])
    if not _is_task_billing_shape(payload):
        return _TaskBillingFacts(
            None,
            None,
            ("task_billing_payload_invalid",),
        )
    assert isinstance(payload, Mapping)
    assessment_digest = payload.get("assessment_digest")
    assessment_body = dict(payload)
    del assessment_body["assessment_digest"]
    issues: list[str] = []
    if not _event_identifier_matches(
        rows[0],
        event_type="billing_assessment",
        payload=payload,
        run_id=fact.raw_run_id,
    ):
        issues.append("task_billing_event_identifier_mismatch")
    if not _digest_matches(assessment_digest, assessment_body):
        issues.append("task_billing_digest_mismatch")
        return _TaskBillingFacts(
            payload,
            None,
            tuple(issues),
        )
    if _optional_timestamp(rows[0]["occurred_at"]) is None:
        issues.append("task_billing_timestamp_invalid")
    if payload.get("runner_id") != fact.raw_runner_id:
        issues.append("task_billing_binding_mismatch")
    if fact.running_observed and not _task_billing_policy_consistent(payload):
        issues.append("task_billing_policy_mismatch")
    return _TaskBillingFacts(
        payload,
        assessment_digest,
        tuple(issues),
    )


def _task_billing_policy_consistent(payload: Mapping[str, Any]) -> bool:
    """Recompute route-specific gates available in the safe projection."""

    runner_id = payload.get("runner_id")
    route = payload.get("route")
    if payload.get("confidence") != AssessmentConfidence.HIGH.value:
        return False
    expected_route = {
        "mock": BillingRoute.MOCK.value,
        "codex": BillingRoute.SUBSCRIPTION_INCLUDED.value,
        "claude": BillingRoute.SUBSCRIPTION_INCLUDED.value,
    }.get(runner_id)
    if expected_route is not None and route != expected_route:
        return False
    if route not in {
        BillingRoute.MOCK.value,
        BillingRoute.LOCAL_NON_AI.value,
        BillingRoute.SUBSCRIPTION_INCLUDED.value,
    }:
        return False
    if route != BillingRoute.SUBSCRIPTION_INCLUDED.value:
        return True
    if (
        payload.get("capacity_state") != CapacityState.AVAILABLE.value
        or payload.get("account_identity_verified") is not True
        or payload.get("attestation_present") is not True
    ):
        return False
    protection = payload.get("paid_continuation_protection")
    if runner_id == "codex":
        safe_protection = (
            PaidContinuationProtection
            .VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED.value
        )
        return bool(
            protection == safe_protection
            and payload.get("paid_credit_balance")
            == PaidCreditBalance.ZERO.value
        )
    return bool(
        protection
        == PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED.value
    )


def _inspect_task_admission_decision(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    rows: list[sqlite3.Row],
    terminal_rows: list[sqlite3.Row],
    shadow_rows: list[sqlite3.Row] | None = None,
    receipt_rows: list[sqlite3.Row] | None = None,
) -> _TaskAdmissionDecisionFacts:
    """Validate and independently re-evaluate the admission PEP decision."""

    required = (
        task_binding.schema_version
        in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    if not required:
        if rows:
            return _empty_task_admission_decision(
                observed=True,
                issue="task_admission_decision_unexpected",
            )
        return _empty_task_admission_decision()
    if len(rows) != 1:
        persistence_stop = bool(
            not rows
            and _is_task_admission_pre_effect_stop(
                fact,
                task_binding,
                None,
                terminal_rows,
                shadow_rows=shadow_rows or [],
                receipt_rows=receipt_rows or [],
            )
        )
        return _empty_task_admission_decision(
            observed=bool(rows),
            issue=(
                None
                if persistence_stop
                else "task_admission_decision_missing"
                if not rows
                else "task_admission_decision_duplicate"
            ),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    occurred_at = _optional_timestamp(row["occurred_at"])
    payload = _bounded_json_mapping(row["payload_json"])
    issues: list[str] = []
    if sequence is None:
        issues.append("task_admission_decision_sequence_invalid")
    if occurred_at is None:
        issues.append("task_admission_decision_timestamp_invalid")
    if not isinstance(payload, Mapping):
        return _empty_task_admission_decision(
            observed=True,
            sequence=sequence,
            occurred_at=occurred_at,
            issue="task_admission_decision_payload_invalid",
            additional_issues=issues,
        )

    failure = payload.get("failure_stage") is not None
    expected_keys = {
        "action_scope",
        "admission_authorization_intent_digest",
        "authorization_eligible",
        "authority_ceiling_satisfied",
        "block_reason_codes",
        "context_digest",
        "controller_owned_mock_runner",
        "decision",
        "decision_current_at_evaluation",
        "decision_digest",
        "derived_permission_class",
        "effect",
        "enforcement_coverage",
        "evaluated_at",
        "execution_selection_digest",
        "legacy_executable",
        "mode",
        "obligations_supported",
        "policy",
        "policy_digest",
        "pre_run_approver_ref",
        "pre_run_approval_required",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "prompt_digest",
        "request",
        "request_digest",
        "requested_permission_class",
        "run_ref",
        "schema_version",
        "task_attempt_binding_digest",
        "task_authorization_intent_digest",
    }
    if failure:
        expected_keys.add("failure_stage")
    if set(payload) != expected_keys:
        issues.append("task_admission_decision_payload_invalid")
    if (
        payload.get("schema_version") != TASK_ADMISSION_EVENT_SCHEMA_VERSION
        or payload.get("mode") != "enforcing"
        or payload.get("action_scope") != TASK_ADMISSION_ACTION_SCOPE
        or payload.get("enforcement_coverage")
        != TASK_ADMISSION_ENFORCEMENT_COVERAGE
    ):
        issues.append("task_admission_decision_payload_invalid")
    if not _event_identifier_matches(
        row,
        event_type=TASK_ADMISSION_DECISION_EVENT_TYPE,
        payload=payload,
        run_id=fact.raw_run_id,
    ):
        issues.append("task_admission_decision_event_identifier_mismatch")

    binding = task_binding.binding
    selected = task_execution_selection.selected
    selected_mock = bool(
        isinstance(selected, Mapping)
        and selected.get("runner_id") == "mock"
        and fact.raw_runner_id == "mock"
    )
    if (
        not isinstance(binding, Mapping)
        or task_binding.binding_digest is None
        or payload.get("run_ref") != fact.run_ref
        or payload.get("run_ref") != binding.get("run_ref")
        or payload.get("profile_ref") != binding.get("profile_ref")
        or payload.get("task_attempt_binding_digest")
        != task_binding.binding_digest
        or payload.get("execution_selection_digest")
        != task_execution_selection.selection_digest
        or payload.get("profile_version_ref")
        != binding.get("profile_version_ref")
        or payload.get("profile_configuration_digest")
        != binding.get("profile_configuration_digest")
        or payload.get("context_digest") != binding.get("context_digest")
        or payload.get("prompt_digest") != binding.get("prompt_digest")
        or payload.get("task_authorization_intent_digest")
        != binding.get("authorization_intent_digest")
        or _permission_class(payload.get("requested_permission_class"))
        != fact.permission_class
        or fact.permission_class
        not in (
            int(PermissionClass.READ_ONLY),
            int(PermissionClass.LOCAL_DRAFT),
        )
        or payload.get("controller_owned_mock_runner") is not selected_mock
        or payload.get("legacy_executable") is not True
        or not isinstance(payload.get("pre_run_approval_required"), bool)
        or not _is_digest(payload.get("pre_run_approver_ref"))
        or not _is_digest(
            payload.get("admission_authorization_intent_digest")
        )
    ):
        issues.append("task_admission_decision_binding_mismatch")

    evaluated_at = _optional_timestamp(payload.get("evaluated_at"))
    if evaluated_at is None or (
        occurred_at is not None and occurred_at < evaluated_at
    ):
        issues.append("task_admission_decision_timestamp_invalid")
    effect = _known_string(payload.get("effect"), _KNOWN_EFFECTS)
    eligible = _optional_boolean(payload.get("authorization_eligible"))
    current = _optional_boolean(
        payload.get("decision_current_at_evaluation")
    )
    if effect is None or eligible is None or current is None:
        issues.append("task_admission_decision_projection_invalid")

    if failure:
        if not _is_exact_task_admission_failure(payload):
            issues.append("task_admission_decision_failure_invalid")
        return _TaskAdmissionDecisionFacts(
            True,
            sequence,
            occurred_at,
            payload,
            None,
            None,
            None,
            None,
            None,
            None,
            effect,
            eligible,
            current,
            None,
            None,
            tuple(sorted(set(issues))),
        )

    request_mapping = payload.get("request")
    policy_mapping = payload.get("policy")
    decision_mapping = payload.get("decision")
    request_digest = payload.get("request_digest")
    policy_digest = payload.get("policy_digest")
    decision_digest = payload.get("decision_digest")
    if not _digest_matches(request_digest, request_mapping):
        issues.append("task_admission_request_digest_mismatch")
        request_digest = None
    if not _digest_matches(policy_digest, policy_mapping):
        issues.append("task_admission_policy_digest_mismatch")
        policy_digest = None
    if not _digest_matches(decision_digest, decision_mapping):
        issues.append("task_admission_decision_digest_mismatch")
        decision_digest = None

    request = _mock_dispatch_request_from_mapping(request_mapping)
    policy = _mock_dispatch_policy_from_mapping(policy_mapping)
    if request is None:
        issues.append("task_admission_request_invalid")
    if policy is None:
        issues.append("task_admission_policy_invalid")
    if not _is_decision_shape(decision_mapping):
        issues.append("task_admission_authorization_decision_invalid")
    if request is not None:
        issues.extend(
            _inspect_task_admission_request_projection(
                fact,
                task_binding,
                task_execution_selection,
                payload,
                request,
            )
        )
    if policy is not None:
        issues.extend(
            _inspect_task_admission_policy_projection(
                policy,
                pre_run_approval_required=(
                    payload.get("pre_run_approval_required") is True
                ),
                pre_run_approver_ref=payload.get("pre_run_approver_ref"),
            )
        )

    expected_decision: Mapping[str, Any] | None = None
    if request is not None and policy is not None:
        try:
            expected_decision = ShadowAuthorizationEvaluator().evaluate(
                request,
                policy,
            ).to_canonical()
        except (TypeError, ValueError, ValidationError):
            issues.append("task_admission_authorization_reevaluation_failed")
    if expected_decision is not None and decision_mapping != expected_decision:
        issues.append("task_admission_authorization_reevaluation_mismatch")

    issued_at = (
        _optional_timestamp(decision_mapping.get("issued_at"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    expires_at = (
        _optional_timestamp(decision_mapping.get("expires_at"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    recomputed_current = bool(
        evaluated_at is not None
        and issued_at is not None
        and expires_at is not None
        and issued_at <= evaluated_at < expires_at
    )
    derived = (
        _permission_class(decision_mapping.get("derived_permission_class"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    recomputed_ceiling = bool(
        derived is not None
        and derived <= int(PermissionClass.LOCAL_DRAFT)
        and fact.permission_class == int(PermissionClass.LOCAL_DRAFT)
    )
    obligations = (
        decision_mapping.get("obligations")
        if isinstance(decision_mapping, Mapping)
        else None
    )
    supported_obligations = _mock_dispatch_obligations_supported(
        effect,
        obligations,
    )
    policy_matches = bool(
        isinstance(decision_mapping, Mapping)
        and request is not None
        and policy is not None
        and decision_mapping.get("request_id") == request.request_id
        and decision_mapping.get("request_digest") == request.digest
        and decision_mapping.get("policy_bundle_id") == policy.bundle_id
        and decision_mapping.get("policy_version") == policy.version
        and decision_mapping.get("policy_digest") == policy.digest
        and issued_at == evaluated_at
    )
    recomputed_blocks: list[str] = []
    if payload.get("controller_owned_mock_runner") is not True:
        recomputed_blocks.append("controller_owned_mock_runner_not_verified")
    if fact.permission_class != int(PermissionClass.LOCAL_DRAFT):
        recomputed_blocks.append("task_permission_class_not_local_draft")
    if payload.get("legacy_executable") is not True:
        recomputed_blocks.append("legacy_gate_not_executable")
    if payload.get("pre_run_approval_required") is True:
        recomputed_blocks.append("pre_run_approval_not_supported")
    if not policy_matches:
        recomputed_blocks.append("authorization_policy_mismatch")
    if effect != AuthorizationEffect.PERMIT.value:
        recomputed_blocks.append("authorization_effect_not_permit")
    if not recomputed_current:
        recomputed_blocks.append("authorization_decision_not_current")
    if not recomputed_ceiling:
        recomputed_blocks.append("authorization_class_ceiling_exceeded")
    if not supported_obligations:
        recomputed_blocks.append("authorization_obligation_unsupported")
    recomputed_eligible = not recomputed_blocks
    if (
        payload.get("effect")
        != (
            decision_mapping.get("effect")
            if isinstance(decision_mapping, Mapping)
            else None
        )
        or payload.get("derived_permission_class") != derived
        or payload.get("decision_current_at_evaluation")
        is not recomputed_current
        or payload.get("authority_ceiling_satisfied")
        is not recomputed_ceiling
        or payload.get("obligations_supported")
        is not supported_obligations
        or payload.get("authorization_eligible") is not recomputed_eligible
        or payload.get("block_reason_codes") != recomputed_blocks
        or payload.get("evaluated_at") != issued_at
    ):
        issues.append("task_admission_decision_projection_mismatch")

    return _TaskAdmissionDecisionFacts(
        True,
        sequence,
        occurred_at,
        payload,
        request_mapping if isinstance(request_mapping, Mapping) else None,
        policy_mapping if isinstance(policy_mapping, Mapping) else None,
        decision_mapping if isinstance(decision_mapping, Mapping) else None,
        request_digest if isinstance(request_digest, str) else None,
        policy_digest if isinstance(policy_digest, str) else None,
        decision_digest if isinstance(decision_digest, str) else None,
        effect,
        eligible,
        current,
        issued_at,
        expires_at,
        tuple(sorted(set(issues))),
    )


def _empty_task_admission_decision(
    *,
    observed: bool = False,
    sequence: int | None = None,
    occurred_at: float | None = None,
    issue: str | None = None,
    additional_issues: list[str] | None = None,
) -> _TaskAdmissionDecisionFacts:
    issues = list(additional_issues or ())
    if issue is not None:
        issues.append(issue)
    return _TaskAdmissionDecisionFacts(
        observed,
        sequence,
        occurred_at,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        tuple(sorted(set(issues))),
    )


def _is_exact_task_admission_failure(payload: Mapping[str, Any]) -> bool:
    return bool(
        payload.get("failure_stage") == "request_or_evaluation"
        and payload.get("request") is None
        and payload.get("request_digest") is None
        and payload.get("policy") is None
        and payload.get("policy_digest") is None
        and payload.get("decision") is None
        and payload.get("decision_digest") is None
        and payload.get("effect") == AuthorizationEffect.INDETERMINATE.value
        and payload.get("derived_permission_class") is None
        and payload.get("decision_current_at_evaluation") is False
        and payload.get("authority_ceiling_satisfied") is False
        and payload.get("obligations_supported") is False
        and payload.get("authorization_eligible") is False
        and payload.get("block_reason_codes")
        == ["authorization_evaluation_failed"]
    )


def _inspect_task_admission_request_projection(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    wrapper: Mapping[str, Any],
    request: AuthorizationRequest,
) -> tuple[str, ...]:
    binding = task_binding.binding
    selected = task_execution_selection.selected
    if not isinstance(binding, Mapping):
        return ("task_admission_request_binding_mismatch",)
    expected_resource_identifier = canonical_digest(
        {
            "execution_selection_digest": task_execution_selection.selection_digest,
            "resource_type": TASK_ADMISSION_RESOURCE_TYPE,
            "run_ref": fact.run_ref,
            "task_attempt_binding_digest": task_binding.binding_digest,
            "workspace_ref": binding.get("workspace_ref"),
        }
    )
    expected_parameters_digest = canonical_digest(
        {
            "admission_authorization_intent_digest": wrapper.get(
                "admission_authorization_intent_digest"
            ),
            "attempt": binding.get("attempt"),
            "context_digest": binding.get("context_digest"),
            "controller_owned_mock_runner": wrapper.get(
                "controller_owned_mock_runner"
            ),
            "execution_selection_digest": task_execution_selection.selection_digest,
            "legacy_permission_class": fact.permission_class,
            "output_schema_digest": binding.get("output_schema_digest"),
            "pre_run_approval_requirements_digest": binding.get(
                "pre_run_approval_requirements_digest"
            ),
            "profile_configuration_digest": binding.get(
                "profile_configuration_digest"
            ),
            "profile_ref": binding.get("profile_ref"),
            "profile_version_ref": binding.get("profile_version_ref"),
            "prompt_digest": binding.get("prompt_digest"),
            "repository_ref": binding.get("repository_ref"),
            "run_directory_ref": canonical_digest(
                {"run_directory": fact.raw_run_directory}
            ),
            "run_ref": fact.run_ref,
            "runner_overrides_digest": binding.get(
                "runner_overrides_digest"
            ),
            "task_attempt_binding_digest": task_binding.binding_digest,
            "task_authorization_intent_digest": binding.get(
                "authorization_intent_digest"
            ),
            "task_definition_digest": binding.get(
                "task_definition_digest"
            ),
            "timeout_seconds": binding.get("timeout_seconds"),
            "workspace_ref": binding.get("workspace_ref"),
        }
    )
    admission_intent = {
        "action": {
            "intended_effect": "admit_profile_backed_mock_task_attempt",
            "operation": TASK_ADMISSION_OPERATION,
            "verb": ActionVerb.CREATE.value,
        },
        "consequences": request.consequences.to_canonical(),
        "resource": {
            "protected": request.resource.protected,
            "resource_type": TASK_ADMISSION_RESOURCE_TYPE,
            "sensitivity": request.resource.sensitivity.value,
            "trust_boundary": "isolated_run_workspace",
        },
    }
    expected = bool(
        request.request_id == f"{TASK_ADMISSION_ACTION_SCOPE}:{fact.run_ref}"
        and request.subject.principal_id == "agent:task-attempt"
        and request.subject.controller_id == "ordomata:local-controller"
        and request.subject.role is Role.IMPLEMENTER
        and request.subject.role_version == "1"
        and request.subject.profile_id == binding.get("profile_ref")
        and request.subject.runner_id == "mock"
        and request.subject.session_id == f"attempt:{fact.run_ref}"
        and request.action.verb is ActionVerb.CREATE
        and request.action.operation == TASK_ADMISSION_OPERATION
        and request.action.parameters_digest == expected_parameters_digest
        and request.action.intended_effect
        == "admit_profile_backed_mock_task_attempt"
        and request.action.tool_id is None
        and not request.action.descriptive_claims
        and request.resource.resource_type == TASK_ADMISSION_RESOURCE_TYPE
        and request.resource.identifier == expected_resource_identifier
        and request.resource.version == binding.get("task_definition_digest")
        and request.resource.owner == "operator:local"
        and request.resource.trust_boundary == "isolated_run_workspace"
        and request.resource.repository_id == binding.get("repository_ref")
        and request.resource.content_digest == binding.get("context_digest")
        and request.environment.isolation_state is IsolationState.VERIFIED
        and request.environment.network_state is NetworkState.DISABLED
        and request.environment.billing_route is BillingRoute.MOCK
        and request.environment.capacity_state is CapacityState.NOT_APPLICABLE
        and request.environment.paid_continuation_protection
        is PaidContinuationProtection.NOT_APPLICABLE
        and request.environment.circuit_state is CircuitState.CLOSED
        and request.environment.flow_state == "admission_proposed"
        and not request.environment.approval_grants
        and wrapper.get("admission_authorization_intent_digest")
        == canonical_digest(admission_intent)
        and isinstance(selected, Mapping)
        and selected.get("runner_id") == "mock"
    )
    issues: list[str] = []
    if not expected:
        issues.append("task_admission_request_binding_mismatch")
    expected_evidence = {
        "subject": EvidenceSource.CONTROLLER,
        "action": EvidenceSource.LOCAL_REGISTRY,
        "resource": EvidenceSource.LOCAL_REGISTRY,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.LOCAL_REGISTRY,
    }
    evidence_by_attribute = {item.attribute: item for item in request.evidence}
    evaluated_at = request.environment.evaluated_at
    if (
        len(request.evidence) != len(expected_evidence)
        or len(evidence_by_attribute) != len(request.evidence)
        or set(evidence_by_attribute) != set(expected_evidence)
    ):
        issues.append("task_admission_evidence_invalid")
    else:
        for attribute, expected_source in expected_evidence.items():
            item = evidence_by_attribute[attribute]
            if (
                item.evidence_id
                != f"{TASK_ADMISSION_ACTION_SCOPE}:{attribute}"
                or item.source is not expected_source
                or item.source_id != f"ordomata:{expected_source.value}"
                or item.observed_at != evaluated_at
                or item.expires_at
                != evaluated_at + _SHADOW_EVIDENCE_LIFETIME_SECONDS
                or item.authenticated is not True
                or item.value_digest
                != canonical_digest(request.attribute_value(attribute))
            ):
                issues.append("task_admission_evidence_invalid")
                break
    return tuple(sorted(set(issues)))


def _inspect_task_admission_policy_projection(
    policy: PolicyBundle,
    *,
    pre_run_approval_required: bool,
    pre_run_approver_ref: Any,
) -> tuple[str, ...]:
    approval_requirements: tuple[ApprovalRequirement, ...] = ()
    if pre_run_approval_required and _is_digest(pre_run_approver_ref):
        approval_requirements = (
            ApprovalRequirement(
                requirement_id=(
                    "task_contract_pre_run_operator_approval"
                ),
                verbs=(ActionVerb.CREATE,),
                resource_types=(TASK_ADMISSION_RESOURCE_TYPE,),
                allowed_approver_ids=(pre_run_approver_ref,),
            ),
        )
    expected = replace(
        PolicyBundle.current_stage(
            issued_at=0.0,
            approval_requirements=approval_requirements,
        ),
        bundle_id=TASK_ADMISSION_POLICY_ID,
        version=TASK_ADMISSION_POLICY_VERSION,
        enabled_classes=(PermissionClass.LOCAL_DRAFT,),
        allowed_verbs=(ActionVerb.CREATE,),
        allowed_roles=(Role.IMPLEMENTER,),
        allowed_operations=(TASK_ADMISSION_OPERATION,),
        allowed_resource_types=(TASK_ADMISSION_RESOURCE_TYPE,),
        allowed_trust_boundaries=("isolated_run_workspace",),
        allowed_flow_states=("admission_proposed",),
        allowed_network_states=(NetworkState.DISABLED,),
        allowed_billing_routes=(BillingRoute.MOCK,),
        approval_requirements=approval_requirements,
    )
    return (
        ()
        if policy.to_canonical() == expected.to_canonical()
        else ("task_admission_policy_mismatch",)
    )


def _inspect_task_admission_receipt(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    decision: _TaskAdmissionDecisionFacts,
    rows: list[sqlite3.Row],
    terminal_rows: list[sqlite3.Row],
    *,
    shadow_rows: list[sqlite3.Row] | None = None,
) -> _TaskAdmissionReceiptFacts:
    enforcing = (
        task_binding.schema_version
        in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    if not enforcing:
        if rows:
            return _empty_task_admission_receipt(
                observed=True,
                issue="task_admission_receipt_unexpected",
            )
        return _empty_task_admission_receipt()

    stop_valid = _is_task_admission_pre_effect_stop(
        fact,
        task_binding,
        decision,
        terminal_rows,
        shadow_rows=shadow_rows or [],
        receipt_rows=rows,
    )
    receipt_expected = bool(
        decision.authorization_eligible is True and not stop_valid
    )
    effect_after_nonpermit = bool(
        decision.observed
        and decision.authorization_eligible is False
        and (
            shadow_rows
            or fact.billing_sequence is not None
            or fact.running_observed
            or fact.accounting_sequence is not None
            or fact.runner_event_count > 0
            or fact.artifact_observed
        )
    )
    if len(rows) != 1:
        missing_issue = (
            "task_admission_effect_after_nonpermit"
            if effect_after_nonpermit
            else "task_admission_receipt_missing"
            if not rows and receipt_expected
            else "task_admission_receipt_duplicate"
            if rows
            else None
        )
        return _empty_task_admission_receipt(
            observed=bool(rows),
            pre_effect_stop_valid=stop_valid,
            issue=missing_issue,
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    occurred_at = _optional_timestamp(row["occurred_at"])
    payload = _bounded_json_mapping(row["payload_json"])
    issues: list[str] = []
    if sequence is None:
        issues.append("task_admission_receipt_sequence_invalid")
    if occurred_at is None:
        issues.append("task_admission_receipt_timestamp_invalid")
    expected_keys = {
        "action_scope",
        "admission_result_digest",
        "decision_digest",
        "enforcement_coverage",
        "execution_selection_digest",
        "mode",
        "profile_ref",
        "receipt",
        "receipt_digest",
        "request_digest",
        "run_ref",
        "schema_version",
        "task_attempt_binding_digest",
    }
    if not isinstance(payload, Mapping) or set(payload) != expected_keys:
        return _empty_task_admission_receipt(
            observed=True,
            sequence=sequence,
            occurred_at=occurred_at,
            issue="task_admission_receipt_payload_invalid",
            additional_issues=issues,
        )
    if (
        payload.get("schema_version") != TASK_ADMISSION_EVENT_SCHEMA_VERSION
        or payload.get("mode") != "enforcing"
        or payload.get("action_scope") != TASK_ADMISSION_ACTION_SCOPE
        or payload.get("enforcement_coverage")
        != TASK_ADMISSION_ENFORCEMENT_COVERAGE
    ):
        issues.append("task_admission_receipt_payload_invalid")
    receipt = payload.get("receipt")
    if not isinstance(receipt, Mapping) or set(receipt) != {
        "completed_at",
        "decision_digest",
        "enforced_action_digest",
        "executor_id",
        "obligation_results",
        "outcome",
        "receipt_id",
        "request_digest",
        "result_digest",
        "started_at",
    }:
        return _empty_task_admission_receipt(
            observed=True,
            sequence=sequence,
            occurred_at=occurred_at,
            payload=payload,
            issue="task_admission_receipt_body_invalid",
            additional_issues=issues,
        )
    binding = task_binding.binding
    expected_result_digest = canonical_digest(
        {
            "admission_state": "admitted",
            "execution_selection_digest": task_execution_selection.selection_digest,
            "run_ref": fact.run_ref,
            "task_attempt_binding_digest": task_binding.binding_digest,
        }
    )
    if (
        not isinstance(binding, Mapping)
        or payload.get("run_ref") != fact.run_ref
        or payload.get("profile_ref") != binding.get("profile_ref")
        or payload.get("task_attempt_binding_digest")
        != task_binding.binding_digest
        or payload.get("execution_selection_digest")
        != task_execution_selection.selection_digest
        or payload.get("request_digest") != decision.request_digest
        or payload.get("decision_digest") != decision.decision_digest
        or payload.get("admission_result_digest") != expected_result_digest
        or receipt.get("request_digest") != decision.request_digest
        or receipt.get("decision_digest") != decision.decision_digest
        or receipt.get("result_digest") != expected_result_digest
    ):
        issues.append("task_admission_receipt_binding_mismatch")
    if not _digest_matches(payload.get("receipt_digest"), receipt):
        issues.append("task_admission_receipt_digest_mismatch")
    expected_receipt_id = canonical_digest(
        {
            "decision_digest": decision.decision_digest,
            "execution_selection_digest": task_execution_selection.selection_digest,
            "request_digest": decision.request_digest,
            "task_attempt_binding_digest": task_binding.binding_digest,
            "receipt_kind": "task_admission_action",
        }
    )
    if (
        receipt.get("receipt_id") != expected_receipt_id
        or row["event_id"] != expected_receipt_id
    ):
        issues.append("task_admission_receipt_event_identifier_mismatch")
    if receipt.get("executor_id") != TASK_ADMISSION_EXECUTOR_ID:
        issues.append("task_admission_receipt_executor_mismatch")
    expected_action_digest = (
        canonical_digest(
            {
                "action": decision.request.get("action"),
                "resource": decision.request.get("resource"),
            }
        )
        if isinstance(decision.request, Mapping)
        else None
    )
    if receipt.get("enforced_action_digest") != expected_action_digest:
        issues.append("task_admission_receipt_action_mismatch")
    decision_obligations = (
        decision.decision.get("obligations")
        if isinstance(decision.decision, Mapping)
        else None
    )
    if not _mock_dispatch_receipt_obligations_match(
        decision_obligations,
        receipt.get("obligation_results"),
    ):
        issues.append("task_admission_receipt_obligation_mismatch")
    outcome = _known_string(
        receipt.get("outcome"),
        frozenset(item.value for item in ReceiptOutcome),
    )
    started_at = _optional_timestamp(receipt.get("started_at"))
    completed_at = _optional_timestamp(receipt.get("completed_at"))
    permit_current = bool(
        decision.effect == AuthorizationEffect.PERMIT.value
        and decision.authorization_eligible is True
        and started_at is not None
        and decision.issued_at is not None
        and decision.expires_at is not None
        and decision.issued_at <= started_at < decision.expires_at
    )
    if outcome != ReceiptOutcome.SUCCEEDED.value:
        issues.append("task_admission_receipt_outcome_invalid")
    if (
        started_at is None
        or completed_at is None
        or completed_at < started_at
        or occurred_at is None
        or occurred_at < completed_at
    ):
        issues.append("task_admission_receipt_timestamp_invalid")
    if not permit_current:
        issues.append("task_admission_receipt_permit_not_current")
    return _TaskAdmissionReceiptFacts(
        True,
        sequence,
        occurred_at,
        payload,
        receipt,
        outcome,
        started_at,
        completed_at,
        permit_current,
        False,
        tuple(sorted(set(issues))),
    )


def _empty_task_admission_receipt(
    *,
    observed: bool = False,
    sequence: int | None = None,
    occurred_at: float | None = None,
    payload: Mapping[str, Any] | None = None,
    pre_effect_stop_valid: bool = False,
    issue: str | None = None,
    additional_issues: list[str] | None = None,
) -> _TaskAdmissionReceiptFacts:
    issues = list(additional_issues or ())
    if issue is not None:
        issues.append(issue)
    return _TaskAdmissionReceiptFacts(
        observed,
        sequence,
        occurred_at,
        payload,
        None,
        None,
        None,
        None,
        None,
        pre_effect_stop_valid,
        tuple(sorted(set(issues))),
    )


def _is_task_admission_pre_effect_stop(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    decision: _TaskAdmissionDecisionFacts | None,
    rows: list[sqlite3.Row],
    *,
    shadow_rows: list[sqlite3.Row],
    receipt_rows: list[sqlite3.Row],
) -> bool:
    """Recognize only exact fail-closed stops before durable admission."""

    if len(rows) != 1 or receipt_rows:
        return False
    row = rows[0]
    payload = _bounded_json_mapping(row["payload_json"])
    sequence = _optional_sequence(row["sequence"])
    if (
        row["event_type"] != "status"
        or not isinstance(payload, Mapping)
        or set(payload) != {"phase"}
        or sequence is None
        or sequence != fact.terminal_sequence
        or task_binding.sequence is None
        or sequence <= task_binding.sequence
        or _optional_timestamp(row["occurred_at"]) is None
        or not _event_identifier_matches_status(row, payload, fact.raw_run_id)
        or fact.billing_sequence is not None
        or fact.running_observed
        or fact.succeeded_observed
        or fact.accounting_sequence is not None
        or fact.runner_event_count != 0
        or fact.artifact_observed
        or fact.task_artifact_intent_event_count != 0
        or fact.task_artifact_action_receipt_event_count != 0
        or shadow_rows
    ):
        return False
    phase = payload.get("phase")
    status = row["status"]
    if decision is None or not decision.observed:
        return bool(
            phase == "task_admission_authorization_persistence"
            and status in {
                RunStatus.FAILED.value,
                RunStatus.CANCELLED.value,
            }
            and fact.latest_status == status
        )
    if decision.sequence is None or sequence <= decision.sequence:
        return False
    if (
        phase == "task_admission_authorization_persistence"
        and status in {RunStatus.FAILED.value, RunStatus.CANCELLED.value}
    ):
        return fact.latest_status == status
    if (
        phase == "task_admission_authorization"
        and status == RunStatus.BLOCKED.value
    ):
        return bool(
            fact.latest_status == status
            and decision.authorization_eligible is False
        )
    if (
        phase == "task_admission_authorization_evaluation"
        and status == RunStatus.CANCELLED.value
    ):
        return bool(
            fact.latest_status == status
            and decision.authorization_eligible is False
            and decision.effect == AuthorizationEffect.INDETERMINATE.value
        )
    if (
        phase == "task_admission_authorization_freshness"
        and status == RunStatus.BLOCKED.value
    ):
        return bool(
            fact.latest_status == status
            and decision.authorization_eligible is True
            and decision.effect == AuthorizationEffect.PERMIT.value
        )
    if (
        phase == "task_admission_action_receipt_persistence"
        and status in {RunStatus.FAILED.value, RunStatus.CANCELLED.value}
    ):
        return bool(
            fact.latest_status == status
            and decision.authorization_eligible is True
            and decision.effect == AuthorizationEffect.PERMIT.value
        )
    return False


def _project_task_admission_enforcement(
    task_binding: _TaskAttemptBindingFacts,
    decision: _TaskAdmissionDecisionFacts,
    receipt: _TaskAdmissionReceiptFacts,
) -> TaskAdmissionEnforcementInspection:
    issues = tuple(sorted(set((*decision.issues, *receipt.issues))))
    return TaskAdmissionEnforcementInspection(
        required=(
            task_binding.schema_version
            in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
        ),
        decision_observed=decision.observed,
        decision_sequence=decision.sequence,
        effect=decision.effect,
        authorization_eligible=decision.authorization_eligible,
        decision_current_at_evaluation=(
            decision.decision_current_at_evaluation
        ),
        action_receipt_observed=receipt.observed,
        action_receipt_sequence=receipt.sequence,
        action_receipt_outcome=receipt.outcome,
        permit_current_at_action_start=(
            receipt.permit_current_at_action_start
        ),
        integrity_issues=issues,
    )


def _inspect_mock_dispatch_decision(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    task_billing: _TaskBillingFacts,
    task_admission_decision: _TaskAdmissionDecisionFacts,
    task_admission_receipt: _TaskAdmissionReceiptFacts,
    shadow_rows: list[sqlite3.Row],
    rows: list[sqlite3.Row],
) -> _MockDispatchDecisionFacts:
    """Validate and independently re-evaluate the enforcing mock decision."""

    required = (
        task_binding.schema_version
        in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
        and not (
            task_binding.schema_version
            in _ADMISSION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
            and task_admission_receipt.pre_effect_stop_valid
        )
    )
    if not required:
        if rows:
            return _empty_mock_dispatch_decision(
                observed=True,
                issue="mock_dispatch_decision_unexpected",
            )
        return _empty_mock_dispatch_decision()
    if len(rows) != 1:
        return _empty_mock_dispatch_decision(
            observed=bool(rows),
            issue=(
                "mock_dispatch_decision_missing"
                if not rows
                else "mock_dispatch_decision_duplicate"
            ),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    occurred_at = _optional_timestamp(row["occurred_at"])
    payload = _bounded_json_mapping(row["payload_json"])
    issues: list[str] = []
    if sequence is None:
        issues.append("mock_dispatch_decision_sequence_invalid")
    if occurred_at is None:
        issues.append("mock_dispatch_decision_timestamp_invalid")
    if not isinstance(payload, Mapping):
        return _empty_mock_dispatch_decision(
            observed=True,
            sequence=sequence,
            occurred_at=occurred_at,
            issue="mock_dispatch_decision_payload_invalid",
            additional_issues=issues,
        )

    failure = payload.get("failure_stage") is not None
    expected_keys = {
        "action_scope",
        "authorization_eligible",
        "authority_ceiling_satisfied",
        "billing_assessment_digest",
        "block_reason_codes",
        "decision",
        "decision_current_at_evaluation",
        "decision_digest",
        "derived_permission_class",
        "effect",
        "enforcement_coverage",
        "evaluated_at",
        "execution_selection_digest",
        "legacy_executable",
        "mode",
        "obligations_supported",
        "policy",
        "policy_digest",
        "request",
        "request_digest",
        "requested_permission_class",
        "schema_version",
        "task_attempt_binding_digest",
        "task_authorization_intent_digest",
    }
    if failure:
        expected_keys.add("failure_stage")
    if set(payload) != expected_keys:
        issues.append("mock_dispatch_decision_payload_invalid")
    if (
        payload.get("schema_version") != MOCK_DISPATCH_EVENT_SCHEMA_VERSION
        or payload.get("mode") != "enforcing"
        or payload.get("action_scope") != MOCK_DISPATCH_ACTION_SCOPE
        or payload.get("enforcement_coverage")
        != TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
    ):
        issues.append("mock_dispatch_decision_payload_invalid")
    if not _event_identifier_matches(
        row,
        event_type=MOCK_DISPATCH_DECISION_EVENT_TYPE,
        payload=payload,
        run_id=fact.raw_run_id,
    ):
        issues.append("mock_dispatch_decision_event_identifier_mismatch")

    binding = task_binding.binding
    expected_permission_class = fact.permission_class
    if (
        not isinstance(binding, Mapping)
        or task_binding.binding_digest is None
        or payload.get("task_attempt_binding_digest")
        != task_binding.binding_digest
        or payload.get("execution_selection_digest")
        != task_execution_selection.selection_digest
        or payload.get("billing_assessment_digest")
        != task_billing.assessment_digest
        or payload.get("task_authorization_intent_digest")
        != binding.get("authorization_intent_digest")
        or payload.get("requested_permission_class")
        != expected_permission_class
        or payload.get("legacy_executable")
        != (
            expected_permission_class
            in {
                int(PermissionClass.READ_ONLY),
                int(PermissionClass.LOCAL_DRAFT),
            }
        )
    ):
        issues.append("mock_dispatch_decision_binding_mismatch")

    evaluated_at = _optional_timestamp(payload.get("evaluated_at"))
    if evaluated_at is None:
        issues.append("mock_dispatch_decision_timestamp_invalid")
    elif occurred_at is not None and occurred_at < evaluated_at:
        issues.append("mock_dispatch_decision_timestamp_invalid")

    effect = _known_string(payload.get("effect"), _KNOWN_EFFECTS)
    eligible = _optional_boolean(payload.get("authorization_eligible"))
    current = _optional_boolean(
        payload.get("decision_current_at_evaluation")
    )
    if effect is None or eligible is None or current is None:
        issues.append("mock_dispatch_decision_projection_invalid")

    if failure:
        if not _is_exact_mock_dispatch_failure(payload):
            issues.append("mock_dispatch_decision_failure_invalid")
        return _MockDispatchDecisionFacts(
            True,
            sequence,
            occurred_at,
            payload,
            None,
            None,
            None,
            None,
            None,
            None,
            effect,
            eligible,
            current,
            None,
            None,
            tuple(sorted(set(issues))),
        )

    request_mapping = payload.get("request")
    policy_mapping = payload.get("policy")
    decision_mapping = payload.get("decision")
    request_digest = payload.get("request_digest")
    policy_digest = payload.get("policy_digest")
    decision_digest = payload.get("decision_digest")
    if not _digest_matches(request_digest, request_mapping):
        issues.append("mock_dispatch_request_digest_mismatch")
        request_digest = None
    if not _digest_matches(policy_digest, policy_mapping):
        issues.append("mock_dispatch_policy_digest_mismatch")
        policy_digest = None
    if not _digest_matches(decision_digest, decision_mapping):
        issues.append("mock_dispatch_decision_digest_mismatch")
        decision_digest = None

    request = _mock_dispatch_request_from_mapping(request_mapping)
    policy = _mock_dispatch_policy_from_mapping(policy_mapping)
    if request is None:
        issues.append("mock_dispatch_request_invalid")
    if policy is None:
        issues.append("mock_dispatch_policy_invalid")
    if not _is_decision_shape(decision_mapping):
        issues.append("mock_dispatch_authorization_decision_invalid")

    if request is not None:
        task_intent = _mock_dispatch_task_intent_from_shadow(
            task_binding,
            shadow_rows,
        )
        issues.extend(
            _inspect_mock_dispatch_request_projection(
                fact,
                task_binding,
                task_execution_selection,
                task_billing,
                request,
                task_intent,
            )
        )
    if policy is not None:
        issues.extend(
            _inspect_mock_dispatch_policy_projection(
                fact,
                task_binding,
                policy,
            )
        )

    expected_decision: Mapping[str, Any] | None = None
    if request is not None and policy is not None:
        try:
            expected_decision = ShadowAuthorizationEvaluator().evaluate(
                request,
                policy,
            ).to_canonical()
        except (TypeError, ValueError, ValidationError):
            issues.append("mock_dispatch_authorization_reevaluation_failed")
    if (
        expected_decision is not None
        and decision_mapping != expected_decision
    ):
        issues.append("mock_dispatch_authorization_reevaluation_mismatch")

    issued_at = (
        _optional_timestamp(decision_mapping.get("issued_at"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    expires_at = (
        _optional_timestamp(decision_mapping.get("expires_at"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    recomputed_current = bool(
        evaluated_at is not None
        and issued_at is not None
        and expires_at is not None
        and issued_at <= evaluated_at < expires_at
    )
    derived = (
        _permission_class(decision_mapping.get("derived_permission_class"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    recomputed_ceiling = bool(
        derived is not None
        and expected_permission_class is not None
        and derived <= expected_permission_class
        and derived <= int(PermissionClass.LOCAL_DRAFT)
    )
    obligations = (
        decision_mapping.get("obligations")
        if isinstance(decision_mapping, Mapping)
        else None
    )
    supported_obligations = _mock_dispatch_obligations_supported(
        effect,
        obligations,
    )
    policy_matches = bool(
        isinstance(decision_mapping, Mapping)
        and request is not None
        and policy is not None
        and decision_mapping.get("request_id") == request.request_id
        and decision_mapping.get("request_digest") == request.digest
        and decision_mapping.get("policy_bundle_id") == policy.bundle_id
        and decision_mapping.get("policy_version") == policy.version
        and decision_mapping.get("policy_digest") == policy.digest
        and issued_at == evaluated_at
    )
    legacy_executable = payload.get("legacy_executable") is True
    recomputed_blocks: list[str] = []
    if not legacy_executable:
        recomputed_blocks.append("legacy_gate_not_executable")
    if not policy_matches:
        recomputed_blocks.append("authorization_policy_mismatch")
    if effect != AuthorizationEffect.PERMIT.value:
        recomputed_blocks.append("authorization_effect_not_permit")
    if not recomputed_current:
        recomputed_blocks.append("authorization_decision_not_current")
    if not recomputed_ceiling:
        recomputed_blocks.append("authorization_class_ceiling_exceeded")
    if not supported_obligations:
        recomputed_blocks.append("authorization_obligation_unsupported")
    recomputed_eligible = not recomputed_blocks
    if (
        payload.get("effect")
        != (
            decision_mapping.get("effect")
            if isinstance(decision_mapping, Mapping)
            else None
        )
        or payload.get("derived_permission_class") != derived
        or payload.get("decision_current_at_evaluation")
        is not recomputed_current
        or payload.get("authority_ceiling_satisfied")
        is not recomputed_ceiling
        or payload.get("obligations_supported")
        is not supported_obligations
        or payload.get("authorization_eligible")
        is not recomputed_eligible
        or payload.get("block_reason_codes") != recomputed_blocks
        or payload.get("evaluated_at") != issued_at
    ):
        issues.append("mock_dispatch_decision_projection_mismatch")

    return _MockDispatchDecisionFacts(
        True,
        sequence,
        occurred_at,
        payload,
        request_mapping if isinstance(request_mapping, Mapping) else None,
        policy_mapping if isinstance(policy_mapping, Mapping) else None,
        decision_mapping if isinstance(decision_mapping, Mapping) else None,
        request_digest if isinstance(request_digest, str) else None,
        policy_digest if isinstance(policy_digest, str) else None,
        decision_digest if isinstance(decision_digest, str) else None,
        effect,
        eligible,
        current,
        issued_at,
        expires_at,
        tuple(sorted(set(issues))),
    )


def _empty_mock_dispatch_decision(
    *,
    observed: bool = False,
    sequence: int | None = None,
    occurred_at: float | None = None,
    issue: str | None = None,
    additional_issues: list[str] | None = None,
) -> _MockDispatchDecisionFacts:
    issues = list(additional_issues or ())
    if issue is not None:
        issues.append(issue)
    return _MockDispatchDecisionFacts(
        observed,
        sequence,
        occurred_at,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        tuple(sorted(set(issues))),
    )


def _is_exact_mock_dispatch_failure(payload: Mapping[str, Any]) -> bool:
    return bool(
        payload.get("failure_stage") == "request_or_evaluation"
        and payload.get("request") is None
        and payload.get("request_digest") is None
        and payload.get("policy") is None
        and payload.get("policy_digest") is None
        and payload.get("decision") is None
        and payload.get("decision_digest") is None
        and payload.get("effect") == AuthorizationEffect.INDETERMINATE.value
        and payload.get("derived_permission_class") is None
        and payload.get("decision_current_at_evaluation") is False
        and payload.get("authority_ceiling_satisfied") is False
        and payload.get("obligations_supported") is False
        and payload.get("authorization_eligible") is False
        and payload.get("block_reason_codes")
        == ["authorization_evaluation_failed"]
    )


def _mock_dispatch_request_from_mapping(
    value: Any,
) -> AuthorizationRequest | None:
    """Reconstruct a typed request without exposing its descriptive fields."""

    if not _is_request_shape(value):
        return None
    assert isinstance(value, Mapping)
    subject = value["subject"]
    action = value["action"]
    resource = value["resource"]
    environment = value["environment"]
    consequences = value["consequences"]
    evidence = value["evidence"]
    assert isinstance(subject, Mapping)
    assert isinstance(action, Mapping)
    assert isinstance(resource, Mapping)
    assert isinstance(environment, Mapping)
    assert isinstance(consequences, Mapping)
    if (
        action.get("descriptive_claims") != []
        or environment.get("approval_grants") != []
        or not isinstance(evidence, list)
        or len(evidence) > _MAX_EVIDENCE_RECORDS
    ):
        return None
    try:
        evidence_values: list[AttributeEvidence] = []
        for item in evidence:
            if not isinstance(item, Mapping) or set(item) != {
                "attribute",
                "authenticated",
                "evidence_id",
                "expires_at",
                "observed_at",
                "source",
                "source_id",
                "value_digest",
            }:
                return None
            observed_at = _optional_timestamp(item.get("observed_at"))
            expires_at = _optional_timestamp(item.get("expires_at"))
            if observed_at is None or expires_at is None:
                return None
            evidence_values.append(
                AttributeEvidence(
                    evidence_id=item["evidence_id"],
                    attribute=item["attribute"],
                    value_digest=item["value_digest"],
                    source=EvidenceSource(item["source"]),
                    source_id=item["source_id"],
                    observed_at=observed_at,
                    expires_at=expires_at,
                    authenticated=item["authenticated"],
                )
            )
        evaluated_at = _optional_timestamp(environment.get("evaluated_at"))
        if evaluated_at is None:
            return None
        request = AuthorizationRequest(
            request_id=value["request_id"],
            subject=SubjectAttributes(
                principal_id=subject["principal_id"],
                controller_id=subject["controller_id"],
                role=Role(subject["role"]),
                role_version=subject["role_version"],
                profile_id=subject["profile_id"],
                runner_id=subject["runner_id"],
                session_id=subject["session_id"],
            ),
            action=ActionAttributes(
                verb=ActionVerb(action["verb"]),
                operation=action["operation"],
                parameters_digest=action["parameters_digest"],
                intended_effect=action["intended_effect"],
                tool_id=action["tool_id"],
                descriptive_claims=(),
            ),
            resource=ResourceAttributes(
                resource_type=resource["resource_type"],
                identifier=resource["identifier"],
                version=resource["version"],
                owner=resource["owner"],
                trust_boundary=resource["trust_boundary"],
                protected=resource["protected"],
                sensitivity=ImpactLevel(resource["sensitivity"]),
                repository_id=resource["repository_id"],
                content_digest=resource["content_digest"],
            ),
            environment=EnvironmentAttributes(
                evaluated_at=evaluated_at,
                isolation_state=IsolationState(
                    environment["isolation_state"]
                ),
                network_state=NetworkState(environment["network_state"]),
                billing_route=BillingRoute(environment["billing_route"]),
                capacity_state=CapacityState(environment["capacity_state"]),
                paid_continuation_protection=PaidContinuationProtection(
                    environment["paid_continuation_protection"]
                ),
                circuit_state=CircuitState(environment["circuit_state"]),
                flow_state=environment["flow_state"],
                approval_grants=(),
            ),
            consequences=ConsequenceVector(
                confidentiality=ImpactLevel(consequences["confidentiality"]),
                integrity=ImpactLevel(consequences["integrity"]),
                availability=ImpactLevel(consequences["availability"]),
                reach=Reach(consequences["reach"]),
                destructive=consequences["destructive"],
                reversible=consequences["reversible"],
                sensitivity=ImpactLevel(consequences["sensitivity"]),
                blast_radius=BlastRadius(consequences["blast_radius"]),
            ),
            evidence=tuple(evidence_values),
        )
    except (KeyError, OverflowError, TypeError, ValueError):
        return None
    return request if request.to_canonical() == value else None


def _mock_dispatch_policy_from_mapping(value: Any) -> PolicyBundle | None:
    """Reconstruct the strict policy bundle used at the dispatch boundary."""

    if not isinstance(value, Mapping) or set(value) != {
        "allowed_billing_routes",
        "allowed_flow_states",
        "allowed_network_states",
        "allowed_operations",
        "allowed_resource_types",
        "allowed_roles",
        "allowed_trust_boundaries",
        "allowed_verbs",
        "approval_requirements",
        "bundle_id",
        "decision_ttl_seconds",
        "enabled_classes",
        "evidence_requirements",
        "issued_at",
        "schema_version",
        "version",
    }:
        return None
    list_keys = {
        "allowed_billing_routes",
        "allowed_flow_states",
        "allowed_network_states",
        "allowed_operations",
        "allowed_resource_types",
        "allowed_roles",
        "allowed_trust_boundaries",
        "allowed_verbs",
        "approval_requirements",
        "enabled_classes",
        "evidence_requirements",
    }
    if any(not isinstance(value.get(key), list) for key in list_keys):
        return None
    try:
        evidence_requirements: list[EvidenceRequirement] = []
        for item in value["evidence_requirements"]:
            if not isinstance(item, Mapping) or set(item) != {
                "attribute",
                "max_age_seconds",
                "trusted_sources",
            } or not isinstance(item.get("trusted_sources"), list):
                return None
            evidence_requirements.append(
                EvidenceRequirement(
                    attribute=item["attribute"],
                    trusted_sources=tuple(
                        EvidenceSource(source)
                        for source in item["trusted_sources"]
                    ),
                    max_age_seconds=float(item["max_age_seconds"]),
                )
            )
        approval_requirements: list[ApprovalRequirement] = []
        for item in value["approval_requirements"]:
            if not isinstance(item, Mapping) or set(item) != {
                "allowed_approver_ids",
                "allowed_approver_roles",
                "permission_classes",
                "require_distinct_principal",
                "requirement_id",
                "resource_types",
                "verbs",
            }:
                return None
            if any(
                not isinstance(item.get(key), list)
                for key in (
                    "allowed_approver_ids",
                    "allowed_approver_roles",
                    "permission_classes",
                    "resource_types",
                    "verbs",
                )
            ):
                return None
            approval_requirements.append(
                ApprovalRequirement(
                    requirement_id=item["requirement_id"],
                    verbs=tuple(ActionVerb(verb) for verb in item["verbs"]),
                    resource_types=tuple(item["resource_types"]),
                    permission_classes=tuple(
                        PermissionClass(permission_class)
                        for permission_class in item["permission_classes"]
                    ),
                    allowed_approver_ids=tuple(
                        item["allowed_approver_ids"]
                    ),
                    allowed_approver_roles=tuple(
                        Role(role) for role in item["allowed_approver_roles"]
                    ),
                    require_distinct_principal=item[
                        "require_distinct_principal"
                    ],
                )
            )
        issued_at = _optional_timestamp(value.get("issued_at"))
        if issued_at is None:
            return None
        policy = PolicyBundle(
            bundle_id=value["bundle_id"],
            version=value["version"],
            issued_at=issued_at,
            evidence_requirements=tuple(evidence_requirements),
            enabled_classes=tuple(
                PermissionClass(item) for item in value["enabled_classes"]
            ),
            allowed_verbs=tuple(
                ActionVerb(item) for item in value["allowed_verbs"]
            ),
            allowed_roles=tuple(
                Role(item) for item in value["allowed_roles"]
            ),
            allowed_operations=tuple(value["allowed_operations"]),
            allowed_resource_types=tuple(value["allowed_resource_types"]),
            allowed_trust_boundaries=tuple(
                value["allowed_trust_boundaries"]
            ),
            allowed_flow_states=tuple(value["allowed_flow_states"]),
            allowed_network_states=tuple(
                NetworkState(item) for item in value["allowed_network_states"]
            ),
            allowed_billing_routes=tuple(
                BillingRoute(item) for item in value["allowed_billing_routes"]
            ),
            approval_requirements=tuple(approval_requirements),
            decision_ttl_seconds=float(value["decision_ttl_seconds"]),
            schema_version=value["schema_version"],
        )
    except (KeyError, OverflowError, TypeError, ValueError):
        return None
    return policy if policy.to_canonical() == value else None


def _inspect_mock_dispatch_request_projection(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    task_billing: _TaskBillingFacts,
    request: AuthorizationRequest,
    task_intent: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    binding = task_binding.binding
    selected = task_execution_selection.selected
    billing = task_billing.payload
    if not isinstance(binding, Mapping):
        return ("mock_dispatch_request_binding_mismatch",)
    expected_parameters_digest = canonical_digest(
        {
            "attempt": binding.get("attempt"),
            "billing_assessment_digest": task_billing.assessment_digest,
            "context_digest": binding.get("context_digest"),
            "execution_selection_digest": binding.get(
                "execution_selection_digest"
            ),
            "output_schema_digest": binding.get("output_schema_digest"),
            "profile_ref": binding.get("profile_ref"),
            "prompt_digest": binding.get("prompt_digest"),
            "run_ref": binding.get("run_ref"),
            "runner_overrides_digest": binding.get(
                "runner_overrides_digest"
            ),
            "task_attempt_binding_digest": task_binding.binding_digest,
            "task_authorization_intent_digest": binding.get(
                "authorization_intent_digest"
            ),
            "task_definition_digest": binding.get(
                "task_definition_digest"
            ),
            "timeout_seconds": binding.get("timeout_seconds"),
            "workspace_ref": binding.get("workspace_ref"),
        }
    )
    expected_resource_identifier = canonical_digest(
        {
            "resource_type": MOCK_DISPATCH_RESOURCE_TYPE,
            "run_ref": binding.get("run_ref"),
            "workspace_ref": binding.get("workspace_ref"),
        }
    )
    expected_profile_ref = (
        selected.get("profile_id")
        if isinstance(selected, Mapping)
        else None
    )
    expected_profile_ref = (
        canonical_digest({"profile_id": expected_profile_ref})
        if isinstance(expected_profile_ref, str)
        else binding.get("profile_ref")
    )
    expected = bool(
        request.request_id
        == f"{MOCK_DISPATCH_ACTION_SCOPE}:{fact.raw_run_id}"
        and request.subject.principal_id == "agent:task-attempt"
        and request.subject.controller_id == "ordomata:local-controller"
        and request.subject.role is Role.IMPLEMENTER
        and request.subject.role_version == "1"
        and request.subject.profile_id == binding.get("profile_ref")
        and request.subject.profile_id == expected_profile_ref
        and request.subject.runner_id == "mock"
        and request.subject.session_id == f"attempt:{fact.raw_run_id}"
        and request.action.verb is ActionVerb.EXECUTE
        and request.action.operation == MOCK_DISPATCH_OPERATION
        and request.action.parameters_digest == expected_parameters_digest
        and request.action.intended_effect
        == "execute_deterministic_in_memory_mock_attempt"
        and request.action.tool_id is None
        and not request.action.descriptive_claims
        and request.resource.resource_type == MOCK_DISPATCH_RESOURCE_TYPE
        and request.resource.identifier == expected_resource_identifier
        and request.resource.version == binding.get("task_definition_digest")
        and request.resource.owner == "operator:local"
        and request.resource.trust_boundary == "isolated_run_workspace"
        and request.resource.repository_id == binding.get("repository_ref")
        and request.resource.content_digest == binding.get("prompt_digest")
        and request.environment.isolation_state is IsolationState.VERIFIED
        and request.environment.network_state is NetworkState.DISABLED
        and request.environment.billing_route is BillingRoute.MOCK
        and isinstance(billing, Mapping)
        and request.environment.capacity_state.value
        == billing.get("capacity_state")
        and request.environment.paid_continuation_protection.value
        == billing.get("paid_continuation_protection")
        and request.environment.circuit_state is CircuitState.CLOSED
        and request.environment.flow_state == "runner_dispatch_proposed"
        and not request.environment.approval_grants
        and billing.get("runner_id") == "mock"
        and billing.get("route") == BillingRoute.MOCK.value
        and billing.get("confidence") == AssessmentConfidence.HIGH.value
    )
    issues: list[str] = []
    if not expected:
        issues.append("mock_dispatch_request_binding_mismatch")
    if not isinstance(task_intent, Mapping):
        issues.append("mock_dispatch_request_intent_mismatch")
    else:
        intent_resource = task_intent.get("resource")
        intent_consequences = task_intent.get("consequences")
        if (
            not isinstance(intent_resource, Mapping)
            or not isinstance(intent_consequences, Mapping)
            or request.resource.protected
            != intent_resource.get("protected")
            or request.resource.sensitivity.value
            != intent_resource.get("sensitivity")
            or request.consequences.to_canonical() != intent_consequences
        ):
            issues.append("mock_dispatch_request_intent_mismatch")
    expected_evidence = {
        "subject": EvidenceSource.CONTROLLER,
        "action": EvidenceSource.LOCAL_REGISTRY,
        "resource": EvidenceSource.LOCAL_REGISTRY,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.LOCAL_REGISTRY,
    }
    evidence_by_attribute = {
        item.attribute: item for item in request.evidence
    }
    evaluated_at = request.environment.evaluated_at
    if (
        len(request.evidence) != len(expected_evidence)
        or len(evidence_by_attribute) != len(request.evidence)
        or set(evidence_by_attribute) != set(expected_evidence)
    ):
        issues.append("mock_dispatch_evidence_invalid")
    else:
        for attribute, expected_source in expected_evidence.items():
            item = evidence_by_attribute[attribute]
            if (
                item.evidence_id
                != f"{MOCK_DISPATCH_ACTION_SCOPE}:{attribute}"
                or item.source is not expected_source
                or item.source_id != f"ordomata:{expected_source.value}"
                or item.observed_at != evaluated_at
                or item.expires_at
                != evaluated_at + _SHADOW_EVIDENCE_LIFETIME_SECONDS
                or item.authenticated is not True
                or item.value_digest
                != canonical_digest(request.attribute_value(attribute))
            ):
                issues.append("mock_dispatch_evidence_invalid")
                break
    return tuple(sorted(set(issues)))


def _mock_dispatch_task_intent_from_shadow(
    task_binding: _TaskAttemptBindingFacts,
    rows: list[sqlite3.Row],
) -> Mapping[str, Any] | None:
    """Recover the validated task intent without treating shadow as policy."""

    binding = task_binding.binding
    if not isinstance(binding, Mapping):
        return None
    candidates: list[Mapping[str, Any]] = []
    for row in rows:
        payload = _bounded_json_mapping(row["payload_json"])
        if (
            not isinstance(payload, Mapping)
            or payload.get("schema_version") != 2
            or payload.get("mode") != "shadow"
            or payload.get("action_scope") != ADMISSION_SCOPE
            or payload.get("task_attempt_binding_digest")
            != task_binding.binding_digest
        ):
            continue
        intent = payload.get("task_authorization_intent")
        intent_digest = payload.get("intent_digest")
        if (
            not _is_task_intent_shape(intent)
            or not isinstance(intent, Mapping)
            or not _digest_matches(intent_digest, intent)
            or intent_digest != binding.get("authorization_intent_digest")
        ):
            continue
        candidates.append(intent)
    return candidates[0] if len(candidates) == 1 else None


def _inspect_mock_dispatch_policy_projection(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    policy: PolicyBundle,
) -> tuple[str, ...]:
    binding = task_binding.binding
    expected_classes = tuple(
        permission_class
        for permission_class in (
            PermissionClass.READ_ONLY,
            PermissionClass.LOCAL_DRAFT,
        )
        if fact.permission_class is not None
        and int(permission_class) <= fact.permission_class
    )
    expected_evidence = tuple(
        sorted(
            PolicyBundle.current_stage().evidence_requirements,
            key=lambda item: item.attribute,
        )
    )
    expected_approvals_digest: str | None = None
    approvals_valid = False
    if not policy.approval_requirements:
        expected_approvals_digest = canonical_digest(
            {"approver": "operator", "required_before_run": False}
        )
        approvals_valid = True
    elif len(policy.approval_requirements) == 1:
        requirement = policy.approval_requirements[0]
        approvals_valid = bool(
            requirement.requirement_id
            == "task_contract_pre_run_operator_approval"
            and requirement.verbs == (ActionVerb.EXECUTE,)
            and requirement.resource_types
            == (MOCK_DISPATCH_RESOURCE_TYPE,)
            and not requirement.permission_classes
            and len(requirement.allowed_approver_ids) == 1
            and _is_digest(requirement.allowed_approver_ids[0])
            and requirement.allowed_approver_roles == (Role.OPERATOR,)
            and requirement.require_distinct_principal is True
        )
        if approvals_valid:
            # The binding intentionally retains only a digest of the private
            # contract approver, while the policy retains a different scoped
            # digest.  Their preimages cannot be linked by this read-only
            # projection, so both are shape-checked but not falsely equated.
            expected_approvals_digest = (
                binding.get("pre_run_approval_requirements_digest")
                if isinstance(binding, Mapping)
                else None
            )
    projection_valid = bool(
        policy.bundle_id == MOCK_DISPATCH_POLICY_ID
        and policy.version == MOCK_DISPATCH_POLICY_VERSION
        and policy.issued_at == 0.0
        and policy.schema_version == MOCK_DISPATCH_EVENT_SCHEMA_VERSION
        and policy.evidence_requirements == expected_evidence
        and policy.enabled_classes == expected_classes
        and policy.allowed_verbs == (ActionVerb.EXECUTE,)
        and policy.allowed_roles == (Role.IMPLEMENTER,)
        and policy.allowed_operations == (MOCK_DISPATCH_OPERATION,)
        and policy.allowed_resource_types == (MOCK_DISPATCH_RESOURCE_TYPE,)
        and policy.allowed_trust_boundaries
        == ("isolated_run_workspace",)
        and policy.allowed_flow_states == ("runner_dispatch_proposed",)
        and policy.allowed_network_states == (NetworkState.DISABLED,)
        and policy.allowed_billing_routes == (BillingRoute.MOCK,)
        and policy.decision_ttl_seconds == 60.0
        and approvals_valid
        and isinstance(binding, Mapping)
        and expected_approvals_digest
        == binding.get("pre_run_approval_requirements_digest")
    )
    return () if projection_valid else ("mock_dispatch_policy_binding_mismatch",)


def _mock_dispatch_obligations_supported(
    effect: str | None,
    obligations: Any,
) -> bool:
    if effect != AuthorizationEffect.PERMIT.value:
        return True
    if not isinstance(obligations, list):
        return False
    values: list[tuple[Any, Any]] = []
    for item in obligations:
        if not isinstance(item, Mapping) or set(item) != {"kind", "value"}:
            return False
        kind = item.get("kind")
        obligation_value = item.get("value")
        if not isinstance(kind, str) or not isinstance(
            obligation_value,
            str,
        ):
            return False
        values.append((kind, obligation_value))
    return frozenset(values) == frozenset(
        {
            (ObligationKind.AUDIT_RECEIPT.value, "append_after_action"),
            (ObligationKind.ISOLATED_LOCAL_ONLY.value, "required"),
        }
    ) and len(values) == 2


def _inspect_mock_dispatch_receipt(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    decision: _MockDispatchDecisionFacts,
    task_accounting: _TaskAccountingFacts,
    rows: list[sqlite3.Row],
    terminal_rows: list[sqlite3.Row],
) -> _MockDispatchReceiptFacts:
    """Validate the exact post-invocation receipt and its temporal links."""

    enforcing = (
        task_binding.schema_version
        in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    if not enforcing:
        if rows:
            return _empty_mock_dispatch_receipt(
                observed=True,
                issue="mock_dispatch_receipt_unexpected",
            )
        return _empty_mock_dispatch_receipt()

    freshness_stop = _is_mock_dispatch_freshness_stop(
        fact,
        decision,
        terminal_rows,
    )
    invocation_began = bool(
        rows or (fact.running_observed and not freshness_stop)
    )
    if len(rows) != 1:
        if not rows and not invocation_began:
            return _empty_mock_dispatch_receipt()
        return _empty_mock_dispatch_receipt(
            observed=bool(rows),
            issue=(
                "mock_dispatch_receipt_missing"
                if not rows
                else "mock_dispatch_receipt_duplicate"
            ),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    occurred_at = _optional_timestamp(row["occurred_at"])
    payload = _bounded_json_mapping(row["payload_json"])
    issues: list[str] = []
    if sequence is None:
        issues.append("mock_dispatch_receipt_sequence_invalid")
    if occurred_at is None:
        issues.append("mock_dispatch_receipt_timestamp_invalid")
    if not isinstance(payload, Mapping) or set(payload) != {
        "action_scope",
        "decision_digest",
        "enforcement_coverage",
        "execution_selection_digest",
        "mode",
        "receipt",
        "receipt_digest",
        "request_digest",
        "schema_version",
        "task_attempt_binding_digest",
    }:
        return _empty_mock_dispatch_receipt(
            observed=True,
            sequence=sequence,
            occurred_at=occurred_at,
            issue="mock_dispatch_receipt_payload_invalid",
            additional_issues=issues,
        )
    if (
        payload.get("schema_version") != MOCK_DISPATCH_EVENT_SCHEMA_VERSION
        or payload.get("mode") != "enforcing"
        or payload.get("action_scope") != MOCK_DISPATCH_ACTION_SCOPE
        or payload.get("enforcement_coverage")
        != TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
    ):
        issues.append("mock_dispatch_receipt_payload_invalid")

    receipt = payload.get("receipt")
    if not isinstance(receipt, Mapping) or set(receipt) != {
        "completed_at",
        "decision_digest",
        "enforced_action_digest",
        "executor_id",
        "obligation_results",
        "outcome",
        "receipt_id",
        "request_digest",
        "result_digest",
        "started_at",
    }:
        return _empty_mock_dispatch_receipt(
            observed=True,
            sequence=sequence,
            occurred_at=occurred_at,
            payload=payload,
            issue="mock_dispatch_receipt_body_invalid",
            additional_issues=issues,
        )

    request_digest = decision.request_digest
    decision_digest = decision.decision_digest
    binding_digest = task_binding.binding_digest
    if (
        payload.get("task_attempt_binding_digest") != binding_digest
        or payload.get("execution_selection_digest")
        != task_execution_selection.selection_digest
        or payload.get("request_digest") != request_digest
        or payload.get("decision_digest") != decision_digest
        or receipt.get("request_digest") != request_digest
        or receipt.get("decision_digest") != decision_digest
    ):
        issues.append("mock_dispatch_receipt_binding_mismatch")
    if not _digest_matches(payload.get("receipt_digest"), receipt):
        issues.append("mock_dispatch_receipt_digest_mismatch")
    expected_receipt_id = (
        canonical_digest(
            {
                "decision_digest": decision_digest,
                "request_digest": request_digest,
                "task_attempt_binding_digest": binding_digest,
                "receipt_kind": "mock_dispatch_action",
            }
        )
        if all(
            isinstance(value, str)
            for value in (decision_digest, request_digest, binding_digest)
        )
        else None
    )
    if (
        receipt.get("receipt_id") != expected_receipt_id
        or row["event_id"] != receipt.get("receipt_id")
    ):
        issues.append("mock_dispatch_receipt_event_identifier_mismatch")
    if receipt.get("executor_id") != MOCK_DISPATCH_EXECUTOR_ID:
        issues.append("mock_dispatch_receipt_executor_mismatch")

    request_mapping = decision.request
    expected_action_digest = (
        canonical_digest(
            {
                "action": request_mapping.get("action"),
                "resource": request_mapping.get("resource"),
            }
        )
        if isinstance(request_mapping, Mapping)
        and isinstance(request_mapping.get("action"), Mapping)
        and isinstance(request_mapping.get("resource"), Mapping)
        else None
    )
    if receipt.get("enforced_action_digest") != expected_action_digest:
        issues.append("mock_dispatch_receipt_action_mismatch")

    decision_obligations = (
        decision.decision.get("obligations")
        if isinstance(decision.decision, Mapping)
        else None
    )
    obligation_results = receipt.get("obligation_results")
    if not _mock_dispatch_receipt_obligations_match(
        decision_obligations,
        obligation_results,
    ):
        issues.append("mock_dispatch_receipt_obligation_mismatch")

    outcome = _known_string(
        receipt.get("outcome"),
        frozenset(item.value for item in ReceiptOutcome),
    )
    started_at = _optional_timestamp(receipt.get("started_at"))
    completed_at = _optional_timestamp(receipt.get("completed_at"))
    permit_current = bool(
        decision.effect == AuthorizationEffect.PERMIT.value
        and decision.authorization_eligible is True
        and started_at is not None
        and decision.issued_at is not None
        and decision.expires_at is not None
        and decision.issued_at <= started_at < decision.expires_at
    )
    if outcome is None:
        issues.append("mock_dispatch_receipt_outcome_invalid")
    if (
        started_at is None
        or completed_at is None
        or completed_at < started_at
        or occurred_at is None
        or occurred_at < completed_at
    ):
        issues.append("mock_dispatch_receipt_timestamp_invalid")
    if not permit_current:
        issues.append("mock_dispatch_receipt_permit_not_current")

    if (
        sequence is not None
        and (
            decision.sequence is None
            or sequence <= decision.sequence
            or fact.running_sequence is None
            or sequence <= fact.running_sequence
            or (
                fact.runner_event_last_sequence is not None
                and sequence <= fact.runner_event_last_sequence
            )
            or (
                fact.accounting_sequence is not None
                and sequence >= fact.accounting_sequence
            )
            or (
                fact.terminal_sequence is not None
                and sequence >= fact.terminal_sequence
            )
        )
    ):
        issues.append("mock_dispatch_receipt_order_invalid")

    accounting = task_accounting.payload
    result_digest = receipt.get("result_digest")
    if isinstance(accounting, Mapping):
        expected_result_digest = canonical_digest(
            {
                "harness_process_started": accounting.get(
                    "harness_process_started"
                ),
                "live_model_execution_occurred": accounting.get(
                    "live_model_execution_occurred"
                ),
                "run_ref": fact.run_ref,
                "runner_event_count": accounting.get("runner_event_count"),
                "runner_id": fact.raw_runner_id,
                "status": accounting.get("result_status"),
            }
        )
        expected_outcome = _mock_dispatch_outcome_for_status(
            accounting.get("result_status")
        )
        if (
            result_digest != expected_result_digest
            or outcome != expected_outcome
        ):
            issues.append("mock_dispatch_receipt_result_mismatch")
    elif result_digest is not None or outcome == ReceiptOutcome.SUCCEEDED.value:
        issues.append("mock_dispatch_receipt_result_mismatch")
    if not _is_optional_digest(result_digest):
        issues.append("mock_dispatch_receipt_body_invalid")

    return _MockDispatchReceiptFacts(
        True,
        sequence,
        occurred_at,
        payload,
        receipt,
        outcome,
        started_at,
        completed_at,
        permit_current,
        tuple(sorted(set(issues))),
    )


def _empty_mock_dispatch_receipt(
    *,
    observed: bool = False,
    sequence: int | None = None,
    occurred_at: float | None = None,
    payload: Mapping[str, Any] | None = None,
    issue: str | None = None,
    additional_issues: list[str] | None = None,
) -> _MockDispatchReceiptFacts:
    issues = list(additional_issues or ())
    if issue is not None:
        issues.append(issue)
    return _MockDispatchReceiptFacts(
        observed,
        sequence,
        occurred_at,
        payload,
        None,
        None,
        None,
        None,
        None,
        tuple(sorted(set(issues))),
    )


def _is_mock_dispatch_freshness_stop(
    fact: _RunFacts,
    decision: _MockDispatchDecisionFacts,
    rows: list[sqlite3.Row],
) -> bool:
    """Recognize only the controller's exact pre-invocation freshness stop."""

    if len(rows) != 1:
        return False
    row = rows[0]
    payload = _bounded_json_mapping(row["payload_json"])
    terminal_sequence = _optional_sequence(row["sequence"])
    return bool(
        row["event_type"] == "status"
        and row["status"] == RunStatus.BLOCKED.value
        and fact.latest_status == RunStatus.BLOCKED.value
        and terminal_sequence == fact.terminal_sequence
        and terminal_sequence is not None
        and fact.running_sequence is not None
        and terminal_sequence > fact.running_sequence
        and decision.sequence is not None
        and terminal_sequence > decision.sequence
        and decision.effect == AuthorizationEffect.PERMIT.value
        and decision.authorization_eligible is True
        and _optional_timestamp(row["occurred_at"]) is not None
        and isinstance(payload, Mapping)
        and payload == {"phase": "mock_dispatch_authorization_freshness"}
        and _event_identifier_matches_status(row, payload, fact.raw_run_id)
    )


def _event_identifier_matches_status(
    row: sqlite3.Row,
    payload: Mapping[str, Any],
    run_id: str,
) -> bool:
    event_id = row["event_id"]
    if not _is_digest(event_id):
        return False
    try:
        return event_id == canonical_digest(
            {
                "event_type": "status",
                "payload": payload,
                "run_id": run_id,
                "status": row["status"],
            }
        )
    except (TypeError, ValueError, RecursionError):
        return False


def _mock_dispatch_receipt_obligations_match(
    decision_obligations: Any,
    obligation_results: Any,
) -> bool:
    if not isinstance(decision_obligations, list) or not isinstance(
        obligation_results,
        list,
    ):
        return False
    expected: list[tuple[Any, Any]] = []
    for item in decision_obligations:
        if not isinstance(item, Mapping) or set(item) != {"kind", "value"}:
            return False
        kind = item.get("kind")
        obligation_value = item.get("value")
        if not isinstance(kind, str) or not isinstance(
            obligation_value,
            str,
        ):
            return False
        expected.append((kind, obligation_value))
    observed: list[tuple[Any, Any]] = []
    for item in obligation_results:
        if not isinstance(item, Mapping) or set(item) != {
            "kind",
            "satisfied",
            "value",
        } or item.get("satisfied") is not True:
            return False
        kind = item.get("kind")
        obligation_value = item.get("value")
        if not isinstance(kind, str) or not isinstance(
            obligation_value,
            str,
        ):
            return False
        observed.append((kind, obligation_value))
    return bool(
        len(observed) == len(set(observed))
        and sorted(observed) == sorted(expected)
    )


def _mock_dispatch_outcome_for_status(status: Any) -> str | None:
    if status == RunStatus.SUCCEEDED.value:
        return ReceiptOutcome.SUCCEEDED.value
    if status == RunStatus.CANCELLED.value:
        return ReceiptOutcome.CANCELLED.value
    if status in {
        RunStatus.FAILED.value,
        RunStatus.BLOCKED.value,
        RunStatus.QUARANTINED.value,
    }:
        return ReceiptOutcome.FAILED.value
    return None


def _project_mock_dispatch_enforcement(
    task_binding: _TaskAttemptBindingFacts,
    decision: _MockDispatchDecisionFacts,
    receipt: _MockDispatchReceiptFacts,
) -> MockDispatchEnforcementInspection:
    issues = tuple(sorted(set((*decision.issues, *receipt.issues))))
    return MockDispatchEnforcementInspection(
        required=(
            task_binding.schema_version
            in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
        ),
        decision_observed=decision.observed,
        decision_sequence=decision.sequence,
        effect=decision.effect,
        authorization_eligible=decision.authorization_eligible,
        decision_current_at_evaluation=(
            decision.decision_current_at_evaluation
        ),
        action_receipt_observed=receipt.observed,
        action_receipt_sequence=receipt.sequence,
        action_receipt_outcome=receipt.outcome,
        permit_current_at_action_start=(
            receipt.permit_current_at_action_start
        ),
        integrity_issues=issues,
    )


def _inspect_local_candidate_publication_decision(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    dispatch_decision: _MockDispatchDecisionFacts,
    dispatch_receipt: _MockDispatchReceiptFacts,
    task_accounting: _TaskAccountingFacts,
    shadow_rows: list[sqlite3.Row],
    artifact_rows: list[sqlite3.Row],
    rows: list[sqlite3.Row],
) -> _LocalCandidatePublicationDecisionFacts:
    """Validate and independently re-evaluate the publication PEP decision."""

    required = (
        task_binding.schema_version
        in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    boundary_observed = _local_candidate_publication_boundary_observed(
        fact,
        shadow_rows,
        artifact_rows,
        rows,
    )
    if not required:
        if rows:
            return _empty_local_candidate_publication_decision(
                observed=True,
                issue="local_candidate_publication_decision_unexpected",
            )
        return _empty_local_candidate_publication_decision()
    if not boundary_observed and not rows:
        return _empty_local_candidate_publication_decision()
    if len(rows) != 1:
        return _empty_local_candidate_publication_decision(
            observed=bool(rows),
            issue=(
                "local_candidate_publication_decision_missing"
                if not rows
                else "local_candidate_publication_decision_duplicate"
            ),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    occurred_at = _optional_timestamp(row["occurred_at"])
    event_id = row["event_id"] if _is_digest(row["event_id"]) else None
    payload = _bounded_json_mapping(row["payload_json"])
    issues: list[str] = []
    if sequence is None:
        issues.append("local_candidate_publication_decision_sequence_invalid")
    if occurred_at is None:
        issues.append("local_candidate_publication_decision_timestamp_invalid")
    if not isinstance(payload, Mapping):
        return _empty_local_candidate_publication_decision(
            observed=True,
            sequence=sequence,
            occurred_at=occurred_at,
            event_id=event_id,
            issue="local_candidate_publication_decision_payload_invalid",
            additional_issues=issues,
        )

    failure = payload.get("failure_stage") is not None
    expected_keys = {
        "action_scope",
        "artifact_digest",
        "artifact_metadata_digest",
        "authorization_eligible",
        "authority_ceiling_satisfied",
        "billing_disposition_digest",
        "block_reason_codes",
        "controller_owned_mock_runner",
        "credential_scan_passed",
        "decision",
        "decision_current_at_evaluation",
        "decision_digest",
        "derived_permission_class",
        "destination_digest",
        "dispatch_action_receipt_digest",
        "dispatch_decision_digest",
        "dispatch_request_digest",
        "effect",
        "enforcement_coverage",
        "evaluated_at",
        "evaluation_accepted",
        "execution_accounting_digest",
        "execution_selection_digest",
        "legacy_executable",
        "mode",
        "obligations_supported",
        "policy",
        "policy_digest",
        "publication_authorization_intent_digest",
        "request",
        "request_digest",
        "requested_permission_class",
        "safe_publication_prerequisites",
        "schema_version",
        "task_attempt_binding_digest",
        "task_authorization_intent_digest",
    }
    if failure:
        expected_keys.add("failure_stage")
    if set(payload) != expected_keys:
        issues.append("local_candidate_publication_decision_payload_invalid")
    if (
        payload.get("schema_version")
        != LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION
        or payload.get("mode") != "enforcing"
        or payload.get("action_scope")
        != LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE
        or payload.get("enforcement_coverage")
        != LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
    ):
        issues.append("local_candidate_publication_decision_payload_invalid")
    if not _event_identifier_matches(
        row,
        event_type=LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
        payload=payload,
        run_id=fact.raw_run_id,
    ):
        issues.append(
            "local_candidate_publication_decision_event_identifier_mismatch"
        )

    binding = task_binding.binding
    accounting = task_accounting.payload
    dispatch_payload = dispatch_receipt.payload
    dispatch_receipt_digest = (
        dispatch_payload.get("receipt_digest")
        if isinstance(dispatch_payload, Mapping)
        else None
    )
    accounting_digest = (
        canonical_digest(accounting)
        if isinstance(accounting, Mapping)
        else None
    )
    expected_class = fact.permission_class
    expected_legacy = expected_class in {
        int(PermissionClass.READ_ONLY),
        int(PermissionClass.LOCAL_DRAFT),
    }
    selected = task_execution_selection.selected
    controller_owned_mock_runner = bool(
        isinstance(binding, Mapping)
        and binding.get("runner_id") == "mock"
        and fact.raw_runner_id == "mock"
        and isinstance(selected, Mapping)
        and selected.get("runner_id") == "mock"
    )
    safe_publication_prerequisites = (
        _local_candidate_publication_prerequisites_satisfied(
            dispatch_payload,
            accounting,
        )
    )
    if (
        not isinstance(binding, Mapping)
        or task_binding.binding_digest is None
        or payload.get("task_attempt_binding_digest")
        != task_binding.binding_digest
        or payload.get("execution_selection_digest")
        != task_execution_selection.selection_digest
        or payload.get("task_authorization_intent_digest")
        != binding.get("authorization_intent_digest")
        or payload.get("dispatch_request_digest")
        != dispatch_decision.request_digest
        or payload.get("dispatch_decision_digest")
        != dispatch_decision.decision_digest
        or payload.get("dispatch_action_receipt_digest")
        != dispatch_receipt_digest
        or payload.get("execution_accounting_digest")
        != accounting_digest
        or payload.get("billing_disposition_digest")
        != task_accounting.billing_disposition_digest
        or payload.get("requested_permission_class") != expected_class
        or payload.get("controller_owned_mock_runner")
        is not controller_owned_mock_runner
        or payload.get("legacy_executable") is not expected_legacy
        or payload.get("safe_publication_prerequisites")
        is not safe_publication_prerequisites
        or payload.get("evaluation_accepted") is not True
        or payload.get("credential_scan_passed") is not True
    ):
        issues.append("local_candidate_publication_decision_binding_mismatch")
    for digest_key in (
        "artifact_digest",
        "artifact_metadata_digest",
        "destination_digest",
        "publication_authorization_intent_digest",
    ):
        if not _is_digest(payload.get(digest_key)):
            issues.append(
                "local_candidate_publication_decision_binding_mismatch"
            )

    publication_shadow = _raw_task_publication_shadow_payload(shadow_rows)
    publication_shadow_request = (
        publication_shadow.get("request")
        if isinstance(publication_shadow, Mapping)
        else None
    )
    publication_shadow_resource = (
        publication_shadow_request.get("resource")
        if isinstance(publication_shadow_request, Mapping)
        else None
    )
    if isinstance(publication_shadow, Mapping) and (
        payload.get("publication_authorization_intent_digest")
        != publication_shadow.get("intent_digest")
        or not isinstance(publication_shadow_resource, Mapping)
        or payload.get("artifact_digest")
        != publication_shadow_resource.get("version")
        or payload.get("artifact_digest")
        != publication_shadow_resource.get("content_digest")
    ):
        issues.append("local_candidate_publication_decision_binding_mismatch")

    evaluated_at = _optional_timestamp(payload.get("evaluated_at"))
    if evaluated_at is None or (
        occurred_at is not None and occurred_at < evaluated_at
    ):
        issues.append("local_candidate_publication_decision_timestamp_invalid")
    effect = _known_string(payload.get("effect"), _KNOWN_EFFECTS)
    eligible = _optional_boolean(payload.get("authorization_eligible"))
    current = _optional_boolean(
        payload.get("decision_current_at_evaluation")
    )
    if effect is None or eligible is None or current is None:
        issues.append("local_candidate_publication_decision_projection_invalid")

    if failure:
        if not _is_exact_local_candidate_publication_failure(payload):
            issues.append("local_candidate_publication_decision_failure_invalid")
        return _LocalCandidatePublicationDecisionFacts(
            True,
            sequence,
            occurred_at,
            event_id,
            payload,
            None,
            None,
            None,
            None,
            None,
            None,
            effect,
            eligible,
            current,
            None,
            None,
            tuple(sorted(set(issues))),
        )

    request_mapping = payload.get("request")
    policy_mapping = payload.get("policy")
    decision_mapping = payload.get("decision")
    request_digest = payload.get("request_digest")
    policy_digest = payload.get("policy_digest")
    decision_digest = payload.get("decision_digest")
    if not _digest_matches(request_digest, request_mapping):
        issues.append("local_candidate_publication_request_digest_mismatch")
        request_digest = None
    if not _digest_matches(policy_digest, policy_mapping):
        issues.append("local_candidate_publication_policy_digest_mismatch")
        policy_digest = None
    if not _digest_matches(decision_digest, decision_mapping):
        issues.append("local_candidate_publication_decision_digest_mismatch")
        decision_digest = None

    request = _mock_dispatch_request_from_mapping(request_mapping)
    policy = _mock_dispatch_policy_from_mapping(policy_mapping)
    if request is None:
        issues.append("local_candidate_publication_request_invalid")
    if policy is None:
        issues.append("local_candidate_publication_policy_invalid")
    if not _is_decision_shape(decision_mapping):
        issues.append("local_candidate_publication_authorization_decision_invalid")

    raw_pre_effect = _raw_enforcing_task_pre_effect_payload(artifact_rows)
    task_intent = _mock_dispatch_task_intent_from_shadow(
        task_binding,
        shadow_rows,
    )
    if request is not None:
        issues.extend(
            _inspect_local_candidate_publication_request_projection(
                fact,
                task_binding,
                task_execution_selection,
                dispatch_decision,
                dispatch_receipt,
                task_accounting,
                payload,
                request,
                task_intent,
                raw_pre_effect,
            )
        )
    if policy is not None:
        issues.extend(
            _inspect_local_candidate_publication_policy_projection(policy)
        )

    expected_decision: Mapping[str, Any] | None = None
    if request is not None and policy is not None:
        try:
            expected_decision = ShadowAuthorizationEvaluator().evaluate(
                request,
                policy,
            ).to_canonical()
        except (TypeError, ValueError, ValidationError):
            issues.append(
                "local_candidate_publication_authorization_reevaluation_failed"
            )
    if expected_decision is not None and decision_mapping != expected_decision:
        issues.append(
            "local_candidate_publication_authorization_reevaluation_mismatch"
        )

    issued_at = (
        _optional_timestamp(decision_mapping.get("issued_at"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    expires_at = (
        _optional_timestamp(decision_mapping.get("expires_at"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    recomputed_current = bool(
        evaluated_at is not None
        and issued_at is not None
        and expires_at is not None
        and issued_at <= evaluated_at < expires_at
    )
    derived = (
        _permission_class(decision_mapping.get("derived_permission_class"))
        if isinstance(decision_mapping, Mapping)
        else None
    )
    recomputed_ceiling = bool(
        derived is not None
        and expected_class is not None
        and derived <= expected_class
        and derived <= int(PermissionClass.LOCAL_DRAFT)
    )
    obligations = (
        decision_mapping.get("obligations")
        if isinstance(decision_mapping, Mapping)
        else None
    )
    supported_obligations = _mock_dispatch_obligations_supported(
        effect,
        obligations,
    )
    policy_matches = bool(
        isinstance(decision_mapping, Mapping)
        and request is not None
        and policy is not None
        and decision_mapping.get("request_id") == request.request_id
        and decision_mapping.get("request_digest") == request.digest
        and decision_mapping.get("policy_bundle_id") == policy.bundle_id
        and decision_mapping.get("policy_version") == policy.version
        and decision_mapping.get("policy_digest") == policy.digest
        and issued_at == evaluated_at
    )
    recomputed_blocks: list[str] = []
    if not controller_owned_mock_runner:
        recomputed_blocks.append("controller_owned_mock_runner_not_verified")
    if not expected_legacy:
        recomputed_blocks.append("legacy_gate_not_executable")
    if not safe_publication_prerequisites:
        recomputed_blocks.append(
            "safe_publication_prerequisites_not_satisfied"
        )
    if not policy_matches:
        recomputed_blocks.append("authorization_policy_mismatch")
    if effect != AuthorizationEffect.PERMIT.value:
        recomputed_blocks.append("authorization_effect_not_permit")
    if not recomputed_current:
        recomputed_blocks.append("authorization_decision_not_current")
    if not recomputed_ceiling:
        recomputed_blocks.append("authorization_class_ceiling_exceeded")
    if not supported_obligations:
        recomputed_blocks.append("authorization_obligation_unsupported")
    reported_blocks = payload.get("block_reason_codes")
    recomputed_eligible = not recomputed_blocks
    if (
        not isinstance(reported_blocks, list)
        or reported_blocks != recomputed_blocks
        or payload.get("decision_current_at_evaluation")
        is not recomputed_current
        or payload.get("authority_ceiling_satisfied")
        is not recomputed_ceiling
        or payload.get("obligations_supported")
        is not supported_obligations
        or payload.get("authorization_eligible")
        is not recomputed_eligible
        or payload.get("derived_permission_class") != derived
        or (
            isinstance(decision_mapping, Mapping)
            and payload.get("effect") != decision_mapping.get("effect")
        )
    ):
        issues.append(
            "local_candidate_publication_decision_projection_mismatch"
        )

    return _LocalCandidatePublicationDecisionFacts(
        True,
        sequence,
        occurred_at,
        event_id,
        payload,
        request_mapping if isinstance(request_mapping, Mapping) else None,
        policy_mapping if isinstance(policy_mapping, Mapping) else None,
        decision_mapping if isinstance(decision_mapping, Mapping) else None,
        request_digest if isinstance(request_digest, str) else None,
        policy_digest if isinstance(policy_digest, str) else None,
        decision_digest if isinstance(decision_digest, str) else None,
        effect,
        eligible,
        current,
        issued_at,
        expires_at,
        tuple(sorted(set(issues))),
    )


def _empty_local_candidate_publication_decision(
    *,
    observed: bool = False,
    sequence: int | None = None,
    occurred_at: float | None = None,
    event_id: str | None = None,
    issue: str | None = None,
    additional_issues: list[str] | None = None,
) -> _LocalCandidatePublicationDecisionFacts:
    issues = list(additional_issues or ())
    if issue is not None:
        issues.append(issue)
    return _LocalCandidatePublicationDecisionFacts(
        observed,
        sequence,
        occurred_at,
        event_id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        tuple(sorted(set(issues))),
    )


def _local_candidate_publication_boundary_observed(
    fact: _RunFacts,
    shadow_rows: list[sqlite3.Row],
    artifact_rows: list[sqlite3.Row],
    decision_rows: list[sqlite3.Row],
) -> bool:
    publication_shadow = any(
        _shadow_row_schema(row) == 5
        and (
            (_bounded_json_mapping(row["payload_json"]) or {}).get(
                "action_scope"
            )
            == PUBLICATION_SCOPE
        )
        for row in shadow_rows
    )
    return bool(
        decision_rows
        or publication_shadow
        or artifact_rows
        or fact.task_artifact_metadata_count > 0
        or fact.succeeded_observed
    )


def _is_exact_local_candidate_publication_failure(
    payload: Mapping[str, Any],
) -> bool:
    digest_keys = {
        "artifact_digest",
        "artifact_metadata_digest",
        "billing_disposition_digest",
        "destination_digest",
        "dispatch_action_receipt_digest",
        "dispatch_decision_digest",
        "dispatch_request_digest",
        "execution_accounting_digest",
        "execution_selection_digest",
        "publication_authorization_intent_digest",
        "task_attempt_binding_digest",
        "task_authorization_intent_digest",
    }
    return bool(
        payload.get("failure_stage") == "request_or_evaluation"
        and all(_is_optional_digest(payload.get(key)) for key in digest_keys)
        and payload.get("request") is None
        and payload.get("request_digest") is None
        and payload.get("policy") is None
        and payload.get("policy_digest") is None
        and payload.get("decision") is None
        and payload.get("decision_digest") is None
        and payload.get("effect") == AuthorizationEffect.INDETERMINATE.value
        and payload.get("derived_permission_class") is None
        and payload.get("decision_current_at_evaluation") is False
        and payload.get("authority_ceiling_satisfied") is False
        and payload.get("obligations_supported") is False
        and payload.get("authorization_eligible") is False
        and payload.get("block_reason_codes")
        == ["authorization_evaluation_failed"]
        and _optional_timestamp(payload.get("evaluated_at")) is not None
        and isinstance(payload.get("controller_owned_mock_runner"), bool)
        and isinstance(payload.get("legacy_executable"), bool)
        and isinstance(payload.get("safe_publication_prerequisites"), bool)
        and isinstance(payload.get("evaluation_accepted"), bool)
        and isinstance(payload.get("credential_scan_passed"), bool)
        and _permission_class(payload.get("requested_permission_class"))
        is not None
    )


def _raw_enforcing_task_pre_effect_payload(
    rows: list[sqlite3.Row],
) -> Mapping[str, Any] | None:
    matches: list[Mapping[str, Any]] = []
    for row in rows:
        if row["event_type"] != TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE:
            continue
        payload = _bounded_json_mapping(row["payload_json"])
        if (
            isinstance(payload, Mapping)
            and payload.get("schema_version") == 3
            and payload.get("mode") == "enforcing"
        ):
            matches.append(payload)
    return matches[0] if len(matches) == 1 else None


def _raw_task_publication_shadow_payload(
    rows: list[sqlite3.Row],
) -> Mapping[str, Any] | None:
    matches: list[Mapping[str, Any]] = []
    for row in rows:
        payload = _bounded_json_mapping(row["payload_json"])
        if (
            isinstance(payload, Mapping)
            and payload.get("schema_version") == 5
            and payload.get("mode") == "shadow"
            and payload.get("action_scope") == PUBLICATION_SCOPE
        ):
            matches.append(payload)
    return matches[0] if len(matches) == 1 else None


def _local_candidate_publication_prerequisites_satisfied(
    dispatch_receipt: Mapping[str, Any] | None,
    accounting: Mapping[str, Any] | None,
) -> bool:
    receipt = (
        dispatch_receipt.get("receipt")
        if isinstance(dispatch_receipt, Mapping)
        else None
    )
    return bool(
        isinstance(receipt, Mapping)
        and receipt.get("outcome") == ReceiptOutcome.SUCCEEDED.value
        and isinstance(accounting, Mapping)
        and accounting.get("billing_matches") is True
        and accounting.get("capacity_state")
        == CapacityState.NOT_APPLICABLE.value
        and accounting.get("paid_capacity_consumed")
        == PaidCapacityConsumed.NOT_APPLICABLE.value
        and accounting.get("incremental_ai_charge")
        == IncrementalAICharge.NONE.value
        and accounting.get("billing_quarantine_required") is False
        and accounting.get("billing_circuit_breaker_required") is False
        and accounting.get("billing_disposition_reason_codes") == []
    )


def _publication_intent_from_task_intent(
    task_intent: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    resource = task_intent.get("resource")
    consequences = task_intent.get("consequences")
    if not isinstance(resource, Mapping) or not isinstance(
        consequences,
        Mapping,
    ):
        return None
    intent = {
        "action": {
            "verb": ActionVerb.CREATE.value,
            "operation": LOCAL_CANDIDATE_PUBLICATION_OPERATION,
            "intended_effect": "create_isolated_local_candidate",
        },
        "resource": {
            "resource_type": LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE,
            "trust_boundary": "isolated_run_workspace",
            "protected": resource.get("protected"),
            "sensitivity": resource.get("sensitivity"),
        },
        "consequences": {
            "availability": consequences.get("availability"),
            "blast_radius": BlastRadius.SINGLE_RESOURCE.value,
            "confidentiality": consequences.get("confidentiality"),
            "destructive": False,
            "integrity": consequences.get("integrity"),
            "reach": Reach.LOCAL.value,
            "reversible": True,
            "sensitivity": consequences.get("sensitivity"),
        },
    }
    return intent if _is_task_intent_shape(intent) else None


def _inspect_local_candidate_publication_request_projection(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    dispatch_decision: _MockDispatchDecisionFacts,
    dispatch_receipt: _MockDispatchReceiptFacts,
    task_accounting: _TaskAccountingFacts,
    wrapper: Mapping[str, Any],
    request: AuthorizationRequest,
    task_intent: Mapping[str, Any] | None,
    pre_effect: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    issues: list[str] = []
    binding = task_binding.binding
    publication_intent = (
        _publication_intent_from_task_intent(task_intent)
        if isinstance(task_intent, Mapping)
        else None
    )
    if not isinstance(binding, Mapping) or publication_intent is None:
        return ("local_candidate_publication_request_intent_mismatch",)
    publication_intent_digest = canonical_digest(publication_intent)
    if wrapper.get("publication_authorization_intent_digest") != (
        publication_intent_digest
    ):
        issues.append("local_candidate_publication_request_intent_mismatch")

    expected_profile_ref = binding.get("profile_ref")
    expected_repository_ref = binding.get("repository_ref")
    artifact_digest = wrapper.get("artifact_digest")
    destination_digest = wrapper.get("destination_digest")
    artifact_metadata_digest = wrapper.get("artifact_metadata_digest")
    expected_identifier = canonical_digest(
        {
            "artifact_metadata_digest": artifact_metadata_digest,
            "destination_digest": destination_digest,
            "resource_type": LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE,
            "run_ref": fact.run_ref,
        }
    )
    expected_consequences = publication_intent["consequences"]
    expected_resource_intent = publication_intent["resource"]
    if (
        request.request_id
        != f"{LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE}:{fact.run_ref}"
        or request.subject.principal_id != "agent:task-attempt"
        or request.subject.controller_id != "ordomata:local-controller"
        or request.subject.role is not Role.IMPLEMENTER
        or request.subject.role_version != "1"
        or request.subject.profile_id != expected_profile_ref
        or request.subject.runner_id != "mock"
        or request.subject.session_id != f"attempt:{fact.run_ref}"
        or request.action.verb is not ActionVerb.CREATE
        or request.action.operation
        != LOCAL_CANDIDATE_PUBLICATION_OPERATION
        or request.action.intended_effect
        != "create_isolated_local_candidate"
        or request.action.tool_id is not None
        or request.action.descriptive_claims
        or request.resource.resource_type
        != LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE
        or request.resource.identifier != expected_identifier
        or request.resource.version != artifact_digest
        or request.resource.owner != "operator:local"
        or request.resource.trust_boundary != "isolated_run_workspace"
        or request.resource.protected
        is not expected_resource_intent.get("protected")
        or request.resource.sensitivity.value
        != expected_resource_intent.get("sensitivity")
        or request.resource.repository_id != expected_repository_ref
        or request.resource.content_digest != artifact_digest
        or request.environment.isolation_state is not IsolationState.VERIFIED
        or request.environment.network_state is not NetworkState.DISABLED
        or request.environment.billing_route is not BillingRoute.LOCAL_NON_AI
        or request.environment.capacity_state
        is not CapacityState.NOT_APPLICABLE
        or request.environment.paid_continuation_protection
        is not PaidContinuationProtection.NOT_APPLICABLE
        or request.environment.circuit_state is not CircuitState.CLOSED
        or request.environment.flow_state
        != "local_candidate_publication_proposed"
        or request.environment.evaluated_at
        != _optional_timestamp(wrapper.get("evaluated_at"))
        or request.environment.approval_grants
        or request.consequences.to_canonical() != expected_consequences
    ):
        issues.append("local_candidate_publication_request_binding_mismatch")

    dispatch_payload = dispatch_receipt.payload
    dispatch_receipt_digest = (
        dispatch_payload.get("receipt_digest")
        if isinstance(dispatch_payload, Mapping)
        else None
    )
    accounting = task_accounting.payload
    candidate = pre_effect
    if isinstance(candidate, Mapping):
        expected_parameters_digest = canonical_digest(
            {
                "artifact_digest": artifact_digest,
                "artifact_kind": candidate.get("artifact_kind"),
                "artifact_metadata_digest": artifact_metadata_digest,
                "artifact_size_bytes": candidate.get("artifact_size_bytes"),
                "billing_disposition_digest": (
                    task_accounting.billing_disposition_digest
                ),
                "controller_owned_mock_runner": True,
                "credential_scan_passed": True,
                "destination_digest": destination_digest,
                "dispatch_action_receipt_digest": dispatch_receipt_digest,
                "dispatch_decision_digest": dispatch_decision.decision_digest,
                "dispatch_request_digest": dispatch_decision.request_digest,
                "evaluation_accepted": True,
                "execution_accounting_digest": (
                    canonical_digest(accounting)
                    if isinstance(accounting, Mapping)
                    else None
                ),
                "execution_selection_digest": (
                    task_execution_selection.selection_digest
                ),
                "legacy_permission_class": fact.permission_class,
                "output_schema_digest": binding.get("output_schema_digest"),
                "profile_ref": expected_profile_ref,
                "publication_authorization_intent_digest": (
                    publication_intent_digest
                ),
                "repository_ref": expected_repository_ref,
                "run_ref": fact.run_ref,
                "safe_publication_prerequisites": True,
                "task_attempt_binding_digest": task_binding.binding_digest,
                "task_authorization_intent_digest": binding.get(
                    "authorization_intent_digest"
                ),
                "task_definition_digest": binding.get(
                    "task_definition_digest"
                ),
                "workspace_ref": binding.get("workspace_ref"),
            }
        )
        if request.action.parameters_digest != expected_parameters_digest:
            issues.append(
                "local_candidate_publication_request_binding_mismatch"
            )
        if (
            candidate.get("artifact_digest") != artifact_digest
            or candidate.get("artifact_record_digest")
            != artifact_metadata_digest
            or candidate.get("destination_digest") != destination_digest
        ):
            issues.append(
                "local_candidate_publication_request_binding_mismatch"
            )

    evidence_by_attribute = {
        item.attribute: item for item in request.evidence
    }
    expected_sources = {
        "subject": EvidenceSource.CONTROLLER,
        "action": EvidenceSource.LOCAL_REGISTRY,
        "resource": EvidenceSource.LOCAL_REGISTRY,
        "environment": EvidenceSource.CONTROLLER,
        "consequences": EvidenceSource.LOCAL_REGISTRY,
    }
    if len(evidence_by_attribute) != 5 or len(request.evidence) != 5:
        issues.append("local_candidate_publication_evidence_invalid")
    else:
        for attribute, source in expected_sources.items():
            evidence = evidence_by_attribute.get(attribute)
            if (
                evidence is None
                or evidence.source is not source
                or evidence.source_id != f"ordomata:{source.value}"
                or evidence.evidence_id
                != f"{LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE}:{attribute}"
                or evidence.authenticated is not True
                or evidence.observed_at != request.environment.evaluated_at
                or evidence.expires_at
                != request.environment.evaluated_at + 120.0
                or evidence.value_digest
                != canonical_digest(request.attribute_value(attribute))
            ):
                issues.append("local_candidate_publication_evidence_invalid")
                break
    return tuple(sorted(set(issues)))


def _inspect_local_candidate_publication_policy_projection(
    policy: PolicyBundle,
) -> tuple[str, ...]:
    expected_evidence = tuple(
        sorted(
            PolicyBundle.current_stage().evidence_requirements,
            key=lambda item: item.attribute,
        )
    )
    valid = bool(
        policy.bundle_id == LOCAL_CANDIDATE_PUBLICATION_POLICY_ID
        and policy.version == LOCAL_CANDIDATE_PUBLICATION_POLICY_VERSION
        and policy.issued_at == 0.0
        and policy.schema_version
        == LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION
        and policy.evidence_requirements == expected_evidence
        and policy.enabled_classes == (PermissionClass.LOCAL_DRAFT,)
        and policy.allowed_verbs == (ActionVerb.CREATE,)
        and policy.allowed_roles == (Role.IMPLEMENTER,)
        and policy.allowed_operations
        == (LOCAL_CANDIDATE_PUBLICATION_OPERATION,)
        and policy.allowed_resource_types
        == (LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE,)
        and policy.allowed_trust_boundaries == ("isolated_run_workspace",)
        and policy.allowed_flow_states
        == ("local_candidate_publication_proposed",)
        and policy.allowed_network_states == (NetworkState.DISABLED,)
        and policy.allowed_billing_routes == (BillingRoute.LOCAL_NON_AI,)
        and not policy.approval_requirements
        and policy.decision_ttl_seconds == 60.0
    )
    return () if valid else ("local_candidate_publication_policy_binding_mismatch",)


def _is_local_candidate_publication_freshness_stop(
    fact: _RunFacts,
    decision: _LocalCandidatePublicationDecisionFacts,
    rows: list[sqlite3.Row],
) -> bool:
    """Recognize only the controller's exact pre-effect freshness stop."""

    if len(rows) != 1:
        return False
    row = rows[0]
    payload = _bounded_json_mapping(row["payload_json"])
    terminal_sequence = _optional_sequence(row["sequence"])
    return bool(
        row["event_type"] == "status"
        and row["status"] == RunStatus.BLOCKED.value
        and fact.latest_status == RunStatus.BLOCKED.value
        and terminal_sequence == fact.terminal_sequence
        and terminal_sequence is not None
        and decision.sequence is not None
        and terminal_sequence > decision.sequence
        and decision.effect == AuthorizationEffect.PERMIT.value
        and decision.authorization_eligible is True
        and _optional_timestamp(row["occurred_at"]) is not None
        and isinstance(payload, Mapping)
        and payload
        == {"phase": "local_candidate_publication_authorization_freshness"}
        and _event_identifier_matches_status(row, payload, fact.raw_run_id)
    )


def _local_candidate_publication_receipts_expected(
    fact: _RunFacts,
    decision: _LocalCandidatePublicationDecisionFacts,
    rows: list[sqlite3.Row],
) -> bool:
    return bool(
        decision.authorization_eligible is True
        and not _is_local_candidate_publication_freshness_stop(
            fact,
            decision,
            rows,
        )
    )


def _project_local_candidate_publication_enforcement(
    task_binding: _TaskAttemptBindingFacts,
    decision: _LocalCandidatePublicationDecisionFacts,
    receipts: _TaskArtifactReceiptFacts,
) -> LocalCandidatePublicationEnforcementInspection:
    action = receipts.action
    effect_started_at = (
        _optional_timestamp(action.get("effect_started_at"))
        if isinstance(action, Mapping)
        else None
    )
    enforcing = (
        task_binding.schema_version
        in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    permit_current = (
        bool(
            decision.effect == AuthorizationEffect.PERMIT.value
            and decision.authorization_eligible is True
            and effect_started_at is not None
            and decision.issued_at is not None
            and decision.expires_at is not None
            and decision.issued_at
            <= effect_started_at
            < decision.expires_at
        )
        if enforcing and action is not None
        else None
    )
    issues = list((*decision.issues, *receipts.issues))
    if enforcing and action is not None and permit_current is not True:
        issues.append("local_candidate_publication_receipt_permit_not_current")
    return LocalCandidatePublicationEnforcementInspection(
        required=enforcing,
        boundary_observed=bool(
            decision.observed
            or receipts.pre_effect is not None
            or receipts.action is not None
            or "local_candidate_publication_decision_missing"
            in decision.issues
        ),
        decision_observed=decision.observed,
        decision_sequence=decision.sequence,
        effect=decision.effect,
        authorization_eligible=decision.authorization_eligible,
        decision_current_at_evaluation=(
            decision.decision_current_at_evaluation
        ),
        pre_effect_observed=receipts.pre_effect is not None,
        pre_effect_sequence=receipts.pre_effect_sequence,
        action_receipt_observed=receipts.action is not None,
        action_receipt_sequence=receipts.action_sequence,
        action_receipt_outcome=(
            action.get("outcome") if isinstance(action, Mapping) else None
        ),
        permit_current_at_effect_start=permit_current,
        integrity_issues=tuple(sorted(set(issues))),
    )


def _inspect_comparison_accounting(
    fact: _RunFacts,
    comparison_binding: _ComparisonBindingFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonAccountingFacts:
    """Validate v2 execution accounting and its canonical disposition link."""

    if comparison_binding.schema_version != 2:
        return _ComparisonAccountingFacts(None, None, None, ())
    if fact.comparison_accounting_event_count == 0:
        return _ComparisonAccountingFacts(
            None,
            None,
            None,
            ("comparison_execution_accounting_missing",),
        )
    if fact.comparison_accounting_event_count != 1 or len(rows) != 1:
        return _ComparisonAccountingFacts(
            None,
            None,
            None,
            ("comparison_execution_accounting_duplicate",),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    payload_json = row["payload_json"]
    if (
        sequence is None
        or not isinstance(payload_json, str)
        or len(payload_json.encode("utf-8", errors="replace"))
        > _MAX_PAYLOAD_BYTES
    ):
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    try:
        payload = json.loads(
            payload_json,
            object_pairs_hook=_unique_json_object,
        )
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    if not _is_comparison_accounting_shape(payload):
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    assert isinstance(payload, Mapping)
    issues: list[str] = []
    if not _event_identifier_matches(
        row,
        event_type="execution_accounting",
        payload=payload,
        run_id=fact.raw_run_id,
    ):
        issues.append(
            "comparison_execution_accounting_event_identifier_mismatch"
        )
    disposition_digest = payload.get("billing_disposition_digest")
    if disposition_digest is None:
        if (
            payload.get("capacity_state") != CapacityState.UNKNOWN.value
            or payload.get("billing_disposition_reason_codes") != []
        ):
            return _invalid_comparison_accounting(
                sequence,
                "comparison_execution_accounting_invalid",
            )
        return _ComparisonAccountingFacts(
            sequence,
            payload,
            None,
            tuple(issues),
        )

    projection = _comparison_accounting_billing_projection(payload)
    if projection is None:
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    if disposition_digest != canonical_digest(projection):
        issues.append("comparison_execution_accounting_digest_mismatch")
        return _ComparisonAccountingFacts(
            sequence,
            payload,
            disposition_digest,
            tuple(issues),
        )
    return _ComparisonAccountingFacts(
        sequence,
        payload,
        disposition_digest,
        tuple(issues),
    )


def _is_comparison_accounting_shape(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != _COMPARISON_ACCOUNTING_KEYS:
        return False
    reason_codes = value.get("billing_disposition_reason_codes")
    failure_code = value.get("failure_code")
    wall_seconds = value.get("wall_seconds")
    optional_boolean_keys = (
        "billing_circuit_breaker_required",
        "billing_matches",
        "billing_quarantine_required",
        "harness_process_started",
        "identity_matches",
        "live_model_execution_occurred",
        "subscription_capacity_consumed",
    )
    return (
        isinstance(value.get("schema_version"), int)
        and not isinstance(value.get("schema_version"), bool)
        and value.get("schema_version") == 2
        and isinstance(value.get("result_observed"), bool)
        and all(
            value.get(key) is None or isinstance(value.get(key), bool)
            for key in optional_boolean_keys
        )
        and _is_optional_digest(value.get("billing_disposition_digest"))
        and _is_optional_non_negative_integer(value.get("runner_event_count"))
        and value.get("runner_event_count") is not None
        and isinstance(value.get("result_status"), str)
        and value.get("result_status")
        in _KNOWN_STATUSES | {"invalid", "unknown"}
        and isinstance(value.get("capacity_state"), str)
        and value.get("capacity_state")
        in {item.value for item in CapacityState}
        and isinstance(value.get("paid_capacity_consumed"), str)
        and value.get("paid_capacity_consumed")
        in {item.value for item in PaidCapacityConsumed}
        and isinstance(value.get("incremental_ai_charge"), str)
        and value.get("incremental_ai_charge")
        in {item.value for item in IncrementalAICharge}
        and isinstance(value.get("usage_observation"), str)
        and value.get("usage_observation")
        in {item.value for item in UsageObservation}
        and isinstance(reason_codes, list)
        and len(reason_codes) <= _MAX_EVIDENCE_RECORDS
        and all(
            isinstance(item, str)
            and _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(item) is not None
            for item in reason_codes
        )
        and (
            failure_code is None
            or (
                isinstance(failure_code, str)
                and _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(failure_code)
                is not None
            )
        )
        and (
            wall_seconds is None
            or _optional_timestamp(wall_seconds) is not None
        )
    )


def _comparison_accounting_billing_projection(
    payload: Mapping[str, Any],
) -> dict[str, Any] | None:
    identity_matches = payload.get("identity_matches")
    billing_matches = payload.get("billing_matches")
    capacity_state = payload.get("capacity_state")
    paid_capacity_consumed = payload.get("paid_capacity_consumed")
    incremental_ai_charge = payload.get("incremental_ai_charge")
    quarantine_required = payload.get("billing_quarantine_required")
    circuit_breaker_required = payload.get(
        "billing_circuit_breaker_required"
    )
    reason_codes = payload.get("billing_disposition_reason_codes")
    if (
        not isinstance(identity_matches, bool)
        or not isinstance(billing_matches, bool)
        or capacity_state not in {item.value for item in CapacityState}
        or paid_capacity_consumed
        not in {item.value for item in PaidCapacityConsumed}
        or incremental_ai_charge
        not in {item.value for item in IncrementalAICharge}
        or not isinstance(quarantine_required, bool)
        or not isinstance(circuit_breaker_required, bool)
        or not isinstance(reason_codes, list)
        or len(reason_codes) > _MAX_EVIDENCE_RECORDS
        or any(
            not isinstance(value, str)
            or _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(value) is None
            for value in reason_codes
        )
    ):
        return None
    return {
        "identity_matches": identity_matches is True,
        "billing_matches": billing_matches is True,
        "capacity_state": capacity_state,
        "paid_capacity_consumed": paid_capacity_consumed,
        "incremental_ai_charge": incremental_ai_charge,
        "quarantine_required": quarantine_required,
        "circuit_breaker_required": circuit_breaker_required,
        "reason_codes": reason_codes,
    }


def _invalid_comparison_accounting(
    sequence: int | None,
    issue: str,
) -> _ComparisonAccountingFacts:
    return _ComparisonAccountingFacts(sequence, None, None, (issue,))


def _inspect_task_accounting(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    rows: list[sqlite3.Row],
    *,
    required: bool,
) -> _TaskAccountingFacts:
    """Validate receipt-aware ordinary execution accounting."""

    if task_binding.binding is None or task_binding.issues:
        return _TaskAccountingFacts(None, None, None, ())
    if fact.comparison_accounting_event_count == 0:
        if not required:
            return _TaskAccountingFacts(None, None, None, ())
        return _TaskAccountingFacts(
            None,
            None,
            None,
            ("task_execution_accounting_missing",),
        )
    if fact.comparison_accounting_event_count != 1 or len(rows) != 1:
        return _TaskAccountingFacts(
            None,
            None,
            None,
            ("task_execution_accounting_duplicate",),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    payload = _bounded_json_mapping(row["payload_json"])
    if sequence is None or not _is_task_accounting_shape(payload):
        return _TaskAccountingFacts(
            sequence,
            None,
            None,
            ("task_execution_accounting_invalid",),
        )
    assert isinstance(payload, Mapping)
    issues: list[str] = []
    if not _event_identifier_matches(
        row,
        event_type="execution_accounting",
        payload=payload,
        run_id=fact.raw_run_id,
    ):
        issues.append("task_execution_accounting_event_identifier_mismatch")
    timestamp_invalid = _optional_timestamp(row["occurred_at"]) is None
    disposition_digest = payload.get("billing_disposition_digest")
    projection = _comparison_accounting_billing_projection(payload)
    if projection is None or not _is_digest(disposition_digest):
        return _TaskAccountingFacts(
            sequence,
            None,
            None,
            ("task_execution_accounting_invalid",),
        )
    if disposition_digest != canonical_digest(projection):
        issues.append("task_execution_accounting_digest_mismatch")
        return _TaskAccountingFacts(
            sequence,
            payload,
            disposition_digest,
            tuple(issues),
        )
    if payload.get("runner_event_count") != fact.runner_event_count:
        issues.append("task_execution_accounting_record_mismatch")
        return _TaskAccountingFacts(
            sequence,
            payload,
            disposition_digest,
            tuple(issues),
        )
    if timestamp_invalid:
        issues.append("task_execution_accounting_timestamp_invalid")
        return _TaskAccountingFacts(
            sequence,
            payload,
            disposition_digest,
            tuple(issues),
        )
    return _TaskAccountingFacts(
        sequence,
        payload,
        disposition_digest,
        tuple(issues),
    )


def _is_task_accounting_shape(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != _TASK_ACCOUNTING_KEYS:
        return False
    comparison_projection = {
        key: value.get(key) for key in _COMPARISON_ACCOUNTING_KEYS
    }
    return (
        _is_comparison_accounting_shape(comparison_projection)
        and _is_optional_digest(value.get("runner_version"))
        and (
            value.get("execution_mode") is None
            or (
                isinstance(value.get("execution_mode"), str)
                and value.get("execution_mode") in _TASK_EXECUTION_MODES
            )
        )
        and value.get("incremental_api_charge")
        in {item.value for item in IncrementalAICharge}
    )


def _inspect_comparison_artifact_receipts(
    fact: _RunFacts,
    comparison_binding: _ComparisonBindingFacts,
    comparison_accounting: _ComparisonAccountingFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonArtifactReceiptFacts:
    """Validate the digest-only Class 1 publication receipt chain."""

    rows_by_type: dict[str, list[sqlite3.Row]] = {
        COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE: [],
        COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE: [],
        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE: [],
    }
    for row in rows:
        event_type = row["event_type"]
        if isinstance(event_type, str) and event_type in rows_by_type:
            rows_by_type[event_type].append(row)

    pre_rows = rows_by_type[COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE]
    legacy_observed_rows = rows_by_type[
        COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE
    ]
    action_rows = rows_by_type[
        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
    ]
    has_v2_pre = any(_artifact_event_schema(row) == 2 for row in pre_rows)
    has_new_receipt_evidence = has_v2_pre or bool(action_rows)

    if comparison_binding.schema_version != 2:
        issues = (
            ("comparison_publication_receipt_binding_invalid",)
            if has_new_receipt_evidence
            else ()
        )
        return _ComparisonArtifactReceiptFacts(
            None,
            None,
            None,
            None,
            None,
            None,
            issues,
        )

    issues: list[str] = []
    publication_expected = (
        fact.succeeded_observed
        or fact.shadow_event_count > 2
        or fact.comparison_artifact_intent_event_count > 0
        or fact.comparison_artifact_observed_event_count > 0
        or fact.comparison_artifact_action_receipt_event_count > 0
    )
    if fact.comparison_artifact_observed_event_count > 0 or legacy_observed_rows:
        issues.append("comparison_publication_legacy_observation_unexpected")

    pre_effect: Mapping[str, Any] | None = None
    pre_sequence: int | None = None
    pre_digest: str | None = None
    if fact.comparison_artifact_intent_event_count == 0:
        if publication_expected:
            issues.append("comparison_publication_pre_effect_receipt_missing")
    elif fact.comparison_artifact_intent_event_count != 1 or len(pre_rows) != 1:
        issues.append("comparison_publication_pre_effect_receipt_duplicate")
    else:
        pre_sequence, pre_effect, pre_digest, pre_issues = (
            _inspect_comparison_pre_effect_receipt(
                pre_rows[0],
                comparison_binding=comparison_binding,
            )
        )
        issues.extend(pre_issues)

    action: Mapping[str, Any] | None = None
    action_sequence: int | None = None
    action_digest: str | None = None
    if fact.comparison_artifact_action_receipt_event_count == 0:
        if publication_expected:
            issues.append("comparison_publication_action_receipt_missing")
    elif (
        fact.comparison_artifact_action_receipt_event_count != 1
        or len(action_rows) != 1
    ):
        issues.append("comparison_publication_action_receipt_duplicate")
    else:
        action_sequence, action, action_digest, action_issues = (
            _inspect_comparison_action_receipt(
                action_rows[0],
                comparison_binding=comparison_binding,
            )
        )
        issues.extend(action_issues)

    if pre_effect is None and action is not None:
        issues.append("comparison_publication_action_receipt_orphaned")
    if pre_effect is not None and action is not None:
        issues.extend(
            _inspect_comparison_receipt_linkage(
                pre_effect,
                pre_effect_receipt_digest=pre_digest,
                action=action,
            )
        )
    if pre_rows or action_rows:
        accounting_digest = comparison_accounting.billing_disposition_digest
        if (
            not _is_digest(accounting_digest)
            or (
                pre_effect is not None
                and pre_effect.get("billing_disposition_digest")
                != accounting_digest
            )
            or (
                action is not None
                and action.get("billing_disposition_digest")
                != accounting_digest
            )
        ):
            issues.append(
                "comparison_publication_billing_disposition_mismatch"
            )
    return _ComparisonArtifactReceiptFacts(
        pre_sequence,
        pre_effect,
        pre_digest,
        action_sequence,
        action,
        action_digest,
        tuple(sorted(set(issues))),
    )


def _artifact_event_schema(row: sqlite3.Row) -> int | None:
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str) or len(
        payload_json.encode("utf-8", errors="replace")
    ) > _MAX_PAYLOAD_BYTES:
        return None
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        return None
    return schema_version


def _bounded_artifact_event_payload(
    row: sqlite3.Row,
) -> tuple[int | None, Mapping[str, Any] | None]:
    sequence = _optional_sequence(row["sequence"])
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str) or len(
        payload_json.encode("utf-8", errors="replace")
    ) > _MAX_PAYLOAD_BYTES:
        return sequence, None
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return sequence, None
    return sequence, payload if isinstance(payload, Mapping) else None


def _bounded_json_mapping(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, str) or len(
        value.encode("utf-8", errors="replace")
    ) > _MAX_PAYLOAD_BYTES:
        return None
    try:
        payload = json.loads(value, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _shadow_row_schema(row: sqlite3.Row) -> int | None:
    payload = _bounded_json_mapping(row["payload_json"])
    if payload is None:
        return None
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        return None
    return schema_version


def _task_publication_shadow_requires_receipts(row: sqlite3.Row) -> bool:
    payload = _bounded_json_mapping(row["payload_json"])
    return bool(
        payload is not None
        and payload.get("schema_version") == 5
        and payload.get("action_scope") == PUBLICATION_SCOPE
        and payload.get("failure_stage") not in {
            "request_construction",
            "evaluation",
        }
    )


def _inspect_comparison_pre_effect_receipt(
    row: sqlite3.Row,
    *,
    comparison_binding: _ComparisonBindingFacts,
) -> tuple[
    int | None,
    Mapping[str, Any] | None,
    str | None,
    tuple[str, ...],
]:
    sequence, payload = _bounded_artifact_event_payload(row)
    if payload is None or set(payload) != {
        "action_digest",
        "artifact_digest",
        "artifact_kind",
        "artifact_size_bytes",
        "authority_basis",
        "authorization_enforced",
        "billing_disposition_digest",
        "comparison_binding_digest",
        "destination_digest",
        "mode",
        "output_withheld",
        "publication_decision_digest",
        "publication_request_digest",
        "publication_shadow_persisted",
        "receipt_digest",
        "receipt_kind",
        "requested_permission_class",
        "schema_version",
        "started_at",
    }:
        return (
            sequence,
            None,
            None,
            ("comparison_publication_pre_effect_receipt_invalid",),
        )

    issues: list[str] = []
    if _optional_timestamp(row["occurred_at"]) is None:
        issues.append(
            "comparison_publication_pre_effect_timestamp_invalid"
        )
    receipt_digest = payload.get("receipt_digest")
    receipt_body = dict(payload)
    del receipt_body["receipt_digest"]
    if not _digest_matches(receipt_digest, receipt_body):
        issues.append("comparison_publication_pre_effect_digest_mismatch")
    if (
        payload.get("schema_version") != 2
        or payload.get("mode") != "shadow"
        or payload.get("receipt_kind") != "pre_effect"
        or payload.get("authorization_enforced") is not False
        or payload.get("authority_basis")
        != "legacy_class_1_local_draft_gate"
        or payload.get("requested_permission_class")
        != int(PermissionClass.LOCAL_DRAFT)
        or payload.get("artifact_kind") != "private_review_output"
        or not isinstance(payload.get("publication_shadow_persisted"), bool)
        or not isinstance(payload.get("output_withheld"), bool)
        or not _is_digest(payload.get("comparison_binding_digest"))
        or not _is_digest(payload.get("destination_digest"))
        or not _is_digest(payload.get("artifact_digest"))
        or not _is_digest(payload.get("billing_disposition_digest"))
        or not _is_positive_integer(payload.get("artifact_size_bytes"))
        or _optional_timestamp(payload.get("started_at")) is None
        or not _is_optional_digest(payload.get("publication_request_digest"))
        or not _is_optional_digest(payload.get("publication_decision_digest"))
        or not _is_optional_digest(payload.get("action_digest"))
    ):
        issues.append("comparison_publication_pre_effect_receipt_invalid")
    if payload.get("comparison_binding_digest") != (
        comparison_binding.binding_digest
    ):
        issues.append("comparison_publication_pre_effect_binding_mismatch")
    if (
        (payload.get("publication_request_digest") is None)
        != (payload.get("action_digest") is None)
        or (
            payload.get("publication_decision_digest") is not None
            and payload.get("publication_request_digest") is None
        )
    ):
        issues.append("comparison_publication_pre_effect_linkage_invalid")
    return (
        sequence,
        payload,
        receipt_digest if _is_digest(receipt_digest) else None,
        tuple(sorted(set(issues))),
    )


def _inspect_comparison_action_receipt(
    row: sqlite3.Row,
    *,
    comparison_binding: _ComparisonBindingFacts,
) -> tuple[
    int | None,
    Mapping[str, Any] | None,
    str | None,
    tuple[str, ...],
]:
    sequence, payload = _bounded_artifact_event_payload(row)
    if payload is None or set(payload) != {
        "action_digest",
        "artifact_kind",
        "authority_basis",
        "authorization_enforced",
        "billing_disposition_digest",
        "completed_at",
        "comparison_binding_digest",
        "destination_digest",
        "executor_id",
        "failure_code",
        "intended_artifact_digest",
        "intended_artifact_size_bytes",
        "mode",
        "obligation_results",
        "observed_artifact_size_bytes",
        "outcome",
        "output_withheld",
        "pre_effect_receipt_digest",
        "publication_decision_digest",
        "publication_request_digest",
        "publication_shadow_persisted",
        "receipt_digest",
        "receipt_id",
        "receipt_kind",
        "result_digest",
        "schema_version",
        "started_at",
    }:
        return (
            sequence,
            None,
            None,
            ("comparison_publication_action_receipt_invalid",),
        )

    issues: list[str] = []
    if _optional_timestamp(row["occurred_at"]) is None:
        issues.append("comparison_publication_action_timestamp_invalid")
    receipt_digest = payload.get("receipt_digest")
    receipt_body = dict(payload)
    del receipt_body["receipt_digest"]
    if not _digest_matches(receipt_digest, receipt_body):
        issues.append("comparison_publication_action_receipt_digest_mismatch")
    started_at = _optional_timestamp(payload.get("started_at"))
    completed_at = _optional_timestamp(payload.get("completed_at"))
    if (
        payload.get("schema_version") != 2
        or payload.get("mode") != "shadow"
        or payload.get("receipt_kind") != "action"
        or payload.get("authorization_enforced") is not False
        or payload.get("authority_basis")
        != "legacy_class_1_local_draft_gate"
        or payload.get("executor_id") != "ordomata:local-controller"
        or payload.get("artifact_kind") != "private_review_output"
        or not isinstance(payload.get("publication_shadow_persisted"), bool)
        or not isinstance(payload.get("output_withheld"), bool)
        or not _is_digest(payload.get("receipt_id"))
        or not _is_digest(payload.get("comparison_binding_digest"))
        or not _is_digest(payload.get("pre_effect_receipt_digest"))
        or not _is_digest(payload.get("destination_digest"))
        or not _is_digest(payload.get("intended_artifact_digest"))
        or not _is_digest(payload.get("billing_disposition_digest"))
        or not _is_positive_integer(payload.get("intended_artifact_size_bytes"))
        or not _is_optional_digest(payload.get("publication_request_digest"))
        or not _is_optional_digest(payload.get("publication_decision_digest"))
        or not _is_optional_digest(payload.get("action_digest"))
        or not _is_optional_digest(payload.get("result_digest"))
        or not _is_optional_non_negative_integer(
            payload.get("observed_artifact_size_bytes")
        )
        or started_at is None
        or completed_at is None
        or (
            started_at is not None
            and completed_at is not None
            and completed_at < started_at
        )
    ):
        issues.append("comparison_publication_action_receipt_invalid")
    if payload.get("comparison_binding_digest") != (
        comparison_binding.binding_digest
    ):
        issues.append("comparison_publication_action_receipt_binding_mismatch")
    expected_receipt_id = canonical_digest(
        {
            "comparison_binding_digest": payload.get(
                "comparison_binding_digest"
            ),
            "destination_digest": payload.get("destination_digest"),
            "pre_effect_receipt_digest": payload.get(
                "pre_effect_receipt_digest"
            ),
        }
    )
    if payload.get("receipt_id") != expected_receipt_id:
        issues.append("comparison_publication_action_receipt_identifier_mismatch")
    if (
        (payload.get("publication_request_digest") is None)
        != (payload.get("action_digest") is None)
        or (
            payload.get("publication_decision_digest") is not None
            and payload.get("publication_request_digest") is None
        )
    ):
        issues.append("comparison_publication_action_receipt_linkage_invalid")
    issues.extend(_inspect_comparison_obligation_results(payload))
    issues.extend(_inspect_comparison_action_outcome(payload))
    return (
        sequence,
        payload,
        receipt_digest if _is_digest(receipt_digest) else None,
        tuple(sorted(set(issues))),
    )


def _inspect_comparison_obligation_results(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    values = payload.get("obligation_results")
    if not isinstance(values, list) or len(values) > _MAX_OBLIGATION_RESULTS:
        return ("comparison_publication_obligation_results_invalid",)
    allowed_kinds = {item.value for item in ObligationKind}
    canonical_values: list[tuple[str, str]] = []
    for value in values:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"kind", "satisfied", "value_digest"}
            or value.get("kind") not in allowed_kinds
            or value.get("satisfied") is not True
            or not _is_digest(value.get("value_digest"))
        ):
            return ("comparison_publication_obligation_results_invalid",)
        canonical_values.append((value["kind"], value["value_digest"]))
    if (
        canonical_values != sorted(canonical_values)
        or len(canonical_values) != len(set(canonical_values))
    ):
        return ("comparison_publication_obligation_results_invalid",)
    return ()


def _inspect_comparison_action_outcome(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    outcome = payload.get("outcome")
    failure_code = payload.get("failure_code")
    result_digest = payload.get("result_digest")
    observed_size = payload.get("observed_artifact_size_bytes")
    intended_digest = payload.get("intended_artifact_digest")
    intended_size = payload.get("intended_artifact_size_bytes")
    expected_failure_codes = {
        ReceiptOutcome.FAILED.value: "artifact_persistence_failed",
        ReceiptOutcome.CANCELLED.value: "artifact_persistence_interrupted",
        ReceiptOutcome.UNKNOWN.value: "artifact_publication_outcome_unknown",
    }
    if outcome == ReceiptOutcome.SUCCEEDED.value:
        valid = (
            failure_code is None
            and result_digest == intended_digest
            and observed_size == intended_size
        )
    elif outcome in expected_failure_codes:
        valid = (
            failure_code == expected_failure_codes[outcome]
            and result_digest is None
            and observed_size is None
        )
    else:
        valid = False
    return () if valid else ("comparison_publication_action_outcome_invalid",)


def _inspect_comparison_action_terminal_linkage(
    fact: _RunFacts,
    receipts: _ComparisonArtifactReceiptFacts,
) -> tuple[str, ...]:
    """Reject impossible artifact-receipt and terminal-status pairings."""

    action = receipts.action
    if not isinstance(action, Mapping):
        return ()
    terminal_statuses = {
        RunStatus.SUCCEEDED.value,
        RunStatus.FAILED.value,
        RunStatus.BLOCKED.value,
        RunStatus.QUARANTINED.value,
        RunStatus.CANCELLED.value,
    }
    terminal_status = fact.latest_status
    if terminal_status not in terminal_statuses:
        return ("comparison_action_receipt_terminal_missing",)
    outcome = action.get("outcome")
    if (
        outcome == ReceiptOutcome.SUCCEEDED.value
        and fact.terminal_artifact_observed is not True
    ):
        return ("comparison_action_receipt_terminal_mismatch",)
    allowed_terminal_statuses = {
        ReceiptOutcome.SUCCEEDED.value: terminal_statuses,
        ReceiptOutcome.FAILED.value: {
            RunStatus.BLOCKED.value,
            RunStatus.FAILED.value,
            RunStatus.QUARANTINED.value,
        },
        ReceiptOutcome.CANCELLED.value: {
            RunStatus.CANCELLED.value,
            RunStatus.QUARANTINED.value,
        },
        ReceiptOutcome.UNKNOWN.value: {RunStatus.QUARANTINED.value},
    }
    allowed = allowed_terminal_statuses.get(outcome)
    if allowed is not None and terminal_status not in allowed:
        return ("comparison_action_receipt_terminal_mismatch",)
    return ()


def _inspect_comparison_receipt_linkage(
    pre_effect: Mapping[str, Any],
    *,
    pre_effect_receipt_digest: str | None,
    action: Mapping[str, Any],
) -> tuple[str, ...]:
    comparisons = (
        ("pre_effect_receipt_digest", pre_effect_receipt_digest),
        ("comparison_binding_digest", pre_effect.get("comparison_binding_digest")),
        (
            "publication_shadow_persisted",
            pre_effect.get("publication_shadow_persisted"),
        ),
        ("publication_request_digest", pre_effect.get("publication_request_digest")),
        ("publication_decision_digest", pre_effect.get("publication_decision_digest")),
        ("action_digest", pre_effect.get("action_digest")),
        ("started_at", pre_effect.get("started_at")),
        ("artifact_kind", pre_effect.get("artifact_kind")),
        ("destination_digest", pre_effect.get("destination_digest")),
        ("output_withheld", pre_effect.get("output_withheld")),
        ("billing_disposition_digest", pre_effect.get("billing_disposition_digest")),
    )
    if any(action.get(key, _MISSING) != expected for key, expected in comparisons):
        return ("comparison_publication_receipt_linkage_mismatch",)
    if (
        action.get("intended_artifact_digest")
        != pre_effect.get("artifact_digest")
        or action.get("intended_artifact_size_bytes")
        != pre_effect.get("artifact_size_bytes")
    ):
        return ("comparison_publication_receipt_linkage_mismatch",)
    return ()


def _inspect_task_artifact_receipts(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_billing: _TaskBillingFacts,
    task_accounting: _TaskAccountingFacts,
    rows: list[sqlite3.Row],
    metadata_rows: list[sqlite3.Row],
    *,
    publication_shadow_observed: bool,
    publication_decision: _LocalCandidatePublicationDecisionFacts,
    terminal_rows: list[sqlite3.Row],
) -> _TaskArtifactReceiptFacts:
    """Validate ordinary local-candidate pre-effect and action receipts."""

    rows_by_type: dict[str, list[sqlite3.Row]] = {
        TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE: [],
        TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE: [],
    }
    for row in rows:
        event_type = row["event_type"]
        if isinstance(event_type, str) and event_type in rows_by_type:
            rows_by_type[event_type].append(row)

    pre_rows = rows_by_type[TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE]
    action_rows = rows_by_type[
        TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
    ]
    has_receipt_evidence = bool(pre_rows or action_rows)
    if task_binding.binding is None or task_binding.issues:
        return _TaskArtifactReceiptFacts(
            None,
            None,
            None,
            None,
            None,
            None,
            False,
            (
                ("task_publication_receipt_binding_invalid",)
                if has_receipt_evidence
                else ()
            ),
        )

    issues: list[str] = []
    enforcing = (
        task_binding.schema_version
        in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    freshness_stop = _is_local_candidate_publication_freshness_stop(
        fact,
        publication_decision,
        terminal_rows,
    )
    publication_expected = (
        publication_decision.authorization_eligible is True
        if enforcing
        else (
            fact.succeeded_observed
            or publication_shadow_observed
            or fact.task_artifact_intent_event_count > 0
            or fact.task_artifact_action_receipt_event_count > 0
        )
    )
    action_expected = publication_expected and not freshness_stop
    if enforcing and publication_decision.authorization_eligible is not True:
        if has_receipt_evidence or fact.task_artifact_metadata_count > 0:
            issues.append(
                "local_candidate_publication_effect_after_nonpermit"
            )
    pre_effect: Mapping[str, Any] | None = None
    pre_sequence: int | None = None
    pre_digest: str | None = None
    if fact.task_artifact_intent_event_count == 0:
        if publication_expected:
            issues.append("task_publication_pre_effect_receipt_missing")
    elif fact.task_artifact_intent_event_count != 1 or len(pre_rows) != 1:
        issues.append("task_publication_pre_effect_receipt_duplicate")
    else:
        pre_sequence, pre_effect, pre_digest, pre_issues = (
            _inspect_task_pre_effect_receipt(
                pre_rows[0],
                fact=fact,
                task_binding=task_binding,
            )
        )
        issues.extend(pre_issues)

    action: Mapping[str, Any] | None = None
    action_sequence: int | None = None
    action_digest: str | None = None
    if fact.task_artifact_action_receipt_event_count == 0:
        if action_expected:
            issues.append("task_publication_action_receipt_missing")
    elif (
        fact.task_artifact_action_receipt_event_count != 1
        or len(action_rows) != 1
    ):
        issues.append("task_publication_action_receipt_duplicate")
    else:
        action_sequence, action, action_digest, action_issues = (
            _inspect_task_action_receipt(
                action_rows[0],
                fact=fact,
                task_binding=task_binding,
            )
        )
        issues.extend(action_issues)

    issues.extend(
        _inspect_task_artifact_metadata_rows(
            fact,
            metadata_rows,
            action=action,
        )
    )

    if pre_effect is None and action is not None:
        issues.append("task_publication_action_receipt_orphaned")
    if pre_effect is not None and action is not None:
        issues.extend(
            _inspect_task_receipt_linkage(
                pre_effect,
                pre_effect_receipt_digest=pre_digest,
                action=action,
            )
        )
    if enforcing and (pre_effect is not None or action is not None):
        issues.extend(
            _inspect_local_candidate_publication_receipt_binding(
                publication_decision,
                pre_effect=pre_effect,
                action=action,
            )
        )
    if has_receipt_evidence:
        accounting_digest = task_accounting.billing_disposition_digest
        if (
            not _is_digest(accounting_digest)
            or (
                pre_effect is not None
                and pre_effect.get("billing_disposition_digest")
                != accounting_digest
            )
            or (
                action is not None
                and action.get("billing_disposition_digest")
                != accounting_digest
            )
        ):
            issues.append("task_publication_billing_disposition_mismatch")
        accounting = task_accounting.payload
        if isinstance(accounting, Mapping) and not (
            accounting.get("result_observed") is True
            and accounting.get("result_status")
            == RunStatus.SUCCEEDED.value
            and accounting.get("identity_matches") is True
            and accounting.get("billing_matches") is True
            and accounting.get("billing_quarantine_required") is False
            and accounting.get("billing_circuit_breaker_required") is False
            and accounting.get("capacity_state")
            in {
                CapacityState.AVAILABLE.value,
                CapacityState.NOT_APPLICABLE.value,
            }
            and accounting.get("paid_capacity_consumed")
            in {
                PaidCapacityConsumed.NO.value,
                PaidCapacityConsumed.NOT_APPLICABLE.value,
            }
            and accounting.get("incremental_ai_charge")
            == IncrementalAICharge.NONE.value
            and accounting.get("incremental_api_charge") == "none"
            and accounting.get("failure_code") is None
        ):
            issues.append(
                "task_publication_execution_accounting_mismatch"
            )
        billing = task_billing.payload
        if (
            isinstance(accounting, Mapping)
            and isinstance(billing, Mapping)
            and billing.get("route") == BillingRoute.MOCK.value
            and not (
                accounting.get("harness_process_started") is False
                and accounting.get("live_model_execution_occurred") is False
                and accounting.get("subscription_capacity_consumed") is False
                and accounting.get("usage_observation")
                == UsageObservation.NOT_APPLICABLE.value
                and accounting.get("execution_mode") == "in_memory_mock"
            )
        ):
            issues.append(
                "task_publication_execution_accounting_mismatch"
            )

    if (
        fact.task_artifact_metadata_count
        > _MAX_TASK_ARTIFACT_METADATA_PER_RUN
    ):
        issues.append("task_artifact_metadata_limit_exceeded")
    if fact.task_artifact_metadata_count > 0 and action is None:
        issues.append("task_artifact_metadata_unlinked")

    artifact_observed = False
    if isinstance(action, Mapping):
        matching_metadata_count = _matching_task_artifact_metadata_count(
            fact,
            action,
            metadata_rows,
        )
        outcome = action.get("outcome")
        if outcome == ReceiptOutcome.SUCCEEDED.value:
            artifact_observed = matching_metadata_count == 1
            if not artifact_observed:
                issues.append("task_action_receipt_artifact_mismatch")
        elif outcome == ReceiptOutcome.UNKNOWN.value:
            artifact_observed = matching_metadata_count == 1
        if (
            matching_metadata_count > 1
            or len(metadata_rows) != matching_metadata_count
        ):
            issues.append("task_action_receipt_artifact_mismatch")

    return _TaskArtifactReceiptFacts(
        pre_sequence,
        pre_effect,
        pre_digest,
        action_sequence,
        action,
        action_digest,
        artifact_observed,
        tuple(sorted(set(issues))),
    )


def _inspect_task_artifact_metadata_rows(
    fact: _RunFacts,
    rows: list[sqlite3.Row],
    *,
    action: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    """Validate private metadata timing and the run-local path boundary."""

    issues: list[str] = []
    expected_started_at = (
        _optional_timestamp(action.get("started_at"))
        if isinstance(action, Mapping)
        else None
    )
    for row in rows:
        if not _task_artifact_path_is_run_local(
            fact.raw_run_directory,
            row["path"],
        ):
            issues.append("task_artifact_destination_invalid")
        created_at = _optional_timestamp(row["created_at"])
        if created_at is None:
            issues.append("task_artifact_metadata_timestamp_invalid")
        elif (
            isinstance(action, Mapping)
            and created_at != expected_started_at
        ):
            issues.append("task_artifact_metadata_timestamp_mismatch")
    return tuple(sorted(set(issues)))


def _task_artifact_path_is_run_local(
    raw_run_directory: Any,
    raw_artifact_path: Any,
) -> bool:
    if (
        not _is_bounded_private_text(raw_run_directory)
        or not _is_bounded_private_text(raw_artifact_path)
    ):
        return False
    run_directory = Path(os.path.abspath(raw_run_directory))
    artifact_path = Path(os.path.abspath(raw_artifact_path))
    if (
        not Path(raw_run_directory).is_absolute()
        or not Path(raw_artifact_path).is_absolute()
        or str(run_directory) != raw_run_directory
        or str(artifact_path) != raw_artifact_path
        or artifact_path == run_directory
    ):
        return False
    try:
        artifact_path.relative_to(run_directory)
    except ValueError:
        return False
    return True


def _inspect_task_pre_effect_receipt(
    row: sqlite3.Row,
    *,
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
) -> tuple[
    int | None,
    Mapping[str, Any] | None,
    str | None,
    tuple[str, ...],
]:
    sequence, payload = _bounded_artifact_event_payload(row)
    expected_keys = {
        "action_digest",
        "artifact_digest",
        "artifact_kind",
        "artifact_record_digest",
        "artifact_size_bytes",
        "authority_basis",
        "authorization_enforced",
        "billing_disposition_digest",
        "credential_scan_passed",
        "destination_digest",
        "evaluation_accepted",
        "mode",
        "publication_decision_digest",
        "publication_request_digest",
        "publication_shadow_persisted",
        "receipt_digest",
        "receipt_kind",
        "requested_permission_class",
        "schema_version",
        "started_at",
        "task_attempt_binding_digest",
    }
    enforcing = (
        task_binding.schema_version
        in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    if enforcing:
        expected_keys.update(
            {
                "publication_authorization_event_id",
                "publication_enforcement_coverage",
                "publication_shadow_decision_digest",
                "publication_shadow_request_digest",
            }
        )
    if payload is None or set(payload) != expected_keys:
        return (
            sequence,
            None,
            None,
            ("task_publication_pre_effect_receipt_invalid",),
        )

    issues: list[str] = []
    occurred_at = _optional_timestamp(row["occurred_at"])
    if occurred_at is None:
        issues.append("task_publication_pre_effect_timestamp_invalid")
    receipt_digest = payload.get("receipt_digest")
    receipt_body = dict(payload)
    del receipt_body["receipt_digest"]
    if not _digest_matches(receipt_digest, receipt_body):
        issues.append("task_publication_pre_effect_digest_mismatch")
    started_at = _optional_timestamp(payload.get("started_at"))
    if (
        payload.get("schema_version") != (3 if enforcing else 2)
        or payload.get("mode") != ("enforcing" if enforcing else "shadow")
        or payload.get("receipt_kind") != "pre_effect"
        or payload.get("authorization_enforced") is not enforcing
        or payload.get("authority_basis")
        != (
            "abac_exact_permit_and_legacy_permission_class_gate"
            if enforcing
            else "legacy_permission_class_gate"
        )
        or fact.permission_class is None
        or _permission_class(payload.get("requested_permission_class"))
        != fact.permission_class
        or not isinstance(payload.get("publication_shadow_persisted"), bool)
        or payload.get("evaluation_accepted") is not True
        or payload.get("credential_scan_passed") is not True
        or not _is_digest(payload.get("task_attempt_binding_digest"))
        or not _is_optional_digest(payload.get("publication_request_digest"))
        or not _is_optional_digest(payload.get("publication_decision_digest"))
        or not _is_optional_digest(payload.get("action_digest"))
        or not _bounded_authorization_identifier(
            payload.get("artifact_kind")
        )
        or not _is_digest(payload.get("destination_digest"))
        or not _is_digest(payload.get("artifact_digest"))
        or not _is_positive_integer(payload.get("artifact_size_bytes"))
        or not _is_digest(payload.get("artifact_record_digest"))
        or not _is_digest(payload.get("billing_disposition_digest"))
        or started_at is None
        or (
            enforcing
            and (
                payload.get("publication_enforcement_coverage")
                != TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
                or not _is_digest(
                    payload.get("publication_authorization_event_id")
                )
                or not _is_optional_digest(
                    payload.get("publication_shadow_request_digest")
                )
                or not _is_optional_digest(
                    payload.get("publication_shadow_decision_digest")
                )
                or not _is_digest(payload.get("publication_request_digest"))
                or not _is_digest(payload.get("publication_decision_digest"))
                or not _is_digest(payload.get("action_digest"))
            )
        )
    ):
        issues.append("task_publication_pre_effect_receipt_invalid")
    if (
        occurred_at is not None
        and started_at is not None
        and occurred_at < started_at
    ):
        issues.append("task_publication_pre_effect_timestamp_invalid")
    if payload.get("task_attempt_binding_digest") != (
        task_binding.binding_digest
    ):
        issues.append("task_publication_pre_effect_binding_mismatch")
    if row["event_id"] != receipt_digest:
        issues.append(
            "task_publication_pre_effect_event_identifier_mismatch"
        )
    if not enforcing and (
        (payload.get("publication_request_digest") is None)
        != (payload.get("action_digest") is None)
        or (
            payload.get("publication_decision_digest") is not None
            and payload.get("publication_request_digest") is None
        )
    ):
        issues.append("task_publication_pre_effect_receipt_linkage_invalid")
    return (
        sequence,
        payload,
        receipt_digest if _is_digest(receipt_digest) else None,
        tuple(sorted(set(issues))),
    )


def _inspect_task_action_receipt(
    row: sqlite3.Row,
    *,
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
) -> tuple[
    int | None,
    Mapping[str, Any] | None,
    str | None,
    tuple[str, ...],
]:
    sequence, payload = _bounded_artifact_event_payload(row)
    expected_keys = {
        "action_digest",
        "artifact_kind",
        "artifact_record_digest",
        "authority_basis",
        "authorization_enforced",
        "billing_disposition_digest",
        "completed_at",
        "credential_scan_passed",
        "destination_digest",
        "evaluation_accepted",
        "executor_id",
        "failure_code",
        "intended_artifact_digest",
        "intended_artifact_size_bytes",
        "mode",
        "obligation_results",
        "observed_artifact_size_bytes",
        "outcome",
        "pre_effect_receipt_digest",
        "publication_decision_digest",
        "publication_request_digest",
        "publication_shadow_persisted",
        "receipt_digest",
        "receipt_id",
        "receipt_kind",
        "requested_permission_class",
        "result_digest",
        "schema_version",
        "started_at",
        "task_attempt_binding_digest",
    }
    enforcing = (
        task_binding.schema_version
        in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
    )
    if enforcing:
        expected_keys.update(
            {
                "effect_started_at",
                "enforcement_receipt",
                "enforcement_receipt_digest",
                "publication_authorization_event_id",
                "publication_enforcement_coverage",
                "publication_shadow_decision_digest",
                "publication_shadow_request_digest",
            }
        )
    if payload is None or set(payload) != expected_keys:
        return (
            sequence,
            None,
            None,
            ("task_publication_action_receipt_invalid",),
        )

    issues: list[str] = []
    if _optional_timestamp(row["occurred_at"]) is None:
        issues.append("task_publication_action_timestamp_invalid")
    receipt_digest = payload.get("receipt_digest")
    receipt_body = dict(payload)
    del receipt_body["receipt_digest"]
    if not _digest_matches(receipt_digest, receipt_body):
        issues.append("task_publication_action_receipt_digest_mismatch")
    started_at = _optional_timestamp(payload.get("started_at"))
    completed_at = _optional_timestamp(payload.get("completed_at"))
    effect_started_at = (
        _optional_timestamp(payload.get("effect_started_at"))
        if enforcing
        else None
    )
    if (
        payload.get("schema_version") != (3 if enforcing else 2)
        or payload.get("mode") != ("enforcing" if enforcing else "shadow")
        or payload.get("receipt_kind") != "action"
        or payload.get("authorization_enforced") is not enforcing
        or payload.get("authority_basis")
        != (
            "abac_exact_permit_and_legacy_permission_class_gate"
            if enforcing
            else "legacy_permission_class_gate"
        )
        or payload.get("executor_id")
        != LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID
        or fact.permission_class is None
        or _permission_class(payload.get("requested_permission_class"))
        != fact.permission_class
        or not isinstance(payload.get("publication_shadow_persisted"), bool)
        or payload.get("evaluation_accepted") is not True
        or payload.get("credential_scan_passed") is not True
        or not _is_digest(payload.get("receipt_id"))
        or not _is_digest(payload.get("task_attempt_binding_digest"))
        or not _is_digest(payload.get("pre_effect_receipt_digest"))
        or not _is_optional_digest(payload.get("publication_request_digest"))
        or not _is_optional_digest(payload.get("publication_decision_digest"))
        or not _is_optional_digest(payload.get("action_digest"))
        or not _bounded_authorization_identifier(
            payload.get("artifact_kind")
        )
        or not _is_digest(payload.get("destination_digest"))
        or not _is_digest(payload.get("intended_artifact_digest"))
        or not _is_positive_integer(
            payload.get("intended_artifact_size_bytes")
        )
        or not _is_digest(payload.get("artifact_record_digest"))
        or not _is_digest(payload.get("billing_disposition_digest"))
        or not _is_optional_digest(payload.get("result_digest"))
        or not _is_optional_non_negative_integer(
            payload.get("observed_artifact_size_bytes")
        )
        or started_at is None
        or completed_at is None
        or (
            started_at is not None
            and completed_at is not None
            and completed_at < started_at
        )
        or (
            enforcing
            and (
                payload.get("publication_enforcement_coverage")
                != TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
                or not _is_digest(
                    payload.get("publication_authorization_event_id")
                )
                or not _is_optional_digest(
                    payload.get("publication_shadow_request_digest")
                )
                or not _is_optional_digest(
                    payload.get("publication_shadow_decision_digest")
                )
                or not _is_digest(payload.get("publication_request_digest"))
                or not _is_digest(payload.get("publication_decision_digest"))
                or not _is_digest(payload.get("action_digest"))
                or _optional_timestamp(payload.get("effect_started_at"))
                is None
                or not _is_digest(payload.get("enforcement_receipt_digest"))
                or not isinstance(payload.get("enforcement_receipt"), Mapping)
            )
        )
    ):
        issues.append("task_publication_action_receipt_invalid")
    if enforcing and (
        effect_started_at is None
        or started_at is None
        or completed_at is None
        or effect_started_at < started_at
        or completed_at < effect_started_at
        or (
            _optional_timestamp(row["occurred_at"]) is not None
            and completed_at > float(row["occurred_at"])
        )
    ):
        issues.append("task_publication_action_timestamp_invalid")
    if payload.get("task_attempt_binding_digest") != (
        task_binding.binding_digest
    ):
        issues.append("task_publication_action_receipt_binding_mismatch")
    expected_receipt_id = canonical_digest(
        {
            "destination_digest": payload.get("destination_digest"),
            "pre_effect_receipt_digest": payload.get(
                "pre_effect_receipt_digest"
            ),
            "task_attempt_binding_digest": payload.get(
                "task_attempt_binding_digest"
            ),
        }
    )
    if payload.get("receipt_id") != expected_receipt_id:
        issues.append("task_publication_action_receipt_identifier_mismatch")
    if row["event_id"] != payload.get("receipt_id"):
        issues.append(
            "task_publication_action_event_identifier_mismatch"
        )
    if not enforcing and (
        (payload.get("publication_request_digest") is None)
        != (payload.get("action_digest") is None)
        or (
            payload.get("publication_decision_digest") is not None
            and payload.get("publication_request_digest") is None
        )
    ):
        issues.append("task_publication_action_receipt_linkage_invalid")
    issues.extend(_inspect_task_obligation_results(payload))
    issues.extend(_inspect_task_action_outcome(payload))
    if enforcing:
        issues.extend(_inspect_task_enforcement_receipt(payload))
    return (
        sequence,
        payload,
        receipt_digest if _is_digest(receipt_digest) else None,
        tuple(sorted(set(issues))),
    )


def _inspect_task_obligation_results(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    values = payload.get("obligation_results")
    if not isinstance(values, list) or len(values) > _MAX_OBLIGATION_RESULTS:
        return ("task_publication_obligation_results_invalid",)
    allowed_kinds = {item.value for item in ObligationKind}
    canonical_values: list[tuple[str, str]] = []
    for value in values:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"kind", "satisfied", "value_digest"}
            or value.get("kind") not in allowed_kinds
            or value.get("satisfied") is not True
            or not _is_digest(value.get("value_digest"))
        ):
            return ("task_publication_obligation_results_invalid",)
        canonical_values.append((value["kind"], value["value_digest"]))
    if (
        canonical_values != sorted(canonical_values)
        or len(canonical_values) != len(set(canonical_values))
    ):
        return ("task_publication_obligation_results_invalid",)
    return ()


def _inspect_task_enforcement_receipt(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    """Validate the typed enforcing receipt embedded in schema-v3 evidence."""

    receipt = payload.get("enforcement_receipt")
    if not isinstance(receipt, Mapping) or set(receipt) != {
        "completed_at",
        "decision_digest",
        "enforced_action_digest",
        "executor_id",
        "obligation_results",
        "outcome",
        "receipt_id",
        "request_digest",
        "result_digest",
        "started_at",
    }:
        return ("task_publication_enforcement_receipt_invalid",)
    if not _digest_matches(
        payload.get("enforcement_receipt_digest"),
        receipt,
    ):
        return ("task_publication_enforcement_receipt_digest_mismatch",)

    effect_started_at = _optional_timestamp(payload.get("effect_started_at"))
    completed_at = _optional_timestamp(payload.get("completed_at"))
    receipt_started_at = _optional_timestamp(receipt.get("started_at"))
    receipt_completed_at = _optional_timestamp(receipt.get("completed_at"))
    raw_results = receipt.get("obligation_results")
    projected_results = payload.get("obligation_results")
    if not isinstance(raw_results, list) or not isinstance(
        projected_results,
        list,
    ):
        return ("task_publication_enforcement_receipt_invalid",)
    expected_projection: list[dict[str, Any]] = []
    raw_pairs: list[tuple[str, str]] = []
    for item in raw_results:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"kind", "satisfied", "value"}
            or not isinstance(item.get("kind"), str)
            or item.get("satisfied") is not True
            or not isinstance(item.get("value"), str)
        ):
            return ("task_publication_enforcement_receipt_invalid",)
        kind = item["kind"]
        value = item["value"]
        raw_pairs.append((kind, value))
        expected_projection.append(
            {
                "kind": kind,
                "satisfied": True,
                "value_digest": canonical_digest({"value": value}),
            }
        )
    expected_projection.sort(
        key=lambda item: (item["kind"], item["value_digest"])
    )
    fixed_obligations = {
        (ObligationKind.AUDIT_RECEIPT.value, "append_after_action"),
        (ObligationKind.ISOLATED_LOCAL_ONLY.value, "required"),
    }
    valid = bool(
        _is_digest(receipt.get("receipt_id"))
        and receipt.get("executor_id")
        == LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID
        and receipt.get("request_digest")
        == payload.get("publication_request_digest")
        and receipt.get("decision_digest")
        == payload.get("publication_decision_digest")
        and receipt.get("enforced_action_digest")
        == payload.get("action_digest")
        and receipt_started_at is not None
        and receipt_started_at == effect_started_at
        and receipt_completed_at is not None
        and receipt_completed_at == completed_at
        and receipt.get("outcome") == payload.get("outcome")
        and receipt.get("result_digest") == payload.get("result_digest")
        and len(raw_pairs) == len(set(raw_pairs))
        and raw_pairs == sorted(raw_pairs)
        and set(raw_pairs) == fixed_obligations
        and projected_results == expected_projection
    )
    return () if valid else ("task_publication_enforcement_receipt_invalid",)


def _inspect_local_candidate_publication_receipt_binding(
    decision: _LocalCandidatePublicationDecisionFacts,
    *,
    pre_effect: Mapping[str, Any] | None,
    action: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    """Bind schema-v3 effect evidence to one authoritative permit event."""

    issues: list[str] = []
    wrapper = decision.payload
    request = decision.request
    authorization_decision = decision.decision
    if (
        not decision.observed
        or not isinstance(wrapper, Mapping)
        or not isinstance(request, Mapping)
        or not isinstance(authorization_decision, Mapping)
        or decision.effect != AuthorizationEffect.PERMIT.value
        or decision.authorization_eligible is not True
        or decision.event_id is None
        or decision.request_digest is None
        or decision.decision_digest is None
    ):
        return ("local_candidate_publication_receipt_authorization_mismatch",)

    request_action = request.get("action")
    request_resource = request.get("resource")
    expected_action_digest = (
        canonical_digest(
            {"action": request_action, "resource": request_resource}
        )
        if isinstance(request_action, Mapping)
        and isinstance(request_resource, Mapping)
        else None
    )
    common_links = {
        "publication_authorization_event_id": decision.event_id,
        "publication_enforcement_coverage": (
            TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
        ),
        "publication_request_digest": decision.request_digest,
        "publication_decision_digest": decision.decision_digest,
        "action_digest": expected_action_digest,
        "task_attempt_binding_digest": wrapper.get(
            "task_attempt_binding_digest"
        ),
        "destination_digest": wrapper.get("destination_digest"),
        "artifact_record_digest": wrapper.get("artifact_metadata_digest"),
        "billing_disposition_digest": wrapper.get(
            "billing_disposition_digest"
        ),
    }
    for receipt in (pre_effect, action):
        if isinstance(receipt, Mapping) and any(
            receipt.get(key) != expected
            for key, expected in common_links.items()
        ):
            issues.append(
                "local_candidate_publication_receipt_authorization_mismatch"
            )

    if isinstance(pre_effect, Mapping) and (
        pre_effect.get("artifact_digest") != wrapper.get("artifact_digest")
        or pre_effect.get("requested_permission_class")
        != wrapper.get("requested_permission_class")
    ):
        issues.append(
            "local_candidate_publication_receipt_authorization_mismatch"
        )
    if isinstance(action, Mapping):
        if (
            action.get("intended_artifact_digest")
            != wrapper.get("artifact_digest")
            or action.get("requested_permission_class")
            != wrapper.get("requested_permission_class")
        ):
            issues.append(
                "local_candidate_publication_receipt_authorization_mismatch"
            )
        enforcement_receipt = action.get("enforcement_receipt")
        expected_receipt_id = canonical_digest(
            {
                "decision_digest": decision.decision_digest,
                "destination_digest": wrapper.get("destination_digest"),
                "request_digest": decision.request_digest,
                "task_attempt_binding_digest": wrapper.get(
                    "task_attempt_binding_digest"
                ),
                "receipt_kind": "local_candidate_publication_action",
            }
        )
        if (
            not isinstance(enforcement_receipt, Mapping)
            or enforcement_receipt.get("receipt_id") != expected_receipt_id
            or not _mock_dispatch_receipt_obligations_match(
                authorization_decision.get("obligations"),
                enforcement_receipt.get("obligation_results"),
            )
        ):
            issues.append(
                "local_candidate_publication_receipt_authorization_mismatch"
            )
    return tuple(sorted(set(issues)))


def _inspect_task_action_outcome(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    outcome = payload.get("outcome")
    failure_code = payload.get("failure_code")
    result_digest = payload.get("result_digest")
    observed_size = payload.get("observed_artifact_size_bytes")
    intended_digest = payload.get("intended_artifact_digest")
    intended_size = payload.get("intended_artifact_size_bytes")
    expected_failure_codes = {
        ReceiptOutcome.FAILED.value: "artifact_persistence_failed",
        ReceiptOutcome.CANCELLED.value: "artifact_persistence_interrupted",
        ReceiptOutcome.UNKNOWN.value: "artifact_publication_outcome_unknown",
    }
    if outcome == ReceiptOutcome.SUCCEEDED.value:
        valid = (
            failure_code is None
            and result_digest == intended_digest
            and observed_size == intended_size
        )
    elif outcome in expected_failure_codes:
        valid = (
            failure_code == expected_failure_codes[outcome]
            and result_digest is None
            and observed_size is None
        )
    else:
        valid = False
    return () if valid else ("task_publication_action_outcome_invalid",)


def _inspect_task_receipt_linkage(
    pre_effect: Mapping[str, Any],
    *,
    pre_effect_receipt_digest: str | None,
    action: Mapping[str, Any],
) -> tuple[str, ...]:
    comparisons: tuple[tuple[str, Any], ...] = (
        ("pre_effect_receipt_digest", pre_effect_receipt_digest),
        (
            "task_attempt_binding_digest",
            pre_effect.get("task_attempt_binding_digest"),
        ),
        (
            "publication_shadow_persisted",
            pre_effect.get("publication_shadow_persisted"),
        ),
        (
            "publication_request_digest",
            pre_effect.get("publication_request_digest"),
        ),
        (
            "publication_decision_digest",
            pre_effect.get("publication_decision_digest"),
        ),
        ("action_digest", pre_effect.get("action_digest")),
        ("started_at", pre_effect.get("started_at")),
        (
            "requested_permission_class",
            pre_effect.get("requested_permission_class"),
        ),
        ("artifact_kind", pre_effect.get("artifact_kind")),
        ("destination_digest", pre_effect.get("destination_digest")),
        (
            "artifact_record_digest",
            pre_effect.get("artifact_record_digest"),
        ),
        (
            "billing_disposition_digest",
            pre_effect.get("billing_disposition_digest"),
        ),
        ("evaluation_accepted", pre_effect.get("evaluation_accepted")),
        (
            "credential_scan_passed",
            pre_effect.get("credential_scan_passed"),
        ),
    )
    if pre_effect.get("schema_version") == 3:
        comparisons = (
            *comparisons,
            (
                "publication_authorization_event_id",
                pre_effect.get("publication_authorization_event_id"),
            ),
            (
                "publication_enforcement_coverage",
                pre_effect.get("publication_enforcement_coverage"),
            ),
            (
                "publication_shadow_request_digest",
                pre_effect.get("publication_shadow_request_digest"),
            ),
            (
                "publication_shadow_decision_digest",
                pre_effect.get("publication_shadow_decision_digest"),
            ),
        )
    if any(action.get(key, _MISSING) != expected for key, expected in comparisons):
        return ("task_publication_receipt_linkage_mismatch",)
    if (
        action.get("intended_artifact_digest")
        != pre_effect.get("artifact_digest")
        or action.get("intended_artifact_size_bytes")
        != pre_effect.get("artifact_size_bytes")
    ):
        return ("task_publication_receipt_linkage_mismatch",)
    return ()


def _matching_task_artifact_metadata_count(
    fact: _RunFacts,
    action: Mapping[str, Any],
    rows: list[sqlite3.Row],
) -> int:
    matches = 0
    for row in rows:
        artifact_id = row["artifact_id"]
        raw_run_id = row["run_id"]
        artifact_kind = row["kind"]
        artifact_path = row["path"]
        artifact_sha256 = row["sha256"]
        media_type = row["media_type"]
        size_bytes = row["size_bytes"]
        if (
            not _is_bounded_private_text(artifact_id)
            or raw_run_id != fact.raw_run_id
            or not _is_bounded_private_text(artifact_kind)
            or not _is_bounded_private_text(artifact_path)
            or not isinstance(artifact_sha256, str)
            or _BARE_SHA256_PATTERN.fullmatch(artifact_sha256) is None
            or not _is_bounded_private_text(media_type)
            or not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes < 0
        ):
            continue
        destination_digest = canonical_digest(
            {"artifact_path": artifact_path}
        )
        artifact_digest = f"sha256:{artifact_sha256}"
        metadata_digest = canonical_digest(
            {
                "artifact_id_ref": canonical_digest(
                    {"artifact_id": artifact_id}
                ),
                "run_ref": canonical_digest({"run_id": raw_run_id}),
                "artifact_kind": artifact_kind,
                "destination_digest": destination_digest,
                "artifact_digest": artifact_digest,
                "media_type": media_type,
                "size_bytes": size_bytes,
            }
        )
        if (
            action.get("artifact_record_digest") == metadata_digest
            and action.get("artifact_kind") == artifact_kind
            and action.get("destination_digest") == destination_digest
            and action.get("intended_artifact_digest") == artifact_digest
            and action.get("intended_artifact_size_bytes") == size_bytes
        ):
            matches += 1
    return matches


def _inspect_task_action_terminal_linkage(
    fact: _RunFacts,
    receipts: _TaskArtifactReceiptFacts,
) -> tuple[str, ...]:
    """Reject impossible task receipt, artifact, and terminal pairings."""

    action = receipts.action
    if not isinstance(action, Mapping):
        return ()
    terminal_statuses = {
        RunStatus.SUCCEEDED.value,
        RunStatus.FAILED.value,
        RunStatus.BLOCKED.value,
        RunStatus.QUARANTINED.value,
        RunStatus.CANCELLED.value,
    }
    terminal_status = fact.latest_status
    if terminal_status not in terminal_statuses:
        return ("task_action_receipt_terminal_missing",)

    outcome = action.get("outcome")
    observed = fact.terminal_artifact_observed
    if outcome == ReceiptOutcome.SUCCEEDED.value:
        valid_observation = receipts.artifact_observed and observed is True
        allowed_statuses = {
            RunStatus.SUCCEEDED.value,
            RunStatus.QUARANTINED.value,
        }
    elif outcome == ReceiptOutcome.FAILED.value:
        valid_observation = observed is False
        allowed_statuses = {
            RunStatus.FAILED.value,
            RunStatus.QUARANTINED.value,
        }
    elif outcome == ReceiptOutcome.CANCELLED.value:
        valid_observation = observed is False
        allowed_statuses = {
            RunStatus.CANCELLED.value,
            RunStatus.QUARANTINED.value,
        }
    elif outcome == ReceiptOutcome.UNKNOWN.value:
        valid_observation = isinstance(observed, bool)
        allowed_statuses = {RunStatus.QUARANTINED.value}
    else:
        return ()
    if not valid_observation or terminal_status not in allowed_statuses:
        return ("task_action_receipt_terminal_mismatch",)
    return ()


def _inspect_task_terminal_evidence(
    fact: _RunFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_accounting: _TaskAccountingFacts,
    receipts: _TaskArtifactReceiptFacts,
    rows: list[sqlite3.Row],
) -> tuple[str, ...]:
    """Validate the deterministic terminal source for successful publication."""

    action = receipts.action
    if (
        task_binding.binding is None
        or task_binding.issues
        or not isinstance(action, Mapping)
        or action.get("outcome") != ReceiptOutcome.SUCCEEDED.value
    ):
        return ()
    if len(rows) != 1:
        return (
            "task_terminal_missing"
            if not rows
            else "task_terminal_duplicate",
        )

    row = rows[0]
    issues: list[str] = []
    sequence = _optional_sequence(row["sequence"])
    if sequence != fact.terminal_sequence:
        issues.append("task_terminal_order_invalid")
    if _optional_timestamp(row["occurred_at"]) is None:
        issues.append("task_terminal_timestamp_invalid")
    payload = _bounded_json_mapping(row["payload_json"])
    if not isinstance(payload, Mapping):
        issues.append("task_terminal_payload_invalid")
        return tuple(sorted(set(issues)))
    if row["event_id"] != canonical_digest(
        {
            "event_type": "status",
            "payload": payload,
            "run_id": fact.raw_run_id,
            "status": row["status"],
        }
    ):
        issues.append("task_terminal_event_identifier_mismatch")

    boolean_keys = _TASK_SUCCESS_TERMINAL_KEYS.difference(
        {"runner_status"}
    )
    if (
        row["event_type"] != "status"
        or row["status"] != RunStatus.SUCCEEDED.value
        or fact.latest_status != RunStatus.SUCCEEDED.value
        or set(payload) != _TASK_SUCCESS_TERMINAL_KEYS
        or any(not isinstance(payload.get(key), bool) for key in boolean_keys)
        or payload.get("runner_status") not in _KNOWN_STATUSES
    ):
        issues.append("task_terminal_payload_invalid")
        return tuple(sorted(set(issues)))

    accounting = task_accounting.payload
    pre_effect = receipts.pre_effect
    if (
        not isinstance(accounting, Mapping)
        or not isinstance(pre_effect, Mapping)
        or payload.get("accepted") is not True
        or payload.get("artifact_recorded") is not True
        or payload.get("artifact_observed") is not True
        or payload.get("artifact_credential_scan_passed") is not True
        or payload.get("accepted")
        != pre_effect.get("evaluation_accepted")
        or payload.get("artifact_credential_scan_passed")
        != pre_effect.get("credential_scan_passed")
        or payload.get("runner_status")
        != accounting.get("result_status")
        or payload.get("billing_assessment_matched_preflight")
        != accounting.get("billing_matches")
        or payload.get("billing_quarantine_required")
        != accounting.get("billing_quarantine_required")
        or payload.get("billing_circuit_breaker_required")
        != accounting.get("billing_circuit_breaker_required")
    ):
        issues.append("task_terminal_record_mismatch")
    return tuple(sorted(set(issues)))


def _inspect_event(
    row: sqlite3.Row,
    *,
    now: float,
    expected_run_id: str,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    comparison_binding: _ComparisonBindingFacts,
    comparison_billing: _ComparisonBillingFacts,
    comparison_accounting: _ComparisonAccountingFacts,
    comparison_artifact_receipts: _ComparisonArtifactReceiptFacts,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    task_billing: _TaskBillingFacts,
    task_accounting: _TaskAccountingFacts,
    task_artifact_receipts: _TaskArtifactReceiptFacts,
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
    if (
        task_binding.observed
        and schema_version in {2, 5}
        and row["event_id"]
        != canonical_digest(
            {
                "event_type": AUTHORIZATION_SHADOW_EVENT_TYPE,
                "payload": payload,
                "run_id": expected_run_id,
            }
        )
    ):
        issues.append("task_shadow_event_identifier_mismatch")
    if payload.get("mode") != "shadow":
        issues.append("mode_invalid")
    raw_scope = payload.get("action_scope")
    action_scope = _known_string(raw_scope, KNOWN_ACTION_SCOPES)
    if action_scope is None:
        issues.append("action_scope_invalid")
    comparison_publication_projection = (
        schema_version == 4
        and action_scope == PUBLICATION_SCOPE
        and comparison_binding.schema_version == 2
        and comparison_binding.binding is not None
        and not comparison_binding.issues
    )
    comparison_trial_projection = schema_version == 3

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
    if schema_version in {2, 3, 4, 5}:
        expected_requested_permission_class = (
            int(PermissionClass.LOCAL_DRAFT)
            if comparison_publication_projection
            else expected_permission_class
        )
        if requested_permission_class is None:
            issues.append("requested_permission_class_invalid")
        elif (
            expected_requested_permission_class is not None
            and requested_permission_class
            != expected_requested_permission_class
        ):
            issues.append("requested_permission_class_run_mismatch")
    legacy_executable = _optional_boolean(payload.get("legacy_executable"))
    if legacy_executable is None:
        issues.append("legacy_executable_invalid")
    recomputed_legacy_executable = (
        True
        if comparison_publication_projection
        and expected_permission_class == int(PermissionClass.READ_ONLY)
        else (
            expected_permission_class
            in {
                int(PermissionClass.READ_ONLY),
                int(PermissionClass.LOCAL_DRAFT),
            }
            if expected_permission_class is not None
            else None
        )
    )
    if (
        schema_version == 4
        and expected_permission_class != int(PermissionClass.READ_ONLY)
    ):
        issues.append("comparison_publication_run_class_invalid")
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
        schema_version in {2, 3, 4, 5}
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
    task_intent_projection_issues: tuple[str, ...] = ()
    if schema_version in {2, 3, 4, 5}:
        task_intent_projection_issues = _inspect_task_intent_projection(
            payload,
            request=request,
            failure_stage=failure_stage,
            action_scope=action_scope,
            comparison_projection=comparison_trial_projection,
            comparison_publication_projection=(
                comparison_publication_projection
            ),
        )
        issues.extend(task_intent_projection_issues)
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

    boundary_projection_issues: tuple[str, ...] = ()
    if (
        schema_version in {2, 3, 4, 5}
        and action_scope is not None
        and isinstance(request, Mapping)
    ):
        boundary_projection_issues = _inspect_boundary_projection(
            request,
            action_scope=action_scope,
            expected_run_id=expected_run_id,
        )
        issues.extend(boundary_projection_issues)

    comparison_publication_binding_issues: tuple[str, ...] = ()
    if schema_version == 3:
        issues.extend(
            _inspect_comparison_shadow_binding(
                payload,
                request=request,
                action_scope=action_scope,
                expected_task_id=expected_task_id,
                expected_task_version=expected_task_version,
                expected_permission_class=expected_permission_class,
                comparison_binding=comparison_binding,
                comparison_billing=comparison_billing,
            )
        )
    elif schema_version == 4:
        comparison_publication_binding_issues = (
            _inspect_comparison_publication_shadow_binding(
                payload,
                request=request,
                action_scope=action_scope,
                expected_task_id=expected_task_id,
                expected_task_version=expected_task_version,
                expected_permission_class=expected_permission_class,
                comparison_binding=comparison_binding,
                comparison_accounting=comparison_accounting,
                comparison_artifact_receipts=(
                    comparison_artifact_receipts
                ),
            )
        )
        issues.extend(comparison_publication_binding_issues)
    elif schema_version == 5:
        issues.extend(
            _inspect_task_publication_shadow_binding(
                payload,
                request=request,
                action_scope=action_scope,
                expected_task_id=expected_task_id,
                expected_task_version=expected_task_version,
                expected_permission_class=expected_permission_class,
                task_binding=task_binding,
                task_accounting=task_accounting,
                task_artifact_receipts=task_artifact_receipts,
            )
        )
    elif (
        schema_version == 2
        and task_binding.observed
        and action_scope in {ADMISSION_SCOPE, DISPATCH_SCOPE}
    ):
        issues.extend(
            _inspect_task_boundary_shadow_binding(
                payload,
                request=request,
                action_scope=action_scope,
                expected_task_id=expected_task_id,
                expected_task_version=expected_task_version,
                expected_permission_class=expected_permission_class,
                task_binding=task_binding,
                task_execution_selection=task_execution_selection,
                task_billing=task_billing,
            )
        )
    elif comparison_binding.observed and action_scope in {
        ADMISSION_SCOPE,
        DISPATCH_SCOPE,
    }:
        issues.append("comparison_shadow_schema_invalid")
    if (
        task_binding.observed
        and action_scope == PUBLICATION_SCOPE
        and schema_version != 5
    ):
        issues.append("task_publication_shadow_schema_invalid")
    if (
        task_binding.observed
        and action_scope in {ADMISSION_SCOPE, DISPATCH_SCOPE}
        and schema_version != 2
    ):
        issues.append("task_boundary_shadow_schema_invalid")

    recomputed_derived_permission_class: int | None = None
    class_derivation_issues: tuple[str, ...] = ()
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
    comparison_publication_authority_exception = (
        comparison_publication_projection
        and expected_permission_class == int(PermissionClass.READ_ONLY)
        and payload.get("requested_permission_class")
        == int(PermissionClass.LOCAL_DRAFT)
        and _is_request_shape(request)
        and request_digest_valid is True
        and recomputed_derived_permission_class
        == int(PermissionClass.LOCAL_DRAFT)
        and not class_derivation_issues
        and not task_intent_projection_issues
        and not boundary_projection_issues
        and not comparison_publication_binding_issues
    )
    authority_ceiling = (
        int(PermissionClass.LOCAL_DRAFT)
        if comparison_publication_authority_exception
        else expected_permission_class
    )
    recomputed_authority_ceiling_parity = (
        recomputed_derived_permission_class <= authority_ceiling
        if (
            recomputed_derived_permission_class is not None
            and authority_ceiling is not None
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
    comparison_projection: bool,
    comparison_publication_projection: bool,
) -> tuple[str, ...]:
    """Validate the safe schema-v2/v3 intent projection without emitting it."""

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
    if comparison_publication_projection:
        allowed_sources = {"comparison_review_artifact_projection"}
    elif comparison_projection:
        allowed_sources = {"comparison_trial_projection"}
    elif action_scope == PUBLICATION_SCOPE:
        allowed_sources = {"controller_boundary_projection"}
    else:
        allowed_sources = {"legacy_permission_class_fallback", "task_contract"}
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
    if comparison_projection:
        issues.extend(_inspect_comparison_intent(intent, action_scope=action_scope))
    elif comparison_publication_projection:
        issues.extend(_inspect_comparison_publication_intent(intent))
    elif action_scope == PUBLICATION_SCOPE:
        issues.extend(_inspect_publication_intent(intent))
    return tuple(issues)


def _inspect_comparison_intent(
    intent: Mapping[str, Any],
    *,
    action_scope: str | None,
) -> tuple[str, ...]:
    """Validate the fixed Class 0 comparison admission/dispatch projection."""

    action = intent["action"]
    resource = intent["resource"]
    consequences = intent["consequences"]
    assert isinstance(action, Mapping)
    assert isinstance(resource, Mapping)
    assert isinstance(consequences, Mapping)
    if action_scope not in {ADMISSION_SCOPE, DISPATCH_SCOPE}:
        return ("comparison_intent_invalid",)
    if (
        action.get("verb") != ActionVerb.READ.value
        or action.get("operation")
        != "comparison.evaluate_immutable_snapshot"
        or action.get("intended_effect")
        != "evaluate_immutable_comparison_snapshot"
        or resource.get("resource_type") != "comparison_snapshot"
        or resource.get("trust_boundary") != "isolated_run_workspace"
        or consequences.get("reach") != Reach.LOCAL.value
        or consequences.get("destructive") is not False
        or consequences.get("reversible") is not True
        or consequences.get("blast_radius")
        != BlastRadius.SINGLE_RESOURCE.value
    ):
        return ("comparison_intent_invalid",)
    return ()


def _inspect_comparison_publication_intent(
    intent: Mapping[str, Any],
) -> tuple[str, ...]:
    """Validate the fixed owner-private Class 1 publication projection."""

    action = intent["action"]
    resource = intent["resource"]
    consequences = intent["consequences"]
    assert isinstance(action, Mapping)
    assert isinstance(resource, Mapping)
    assert isinstance(consequences, Mapping)
    if (
        action.get("verb") != ActionVerb.CREATE.value
        or action.get("operation") != "artifact.publish_private_review"
        or action.get("intended_effect")
        != "create_owner_private_review_artifact"
        or resource.get("resource_type") != "private_review_artifact"
        or resource.get("trust_boundary") != "isolated_run_workspace"
        or consequences.get("reach") != Reach.LOCAL.value
        or consequences.get("destructive") is not False
        or consequences.get("reversible") is not True
        or consequences.get("blast_radius")
        != BlastRadius.SINGLE_RESOURCE.value
    ):
        return ("comparison_publication_intent_invalid",)
    return ()


def _inspect_comparison_shadow_binding(
    payload: Mapping[str, Any],
    *,
    request: Any,
    action_scope: str | None,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    comparison_binding: _ComparisonBindingFacts,
    comparison_billing: _ComparisonBillingFacts,
) -> tuple[str, ...]:
    """Bind a schema-v3 shadow to its controller-authored trial metadata."""

    issues: list[str] = []
    if action_scope not in {ADMISSION_SCOPE, DISPATCH_SCOPE}:
        issues.append("comparison_shadow_schema_invalid")
    if expected_permission_class != int(PermissionClass.READ_ONLY):
        issues.append("comparison_request_binding_mismatch")
    reported_binding_digest = payload.get("comparison_binding_digest")
    if (
        comparison_binding.binding_digest is None
        or reported_binding_digest != comparison_binding.binding_digest
    ):
        issues.append("comparison_shadow_binding_digest_mismatch")

    binding = comparison_binding.binding
    if not isinstance(binding, Mapping) or not isinstance(request, Mapping):
        return tuple(issues)

    subject = request.get("subject")
    resource = request.get("resource")
    action = request.get("action")
    if (
        not isinstance(subject, Mapping)
        or subject.get("profile_id") != binding["profile_ref"]
        or subject.get("runner_id") != binding["runner_id"]
        or not isinstance(resource, Mapping)
        or resource.get("repository_id") != binding["repository_ref"]
        or resource.get("version") != binding["snapshot_digest"]
        or resource.get("content_digest")
        != (
            binding["context_digest"]
            if action_scope == ADMISSION_SCOPE
            else binding["prompt_digest"]
        )
        or not isinstance(action, Mapping)
    ):
        issues.append("comparison_request_binding_mismatch")
        return tuple(issues)

    if action_scope == ADMISSION_SCOPE:
        boundary_parameters = {
            "comparison_binding_digest": comparison_binding.binding_digest,
            "context_digest": binding["context_digest"],
            "snapshot_digest": binding["snapshot_digest"],
        }
    elif action_scope == DISPATCH_SCOPE:
        boundary_parameters = {
            "comparison_binding_digest": comparison_binding.binding_digest,
            "prompt_digest": binding["prompt_digest"],
            "snapshot_digest": binding["snapshot_digest"],
        }
    else:
        return tuple(issues)
    expected_parameters_digest = canonical_digest(
        {
            "action_scope": action_scope,
            "intent_digest": payload.get("intent_digest"),
            "intent_source": "comparison_trial_projection",
            "legacy_permission_class": int(PermissionClass.READ_ONLY),
            "output_schema_digest": binding["output_schema_digest"],
            "parameters": boundary_parameters,
            "profile_ref": binding["profile_ref"],
            "runner_id": binding["runner_id"],
            "task_definition_digest": binding["task_definition_digest"],
            "task_id": expected_task_id,
            "task_version": expected_task_version,
        }
    )
    if action.get("parameters_digest") != expected_parameters_digest:
        issues.append("comparison_request_binding_mismatch")
    issues.extend(
        _inspect_comparison_request_environment(
            request,
            comparison_billing=comparison_billing,
        )
    )
    return tuple(issues)


def _inspect_comparison_publication_shadow_binding(
    payload: Mapping[str, Any],
    *,
    request: Any,
    action_scope: str | None,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    comparison_binding: _ComparisonBindingFacts,
    comparison_accounting: _ComparisonAccountingFacts,
    comparison_artifact_receipts: _ComparisonArtifactReceiptFacts,
) -> tuple[str, ...]:
    """Bind a schema-v4 Class 1 shadow to its exact private artifact."""

    issues: list[str] = []
    if (
        action_scope != PUBLICATION_SCOPE
        or comparison_binding.schema_version != 2
        or comparison_binding.binding is None
    ):
        issues.append("comparison_publication_shadow_schema_invalid")
    if expected_permission_class != int(PermissionClass.READ_ONLY):
        issues.append("comparison_publication_run_class_invalid")
    if payload.get("requested_permission_class") != int(
        PermissionClass.LOCAL_DRAFT
    ):
        issues.append("comparison_publication_requested_class_invalid")
    if payload.get("comparison_binding_digest") != (
        comparison_binding.binding_digest
    ):
        issues.append("comparison_publication_shadow_binding_mismatch")

    accounting_digest = comparison_accounting.billing_disposition_digest
    if not _is_digest(accounting_digest):
        issues.append("comparison_publication_billing_disposition_mismatch")

    pre_effect = comparison_artifact_receipts.pre_effect
    if not isinstance(pre_effect, Mapping):
        return tuple(issues)
    if pre_effect.get("billing_disposition_digest") != accounting_digest:
        issues.append("comparison_publication_billing_disposition_mismatch")
    if pre_effect.get("publication_shadow_persisted") is not True:
        issues.append("comparison_publication_shadow_receipt_mismatch")
    if (
        pre_effect.get("publication_request_digest")
        != payload.get("request_digest")
        or pre_effect.get("publication_decision_digest")
        != payload.get("decision_digest")
    ):
        issues.append("comparison_publication_shadow_receipt_mismatch")

    binding = comparison_binding.binding
    if not isinstance(binding, Mapping) or not isinstance(request, Mapping):
        return tuple(issues)
    subject = request.get("subject")
    resource = request.get("resource")
    action = request.get("action")
    environment = request.get("environment")
    if (
        not isinstance(subject, Mapping)
        or subject.get("profile_id") != binding["profile_ref"]
        or subject.get("runner_id") != binding["runner_id"]
        or not isinstance(resource, Mapping)
        or resource.get("repository_id") != binding["repository_ref"]
        or resource.get("version") != pre_effect.get("artifact_digest")
        or resource.get("content_digest") != pre_effect.get("artifact_digest")
        or not isinstance(action, Mapping)
        or not isinstance(environment, Mapping)
        or environment.get("isolation_state") != "verified"
        or environment.get("network_state") != "disabled"
        or environment.get("billing_route") != BillingRoute.LOCAL_NON_AI.value
        or environment.get("capacity_state")
        != CapacityState.NOT_APPLICABLE.value
        or environment.get("paid_continuation_protection")
        != PaidContinuationProtection.NOT_APPLICABLE.value
        or environment.get("circuit_state") != "closed"
    ):
        issues.append("comparison_publication_request_binding_mismatch")
        return tuple(issues)

    expected_action_digest = canonical_digest(
        {
            "action": action,
            "resource": resource,
        }
    )
    if pre_effect.get("action_digest") != expected_action_digest:
        issues.append("comparison_publication_action_digest_mismatch")
    parameters = {
        "artifact_digest": pre_effect.get("artifact_digest"),
        "artifact_kind": pre_effect.get("artifact_kind"),
        "artifact_size_bytes": pre_effect.get("artifact_size_bytes"),
        "billing_disposition_digest": accounting_digest,
        "comparison_binding_digest": comparison_binding.binding_digest,
        "destination_digest": pre_effect.get("destination_digest"),
        "output_withheld": pre_effect.get("output_withheld"),
    }
    expected_parameters_digest = canonical_digest(
        {
            "action_scope": PUBLICATION_SCOPE,
            "intent_digest": payload.get("intent_digest"),
            "intent_source": "comparison_review_artifact_projection",
            "legacy_permission_class": int(PermissionClass.LOCAL_DRAFT),
            "output_schema_digest": binding["output_schema_digest"],
            "parameters": parameters,
            "profile_ref": binding["profile_ref"],
            "runner_id": binding["runner_id"],
            "task_definition_digest": binding["task_definition_digest"],
            "task_id": expected_task_id,
            "task_version": expected_task_version,
        }
    )
    if action.get("parameters_digest") != expected_parameters_digest:
        issues.append("comparison_publication_request_binding_mismatch")

    action_receipt = comparison_artifact_receipts.action
    decision = payload.get("decision")
    if isinstance(action_receipt, Mapping) and isinstance(decision, Mapping):
        issues.extend(
            _inspect_comparison_receipt_obligation_linkage(
                decision,
                action_receipt=action_receipt,
            )
        )
    return tuple(issues)


def _inspect_task_boundary_shadow_binding(
    payload: Mapping[str, Any],
    *,
    request: Any,
    action_scope: str | None,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    task_binding: _TaskAttemptBindingFacts,
    task_execution_selection: _TaskExecutionSelectionFacts,
    task_billing: _TaskBillingFacts,
) -> tuple[str, ...]:
    """Bind ordinary admission and dispatch shadows to immutable inputs."""

    issues: list[str] = []
    if action_scope not in {ADMISSION_SCOPE, DISPATCH_SCOPE}:
        issues.append("task_boundary_shadow_schema_invalid")
    binding = task_binding.binding
    if (
        not isinstance(binding, Mapping)
        or task_binding.issues
        or payload.get("task_attempt_binding_digest")
        != task_binding.binding_digest
    ):
        issues.append("task_shadow_binding_digest_mismatch")
        return tuple(issues)
    if payload.get("requested_permission_class") != expected_permission_class:
        issues.append("task_boundary_requested_class_invalid")
    if payload.get("intent_digest") != binding[
        "authorization_intent_digest"
    ]:
        issues.append("task_boundary_intent_binding_mismatch")
    if (
        task_binding.schema_version
        in _SELECTED_TASK_BINDING_SCHEMA_VERSIONS
    ):
        selection_digest = binding.get("execution_selection_digest")
        if (
            task_execution_selection.issues
            or task_execution_selection.selection_digest
            != selection_digest
        ):
            issues.append("execution_selection_boundary_binding_mismatch")
    if payload.get("failure_stage") == "request_construction":
        return tuple(issues)
    if not isinstance(request, Mapping):
        issues.append("task_boundary_request_binding_mismatch")
        return tuple(issues)

    subject = request.get("subject")
    resource = request.get("resource")
    action = request.get("action")
    if (
        not isinstance(subject, Mapping)
        or subject.get("profile_id") != binding["profile_ref"]
        or subject.get("runner_id") != binding["runner_id"]
        or not isinstance(resource, Mapping)
        or resource.get("repository_id") != binding["repository_ref"]
        or resource.get("version") != binding["task_definition_digest"]
        or not isinstance(action, Mapping)
    ):
        issues.append("task_boundary_request_binding_mismatch")
        return tuple(issues)

    if action_scope == ADMISSION_SCOPE:
        expected_content_digest = binding["context_digest"]
        parameters = {
            "context_digest": binding["context_digest"],
            "prompt_digest": binding["prompt_digest"],
            "task_attempt_binding_digest": task_binding.binding_digest,
        }
    else:
        expected_content_digest = binding["prompt_digest"]
        billing_payload = task_billing.payload
        parameters = {
            "attempt": binding["attempt"],
            "billing_assessment_digest": task_billing.assessment_digest,
            "context_digest": binding["context_digest"],
            "prompt_digest": binding["prompt_digest"],
            "runner_overrides_digest": binding[
                "runner_overrides_digest"
            ],
            "task_attempt_binding_digest": task_binding.binding_digest,
            "timeout_seconds": binding["timeout_seconds"],
        }
        environment = request.get("environment")
        mock_runner = binding.get("runner_id") == "mock"
        expected_route = (
            BillingRoute.MOCK.value
            if mock_runner
            else billing_payload.get("route")
            if isinstance(billing_payload, Mapping)
            else None
        )
        expected_capacity = (
            CapacityState.NOT_APPLICABLE.value
            if mock_runner
            else billing_payload.get("capacity_state")
            if isinstance(billing_payload, Mapping)
            else None
        )
        expected_paid_continuation = (
            PaidContinuationProtection.NOT_APPLICABLE.value
            if mock_runner
            else billing_payload.get("paid_continuation_protection")
            if isinstance(billing_payload, Mapping)
            else None
        )
        if (
            task_billing.issues
            or not isinstance(billing_payload, Mapping)
            or not _is_digest(task_billing.assessment_digest)
            or not isinstance(environment, Mapping)
            or environment.get("isolation_state") != "verified"
            or environment.get("network_state")
            != ("disabled" if mock_runner else "unknown")
            or environment.get("billing_route") != expected_route
            or environment.get("capacity_state") != expected_capacity
            or environment.get("paid_continuation_protection")
            != expected_paid_continuation
            or environment.get("circuit_state")
            != ("closed" if mock_runner else "unknown")
        ):
            issues.append("task_dispatch_billing_binding_mismatch")
    if (
        task_binding.schema_version
        in _SELECTED_TASK_BINDING_SCHEMA_VERSIONS
    ):
        parameters["execution_selection_digest"] = binding[
            "execution_selection_digest"
        ]
    if resource.get("content_digest") != expected_content_digest:
        issues.append("task_boundary_request_binding_mismatch")

    expected_parameters_digest = canonical_digest(
        {
            "action_scope": action_scope,
            "intent_digest": payload.get("intent_digest"),
            "intent_source": payload.get("intent_source"),
            "legacy_permission_class": expected_permission_class,
            "output_schema_digest": binding["output_schema_digest"],
            "parameters": parameters,
            "profile_ref": binding["profile_ref"],
            "runner_id": binding["runner_id"],
            "task_definition_digest": binding[
                "task_definition_digest"
            ],
            "task_id": expected_task_id,
            "task_version": expected_task_version,
        }
    )
    if action.get("parameters_digest") != expected_parameters_digest:
        issues.append("task_boundary_request_binding_mismatch")
    return tuple(issues)


def _inspect_task_publication_shadow_binding(
    payload: Mapping[str, Any],
    *,
    request: Any,
    action_scope: str | None,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    task_binding: _TaskAttemptBindingFacts,
    task_accounting: _TaskAccountingFacts,
    task_artifact_receipts: _TaskArtifactReceiptFacts,
) -> tuple[str, ...]:
    """Bind a schema-v5 ordinary shadow to its task and receipt chain."""

    issues: list[str] = []
    if action_scope != PUBLICATION_SCOPE:
        issues.append("task_shadow_schema_invalid")
    if (
        task_binding.binding is None
        or task_binding.issues
        or payload.get("task_attempt_binding_digest")
        != task_binding.binding_digest
    ):
        issues.append("task_shadow_binding_digest_mismatch")
    if payload.get("requested_permission_class") != expected_permission_class:
        issues.append("task_publication_requested_class_invalid")
    if payload.get("failure_stage") in {
        "request_construction",
        "evaluation",
    }:
        return tuple(issues)

    accounting_payload = task_accounting.payload
    accounting_digest = task_accounting.billing_disposition_digest
    if not isinstance(accounting_payload, Mapping) or not _is_digest(
        accounting_digest
    ):
        issues.append("task_publication_billing_disposition_mismatch")

    pre_effect = task_artifact_receipts.pre_effect
    if not isinstance(pre_effect, Mapping):
        return tuple(issues)
    if pre_effect.get("billing_disposition_digest") != accounting_digest:
        issues.append("task_publication_billing_disposition_mismatch")
    if pre_effect.get("publication_shadow_persisted") is not True:
        issues.append("task_publication_shadow_receipt_mismatch")
    shadow_request_key = (
        "publication_shadow_request_digest"
        if task_binding.schema_version
        in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
        else "publication_request_digest"
    )
    shadow_decision_key = (
        "publication_shadow_decision_digest"
        if task_binding.schema_version
        in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
        else "publication_decision_digest"
    )
    if (
        pre_effect.get(shadow_request_key)
        != payload.get("request_digest")
        or pre_effect.get(shadow_decision_key)
        != payload.get("decision_digest")
    ):
        issues.append("task_publication_shadow_receipt_mismatch")

    binding = task_binding.binding
    if not isinstance(binding, Mapping) or not isinstance(request, Mapping):
        return tuple(issues)
    subject = request.get("subject")
    resource = request.get("resource")
    action = request.get("action")
    environment = request.get("environment")
    if (
        not isinstance(subject, Mapping)
        or subject.get("profile_id") != binding["profile_ref"]
        or subject.get("runner_id") != binding["runner_id"]
        or not isinstance(resource, Mapping)
        or resource.get("repository_id") != binding["repository_ref"]
        or resource.get("version") != pre_effect.get("artifact_digest")
        or resource.get("content_digest")
        != pre_effect.get("artifact_digest")
        or not isinstance(action, Mapping)
        or not isinstance(environment, Mapping)
        or environment.get("isolation_state") != "verified"
        or environment.get("network_state") != "disabled"
        or environment.get("billing_route") != BillingRoute.LOCAL_NON_AI.value
        or environment.get("capacity_state")
        != CapacityState.NOT_APPLICABLE.value
        or environment.get("paid_continuation_protection")
        != PaidContinuationProtection.NOT_APPLICABLE.value
        or environment.get("circuit_state") != "closed"
    ):
        issues.append("task_publication_request_binding_mismatch")
        return tuple(issues)

    expected_action_digest = canonical_digest(
        {
            "action": action,
            "resource": resource,
        }
    )
    if (
        task_binding.schema_version
        not in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
        and pre_effect.get("action_digest") != expected_action_digest
    ):
        issues.append("task_publication_action_digest_mismatch")

    if isinstance(accounting_payload, Mapping):
        billing_disposition = {
            "identity_matches": accounting_payload.get("identity_matches"),
            "billing_matches": accounting_payload.get("billing_matches"),
            "capacity_state": accounting_payload.get("capacity_state"),
            "paid_capacity_consumed": accounting_payload.get(
                "paid_capacity_consumed"
            ),
            "incremental_ai_charge": accounting_payload.get(
                "incremental_ai_charge"
            ),
            "quarantine_required": accounting_payload.get(
                "billing_quarantine_required"
            ),
            "circuit_breaker_required": accounting_payload.get(
                "billing_circuit_breaker_required"
            ),
            "reason_codes": accounting_payload.get(
                "billing_disposition_reason_codes"
            ),
            "billing_disposition_digest": accounting_digest,
        }
        parameters = {
            "artifact_digest": pre_effect.get("artifact_digest"),
            "artifact_kind": pre_effect.get("artifact_kind"),
            "artifact_size_bytes": pre_effect.get("artifact_size_bytes"),
            "billing_disposition": billing_disposition,
            "credential_scan_passed": pre_effect.get(
                "credential_scan_passed"
            ),
            "destination_digest": pre_effect.get("destination_digest"),
            "evaluation_accepted": pre_effect.get("evaluation_accepted"),
            "task_attempt_binding_digest": task_binding.binding_digest,
        }
        expected_parameters_digest = canonical_digest(
            {
                "action_scope": PUBLICATION_SCOPE,
                "intent_digest": payload.get("intent_digest"),
                "intent_source": "controller_boundary_projection",
                "legacy_permission_class": expected_permission_class,
                "output_schema_digest": binding["output_schema_digest"],
                "parameters": parameters,
                "profile_ref": binding["profile_ref"],
                "runner_id": binding["runner_id"],
                "task_definition_digest": binding[
                    "task_definition_digest"
                ],
                "task_id": expected_task_id,
                "task_version": expected_task_version,
            }
        )
        if action.get("parameters_digest") != expected_parameters_digest:
            issues.append("task_publication_request_binding_mismatch")

    action_receipt = task_artifact_receipts.action
    decision = payload.get("decision")
    if (
        task_binding.schema_version
        not in _PUBLICATION_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS
        and isinstance(action_receipt, Mapping)
        and isinstance(decision, Mapping)
    ):
        issues.extend(
            _inspect_task_receipt_obligation_linkage(
                decision,
                action_receipt=action_receipt,
            )
        )
    return tuple(issues)


def _inspect_task_receipt_obligation_linkage(
    decision: Mapping[str, Any],
    *,
    action_receipt: Mapping[str, Any],
) -> tuple[str, ...]:
    obligations = decision.get("obligations")
    results = action_receipt.get("obligation_results")
    if not isinstance(obligations, list) or not isinstance(results, list):
        return ("task_publication_obligation_linkage_mismatch",)
    if any(
        not isinstance(item, Mapping)
        or set(item) != {"kind", "value"}
        or not isinstance(item.get("kind"), str)
        or not isinstance(item.get("value"), str)
        for item in obligations
    ) or any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("kind"), str)
        or not _is_digest(item.get("value_digest"))
        for item in results
    ):
        return ("task_publication_obligation_linkage_mismatch",)
    expected = sorted(
        (
            item.get("kind"),
            canonical_digest({"value": item.get("value")}),
        )
        for item in obligations
    )
    observed = sorted(
        (item.get("kind"), item.get("value_digest"))
        for item in results
    )
    if expected != observed:
        return ("task_publication_obligation_linkage_mismatch",)
    return ()


def _inspect_comparison_receipt_obligation_linkage(
    decision: Mapping[str, Any],
    *,
    action_receipt: Mapping[str, Any],
) -> tuple[str, ...]:
    obligations = decision.get("obligations")
    results = action_receipt.get("obligation_results")
    if not isinstance(obligations, list) or not isinstance(results, list):
        return ("comparison_publication_obligation_linkage_mismatch",)
    if any(
        not isinstance(item, Mapping)
        or set(item) != {"kind", "value"}
        or not isinstance(item.get("kind"), str)
        or not isinstance(item.get("value"), str)
        for item in obligations
    ) or any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("kind"), str)
        or not _is_digest(item.get("value_digest"))
        for item in results
    ):
        return ("comparison_publication_obligation_linkage_mismatch",)
    expected = sorted(
        (
            item.get("kind"),
            canonical_digest({"value": item.get("value")}),
        )
        for item in obligations
    )
    observed = sorted(
        (item.get("kind"), item.get("value_digest"))
        for item in results
    )
    if expected != observed:
        return ("comparison_publication_obligation_linkage_mismatch",)
    return ()


def _inspect_comparison_request_environment(
    request: Mapping[str, Any],
    *,
    comparison_billing: _ComparisonBillingFacts,
) -> tuple[str, ...]:
    """Compare v3 environment attributes with bound billing evidence."""

    payload = comparison_billing.payload
    if not isinstance(payload, Mapping):
        return ()
    environment = request.get("environment")
    if not isinstance(environment, Mapping):
        return ("comparison_billing_environment_mismatch",)
    issues: list[str] = []
    expected_route = payload["route"]
    expected_capacity_state = payload["capacity_state"]
    expected_paid_continuation = payload["paid_continuation_protection"]
    if payload["runner_id"] == "mock":
        expected_route = BillingRoute.MOCK.value
        expected_capacity_state = CapacityState.NOT_APPLICABLE.value
        expected_paid_continuation = (
            PaidContinuationProtection.NOT_APPLICABLE.value
        )
    if (
        environment.get("billing_route") != expected_route
        or environment.get("capacity_state") != expected_capacity_state
        or environment.get("paid_continuation_protection")
        != expected_paid_continuation
    ):
        issues.append("comparison_billing_environment_mismatch")

    evaluated_at = _optional_timestamp(environment.get("evaluated_at"))
    expected_window = comparison_billing.evidence_window
    if payload["runner_id"] == "mock" and evaluated_at is not None:
        expected_window = (
            evaluated_at,
            evaluated_at + _SHADOW_EVIDENCE_LIFETIME_SECONDS,
        )
    evidence = request.get("evidence")
    environment_evidence = (
        [
            item
            for item in evidence
            if isinstance(item, Mapping)
            and item.get("attribute") == "environment"
        ]
        if isinstance(evidence, list)
        else []
    )
    if expected_window is None:
        if environment_evidence:
            issues.append("comparison_billing_evidence_window_mismatch")
    elif (
        len(environment_evidence) != 1
        or _optional_timestamp(environment_evidence[0].get("observed_at"))
        != expected_window[0]
        or _optional_timestamp(environment_evidence[0].get("expires_at"))
        != expected_window[1]
    ):
        issues.append("comparison_billing_evidence_window_mismatch")
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


def _is_comparison_binding_shape(value: Any) -> bool:
    """Accept only the fixed, digest-only comparison binding schema."""

    if not isinstance(value, Mapping) or set(value) != {
        "attempt",
        "billing_assessment_digest",
        "comparison_ref",
        "context_digest",
        "controls_digest",
        "kind",
        "order_index",
        "output_schema_digest",
        "permission_class",
        "plan_digest",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "prompt_digest",
        "repetition",
        "repository_ref",
        "runner_id",
        "runner_overrides_digest",
        "snapshot_digest",
        "task_definition_digest",
        "timeout_seconds",
        "trial_ref",
    }:
        return False
    digest_fields = {
        "billing_assessment_digest",
        "comparison_ref",
        "context_digest",
        "controls_digest",
        "output_schema_digest",
        "plan_digest",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "prompt_digest",
        "repository_ref",
        "runner_overrides_digest",
        "snapshot_digest",
        "task_definition_digest",
        "trial_ref",
    }
    if any(not _is_digest(value.get(field)) for field in digest_fields):
        return False
    repetition = value.get("repetition")
    order_index = value.get("order_index")
    timeout_seconds = value.get("timeout_seconds")
    attempt = value.get("attempt")
    permission_class = value.get("permission_class")
    return (
        value.get("kind") == COMPARISON_RUN_KIND
        and _bounded_authorization_identifier(value.get("runner_id"))
        and isinstance(permission_class, int)
        and not isinstance(permission_class, bool)
        and permission_class == int(PermissionClass.READ_ONLY)
        and isinstance(repetition, int)
        and not isinstance(repetition, bool)
        and repetition > 0
        and isinstance(order_index, int)
        and not isinstance(order_index, bool)
        and order_index >= 0
        and isinstance(timeout_seconds, int)
        and not isinstance(timeout_seconds, bool)
        and timeout_seconds > 0
        and isinstance(attempt, int)
        and not isinstance(attempt, bool)
        and attempt > 0
    )


def _is_task_attempt_binding_shape(
    value: Any,
    *,
    schema_version: int,
) -> bool:
    """Accept only the fixed digest-only ordinary task binding schema."""

    expected_keys = {
        "attempt",
        "authorization_intent_digest",
        "context_digest",
        "kind",
        "output_schema_digest",
        "permission_class",
        "profile_ref",
        "prompt_digest",
        "repository_ref",
        "run_ref",
        "runner_id",
        "runner_overrides_digest",
        "task_definition_digest",
        "task_id",
        "task_version",
        "timeout_seconds",
    }
    digest_fields = {
        "authorization_intent_digest",
        "context_digest",
        "output_schema_digest",
        "profile_ref",
        "prompt_digest",
        "repository_ref",
        "run_ref",
        "runner_overrides_digest",
        "task_definition_digest",
    }
    if schema_version in _SELECTED_TASK_BINDING_SCHEMA_VERSIONS:
        expected_keys.update(
            {
                "execution_selection_digest",
                "profile_configuration_digest",
                "profile_version_ref",
            }
        )
        digest_fields.update(
            {
                "execution_selection_digest",
                "profile_configuration_digest",
                "profile_version_ref",
            }
        )
        if schema_version in _DISPATCH_ENFORCING_TASK_BINDING_SCHEMA_VERSIONS:
            expected_keys.update(
                {
                    "pre_run_approval_requirements_digest",
                    "workspace_ref",
                }
            )
            digest_fields.update(
                {
                    "pre_run_approval_requirements_digest",
                    "workspace_ref",
                }
            )
    elif schema_version != 1:
        return False
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        return False
    if any(not _is_digest(value.get(field)) for field in digest_fields):
        return False
    timeout_seconds = value.get("timeout_seconds")
    attempt = value.get("attempt")
    permission_class = _permission_class(value.get("permission_class"))
    return (
        value.get("kind") == TASK_ATTEMPT_RUN_KIND
        and _is_safe_identifier(value.get("task_id"))
        and _is_safe_identifier(value.get("task_version"))
        and _is_safe_identifier(value.get("runner_id"))
        and permission_class
        in {
            int(PermissionClass.READ_ONLY),
            int(PermissionClass.LOCAL_DRAFT),
        }
        and isinstance(timeout_seconds, int)
        and not isinstance(timeout_seconds, bool)
        and timeout_seconds > 0
        and isinstance(attempt, int)
        and not isinstance(attempt, bool)
        and attempt > 0
    )


def _is_task_billing_shape(value: Any) -> bool:
    """Accept only the digest-bearing ordinary billing projection."""

    if not isinstance(value, Mapping) or set(value) != {
        "account_identity_verified",
        "assessment_digest",
        "attestation_present",
        "capacity_state",
        "confidence",
        "paid_continuation_protection",
        "paid_credit_balance",
        "route",
        "runner_id",
        "schema_version",
        "subscription_name",
    }:
        return False
    subscription_name = value.get("subscription_name")
    return (
        isinstance(value.get("schema_version"), int)
        and not isinstance(value.get("schema_version"), bool)
        and value.get("schema_version") == 1
        and _is_digest(value.get("assessment_digest"))
        and _bounded_authorization_identifier(value.get("runner_id"))
        and value.get("route") in {item.value for item in BillingRoute}
        and value.get("confidence")
        in {item.value for item in AssessmentConfidence}
        and value.get("capacity_state")
        in {item.value for item in CapacityState}
        and value.get("paid_continuation_protection")
        in {item.value for item in PaidContinuationProtection}
        and value.get("paid_credit_balance")
        in {item.value for item in PaidCreditBalance}
        and (
            subscription_name is None
            or _is_bounded_private_text(subscription_name)
        )
        and isinstance(value.get("account_identity_verified"), bool)
        and isinstance(value.get("attestation_present"), bool)
    )


def _is_comparison_billing_shape(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "account_identity_ref",
        "assessment_digest",
        "attestation",
        "capacity_expires_at",
        "capacity_observed_at",
        "capacity_state",
        "confidence",
        "paid_continuation_protection",
        "paid_credit_balance",
        "route",
        "runner_id",
        "schema_version",
        "subscription_ref",
    }:
        return False
    if (
        value.get("schema_version") != 1
        or not _is_digest(value.get("assessment_digest"))
        or not _bounded_authorization_identifier(value.get("runner_id"))
        or value.get("route") not in {item.value for item in BillingRoute}
        or value.get("confidence")
        not in {item.value for item in AssessmentConfidence}
        or value.get("capacity_state")
        not in {item.value for item in CapacityState}
        or value.get("paid_continuation_protection")
        not in {item.value for item in PaidContinuationProtection}
        or value.get("paid_credit_balance")
        not in {item.value for item in PaidCreditBalance}
        or not _is_optional_digest(value.get("subscription_ref"))
        or not _is_optional_digest(value.get("account_identity_ref"))
        or not _is_optional_timestamp_value(value.get("capacity_observed_at"))
        or not _is_optional_timestamp_value(value.get("capacity_expires_at"))
    ):
        return False
    capacity_observed_at = value.get("capacity_observed_at")
    capacity_expires_at = value.get("capacity_expires_at")
    if (
        capacity_observed_at is not None
        and capacity_expires_at is not None
        and float(capacity_expires_at) <= float(capacity_observed_at)
    ):
        return False

    attestation = value.get("attestation")
    if attestation is None:
        return True
    if not isinstance(attestation, Mapping) or set(attestation) != {
        "account_identity_ref",
        "billing_route",
        "capacity_state",
        "confidence",
        "expires_at",
        "observed_at",
        "paid_continuation_protection",
        "runner_id",
    }:
        return False
    observed_at = attestation.get("observed_at")
    expires_at = attestation.get("expires_at")
    return (
        attestation.get("runner_id") == value.get("runner_id")
        and attestation.get("billing_route") == value.get("route")
        and attestation.get("capacity_state") == value.get("capacity_state")
        and attestation.get("paid_continuation_protection")
        == value.get("paid_continuation_protection")
        and attestation.get("account_identity_ref")
        == value.get("account_identity_ref")
        and attestation.get("confidence")
        in {item.value for item in AssessmentConfidence}
        and _is_required_timestamp_value(observed_at)
        and _is_required_timestamp_value(expires_at)
        and float(expires_at) > float(observed_at)
    )


def _comparison_billing_evidence_window(
    payload: Mapping[str, Any],
) -> tuple[float, float] | None:
    observations: list[float] = []
    expiries: list[float] = []
    capacity_observed_at = payload["capacity_observed_at"]
    capacity_expires_at = payload["capacity_expires_at"]
    if capacity_observed_at is not None:
        observations.append(float(capacity_observed_at))
    if capacity_expires_at is not None:
        expiries.append(float(capacity_expires_at))
    attestation = payload["attestation"]
    if isinstance(attestation, Mapping):
        observations.append(float(attestation["observed_at"]))
        expiries.append(float(attestation["expires_at"]))
    if not observations or not expiries:
        return None
    return min(observations), min(expiries)


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


def _event_identifier_matches(
    row: sqlite3.Row,
    *,
    event_type: str,
    payload: Mapping[str, Any],
    run_id: str,
) -> bool:
    """Verify the controller-derived identifier for a durable run event."""

    event_id = row["event_id"]
    if not _is_digest(event_id):
        return False
    try:
        return event_id == canonical_digest(
            {
                "event_type": event_type,
                "payload": payload,
                "run_id": run_id,
            }
        )
    except (TypeError, ValueError, RecursionError):
        return False


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _is_optional_digest(value: Any) -> bool:
    return value is None or _is_digest(value)


def _is_required_timestamp_value(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _is_optional_timestamp_value(value: Any) -> bool:
    return value is None or _is_required_timestamp_value(value)


def _normalize_sha256_digest(value: Any) -> str | None:
    if _is_digest(value):
        assert isinstance(value, str)
        return value
    if isinstance(value, str) and _BARE_SHA256_PATTERN.fullmatch(value) is not None:
        return f"sha256:{value}"
    return None


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


def _is_safe_identifier(value: Any) -> bool:
    return isinstance(value, str) and _safe_run_identifier(value) == value


def _is_safe_optional_text(value: Any) -> bool:
    if value is None:
        return True
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        return False
    folded = value.casefold()
    return not (
        any(marker in folded for marker in _SENSITIVE_IDENTIFIER_MARKERS)
        or folded.startswith(_SENSITIVE_IDENTIFIER_PREFIXES)
    )


def _is_bounded_private_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 4096
        and "\x00" not in value
    )


def _permission_class(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return int(PermissionClass(value))
    except ValueError:
        return None


def _is_positive_integer(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    )


def _is_optional_non_negative_integer(value: Any) -> bool:
    return value is None or (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


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
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        return None
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
    "COMPARISON_ACTION_RECEIPT_COVERAGE",
    "COMPARISON_FULL_SHADOW_COVERAGE",
    "COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE",
    "COMPARISON_RUN_KIND",
    "COMPARISON_SHADOW_COVERAGE",
    "DISPATCH_SCOPE",
    "EvidenceFreshnessInspection",
    "KNOWN_ACTION_SCOPES",
    "LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE",
    "LocalCandidatePublicationEnforcementInspection",
    "MockDispatchEnforcementInspection",
    "PUBLICATION_SCOPE",
    "RunAuthorizationInspection",
    "ShadowDecisionInspection",
    "SUPPORTED_SHADOW_SCHEMA_VERSIONS",
    "TASK_ATTEMPT_RUN_KIND",
    "TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE",
    "TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE",
    "TASK_ATTEMPT_BINDING_EVENT_TYPE",
    "TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE",
    "TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE",
    "TASK_ATTEMPT_SHADOW_COVERAGE",
    "TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE",
    "TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE",
    "TaskAdmissionEnforcementInspection",
    "inspect_authorization_shadows",
]
