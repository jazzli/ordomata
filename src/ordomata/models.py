"""Provider-neutral value objects shared by orchestration components."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any, Mapping


class BillingRoute(StrEnum):
    SUBSCRIPTION_INCLUDED = "subscription_included"
    PURCHASED_PRODUCT_CREDIT = "purchased_product_credit"
    SUBSCRIPTION_OVERAGE = "subscription_overage"
    SEPARATELY_BILLED_API = "separately_billed_api"
    CLOUD_PROVIDER_BILLING = "cloud_provider_billing"
    LOCAL_NON_AI = "local_non_ai"
    UNKNOWN = "unknown"
    MOCK = "mock"


class AssessmentConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CapacityState(StrEnum):
    """Availability of the included subscription capacity pool."""

    AVAILABLE = "available"
    LIMIT_REACHED = "limit_reached"
    BLOCKED_UNTIL_RESET = "blocked_until_reset"
    COOLDOWN = "cooldown"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class PaidContinuationProtection(StrEnum):
    """Whether an account is prevented from spilling into paid capacity."""

    PROVIDER_ENFORCED_DISABLED = "provider_enforced_disabled"
    VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED = (
        "verified_zero_balance_and_auto_top_up_disabled"
    )
    ENABLED = "enabled"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class PaidCreditBalance(StrEnum):
    """Sanitized observation of a paid product-credit pool.

    The numeric balance is deliberately never represented by the model.
    """

    ZERO = "zero"
    POSITIVE = "positive"
    UNLIMITED = "unlimited"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class PaidCapacityConsumed(StrEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class IncrementalAICharge(StrEnum):
    NONE = "none"
    POSSIBLE = "possible"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


class CircuitBreakerState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class PermissionClass(IntEnum):
    READ_ONLY = 0
    LOCAL_DRAFT = 1
    REVERSIBLE_INTERNAL_WRITE = 2
    EXTERNAL_CONSEQUENTIAL = 3


class RunStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    CANCELLED = "cancelled"


class UsageObservation(StrEnum):
    OBSERVED = "observed"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class RunnerCapabilities:
    runner_id: str
    installed: bool
    version: str | None = None
    non_interactive: bool = False
    structured_output_modes: tuple[str, ...] = ()
    session_resume: bool = False
    sandbox_modes: tuple[str, ...] = ()
    permission_modes: tuple[str, ...] = ()
    usage_telemetry: bool = False
    scheduler_support: bool = False
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BillingSafetyAttestation:
    """Short-lived, non-secret evidence binding an account to safe settings.

    ``account_identity_fingerprint`` is an Ordomata-generated digest, never an
    email address, account identifier, token, or provider credential.
    """

    runner_id: str
    account_identity_fingerprint: str = field(repr=False)
    billing_route: BillingRoute = BillingRoute.UNKNOWN
    capacity_state: CapacityState = CapacityState.UNKNOWN
    paid_continuation_protection: PaidContinuationProtection = (
        PaidContinuationProtection.UNKNOWN
    )
    observed_at: float = 0.0
    expires_at: float = 0.0
    confidence: AssessmentConfidence = AssessmentConfidence.LOW
    evidence: tuple[str, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class BillingRouteAssessment:
    runner_id: str
    route: BillingRoute
    confidence: AssessmentConfidence
    subscription_name: str | None = None
    evidence: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    risky_environment_names: tuple[str, ...] = ()
    capacity_state: CapacityState = CapacityState.UNKNOWN
    paid_continuation_protection: PaidContinuationProtection = (
        PaidContinuationProtection.UNKNOWN
    )
    paid_credit_balance: PaidCreditBalance = PaidCreditBalance.UNKNOWN
    account_identity_fingerprint: str | None = field(default=None, repr=False)
    capacity_observed_at: float | None = None
    capacity_expires_at: float | None = None
    attestation: BillingSafetyAttestation | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class EnvironmentValidation:
    valid: bool
    sanitized_environment: Mapping[str, str] = field(repr=False)
    retained_names: tuple[str, ...] = ()
    excluded_names: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AgentEvent:
    event_type: str
    payload: Mapping[str, Any]
    credential_material_detected: bool = False


@dataclass(frozen=True, slots=True)
class RunRequest:
    run_id: str
    task_id: str
    task_version: str
    prompt: str
    workspace: Path
    run_directory: Path
    output_schema: Mapping[str, Any]
    permission_class: PermissionClass
    timeout_seconds: int
    attempt: int = 1
    runner_overrides: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RunnerExecutionResult:
    runner_id: str
    run_id: str
    status: RunStatus
    billing_assessment: BillingRouteAssessment
    exit_code: int | None = None
    session_id: str | None = None
    output: Any = None
    usage: Mapping[str, Any] = field(default_factory=dict)
    usage_observation: UsageObservation = UsageObservation.UNAVAILABLE
    events: tuple[AgentEvent, ...] = ()
    errors: tuple[str, ...] = ()
    credential_material_detected: bool = False
    runner_version: str | None = None
    execution_mode: str | None = None
    harness_process_started: bool = False
    live_model_execution_occurred: bool | None = None
    subscription_capacity_consumed: bool | None = None
    paid_capacity_consumed: PaidCapacityConsumed = PaidCapacityConsumed.UNKNOWN
    incremental_ai_charge: IncrementalAICharge = IncrementalAICharge.UNKNOWN
    postflight_billing_assessment: BillingRouteAssessment | None = field(
        default=None, repr=False
    )
    billing_quarantine_required: bool = False
    billing_circuit_breaker_required: bool = False
    billing_disposition_reasons: tuple[str, ...] = ()
    wall_seconds: float | None = None
