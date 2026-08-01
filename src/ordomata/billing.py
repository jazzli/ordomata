"""Fail-closed enforcement for subscription-only model execution.

Billing decisions are deliberately independent from runner prompts and model
output.  A live coding harness may run only after its adapter has positively
identified a first-party subscription route and the operator has enabled the
per-process live-run gate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Protocol

from .errors import BillingRouteBlocked, LiveRunDisabled
from .models import (
    AgentEvent,
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PaidContinuationProtection,
    PaidCreditBalance,
)


LIVE_RUN_ENVIRONMENT_NAME = "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS"
LEGACY_LIVE_RUN_ENVIRONMENT_NAME = "AGENTOPS_ALLOW_SUBSCRIPTION_RUNS"
MAX_BILLING_ATTESTATION_LIFETIME_SECONDS = 24 * 60 * 60
LIVE_RUN_EVIDENCE_MARGIN_SECONDS = 10.0
BILLING_DISPATCH_COMPLETION_MARGIN_SECONDS = 60.0
_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
_EVIDENCE_CODE_PATTERN = re.compile(r"[a-z0-9_]{1,80}")
_ATTESTATION_FILE_MAX_BYTES = 64 * 1024
_ATTESTATION_EVIDENCE_RULES = {
    "codex": (
        frozenset({"provider_ui_auto_top_up_disabled"}),
        frozenset({"provider_ui_auto_top_up_disabled"}),
    ),
    "claude": (
        frozenset(
            {
                "provider_ui_extra_usage_disabled",
                "provider_ui_included_capacity_available",
            }
        ),
        frozenset(
            {
                "provider_ui_extra_usage_disabled",
                "provider_ui_included_capacity_available",
            }
        ),
    ),
}


class BillingAttestationLoader(Protocol):
    """Read a current local attestation for one already-fingerprinted account."""

    def load(
        self,
        runner_id: str,
        account_identity_fingerprint: str | None,
    ) -> BillingSafetyAttestation | None: ...


class BillingCircuitGuard(Protocol):
    """Atomically reserve and finalize one live subscription dispatch.

    A plain breaker read is not sufficient: two workers could both observe a
    closed breaker and launch before either records its post-run billing
    disposition.  Implementations therefore reserve the relevant durable
    capacity scope in the same transaction that checks the breaker.
    """

    def assert_closed(self, assessment: BillingRouteAssessment) -> None: ...

    def reserve_dispatch(
        self,
        assessment: BillingRouteAssessment,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> BillingDispatchReservation | None: ...

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
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class BillingDispatchReservation:
    """Opaque-enough durable lease receipt returned to a live harness.

    Account identities remain represented only by their provider-scoped
    fingerprint.  Callers must return the complete receipt to the same guard;
    they must not construct or mutate one themselves.
    """

    reservation_id: str
    runner_id: str
    account_identity_fingerprint: str
    profile_id: str | None
    owner_id: str
    lease_keys: tuple[str, ...]
    acquired_at: float
    expires_at: float


class FileBillingAttestationLoader:
    """Strict read-only loader for a local, ignored, owner-private JSON file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(
        self,
        runner_id: str,
        account_identity_fingerprint: str | None,
    ) -> BillingSafetyAttestation | None:
        if not _valid_fingerprint(account_identity_fingerprint):
            return None
        descriptor: int | None = None
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                return None
            if metadata.st_size > _ATTESTATION_FILE_MAX_BYTES:
                return None
            if metadata.st_mode & 0o077:
                return None
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                return None
            raw = _read_bounded_descriptor(
                descriptor, maximum_bytes=_ATTESTATION_FILE_MAX_BYTES
            )
            if len(raw) > _ATTESTATION_FILE_MAX_BYTES:
                return None
            document = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not isinstance(document, Mapping) or document.get("schema_version") != 1:
            return None
        raw_attestations = document.get("attestations")
        if not isinstance(raw_attestations, list):
            return None
        matches: list[BillingSafetyAttestation] = []
        for raw in raw_attestations:
            parsed = _parse_file_attestation(raw)
            if (
                parsed is not None
                and parsed.runner_id == runner_id
                and hmac.compare_digest(
                    parsed.account_identity_fingerprint,
                    account_identity_fingerprint or "",
                )
            ):
                matches.append(parsed)
        return matches[0] if len(matches) == 1 else None


def _read_bounded_descriptor(descriptor: int, *, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    observed = 0
    while True:
        chunk = os.read(descriptor, min(8_192, maximum_bytes + 1 - observed))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        observed += len(chunk)
        if observed > maximum_bytes:
            return b"".join(chunks)


@dataclass(frozen=True, slots=True)
class BillingPostRunDisposition:
    """Sanitized deterministic response to post-run billing evidence."""

    capacity_state: CapacityState
    paid_capacity_consumed: PaidCapacityConsumed
    incremental_ai_charge: IncrementalAICharge
    quarantine_required: bool
    circuit_breaker_required: bool
    reasons: tuple[str, ...] = ()


def fingerprint_account_identity(provider: str, identity: str) -> str:
    """Return a provider-scoped digest without retaining the raw identity."""

    if (
        not isinstance(provider, str)
        or not provider.strip()
        or not isinstance(identity, str)
        or not identity.strip()
        or len(provider) > 100
        or len(identity) > 1_024
    ):
        raise ValueError("provider and account identity must be bounded non-empty text")
    # This v1 domain separator is persisted indirectly through account-bound
    # attestations and billing-circuit evidence.  Its pre-rename spelling is
    # an immutable protocol identifier, not current product branding.
    material = (
        "agentops-account-fingerprint-v1\0"
        + provider.strip().casefold()
        + "\0"
        + identity.strip().casefold()
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _parse_file_attestation(value: Any) -> BillingSafetyAttestation | None:
    if not isinstance(value, Mapping):
        return None
    allowed_keys = {
        "runner_id",
        "account_identity_fingerprint",
        "billing_route",
        "capacity_state",
        "paid_continuation_protection",
        "observed_at",
        "expires_at",
        "confidence",
        "evidence_codes",
    }
    if set(value) != allowed_keys:
        return None
    runner_id = value.get("runner_id")
    fingerprint = value.get("account_identity_fingerprint")
    evidence_codes = value.get("evidence_codes")
    if (
        not isinstance(runner_id, str)
        or runner_id not in {"codex", "claude"}
        or not _valid_fingerprint(fingerprint)
        or not isinstance(evidence_codes, list)
        or not evidence_codes
        or any(
            not isinstance(code, str)
            or _EVIDENCE_CODE_PATTERN.fullmatch(code) is None
            for code in evidence_codes
        )
        or len(set(evidence_codes)) != len(evidence_codes)
    ):
        return None
    try:
        route = BillingRoute(value["billing_route"])
        capacity = CapacityState(value["capacity_state"])
        protection = PaidContinuationProtection(
            value["paid_continuation_protection"]
        )
        confidence = AssessmentConfidence(value["confidence"])
    except (KeyError, TypeError, ValueError):
        return None
    allowed_codes, required_codes = _ATTESTATION_EVIDENCE_RULES[runner_id]
    selected_codes = frozenset(evidence_codes)
    if not selected_codes.issubset(allowed_codes) or not required_codes.issubset(
        selected_codes
    ):
        return None
    if (
        route is not BillingRoute.SUBSCRIPTION_INCLUDED
        or capacity is not CapacityState.AVAILABLE
        or confidence is not AssessmentConfidence.HIGH
    ):
        return None
    if runner_id == "codex" and protection is not (
        PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
    ):
        return None
    if runner_id == "claude" and protection is not (
        PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED
    ):
        return None
    observed_at = value.get("observed_at")
    expires_at = value.get("expires_at")
    if not _valid_timestamp(observed_at) or not _valid_timestamp(expires_at):
        return None
    return BillingSafetyAttestation(
        runner_id=runner_id,
        account_identity_fingerprint=fingerprint,
        billing_route=route,
        capacity_state=capacity,
        paid_continuation_protection=protection,
        observed_at=float(observed_at),
        expires_at=float(expires_at),
        confidence=confidence,
        evidence=tuple(f"operator_attestation:{code}" for code in evidence_codes),
    )


class BillingPolicy:
    """Central, non-configurable allowlist for execution billing routes.

    There is intentionally no ``allow_api`` escape hatch.  Constructing a
    policy cannot widen the set of accepted routes.
    """

    _AUTOMATIC_ROUTES = frozenset(
        {
            BillingRoute.SUBSCRIPTION_INCLUDED,
            BillingRoute.LOCAL_NON_AI,
            BillingRoute.MOCK,
        }
    )
    _BLOCKED_ROUTES = frozenset(
        {
            BillingRoute.PURCHASED_PRODUCT_CREDIT,
            BillingRoute.SUBSCRIPTION_OVERAGE,
            BillingRoute.SEPARATELY_BILLED_API,
            BillingRoute.CLOUD_PROVIDER_BILLING,
            BillingRoute.UNKNOWN,
        }
    )

    @classmethod
    def route_is_allowed(
        cls,
        assessment: BillingRouteAssessment,
        *,
        now: float | None = None,
        required_valid_until: float | None = None,
    ) -> bool:
        """Return whether all route, capacity, and spillover gates are safe."""

        if assessment.confidence is not AssessmentConfidence.HIGH:
            return False
        if assessment.route in {BillingRoute.LOCAL_NON_AI, BillingRoute.MOCK}:
            return True
        if assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
            return False
        return not cls.subscription_blockers(
            assessment,
            now=now,
            required_valid_until=required_valid_until,
        )

    @classmethod
    def subscription_blockers(
        cls,
        assessment: BillingRouteAssessment,
        *,
        now: float | None = None,
        required_valid_until: float | None = None,
    ) -> tuple[str, ...]:
        """Return fixed reason codes; never include account or balance values."""

        blockers: list[str] = []
        checked_at = time.time() if now is None else now
        if not _valid_timestamp(checked_at):
            return ("invalid_policy_clock",)
        valid_until = (
            checked_at if required_valid_until is None else required_valid_until
        )
        if not _valid_timestamp(valid_until) or valid_until < checked_at:
            return ("invalid_required_valid_until",)
        if assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
            blockers.append("route_not_subscription_included")
        if assessment.confidence is not AssessmentConfidence.HIGH:
            blockers.append("route_confidence_not_high")
        if assessment.capacity_state is not CapacityState.AVAILABLE:
            blockers.append("included_capacity_not_available")
        if not _current_window(
            assessment.capacity_observed_at,
            assessment.capacity_expires_at,
            checked_at,
            required_valid_until=valid_until,
        ):
            blockers.append("capacity_evidence_not_current")
        if not _valid_fingerprint(assessment.account_identity_fingerprint):
            blockers.append("account_identity_unverified")

        attestation = assessment.attestation
        if attestation is None:
            blockers.append("paid_continuation_attestation_missing")
            return tuple(blockers)
        if attestation.runner_id != assessment.runner_id:
            blockers.append("attestation_runner_mismatch")
        if attestation.billing_route is not BillingRoute.SUBSCRIPTION_INCLUDED:
            blockers.append("attestation_route_mismatch")
        if attestation.confidence is not AssessmentConfidence.HIGH:
            blockers.append("attestation_confidence_not_high")
        if attestation.capacity_state is not assessment.capacity_state:
            blockers.append("attestation_capacity_mismatch")
        if (
            attestation.paid_continuation_protection
            is not assessment.paid_continuation_protection
        ):
            blockers.append("attestation_protection_mismatch")
        if not attestation.evidence:
            blockers.append("attestation_evidence_missing")
        elif not _attestation_evidence_is_authorized(attestation):
            blockers.append("attestation_evidence_not_authorized")
        if not _current_window(
            attestation.observed_at,
            attestation.expires_at,
            checked_at,
            required_valid_until=valid_until,
        ):
            blockers.append("attestation_not_current")
        elif (
            attestation.expires_at - attestation.observed_at
            > MAX_BILLING_ATTESTATION_LIFETIME_SECONDS
        ):
            blockers.append("attestation_lifetime_too_long")
        if not _valid_fingerprint(attestation.account_identity_fingerprint):
            blockers.append("attested_account_identity_invalid")
        elif not _valid_fingerprint(
            assessment.account_identity_fingerprint
        ) or not hmac.compare_digest(
            attestation.account_identity_fingerprint,
            assessment.account_identity_fingerprint or "",
        ):
            blockers.append("attested_account_identity_mismatch")

        protection = assessment.paid_continuation_protection
        if assessment.runner_id == "codex":
            if protection is not (
                PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
            ):
                blockers.append("codex_paid_continuation_not_disabled")
            if assessment.paid_credit_balance is not PaidCreditBalance.ZERO:
                blockers.append("codex_paid_credit_balance_not_zero")
        elif assessment.runner_id == "claude":
            if protection is not PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED:
                blockers.append("claude_extra_usage_not_disabled")
        elif protection is not PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED:
            blockers.append("paid_continuation_not_provider_disabled")
        return tuple(blockers)

    @classmethod
    def assert_route_allowed(
        cls,
        assessment: BillingRouteAssessment,
        *,
        now: float | None = None,
        required_valid_until: float | None = None,
    ) -> None:
        """Reject prohibited, unknown, or weakly evidenced billing routes."""

        if assessment.route in cls._BLOCKED_ROUTES:
            raise BillingRouteBlocked(
                f"Runner {assessment.runner_id!r} is blocked: billing route "
                f"{assessment.route.value!r} is not subscription-safe."
            )
        if assessment.route not in cls._AUTOMATIC_ROUTES:
            raise BillingRouteBlocked(
                f"Runner {assessment.runner_id!r} is blocked: unsupported billing route."
            )
        if assessment.confidence is not AssessmentConfidence.HIGH:
            raise BillingRouteBlocked(
                f"Runner {assessment.runner_id!r} is blocked: billing route could "
                "not be verified with high confidence."
            )
        if assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
            blockers = cls.subscription_blockers(
                assessment,
                now=now,
                required_valid_until=required_valid_until,
            )
            if blockers:
                raise BillingRouteBlocked(
                    f"Runner {assessment.runner_id!r} is blocked: subscription "
                    "billing safety evidence failed closed ("
                    + ", ".join(blockers)
                    + ")."
                )

    @staticmethod
    def live_run_gate_state(
        environment: Mapping[str, str] | None = None,
    ) -> str:
        """Describe the canonical/legacy opt-in pair without exposing values."""

        source = os.environ if environment is None else environment
        canonical_present = LIVE_RUN_ENVIRONMENT_NAME in source
        legacy_present = LEGACY_LIVE_RUN_ENVIRONMENT_NAME in source
        if not canonical_present and not legacy_present:
            return "unset"
        if canonical_present and legacy_present:
            canonical_enabled = source.get(LIVE_RUN_ENVIRONMENT_NAME) == "1"
            legacy_enabled = source.get(LEGACY_LIVE_RUN_ENVIRONMENT_NAME) == "1"
            if canonical_enabled and legacy_enabled:
                return "enabled_both_exactly"
            if source.get(LIVE_RUN_ENVIRONMENT_NAME) != source.get(
                LEGACY_LIVE_RUN_ENVIRONMENT_NAME
            ):
                return "conflicting_values"
            return "both_set_but_not_exactly_enabled"
        if canonical_present:
            return (
                "enabled_exactly"
                if source.get(LIVE_RUN_ENVIRONMENT_NAME) == "1"
                else "set_but_not_exactly_enabled"
            )
        return (
            "enabled_via_legacy_alias"
            if source.get(LEGACY_LIVE_RUN_ENVIRONMENT_NAME) == "1"
            else "legacy_set_but_not_exactly_enabled"
        )

    @staticmethod
    def live_run_enabled(environment: Mapping[str, str] | None = None) -> bool:
        """Enable only an exact, non-conflicting canonical or legacy opt-in."""

        return BillingPolicy.live_run_gate_state(environment) in {
            "enabled_exactly",
            "enabled_via_legacy_alias",
            "enabled_both_exactly",
        }

    @classmethod
    def assert_live_run_allowed(
        cls,
        assessment: BillingRouteAssessment,
        environment: Mapping[str, str] | None = None,
        *,
        now: float | None = None,
        required_valid_until: float | None = None,
    ) -> None:
        """Enforce both billing safety and the explicit live-run opt-in.

        Route enforcement is performed first so setting the gate can never be
        construed as permission to use an API or cloud route.
        """

        cls.assert_route_allowed(
            assessment,
            now=now,
            required_valid_until=required_valid_until,
        )
        if assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
            if not cls.live_run_enabled(environment):
                raise LiveRunDisabled(
                    "Subscription harness execution is disabled. Set "
                    f"{LIVE_RUN_ENVIRONMENT_NAME}=1 for an explicitly verified "
                    "subscription-backed run."
                )

    # Concise aliases used by orchestration call sites.
    enforce = assert_route_allowed
    enforce_live = assert_live_run_allowed

    @classmethod
    def assess_post_run(
        cls,
        preflight: BillingRouteAssessment,
        postflight: BillingRouteAssessment | None,
        events: Sequence[AgentEvent],
        *,
        now: float | None = None,
    ) -> BillingPostRunDisposition:
        """Fail closed on paid, changed-account, or unknown postflight evidence."""

        signals = _billing_signals(events)
        if "paid_consumed" in signals:
            return BillingPostRunDisposition(
                capacity_state=CapacityState.UNKNOWN,
                paid_capacity_consumed=PaidCapacityConsumed.YES,
                incremental_ai_charge=IncrementalAICharge.CONFIRMED,
                quarantine_required=True,
                circuit_breaker_required=True,
                reasons=("post_run_paid_capacity_consumed",),
            )
        if (
            postflight is not None
            and postflight.route
            in {
                BillingRoute.PURCHASED_PRODUCT_CREDIT,
                BillingRoute.SUBSCRIPTION_OVERAGE,
            }
        ) or "paid_available" in signals:
            return BillingPostRunDisposition(
                capacity_state=(
                    CapacityState.UNKNOWN
                    if postflight is None
                    else postflight.capacity_state
                ),
                paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
                incremental_ai_charge=IncrementalAICharge.POSSIBLE,
                quarantine_required=True,
                circuit_breaker_required=True,
                reasons=("post_run_paid_route_possible",),
            )
        if "account_changed" in signals:
            return _unknown_post_run("post_run_account_changed")
        included_limit = "included_limit_reached" in signals or (
            postflight is not None
            and postflight.capacity_state
            in {CapacityState.LIMIT_REACHED, CapacityState.BLOCKED_UNTIL_RESET}
        )
        if included_limit and postflight is not None:
            normalized_postflight = replace(
                postflight,
                capacity_state=CapacityState.AVAILABLE,
            )
            if (
                cls.route_is_allowed(preflight, now=now)
                and cls.route_is_allowed(normalized_postflight, now=now)
                and _same_billing_identity(preflight, postflight)
            ):
                return BillingPostRunDisposition(
                    capacity_state=CapacityState.BLOCKED_UNTIL_RESET,
                    paid_capacity_consumed=PaidCapacityConsumed.NO,
                    incremental_ai_charge=IncrementalAICharge.NONE,
                    quarantine_required=True,
                    circuit_breaker_required=False,
                    reasons=("included_capacity_exhausted",),
                )
        if postflight is None or not cls.route_is_allowed(postflight, now=now):
            return _unknown_post_run("post_run_billing_evidence_unknown")
        if not _same_billing_identity(preflight, postflight):
            return _unknown_post_run("post_run_billing_identity_changed")
        return BillingPostRunDisposition(
            capacity_state=postflight.capacity_state,
            paid_capacity_consumed=PaidCapacityConsumed.NO,
            incremental_ai_charge=IncrementalAICharge.NONE,
            quarantine_required=False,
            circuit_breaker_required=False,
        )


def _valid_timestamp(value: float | None) -> bool:
    return (
        value is not None
        and not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _current_window(
    observed_at: float | None,
    expires_at: float | None,
    now: float,
    *,
    required_valid_until: float | None = None,
) -> bool:
    valid_until = now if required_valid_until is None else required_valid_until
    return (
        _valid_timestamp(observed_at)
        and _valid_timestamp(expires_at)
        and float(observed_at) <= now < float(expires_at)
        and valid_until < float(expires_at)
        and float(expires_at) > float(observed_at)
    )


def _valid_fingerprint(value: str | None) -> bool:
    return isinstance(value, str) and _FINGERPRINT_PATTERN.fullmatch(value) is not None


def _attestation_evidence_is_authorized(attestation: BillingSafetyAttestation) -> bool:
    selected = frozenset(attestation.evidence)
    if len(selected) != len(attestation.evidence):
        return False
    if attestation.runner_id == "codex":
        required = frozenset(
            {"operator_attestation:provider_ui_auto_top_up_disabled"}
        )
    elif attestation.runner_id == "claude":
        required = frozenset(
            {
                "operator_attestation:provider_ui_extra_usage_disabled",
                "operator_attestation:provider_ui_included_capacity_available",
            }
        )
    else:
        required = frozenset(
            {"operator_attestation:provider_enforced_paid_continuation_disabled"}
        )
    return selected == required


def _same_billing_identity(
    preflight: BillingRouteAssessment,
    postflight: BillingRouteAssessment,
) -> bool:
    if (
        preflight.runner_id != postflight.runner_id
        or preflight.route is not postflight.route
        or preflight.paid_continuation_protection
        is not postflight.paid_continuation_protection
        or not _valid_fingerprint(preflight.account_identity_fingerprint)
        or not _valid_fingerprint(postflight.account_identity_fingerprint)
    ):
        return False
    return hmac.compare_digest(
        preflight.account_identity_fingerprint or "",
        postflight.account_identity_fingerprint or "",
    )


def _unknown_post_run(reason: str) -> BillingPostRunDisposition:
    return BillingPostRunDisposition(
        capacity_state=CapacityState.UNKNOWN,
        paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
        incremental_ai_charge=IncrementalAICharge.UNKNOWN,
        quarantine_required=True,
        circuit_breaker_required=True,
        reasons=(reason,),
    )


def _billing_signals(events: Sequence[AgentEvent]) -> frozenset[str]:
    """Extract fixed signal classes without retaining raw diagnostic values."""

    signals: set[str] = set()
    for event in events:
        event_type = _normalize_signal_name(event.event_type)
        is_error_result = (
            event_type == "result" and event.payload.get("is_error") is True
        )
        # Provider billing metadata can accompany an otherwise successful
        # ordinary event. Inspect only bounded, billing-related payload keys,
        # but do so for every event rather than trusting its type as a gate.
        scalars: list[str] = [event_type]
        _collect_signal_scalars(event.payload, scalars, depth=0)
        if is_error_result and isinstance(event.payload.get("result"), str):
            scalars.append(str(event.payload["result"])[:200])
        joined = " ".join(scalars).casefold()
        normalized = _normalize_signal_name(joined)
        if any(
            marker in normalized
            for marker in (
                "paid_capacity_consumed_true",
                "purchased_credit_consumed_true",
                "overage_consumed_true",
                "extra_usage_consumed_true",
                "incremental_ai_charge_confirmed",
            )
        ):
            signals.add("paid_consumed")
        if any(
            marker in normalized
            for marker in (
                "billing_route_purchased_product_credit",
                "billing_route_subscription_overage",
                "has_credits_true",
                "unlimited_true",
                "extra_usage_enabled_true",
                "overage_enabled_true",
                "purchased_credit",
                "paid_usage",
                "workspace_owner_credits_depleted",
                "workspace_member_credits_depleted",
            )
        ):
            signals.add("paid_available")
        if any(
            marker in normalized
            for marker in (
                "rate_limit_reached",
                "usage_limit_reached",
                "quota_exhausted",
                "included_limit_reached",
                "capacity_state_limit_reached",
            )
        ):
            signals.add("included_limit_reached")
        if any(
            marker in normalized
            for marker in (
                "account_switched",
                "account_changed",
                "account_mismatch",
                "identity_mismatch",
            )
        ):
            signals.add("account_changed")
    return frozenset(signals)


def _normalize_signal_name(value: str) -> str:
    snake_case = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", snake_case.casefold()).strip("_")


def _collect_signal_scalars(value: Any, output: list[str], *, depth: int) -> None:
    if depth > 4 or len(output) >= 100:
        return
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                continue
            normalized_key = _normalize_signal_name(key)
            if not any(
                fragment in normalized_key
                for fragment in (
                    "billing",
                    "charge",
                    "credit",
                    "limit",
                    "quota",
                    "capacity",
                    "overage",
                    "usage",
                    "account",
                    "identity",
                    "error",
                    "code",
                    "message",
                    "route",
                    "unlimited",
                )
            ):
                continue
            if isinstance(nested, (str, bool, int, float)):
                output.append(f"{normalized_key} {str(nested)[:200]}")
            elif isinstance(nested, (Mapping, list, tuple)):
                output.append(normalized_key)
                _collect_signal_scalars(nested, output, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for nested in value[:20]:
            _collect_signal_scalars(nested, output, depth=depth + 1)


__all__ = [
    "BILLING_DISPATCH_COMPLETION_MARGIN_SECONDS",
    "BillingPolicy",
    "BillingPostRunDisposition",
    "BillingAttestationLoader",
    "BillingCircuitGuard",
    "BillingDispatchReservation",
    "FileBillingAttestationLoader",
    "LEGACY_LIVE_RUN_ENVIRONMENT_NAME",
    "LIVE_RUN_ENVIRONMENT_NAME",
    "LIVE_RUN_EVIDENCE_MARGIN_SECONDS",
    "MAX_BILLING_ATTESTATION_LIFETIME_SECONDS",
    "fingerprint_account_identity",
]
