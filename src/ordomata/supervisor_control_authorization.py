"""Authoritative ABAC gate for reversible local supervisor control changes.

This module deliberately authorizes only one controller bookkeeping effect:
an exact transition of the local, dispatch-disabled supervisor control state.
It cannot authorize a flow admission, cancellation, claim, worker dispatch,
repository mutation, network action, external effect, or Permission Class 2/3
work.  Sticky cancellation remains a separate fail-safe, shadow-only path.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
import re
from typing import Any, Mapping

from .authorization import (
    ActionAttributes,
    ActionReceipt,
    ActionVerb,
    AttributeEvidence,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationEvaluator,
    AuthorizationRequest,
    BlastRadius,
    CircuitState,
    ConsequenceVector,
    EnvironmentAttributes,
    EvidenceSource,
    ImpactLevel,
    IsolationState,
    NetworkState,
    ObligationKind,
    ObligationResult,
    PolicyBundle,
    Reach,
    ReceiptOutcome,
    ResourceAttributes,
    Role,
    SubjectAttributes,
    canonical_digest,
)
from .errors import AuthorizationBlocked, ValidationError
from .models import (
    BillingRoute,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
)


SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE = (
    "supervisor_control_transition_only"
)
SUPERVISOR_CONTROL_AUTHORIZATION_ENFORCEMENT_COVERAGE = (
    "authoritative_reversible_local_control_transition_only"
)
SUPERVISOR_CONTROL_AUTHORIZATION_OPERATION = "supervisor.control_transition"
SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE = "supervisor_control_state"
SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_ID = (
    "ordomata.phase-1c.supervisor-control-enforcement"
)
SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_VERSION = "1.0.0"
SUPERVISOR_CONTROL_AUTHORIZATION_EXECUTOR_ID = "ordomata:local-controller"
SUPERVISOR_CONTROL_AUTHORIZATION_EVENT_SCHEMA_VERSION = 1

_EVIDENCE_LIFETIME_SECONDS = 60.0
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REASON_PATTERN = re.compile(r"[a-z0-9_]{1,100}\Z")
_CONTROL_MODES = frozenset(
    {"stopped", "running", "paused", "draining", "stop_requested"}
)
_CONTROL_TRANSITIONS = {
    "stopped": frozenset({"running"}),
    "running": frozenset({"paused", "draining", "stop_requested"}),
    "paused": frozenset({"running", "draining", "stop_requested"}),
    "draining": frozenset({"stopped"}),
    "stop_requested": frozenset({"stopped"}),
}
_FIXED_PERMIT_OBLIGATIONS = frozenset(
    {
        (ObligationKind.AUDIT_RECEIPT, "append_after_action"),
        (ObligationKind.ISOLATED_LOCAL_ONLY, "required"),
    }
)

# The authoritative replay must not depend on a patched first-pass evaluator.
_BUILTIN_AUTHORIZATION_EVALUATOR = AuthorizationEvaluator
_BUILTIN_AUTHORIZATION_EVALUATE = AuthorizationEvaluator.evaluate


@dataclass(frozen=True, slots=True)
class SupervisorControlTransition:
    """One privacy-bounded, exact local supervisor control transition."""

    previous_control_event_id: str
    previous_revision: int
    previous_mode: str
    control_event_id: str
    target_revision: int
    target_mode: str
    actor_ref: str
    reason_code: str
    occurred_at: float

    def __post_init__(self) -> None:
        for name in ("previous_control_event_id", "control_event_id"):
            _require_text(name, getattr(self, name), maximum=256)
        if (
            type(self.previous_revision) is not int
            or self.previous_revision < 0
            or type(self.target_revision) is not int
            or self.target_revision != self.previous_revision + 1
        ):
            raise ValidationError("supervisor control transition revisions are invalid")
        if (
            self.previous_mode not in _CONTROL_MODES
            or self.target_mode not in _CONTROL_MODES
            or self.target_mode
            not in _CONTROL_TRANSITIONS[self.previous_mode]
        ):
            raise ValidationError("supervisor control transition is invalid")
        _require_digest("supervisor control actor reference", self.actor_ref)
        if (
            type(self.reason_code) is not str
            or _REASON_PATTERN.fullmatch(self.reason_code) is None
        ):
            raise ValidationError("supervisor control reason code is invalid")
        _require_timestamp("supervisor control transition time", self.occurred_at)

    def previous_to_canonical(self) -> dict[str, Any]:
        """Return the immutable source revision without raw operator identity."""

        return {
            "event_id": self.previous_control_event_id,
            "revision": self.previous_revision,
            "mode": self.previous_mode,
        }

    def target_to_canonical(self) -> dict[str, Any]:
        """Return the exact desired local control state."""

        return {
            "event_id": self.control_event_id,
            "revision": self.target_revision,
            "mode": self.target_mode,
            "actor_ref": self.actor_ref,
            "reason_code": self.reason_code,
            "occurred_at": float(self.occurred_at),
        }

    def to_canonical(self) -> dict[str, Any]:
        return {
            "previous": self.previous_to_canonical(),
            "target": self.target_to_canonical(),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class SupervisorControlAuthorization:
    """Exact request, fixed policy, and decision at the control PEP."""

    transition: SupervisorControlTransition
    request: AuthorizationRequest
    policy: PolicyBundle
    decision: AuthorizationDecision
    legacy_executable: bool
    authority_ceiling_satisfied: bool
    obligations_supported: bool
    decision_current_at_evaluation: bool
    block_reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.transition, SupervisorControlTransition)
            or type(self.request) is not AuthorizationRequest
            or type(self.policy) is not PolicyBundle
            or type(self.decision) is not AuthorizationDecision
            or type(self.legacy_executable) is not bool
            or type(self.authority_ceiling_satisfied) is not bool
            or type(self.obligations_supported) is not bool
            or type(self.decision_current_at_evaluation) is not bool
            or type(self.block_reason_codes) is not tuple
            or any(type(code) is not str for code in self.block_reason_codes)
            or len(set(self.block_reason_codes)) != len(self.block_reason_codes)
        ):
            raise ValidationError("supervisor control authorization is invalid")

    @property
    def authorized_at_evaluation(self) -> bool:
        return not self.block_reason_codes

    def to_event_payload(self) -> dict[str, Any]:
        """Return the strict privacy-safe decision record for durable append."""

        return {
            "schema_version": SUPERVISOR_CONTROL_AUTHORIZATION_EVENT_SCHEMA_VERSION,
            "mode": "enforcing",
            "action_scope": SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE,
            "enforcement_coverage": (
                SUPERVISOR_CONTROL_AUTHORIZATION_ENFORCEMENT_COVERAGE
            ),
            "control_transition": self.transition.to_canonical(),
            "control_transition_digest": self.transition.digest,
            "request": self.request.to_canonical(),
            "request_digest": self.request.digest,
            "policy": self.policy.to_canonical(),
            "policy_digest": self.policy.digest,
            "decision": self.decision.to_canonical(),
            "decision_digest": self.decision.digest,
            "effect": self.decision.effect.value,
            "derived_permission_class": int(
                self.decision.derived_permission_class
            ),
            "legacy_executable": self.legacy_executable,
            "decision_current_at_evaluation": (
                self.decision_current_at_evaluation
            ),
            "authority_ceiling_satisfied": self.authority_ceiling_satisfied,
            "obligations_supported": self.obligations_supported,
            "authorization_eligible": self.authorized_at_evaluation,
            "block_reason_codes": list(self.block_reason_codes),
            "evaluated_at": float(self.request.environment.evaluated_at),
        }


def evaluate_supervisor_control_authorization(
    *,
    transition: SupervisorControlTransition,
    legacy_executable: bool,
) -> SupervisorControlAuthorization:
    """Evaluate one exact reversible supervisor-control transition.

    The public evaluation path itself uses the captured shipped evaluator.  The
    mutable supervisor code is still required to perform a final exact replay
    after durable decision readback and immediately before the state change.
    """

    return _evaluate_supervisor_control_authorization(
        transition=transition,
        legacy_executable=legacy_executable,
    )


def _evaluate_supervisor_control_authorization(
    *,
    transition: SupervisorControlTransition,
    legacy_executable: bool,
) -> SupervisorControlAuthorization:
    """Build and evaluate with the captured shipped policy implementation."""

    if not isinstance(transition, SupervisorControlTransition):
        raise ValidationError("supervisor control transition is invalid")
    if type(legacy_executable) is not bool:
        raise ValidationError("supervisor control legacy gate is invalid")
    request = _build_request(transition)
    policy = _build_policy(transition)
    decision = _evaluate_fixed(request, policy)
    if type(decision) is not AuthorizationDecision:
        raise ValidationError("supervisor control evaluator returned an invalid decision")
    policy_matches = _policy_and_decision_match(
        request,
        policy,
        decision,
        evaluated_at=transition.occurred_at,
    )
    current = decision.issued_at <= transition.occurred_at < decision.expires_at
    ceiling = (
        decision.derived_permission_class is PermissionClass.LOCAL_DRAFT
    )
    obligations = _obligations_supported(decision)
    reasons: list[str] = []
    if not legacy_executable:
        reasons.append("legacy_transition_not_executable")
    if not policy_matches:
        reasons.append("authorization_policy_mismatch")
    if decision.effect is not AuthorizationEffect.PERMIT:
        reasons.append("authorization_effect_not_permit")
    if not current:
        reasons.append("authorization_decision_not_current")
    if not ceiling:
        reasons.append("authorization_class_ceiling_exceeded")
    if not obligations:
        reasons.append("authorization_obligation_unsupported")
    return SupervisorControlAuthorization(
        transition=transition,
        request=request,
        policy=policy,
        decision=decision,
        legacy_executable=legacy_executable,
        authority_ceiling_satisfied=ceiling,
        obligations_supported=obligations,
        decision_current_at_evaluation=current,
        block_reason_codes=tuple(reasons),
    )


def assert_supervisor_control_transition_authorized(
    authorization: SupervisorControlAuthorization,
    *,
    transition: SupervisorControlTransition,
    action_started_at: float,
    persisted_payload: Mapping[str, Any],
) -> None:
    """Require a freshly replayed, exact persisted permit before mutation."""

    if not isinstance(authorization, SupervisorControlAuthorization):
        raise AuthorizationBlocked(
            "supervisor control transition requires a typed authorization permit"
        )
    try:
        rebuilt = _evaluate_supervisor_control_authorization(
            transition=transition,
            legacy_executable=authorization.legacy_executable,
        )
        exact = bool(
            authorization == rebuilt
            and authorization.to_event_payload() == dict(persisted_payload)
        )
    except Exception:
        exact = False
    if not exact:
        raise AuthorizationBlocked(
            "supervisor control transition requires an exact persisted authorization permit"
        )
    _assert_current_permit(authorization, action_started_at=action_started_at)


def build_supervisor_control_action_receipt(
    *,
    authorization: SupervisorControlAuthorization,
    action_started_at: float,
    completed_at: float,
) -> dict[str, Any]:
    """Build the exact receipt for the completed local control transition."""

    _assert_current_permit(authorization, action_started_at=action_started_at)
    _require_timestamp("supervisor control receipt completion time", completed_at)
    if completed_at < action_started_at:
        raise ValidationError(
            "supervisor control receipt completion precedes action start"
        )
    obligation_results = tuple(
        ObligationResult(
            kind=obligation.kind,
            value=obligation.value,
            satisfied=True,
        )
        for obligation in authorization.decision.obligations
    )
    result_digest = canonical_digest(
        {
            "result": "supervisor_control_transition_applied",
            "control_transition": authorization.transition.to_canonical(),
        }
    )
    receipt_id = canonical_digest(
        {
            "receipt_kind": "supervisor_control_transition_action",
            "control_event_id": authorization.transition.control_event_id,
            "request_digest": authorization.request.digest,
            "decision_digest": authorization.decision.digest,
        }
    )
    receipt = ActionReceipt.record(
        receipt_id=receipt_id,
        decision=authorization.decision,
        request=authorization.request,
        executor_id=SUPERVISOR_CONTROL_AUTHORIZATION_EXECUTOR_ID,
        started_at=action_started_at,
        completed_at=completed_at,
        outcome=ReceiptOutcome.SUCCEEDED,
        obligation_results=obligation_results,
        result_digest=result_digest,
    )
    return {
        "schema_version": SUPERVISOR_CONTROL_AUTHORIZATION_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE,
        "enforcement_coverage": (
            SUPERVISOR_CONTROL_AUTHORIZATION_ENFORCEMENT_COVERAGE
        ),
        "control_transition_digest": authorization.transition.digest,
        "control_event_id": authorization.transition.control_event_id,
        "request_digest": authorization.request.digest,
        "decision_digest": authorization.decision.digest,
        "control_result_digest": result_digest,
        "receipt": receipt.to_canonical(),
        "receipt_digest": receipt.digest,
    }


def _build_request(
    transition: SupervisorControlTransition,
) -> AuthorizationRequest:
    source = transition.previous_to_canonical()
    target = transition.target_to_canonical()
    request = AuthorizationRequest(
        request_id=(
            f"{SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE}:"
            f"{transition.control_event_id}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="ordomata:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest(
                {"profile_id": "supervisor_control_bookkeeping"}
            ),
            runner_id="local_non_ai",
            session_id=None,
        ),
        action=ActionAttributes(
            verb=ActionVerb.MODIFY,
            operation=SUPERVISOR_CONTROL_AUTHORIZATION_OPERATION,
            parameters_digest=canonical_digest(
                {
                    "source": source,
                    "target": target,
                }
            ),
            intended_effect="apply_local_supervisor_control_transition",
        ),
        resource=ResourceAttributes(
            resource_type=SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE,
            identifier=canonical_digest(
                {
                    "resource_type": (
                        SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE
                    ),
                    "control_event_id": transition.control_event_id,
                }
            ),
            version=canonical_digest(source),
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(source),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=transition.occurred_at,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.LOCAL_NON_AI,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=(
                PaidContinuationProtection.NOT_APPLICABLE
            ),
            circuit_state=CircuitState.CLOSED,
            flow_state=f"control_{transition.previous_mode}",
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
    sources = (
        ("subject", EvidenceSource.CONTROLLER),
        ("action", EvidenceSource.CONTROLLER),
        ("resource", EvidenceSource.LOCAL_REGISTRY),
        ("environment", EvidenceSource.CONTROLLER),
        ("consequences", EvidenceSource.LOCAL_REGISTRY),
    )
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=(
                f"{SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE}:"
                f"{attribute}"
            ),
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id=f"ordomata:{source.value}",
            observed_at=transition.occurred_at,
            expires_at=(
                transition.occurred_at + _EVIDENCE_LIFETIME_SECONDS
            ),
            authenticated=True,
        )
        for attribute, source in sources
    )
    return replace(request, evidence=evidence)


def _build_policy(transition: SupervisorControlTransition) -> PolicyBundle:
    base = PolicyBundle.current_stage(issued_at=0.0)
    return PolicyBundle(
        bundle_id=SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_ID,
        version=SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_VERSION,
        issued_at=base.issued_at,
        evidence_requirements=base.evidence_requirements,
        enabled_classes=(PermissionClass.LOCAL_DRAFT,),
        allowed_verbs=(ActionVerb.MODIFY,),
        allowed_roles=(Role.CONTROLLER,),
        allowed_operations=(SUPERVISOR_CONTROL_AUTHORIZATION_OPERATION,),
        allowed_resource_types=(
            SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE,
        ),
        allowed_trust_boundaries=("local_control_plane",),
        allowed_flow_states=(f"control_{transition.previous_mode}",),
        allowed_network_states=(NetworkState.DISABLED,),
        allowed_billing_routes=(BillingRoute.LOCAL_NON_AI,),
        approval_requirements=(),
        decision_ttl_seconds=base.decision_ttl_seconds,
    )


def _evaluate_fixed(
    request: AuthorizationRequest,
    policy: PolicyBundle,
) -> AuthorizationDecision:
    evaluator = _BUILTIN_AUTHORIZATION_EVALUATOR()
    return _BUILTIN_AUTHORIZATION_EVALUATE(evaluator, request, policy)


def _assert_current_permit(
    authorization: SupervisorControlAuthorization,
    *,
    action_started_at: float,
) -> None:
    if not isinstance(authorization, SupervisorControlAuthorization):
        raise AuthorizationBlocked(
            "supervisor control transition requires a typed authorization permit"
        )
    try:
        rebuilt = _evaluate_supervisor_control_authorization(
            transition=authorization.transition,
            legacy_executable=authorization.legacy_executable,
        )
        fixed_policy = _build_policy(authorization.transition)
        replayed = _evaluate_fixed(authorization.request, fixed_policy)
    except Exception:
        rebuilt = None
        fixed_policy = None
        replayed = None
    obligations = tuple(
        (item.kind, item.value) for item in authorization.decision.obligations
    )
    request = authorization.request
    decision = authorization.decision
    if (
        authorization != rebuilt
        or not authorization.authorized_at_evaluation
        or not authorization.legacy_executable
        or not authorization.authority_ceiling_satisfied
        or not authorization.obligations_supported
        or authorization.policy != fixed_policy
        or decision != replayed
        or decision.effect is not AuthorizationEffect.PERMIT
        or decision.derived_permission_class is not PermissionClass.LOCAL_DRAFT
        or decision.request_id != request.request_id
        or decision.request_digest != request.digest
        or decision.policy_bundle_id != authorization.policy.bundle_id
        or decision.policy_version != authorization.policy.version
        or decision.policy_digest != authorization.policy.digest
        or request.subject.role is not Role.CONTROLLER
        or request.subject.runner_id != "local_non_ai"
        or request.action.verb is not ActionVerb.MODIFY
        or request.action.operation
        != SUPERVISOR_CONTROL_AUTHORIZATION_OPERATION
        or request.action.intended_effect
        != "apply_local_supervisor_control_transition"
        or request.resource.resource_type
        != SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE
        or request.resource.trust_boundary != "local_control_plane"
        or request.environment.isolation_state is not IsolationState.VERIFIED
        or request.environment.network_state is not NetworkState.DISABLED
        or request.environment.billing_route is not BillingRoute.LOCAL_NON_AI
        or request.environment.capacity_state is not CapacityState.NOT_APPLICABLE
        or request.environment.paid_continuation_protection
        is not PaidContinuationProtection.NOT_APPLICABLE
        or request.environment.circuit_state is not CircuitState.CLOSED
        or request.environment.flow_state
        != f"control_{authorization.transition.previous_mode}"
        or request.consequences.reach is not Reach.LOCAL
        or request.consequences.destructive
        or not request.consequences.reversible
        or request.consequences.blast_radius is not BlastRadius.SINGLE_RESOURCE
        or len(obligations) != len(_FIXED_PERMIT_OBLIGATIONS)
        or len(set(obligations)) != len(obligations)
        or frozenset(obligations) != _FIXED_PERMIT_OBLIGATIONS
        or not _valid_timestamp(action_started_at)
        or action_started_at < decision.issued_at
        or action_started_at >= decision.expires_at
    ):
        raise AuthorizationBlocked(
            "supervisor control transition requires a fresh exact Class 1 authorization permit"
        )


def _policy_and_decision_match(
    request: AuthorizationRequest,
    policy: PolicyBundle,
    decision: AuthorizationDecision,
    *,
    evaluated_at: float,
) -> bool:
    return bool(
        decision.request_id == request.request_id
        and decision.request_digest == request.digest
        and decision.policy_bundle_id == policy.bundle_id
        and decision.policy_version == policy.version
        and decision.policy_digest == policy.digest
        and decision.issued_at == evaluated_at
    )


def _obligations_supported(decision: AuthorizationDecision) -> bool:
    if decision.effect is not AuthorizationEffect.PERMIT:
        return True
    obligations = tuple(
        (item.kind, item.value) for item in decision.obligations
    )
    return bool(
        len(obligations) == len(_FIXED_PERMIT_OBLIGATIONS)
        and len(set(obligations)) == len(obligations)
        and frozenset(obligations) == _FIXED_PERMIT_OBLIGATIONS
    )


def _require_text(name: str, value: Any, *, maximum: int) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or len(value.encode("utf-8")) > maximum
    ):
        raise ValidationError(f"{name} is invalid")


def _require_digest(name: str, value: Any) -> None:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValidationError(f"{name} is invalid")


def _require_timestamp(name: str, value: Any) -> None:
    if not _valid_timestamp(value):
        raise ValidationError(f"{name} is invalid")


def _valid_timestamp(value: Any) -> bool:
    return bool(
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


__all__ = [
    "SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE",
    "SUPERVISOR_CONTROL_AUTHORIZATION_ENFORCEMENT_COVERAGE",
    "SUPERVISOR_CONTROL_AUTHORIZATION_EVENT_SCHEMA_VERSION",
    "SUPERVISOR_CONTROL_AUTHORIZATION_EXECUTOR_ID",
    "SUPERVISOR_CONTROL_AUTHORIZATION_OPERATION",
    "SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_ID",
    "SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_VERSION",
    "SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE",
    "SupervisorControlAuthorization",
    "SupervisorControlTransition",
    "assert_supervisor_control_transition_authorized",
    "build_supervisor_control_action_receipt",
    "evaluate_supervisor_control_authorization",
]
