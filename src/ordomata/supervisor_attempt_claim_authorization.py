"""Authoritative ABAC gate for local mock-only supervisor attempt claims.

This module authorizes one narrow controller bookkeeping effect: atomically
append a fenced attempt claim, its initial created-attempt event, and the
corresponding running flow revision in the local supervisor store.  It does
not authorize worker dispatch, task execution, cancellation, repository
mutation, network access, an external effect, or Permission Class 2/3 work.
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


SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE = (
    "supervisor_mock_attempt_claim_only"
)
SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ENFORCEMENT_COVERAGE = (
    "authoritative_local_mock_attempt_claim_only"
)
SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_OPERATION = "supervisor.attempt_claim"
SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_RESOURCE_TYPE = "supervisor_attempt"
SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_ID = (
    "ordomata.phase-1c.supervisor-attempt-claim-enforcement"
)
SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_VERSION = "1.0.0"
SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EXECUTOR_ID = "ordomata:local-controller"
SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EVENT_SCHEMA_VERSION = 1

_EVIDENCE_LIFETIME_SECONDS = 60.0
_CANONICAL_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_FIXED_PERMIT_OBLIGATIONS = frozenset(
    {
        (ObligationKind.AUDIT_RECEIPT, "append_after_action"),
        (ObligationKind.ISOLATED_LOCAL_ONLY, "required"),
    }
)

# The final replay must not depend on a patched first-pass evaluator.
_BUILTIN_AUTHORIZATION_EVALUATOR = AuthorizationEvaluator
_BUILTIN_AUTHORIZATION_EVALUATE = AuthorizationEvaluator.evaluate


@dataclass(frozen=True, slots=True)
class SupervisorAttemptClaim:
    """One exact, privacy-bounded local mock attempt-claim target."""

    flow_id: str
    attempt_id: str
    run_id: str
    source_flow_revision: int
    target_flow_revision: int
    control_revision: int
    attempt_number: int
    flow_request_digest: str
    input_digest: str
    instance_owner_ref: str
    lease_owner_ref: str
    lease_keys_digest: str
    deadline_at: float
    lease_expires_at: float
    attempt_event_id: str
    flow_event_id: str
    occurred_at: float

    def __post_init__(self) -> None:
        for name in (
            "flow_id",
            "attempt_id",
            "run_id",
            "attempt_event_id",
            "flow_event_id",
        ):
            _require_text(f"supervisor {name.replace('_', ' ')}", getattr(self, name), maximum=256)
        if (
            type(self.source_flow_revision) is not int
            or self.source_flow_revision < 1
            or type(self.target_flow_revision) is not int
            or self.target_flow_revision != self.source_flow_revision + 1
        ):
            raise ValidationError("supervisor attempt claim flow revisions are invalid")
        if type(self.control_revision) is not int or self.control_revision < 1:
            raise ValidationError("supervisor attempt claim control revision is invalid")
        if type(self.attempt_number) is not int or self.attempt_number < 1:
            raise ValidationError("supervisor attempt claim number is invalid")
        for name in ("flow_request_digest", "input_digest"):
            value = getattr(self, name)
            if type(value) is not str or _HEX_DIGEST_PATTERN.fullmatch(value) is None:
                raise ValidationError(f"supervisor attempt claim {name} is invalid")
        for name in (
            "instance_owner_ref",
            "lease_owner_ref",
            "lease_keys_digest",
        ):
            _require_digest(f"supervisor attempt claim {name}", getattr(self, name))
        _require_timestamp("supervisor attempt claim deadline", self.deadline_at)
        _require_timestamp(
            "supervisor attempt claim lease expiry", self.lease_expires_at
        )
        _require_timestamp("supervisor attempt claim time", self.occurred_at)
        if not (
            self.lease_expires_at > self.occurred_at
            and self.deadline_at > self.occurred_at
            and self.lease_expires_at <= self.deadline_at
        ):
            raise ValidationError("supervisor attempt claim timing is invalid")

    @property
    def flow_id_ref(self) -> str:
        return canonical_digest({"flow_id": self.flow_id})

    @property
    def attempt_id_ref(self) -> str:
        return canonical_digest({"attempt_id": self.attempt_id})

    @property
    def run_id_ref(self) -> str:
        return canonical_digest({"run_id": self.run_id})

    @property
    def attempt_event_ref(self) -> str:
        return canonical_digest({"attempt_event_id": self.attempt_event_id})

    @property
    def flow_event_ref(self) -> str:
        return canonical_digest({"flow_event_id": self.flow_event_id})

    def source_to_canonical(self) -> dict[str, Any]:
        """Return the queued source state without exposing raw identifiers."""

        return {
            "flow_id_ref": self.flow_id_ref,
            "revision": self.source_flow_revision,
            "state": "queued",
            "cancellation_requested": False,
            "active_attempt_ref": None,
            "control_revision": self.control_revision,
        }

    def target_to_canonical(self) -> dict[str, Any]:
        """Return the exact claim effects without exposing raw identifiers."""

        return {
            "flow_id_ref": self.flow_id_ref,
            "attempt_id_ref": self.attempt_id_ref,
            "run_id_ref": self.run_id_ref,
            "attempt_event_ref": self.attempt_event_ref,
            "flow_event_ref": self.flow_event_ref,
            "revision": self.target_flow_revision,
            "state": "running",
            "cancellation_requested": False,
            "active_attempt_ref": self.attempt_id_ref,
            "attempt_number": self.attempt_number,
            "flow_request_digest": self.flow_request_digest,
            "input_digest": self.input_digest,
            "instance_owner_ref": self.instance_owner_ref,
            "lease_owner_ref": self.lease_owner_ref,
            "lease_keys_digest": self.lease_keys_digest,
            "deadline_at": float(self.deadline_at),
            "lease_expires_at": float(self.lease_expires_at),
            "occurred_at": float(self.occurred_at),
        }

    def to_canonical(self) -> dict[str, Any]:
        return {
            "source": self.source_to_canonical(),
            "target": self.target_to_canonical(),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class SupervisorAttemptClaimAuthorization:
    """Exact request, fixed policy, and decision at the attempt-claim PEP."""

    claim: SupervisorAttemptClaim
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
            not isinstance(self.claim, SupervisorAttemptClaim)
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
            raise ValidationError("supervisor attempt claim authorization is invalid")

    @property
    def authorized_at_evaluation(self) -> bool:
        return not self.block_reason_codes

    def to_event_payload(self) -> dict[str, Any]:
        """Return the strict privacy-safe decision record for durable append."""

        return {
            "schema_version": SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EVENT_SCHEMA_VERSION,
            "mode": "enforcing",
            "action_scope": SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE,
            "enforcement_coverage": (
                SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ENFORCEMENT_COVERAGE
            ),
            "attempt_claim": self.claim.to_canonical(),
            "attempt_claim_digest": self.claim.digest,
            "request": self.request.to_canonical(),
            "request_digest": self.request.digest,
            "policy": self.policy.to_canonical(),
            "policy_digest": self.policy.digest,
            "decision": self.decision.to_canonical(),
            "decision_digest": self.decision.digest,
            "effect": self.decision.effect.value,
            "derived_permission_class": int(self.decision.derived_permission_class),
            "legacy_executable": self.legacy_executable,
            "decision_current_at_evaluation": self.decision_current_at_evaluation,
            "authority_ceiling_satisfied": self.authority_ceiling_satisfied,
            "obligations_supported": self.obligations_supported,
            "authorization_eligible": self.authorized_at_evaluation,
            "block_reason_codes": list(self.block_reason_codes),
            "evaluated_at": float(self.request.environment.evaluated_at),
        }


def evaluate_supervisor_attempt_claim_authorization(
    *,
    claim: SupervisorAttemptClaim,
    legacy_executable: bool,
) -> SupervisorAttemptClaimAuthorization:
    """Evaluate one exact local mock attempt claim."""

    return _evaluate_supervisor_attempt_claim_authorization(
        claim=claim,
        legacy_executable=legacy_executable,
    )


def _evaluate_supervisor_attempt_claim_authorization(
    *,
    claim: SupervisorAttemptClaim,
    legacy_executable: bool,
) -> SupervisorAttemptClaimAuthorization:
    if not isinstance(claim, SupervisorAttemptClaim):
        raise ValidationError("supervisor attempt claim is invalid")
    if type(legacy_executable) is not bool:
        raise ValidationError("supervisor attempt claim legacy gate is invalid")
    request = _build_request(claim)
    policy = _build_policy(claim)
    decision = _evaluate_fixed(request, policy)
    if type(decision) is not AuthorizationDecision:
        raise ValidationError("supervisor attempt claim evaluator returned an invalid decision")
    policy_matches = _policy_and_decision_match(
        request,
        policy,
        decision,
        evaluated_at=claim.occurred_at,
    )
    current = decision.issued_at <= claim.occurred_at < decision.expires_at
    ceiling = decision.derived_permission_class is PermissionClass.LOCAL_DRAFT
    obligations = _obligations_supported(decision)
    reasons: list[str] = []
    if not legacy_executable:
        reasons.append("legacy_claim_not_executable")
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
    return SupervisorAttemptClaimAuthorization(
        claim=claim,
        request=request,
        policy=policy,
        decision=decision,
        legacy_executable=legacy_executable,
        authority_ceiling_satisfied=ceiling,
        obligations_supported=obligations,
        decision_current_at_evaluation=current,
        block_reason_codes=tuple(reasons),
    )


def assert_supervisor_attempt_claim_authorized(
    authorization: SupervisorAttemptClaimAuthorization,
    *,
    claim: SupervisorAttemptClaim,
    action_started_at: float,
    persisted_payload: Mapping[str, Any],
) -> None:
    """Require a freshly replayed, exact persisted permit before claiming."""

    if not isinstance(authorization, SupervisorAttemptClaimAuthorization):
        raise AuthorizationBlocked(
            "supervisor attempt claim requires a typed authorization permit"
        )
    try:
        rebuilt = _evaluate_supervisor_attempt_claim_authorization(
            claim=claim,
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
            "supervisor attempt claim requires an exact persisted authorization permit"
        )
    _assert_current_permit(authorization, action_started_at=action_started_at)


def build_supervisor_attempt_claim_action_receipt(
    *,
    authorization: SupervisorAttemptClaimAuthorization,
    action_started_at: float,
    completed_at: float,
) -> dict[str, Any]:
    """Build the exact receipt for the completed local attempt claim."""

    _assert_current_permit(authorization, action_started_at=action_started_at)
    _require_timestamp("supervisor attempt claim receipt completion time", completed_at)
    if completed_at < action_started_at:
        raise ValidationError("supervisor attempt claim receipt completion precedes action start")
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
            "result": "supervisor_mock_attempt_claimed",
            "attempt_claim": authorization.claim.to_canonical(),
        }
    )
    receipt_id = canonical_digest(
        {
            "receipt_kind": "supervisor_attempt_claim_action",
            "attempt_id_ref": authorization.claim.attempt_id_ref,
            "request_digest": authorization.request.digest,
            "decision_digest": authorization.decision.digest,
        }
    )
    receipt = ActionReceipt.record(
        receipt_id=receipt_id,
        decision=authorization.decision,
        request=authorization.request,
        executor_id=SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EXECUTOR_ID,
        started_at=action_started_at,
        completed_at=completed_at,
        outcome=ReceiptOutcome.SUCCEEDED,
        obligation_results=obligation_results,
        result_digest=result_digest,
    )
    return {
        "schema_version": SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE,
        "enforcement_coverage": (
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ENFORCEMENT_COVERAGE
        ),
        "attempt_claim_digest": authorization.claim.digest,
        "flow_id_ref": authorization.claim.flow_id_ref,
        "attempt_id_ref": authorization.claim.attempt_id_ref,
        "attempt_event_ref": authorization.claim.attempt_event_ref,
        "flow_event_ref": authorization.claim.flow_event_ref,
        "request_digest": authorization.request.digest,
        "decision_digest": authorization.decision.digest,
        "attempt_claim_result_digest": result_digest,
        "receipt": receipt.to_canonical(),
        "receipt_digest": receipt.digest,
    }


def _build_request(claim: SupervisorAttemptClaim) -> AuthorizationRequest:
    source = claim.source_to_canonical()
    target = claim.target_to_canonical()
    request = AuthorizationRequest(
        request_id=(
            f"{SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE}:"
            f"{claim.attempt_id_ref}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="ordomata:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest(
                {"profile_id": "supervisor_attempt_claim_bookkeeping"}
            ),
            runner_id="local_non_ai",
            session_id=None,
        ),
        action=ActionAttributes(
            verb=ActionVerb.CREATE,
            operation=SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_OPERATION,
            parameters_digest=canonical_digest({"source": source, "target": target}),
            intended_effect="append_local_mock_attempt_claim",
        ),
        resource=ResourceAttributes(
            resource_type=SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_RESOURCE_TYPE,
            identifier=claim.attempt_id_ref,
            version=canonical_digest(source),
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(
                {
                    "flow_request_digest": claim.flow_request_digest,
                    "input_digest": claim.input_digest,
                }
            ),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=claim.occurred_at,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.LOCAL_NON_AI,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=(
                PaidContinuationProtection.NOT_APPLICABLE
            ),
            circuit_state=CircuitState.CLOSED,
            flow_state="claim_queued",
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
                f"{SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE}:"
                f"{attribute}"
            ),
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id=f"ordomata:{source.value}",
            observed_at=claim.occurred_at,
            expires_at=claim.occurred_at + _EVIDENCE_LIFETIME_SECONDS,
            authenticated=True,
        )
        for attribute, source in sources
    )
    return replace(request, evidence=evidence)


def _build_policy(claim: SupervisorAttemptClaim) -> PolicyBundle:
    base = PolicyBundle.current_stage(issued_at=0.0)
    return PolicyBundle(
        bundle_id=SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_ID,
        version=SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_VERSION,
        issued_at=base.issued_at,
        evidence_requirements=base.evidence_requirements,
        enabled_classes=(PermissionClass.LOCAL_DRAFT,),
        allowed_verbs=(ActionVerb.CREATE,),
        allowed_roles=(Role.CONTROLLER,),
        allowed_operations=(SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_OPERATION,),
        allowed_resource_types=(
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_RESOURCE_TYPE,
        ),
        allowed_trust_boundaries=("local_control_plane",),
        allowed_flow_states=("claim_queued",),
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
    authorization: SupervisorAttemptClaimAuthorization,
    *,
    action_started_at: float,
) -> None:
    if not isinstance(authorization, SupervisorAttemptClaimAuthorization):
        raise AuthorizationBlocked(
            "supervisor attempt claim requires a typed authorization permit"
        )
    try:
        rebuilt = _evaluate_supervisor_attempt_claim_authorization(
            claim=authorization.claim,
            legacy_executable=authorization.legacy_executable,
        )
        fixed_policy = _build_policy(authorization.claim)
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
        or request.action.verb is not ActionVerb.CREATE
        or request.action.operation
        != SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_OPERATION
        or request.action.intended_effect != "append_local_mock_attempt_claim"
        or request.resource.resource_type
        != SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_RESOURCE_TYPE
        or request.resource.trust_boundary != "local_control_plane"
        or request.environment.isolation_state is not IsolationState.VERIFIED
        or request.environment.network_state is not NetworkState.DISABLED
        or request.environment.billing_route is not BillingRoute.LOCAL_NON_AI
        or request.environment.capacity_state is not CapacityState.NOT_APPLICABLE
        or request.environment.paid_continuation_protection
        is not PaidContinuationProtection.NOT_APPLICABLE
        or request.environment.circuit_state is not CircuitState.CLOSED
        or request.environment.flow_state != "claim_queued"
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
            "supervisor attempt claim requires a fresh exact Class 1 authorization permit"
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
    obligations = tuple((item.kind, item.value) for item in decision.obligations)
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
    if type(value) is not str or _CANONICAL_DIGEST_PATTERN.fullmatch(value) is None:
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
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE",
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ENFORCEMENT_COVERAGE",
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EVENT_SCHEMA_VERSION",
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EXECUTOR_ID",
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_OPERATION",
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_ID",
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_VERSION",
    "SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_RESOURCE_TYPE",
    "SupervisorAttemptClaim",
    "SupervisorAttemptClaimAuthorization",
    "assert_supervisor_attempt_claim_authorized",
    "build_supervisor_attempt_claim_action_receipt",
    "evaluate_supervisor_attempt_claim_authorization",
]
