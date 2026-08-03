"""Authoritative ABAC gate for one local supervisor pre-dispatch intent.

This module authorizes only the append-only ``created`` to ``dispatching``
attempt-event transition in the local, mock-only supervisor store.  The
transition records controller bookkeeping intent; it does not launch a worker
or authorize task execution, repository mutation, subprocesses, network
access, external effects, or Permission Class 2/3 work.
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


SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE = (
    "supervisor_local_attempt_pre_dispatch_intent_only"
)
SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ENFORCEMENT_COVERAGE = (
    "authoritative_local_attempt_pre_dispatch_intent_only"
)
SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_OPERATION = (
    "supervisor.attempt_pre_dispatch_intent"
)
SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_RESOURCE_TYPE = "supervisor_attempt"
SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_ID = (
    "ordomata.phase-1c.supervisor-pre-dispatch-intent-enforcement"
)
SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_VERSION = "1.0.0"
SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EXECUTOR_ID = (
    "ordomata:local-controller"
)
SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EVENT_SCHEMA_VERSION = 1

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
class SupervisorPreDispatchIntentLease:
    """One redacted, active lease fact bound into a local intent permit."""

    lease_key_ref: str
    lease_owner_ref: str
    acquired_at: float
    renewed_at: float
    expires_at: float

    def __post_init__(self) -> None:
        _require_digest("supervisor pre-dispatch lease key reference", self.lease_key_ref)
        _require_digest(
            "supervisor pre-dispatch lease owner reference", self.lease_owner_ref
        )
        for name in ("acquired_at", "renewed_at", "expires_at"):
            _require_timestamp(
                f"supervisor pre-dispatch lease {name.replace('_', ' ')}",
                getattr(self, name),
            )
        if self.acquired_at > self.renewed_at:
            raise ValidationError("supervisor pre-dispatch lease timing is invalid")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "lease_key_ref": self.lease_key_ref,
            "lease_owner_ref": self.lease_owner_ref,
            "acquired_at": float(self.acquired_at),
            "renewed_at": float(self.renewed_at),
            "expires_at": float(self.expires_at),
        }


@dataclass(frozen=True, slots=True)
class SupervisorPreDispatchIntent:
    """One exact, privacy-bounded local ``created`` to ``dispatching`` target."""

    flow_id: str
    attempt_id: str
    run_id: str
    source_flow_event_id: str
    source_flow_revision: int
    source_flow_occurred_at: float
    source_attempt_event_id: str
    source_attempt_revision: int
    source_attempt_occurred_at: float
    target_attempt_event_id: str
    target_attempt_revision: int
    flow_request_digest: str
    input_digest: str
    lease_owner_ref: str
    lease_keys_digest: str
    lease_snapshot: tuple[SupervisorPreDispatchIntentLease, ...]
    deadline_at: float
    occurred_at: float

    def __post_init__(self) -> None:
        for name in (
            "flow_id",
            "attempt_id",
            "run_id",
            "source_flow_event_id",
            "source_attempt_event_id",
            "target_attempt_event_id",
        ):
            _require_text(
                f"supervisor pre-dispatch {name.replace('_', ' ')}",
                getattr(self, name),
                maximum=256,
            )
        if self.source_attempt_event_id == self.target_attempt_event_id:
            raise ValidationError("supervisor pre-dispatch attempt events are invalid")
        if type(self.source_flow_revision) is not int or self.source_flow_revision < 1:
            raise ValidationError("supervisor pre-dispatch flow revision is invalid")
        if (
            type(self.source_attempt_revision) is not int
            or self.source_attempt_revision != 1
            or type(self.target_attempt_revision) is not int
            or self.target_attempt_revision != self.source_attempt_revision + 1
        ):
            raise ValidationError("supervisor pre-dispatch attempt revisions are invalid")
        for name in ("flow_request_digest", "input_digest"):
            value = getattr(self, name)
            if type(value) is not str or _HEX_DIGEST_PATTERN.fullmatch(value) is None:
                raise ValidationError(f"supervisor pre-dispatch {name} is invalid")
        for name in ("lease_owner_ref", "lease_keys_digest"):
            _require_digest(f"supervisor pre-dispatch {name}", getattr(self, name))
        for name in (
            "source_flow_occurred_at",
            "source_attempt_occurred_at",
            "deadline_at",
            "occurred_at",
        ):
            _require_timestamp(
                f"supervisor pre-dispatch {name.replace('_', ' ')}",
                getattr(self, name),
            )
        if not (
            self.source_flow_occurred_at == self.source_attempt_occurred_at
            and self.source_attempt_occurred_at <= self.occurred_at
            and self.deadline_at > self.occurred_at
        ):
            raise ValidationError("supervisor pre-dispatch timing is invalid")
        if (
            type(self.lease_snapshot) is not tuple
            or not self.lease_snapshot
            or any(
                not isinstance(item, SupervisorPreDispatchIntentLease)
                for item in self.lease_snapshot
            )
            or len({item.lease_key_ref for item in self.lease_snapshot})
            != len(self.lease_snapshot)
        ):
            raise ValidationError("supervisor pre-dispatch lease snapshot is invalid")
        for lease in self.lease_snapshot:
            if (
                lease.lease_owner_ref != self.lease_owner_ref
                or lease.acquired_at != self.source_attempt_occurred_at
                or not (
                    lease.acquired_at
                    <= lease.renewed_at
                    <= self.occurred_at
                    < lease.expires_at
                    <= self.deadline_at
                )
            ):
                raise ValidationError("supervisor pre-dispatch lease snapshot is invalid")

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
    def source_flow_event_ref(self) -> str:
        return canonical_digest({"flow_event_id": self.source_flow_event_id})

    @property
    def source_attempt_event_ref(self) -> str:
        return canonical_digest(
            {"attempt_event_id": self.source_attempt_event_id}
        )

    @property
    def target_attempt_event_ref(self) -> str:
        return canonical_digest(
            {"attempt_event_id": self.target_attempt_event_id}
        )

    @property
    def lease_snapshot_digest(self) -> str:
        return canonical_digest(
            {"leases": [item.to_canonical() for item in self.lease_snapshot]}
        )

    def source_to_canonical(self) -> dict[str, Any]:
        """Return exact source facts without raw caller-supplied identifiers."""

        return {
            "flow_id_ref": self.flow_id_ref,
            "flow_event_ref": self.source_flow_event_ref,
            "flow_revision": self.source_flow_revision,
            "flow_state": "running",
            "cancellation_requested": False,
            "active_attempt_ref": self.attempt_id_ref,
            "flow_occurred_at": float(self.source_flow_occurred_at),
            "attempt_id_ref": self.attempt_id_ref,
            "run_id_ref": self.run_id_ref,
            "attempt_event_ref": self.source_attempt_event_ref,
            "attempt_revision": self.source_attempt_revision,
            "attempt_state": "created",
            "attempt_reason_code": "claim_created",
            "attempt_occurred_at": float(self.source_attempt_occurred_at),
            "flow_request_digest": self.flow_request_digest,
            "input_digest": self.input_digest,
            "lease_owner_ref": self.lease_owner_ref,
            "lease_keys_digest": self.lease_keys_digest,
            "lease_snapshot": [
                item.to_canonical() for item in self.lease_snapshot
            ],
            "lease_snapshot_digest": self.lease_snapshot_digest,
            "deadline_at": float(self.deadline_at),
        }

    def target_to_canonical(self) -> dict[str, Any]:
        """Return the single local state write this permit can cover."""

        return {
            "attempt_id_ref": self.attempt_id_ref,
            "attempt_event_ref": self.target_attempt_event_ref,
            "attempt_revision": self.target_attempt_revision,
            "attempt_state": "dispatching",
            "attempt_reason_code": "dispatch_intent_recorded",
            "attempt_occurred_at": float(self.occurred_at),
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
class SupervisorPreDispatchIntentAuthorization:
    """Exact request, fixed policy, and decision at the local intent PEP."""

    intent: SupervisorPreDispatchIntent
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
            not isinstance(self.intent, SupervisorPreDispatchIntent)
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
            raise ValidationError("supervisor pre-dispatch authorization is invalid")

    @property
    def authorized_at_evaluation(self) -> bool:
        return not self.block_reason_codes

    def to_event_payload(self) -> dict[str, Any]:
        """Return the strict privacy-safe decision record for durable append."""

        return {
            "schema_version": (
                SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EVENT_SCHEMA_VERSION
            ),
            "mode": "enforcing",
            "action_scope": (
                SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE
            ),
            "enforcement_coverage": (
                SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ENFORCEMENT_COVERAGE
            ),
            "pre_dispatch_intent": self.intent.to_canonical(),
            "pre_dispatch_intent_digest": self.intent.digest,
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


def evaluate_supervisor_pre_dispatch_intent_authorization(
    *,
    intent: SupervisorPreDispatchIntent,
    legacy_executable: bool,
) -> SupervisorPreDispatchIntentAuthorization:
    """Evaluate one exact local pre-dispatch bookkeeping transition."""

    return _evaluate_supervisor_pre_dispatch_intent_authorization(
        intent=intent,
        legacy_executable=legacy_executable,
    )


def _evaluate_supervisor_pre_dispatch_intent_authorization(
    *,
    intent: SupervisorPreDispatchIntent,
    legacy_executable: bool,
) -> SupervisorPreDispatchIntentAuthorization:
    if not isinstance(intent, SupervisorPreDispatchIntent):
        raise ValidationError("supervisor pre-dispatch intent is invalid")
    if type(legacy_executable) is not bool:
        raise ValidationError("supervisor pre-dispatch legacy gate is invalid")
    request = _build_request(intent)
    policy = _build_policy(intent)
    decision = _evaluate_fixed(request, policy)
    if type(decision) is not AuthorizationDecision:
        raise ValidationError(
            "supervisor pre-dispatch evaluator returned an invalid decision"
        )
    policy_matches = _policy_and_decision_match(
        request,
        policy,
        decision,
        evaluated_at=intent.occurred_at,
    )
    current = decision.issued_at <= intent.occurred_at < decision.expires_at
    ceiling = decision.derived_permission_class is PermissionClass.LOCAL_DRAFT
    obligations = _obligations_supported(decision)
    reasons: list[str] = []
    if not legacy_executable:
        reasons.append("legacy_pre_dispatch_intent_not_executable")
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
    return SupervisorPreDispatchIntentAuthorization(
        intent=intent,
        request=request,
        policy=policy,
        decision=decision,
        legacy_executable=legacy_executable,
        authority_ceiling_satisfied=ceiling,
        obligations_supported=obligations,
        decision_current_at_evaluation=current,
        block_reason_codes=tuple(reasons),
    )


def assert_supervisor_pre_dispatch_intent_authorized(
    authorization: SupervisorPreDispatchIntentAuthorization,
    *,
    intent: SupervisorPreDispatchIntent,
    action_started_at: float,
    persisted_payload: Mapping[str, Any],
) -> None:
    """Require a freshly replayed exact permit before appending the target."""

    if not isinstance(authorization, SupervisorPreDispatchIntentAuthorization):
        raise AuthorizationBlocked(
            "supervisor pre-dispatch intent requires a typed authorization permit"
        )
    try:
        rebuilt = _evaluate_supervisor_pre_dispatch_intent_authorization(
            intent=intent,
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
            "supervisor pre-dispatch intent requires an exact persisted authorization permit"
        )
    _assert_current_permit(authorization, action_started_at=action_started_at)


def build_supervisor_pre_dispatch_intent_action_receipt(
    *,
    authorization: SupervisorPreDispatchIntentAuthorization,
    action_started_at: float,
    completed_at: float,
) -> dict[str, Any]:
    """Build the exact receipt for the completed local intent append."""

    _assert_current_permit(authorization, action_started_at=action_started_at)
    _require_timestamp(
        "supervisor pre-dispatch receipt completion time", completed_at
    )
    if completed_at < action_started_at:
        raise ValidationError(
            "supervisor pre-dispatch receipt completion precedes action start"
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
            "result": "supervisor_local_attempt_pre_dispatch_intent_recorded",
            "pre_dispatch_intent": authorization.intent.to_canonical(),
        }
    )
    receipt_id = canonical_digest(
        {
            "receipt_kind": "supervisor_pre_dispatch_intent_action",
            "target_attempt_event_ref": (
                authorization.intent.target_attempt_event_ref
            ),
            "request_digest": authorization.request.digest,
            "decision_digest": authorization.decision.digest,
        }
    )
    receipt = ActionReceipt.record(
        receipt_id=receipt_id,
        decision=authorization.decision,
        request=authorization.request,
        executor_id=SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EXECUTOR_ID,
        started_at=action_started_at,
        completed_at=completed_at,
        outcome=ReceiptOutcome.SUCCEEDED,
        obligation_results=obligation_results,
        result_digest=result_digest,
    )
    return {
        "schema_version": (
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EVENT_SCHEMA_VERSION
        ),
        "mode": "enforcing",
        "action_scope": SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE,
        "enforcement_coverage": (
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ENFORCEMENT_COVERAGE
        ),
        "pre_dispatch_intent_digest": authorization.intent.digest,
        "flow_id_ref": authorization.intent.flow_id_ref,
        "attempt_id_ref": authorization.intent.attempt_id_ref,
        "source_flow_event_ref": authorization.intent.source_flow_event_ref,
        "source_attempt_event_ref": authorization.intent.source_attempt_event_ref,
        "target_attempt_event_ref": authorization.intent.target_attempt_event_ref,
        "request_digest": authorization.request.digest,
        "decision_digest": authorization.decision.digest,
        "pre_dispatch_intent_result_digest": result_digest,
        "receipt": receipt.to_canonical(),
        "receipt_digest": receipt.digest,
    }


def _build_request(intent: SupervisorPreDispatchIntent) -> AuthorizationRequest:
    source = intent.source_to_canonical()
    target = intent.target_to_canonical()
    request = AuthorizationRequest(
        request_id=(
            f"{SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE}:"
            f"{intent.target_attempt_event_ref}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:local",
            controller_id="ordomata:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id=canonical_digest(
                {"profile_id": "supervisor_pre_dispatch_intent_bookkeeping"}
            ),
            runner_id="local_non_ai",
            session_id=None,
        ),
        action=ActionAttributes(
            verb=ActionVerb.MODIFY,
            operation=SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_OPERATION,
            parameters_digest=canonical_digest({"source": source, "target": target}),
            intended_effect="append_local_attempt_dispatch_intent_only",
        ),
        resource=ResourceAttributes(
            resource_type=SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_RESOURCE_TYPE,
            identifier=intent.attempt_id_ref,
            version=canonical_digest(source),
            owner="operator:local",
            trust_boundary="local_control_plane",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            content_digest=canonical_digest(
                {
                    "flow_request_digest": intent.flow_request_digest,
                    "input_digest": intent.input_digest,
                    "source": source,
                }
            ),
        ),
        environment=EnvironmentAttributes(
            evaluated_at=intent.occurred_at,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.LOCAL_NON_AI,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=(
                PaidContinuationProtection.NOT_APPLICABLE
            ),
            circuit_state=CircuitState.CLOSED,
            flow_state="attempt_pre_dispatch_created",
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
                f"{SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE}:"
                f"{attribute}"
            ),
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id=f"ordomata:{source.value}",
            observed_at=intent.occurred_at,
            expires_at=intent.occurred_at + _EVIDENCE_LIFETIME_SECONDS,
            authenticated=True,
        )
        for attribute, source in sources
    )
    return replace(request, evidence=evidence)


def _build_policy(intent: SupervisorPreDispatchIntent) -> PolicyBundle:
    base = PolicyBundle.current_stage(issued_at=0.0)
    return PolicyBundle(
        bundle_id=SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_ID,
        version=SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_VERSION,
        issued_at=base.issued_at,
        evidence_requirements=base.evidence_requirements,
        enabled_classes=(PermissionClass.LOCAL_DRAFT,),
        allowed_verbs=(ActionVerb.MODIFY,),
        allowed_roles=(Role.CONTROLLER,),
        allowed_operations=(SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_OPERATION,),
        allowed_resource_types=(
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_RESOURCE_TYPE,
        ),
        allowed_trust_boundaries=("local_control_plane",),
        allowed_flow_states=("attempt_pre_dispatch_created",),
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
    authorization: SupervisorPreDispatchIntentAuthorization,
    *,
    action_started_at: float,
) -> None:
    if not isinstance(authorization, SupervisorPreDispatchIntentAuthorization):
        raise AuthorizationBlocked(
            "supervisor pre-dispatch intent requires a typed authorization permit"
        )
    try:
        rebuilt = _evaluate_supervisor_pre_dispatch_intent_authorization(
            intent=authorization.intent,
            legacy_executable=authorization.legacy_executable,
        )
        fixed_policy = _build_policy(authorization.intent)
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
        != SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_OPERATION
        or request.action.intended_effect
        != "append_local_attempt_dispatch_intent_only"
        or request.resource.resource_type
        != SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_RESOURCE_TYPE
        or request.resource.identifier != authorization.intent.attempt_id_ref
        or request.resource.trust_boundary != "local_control_plane"
        or request.environment.isolation_state is not IsolationState.VERIFIED
        or request.environment.network_state is not NetworkState.DISABLED
        or request.environment.billing_route is not BillingRoute.LOCAL_NON_AI
        or request.environment.capacity_state is not CapacityState.NOT_APPLICABLE
        or request.environment.paid_continuation_protection
        is not PaidContinuationProtection.NOT_APPLICABLE
        or request.environment.circuit_state is not CircuitState.CLOSED
        or request.environment.flow_state != "attempt_pre_dispatch_created"
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
            "supervisor pre-dispatch intent requires a fresh exact Class 1 authorization permit"
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
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE",
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ENFORCEMENT_COVERAGE",
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EVENT_SCHEMA_VERSION",
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EXECUTOR_ID",
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_OPERATION",
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_ID",
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_VERSION",
    "SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_RESOURCE_TYPE",
    "SupervisorPreDispatchIntent",
    "SupervisorPreDispatchIntentAuthorization",
    "SupervisorPreDispatchIntentLease",
    "assert_supervisor_pre_dispatch_intent_authorized",
    "build_supervisor_pre_dispatch_intent_action_receipt",
    "evaluate_supervisor_pre_dispatch_intent_authorization",
]
