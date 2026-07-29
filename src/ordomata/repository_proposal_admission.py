"""Non-enforcing ABAC shadow for one repository-proposal admission.

The public entry point accepts only a durable state path, a run identifier,
and the controller's evaluation time.  It freshly invokes the independent
repository-proposal inspector and never accepts a caller-supplied inspection
report, policy, request, evaluator, or permission class.  A clean inspection
may produce an observational shadow permit; that permit is not reusable
authority and this module exposes no enforcement, persistence, receipt, or
execution API.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
import os
import re
from typing import Any

from .authorization import (
    ActionAttributes,
    ActionVerb,
    AttributeEvidence,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationRequest,
    BlastRadius,
    CircuitState,
    ConsequenceVector,
    DecisionObligation,
    DecisionReason,
    EnvironmentAttributes,
    EvidenceRequirement,
    EvidenceSource,
    ImpactLevel,
    IsolationState,
    NetworkState,
    ObligationKind,
    PolicyBundle,
    Reach,
    ResourceAttributes,
    Role,
    ShadowAuthorizationEvaluator,
    SubjectAttributes,
    canonical_digest,
    derive_permission_class,
)
from .errors import ValidationError
from .models import (
    BillingRoute,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
)
from .repository_proposal_inspection import (
    RepositoryProposalInspectionReport,
    inspect_repository_proposal_evidence,
)


REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION = 1
REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND = (
    "repository_proposal_admission_authorization_shadow"
)
REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE = (
    "repository_proposal_admission_only"
)
REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID = (
    "ordomata.phase-3.repository-proposal-admission-shadow"
)
REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION = "1.0.0"

REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION = (
    "repository_proposal.admission_shadow.observe_read_only"
)
REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION = (
    "repository_proposal.admission_shadow.nominate_local_draft"
)
REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE = (
    "repository_proposal_read_only_admission_shadow"
)
REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE = (
    "repository_proposal_local_draft_admission_shadow"
)

_RUNNER_ID = "repository-proposal-disabled"
_FLOW_STATE = "repository_proposal_admission_proposed"
_TRUST_BOUNDARY = "local_control_plane"
_EVIDENCE_LIFETIME_SECONDS = 60.0
_DECISION_TTL_SECONDS = 30.0
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")

_EVALUATION_STATUSES = frozenset(
    {"evaluated", "not_evaluated", "failed"}
)
_BLOCK_REASON_ORDER = (
    "inspection_not_clean_complete",
    "inspection_run_binding_mismatch",
    "authorization_evaluation_failed",
    "authorization_replay_mismatch",
    "authorization_effect_not_permit",
    "authorization_decision_not_current",
    "authorization_permission_class_mismatch",
    "authorization_obligations_unexpected",
)
_BLOCK_REASON_CODES = frozenset(_BLOCK_REASON_ORDER)
_BLOCK_REASON_RANK = {
    code: index for index, code in enumerate(_BLOCK_REASON_ORDER)
}

_INVALID_REQUEST_MESSAGE = (
    "repository proposal admission shadow request is invalid"
)
_INVALID_INSPECTION_MESSAGE = (
    "repository proposal admission shadow inspection result is invalid"
)
_INVALID_RESULT_MESSAGE = (
    "repository proposal admission shadow result is invalid"
)

# Capture the shipped proof and replay boundaries.  The public API deliberately
# offers no dependency-injection hook for either of them.
_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE = (
    inspect_repository_proposal_evidence
)
_BUILTIN_INSPECTION_TO_MAPPING = (
    RepositoryProposalInspectionReport.to_mapping
)
_BUILTIN_SHADOW_AUTHORIZATION_EVALUATOR = ShadowAuthorizationEvaluator
_BUILTIN_SHADOW_AUTHORIZATION_EVALUATE = (
    ShadowAuthorizationEvaluator.evaluate
)


@dataclass(frozen=True, slots=True)
class _AdmissionProjection:
    permission_class: PermissionClass
    verb: ActionVerb
    operation: str
    intended_effect: str
    resource_type: str
    obligation_kind: ObligationKind


_PROJECTIONS = {
    PermissionClass.READ_ONLY: _AdmissionProjection(
        permission_class=PermissionClass.READ_ONLY,
        verb=ActionVerb.READ,
        operation=REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION,
        intended_effect=(
            "observe_read_only_repository_proposal_admission_without_effect"
        ),
        resource_type=(
            REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE
        ),
        obligation_kind=ObligationKind.READ_ONLY,
    ),
    PermissionClass.LOCAL_DRAFT: _AdmissionProjection(
        permission_class=PermissionClass.LOCAL_DRAFT,
        verb=ActionVerb.CREATE,
        operation=REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION,
        intended_effect=(
            "nominate_local_draft_repository_proposal_without_effect"
        ),
        resource_type=(
            REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE
        ),
        obligation_kind=ObligationKind.ISOLATED_LOCAL_ONLY,
    ),
}


@dataclass(frozen=True, slots=True, init=False)
class RepositoryProposalAdmissionShadow:
    """One bounded, non-authoritative repository-proposal observation."""

    run_ref: str
    inspection: RepositoryProposalInspectionReport
    inspection_digest: str
    evaluated_at: float
    requested_permission_class: PermissionClass | None
    evaluation_status: str
    request: AuthorizationRequest | None
    policy: PolicyBundle | None
    decision: AuthorizationDecision | None
    block_reason_codes: tuple[str, ...]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError(
            "repository proposal admission shadows are factory-created"
        )

    def __setstate__(self, state: Any) -> None:
        del state
        raise TypeError(
            "repository proposal admission shadows are factory-created"
        )

    def __post_init__(self) -> None:
        if (
            not _is_digest(self.run_ref)
            or type(self.inspection) is not RepositoryProposalInspectionReport
            or not _is_digest(self.inspection_digest)
            or not _is_timestamp(self.evaluated_at)
            or self.evaluation_status not in _EVALUATION_STATUSES
            or type(self.block_reason_codes) is not tuple
            or any(
                code not in _BLOCK_REASON_CODES
                for code in self.block_reason_codes
            )
            or len(set(self.block_reason_codes))
            != len(self.block_reason_codes)
            or self.block_reason_codes
            != tuple(
                sorted(
                    self.block_reason_codes,
                    key=_BLOCK_REASON_RANK.__getitem__,
                )
            )
        ):
            raise ValidationError(_INVALID_RESULT_MESSAGE)

        inspection_mapping = _BUILTIN_INSPECTION_TO_MAPPING(
            self.inspection
        )
        if canonical_digest(inspection_mapping) != self.inspection_digest:
            raise ValidationError(_INVALID_RESULT_MESSAGE)

        inspected_class = _inspection_permission_class(self.inspection)
        if self.requested_permission_class is not inspected_class:
            raise ValidationError(_INVALID_RESULT_MESSAGE)

        values = (self.request, self.policy, self.decision)
        if self.evaluation_status == "evaluated":
            if (
                self.run_ref != self.inspection.run_ref
                or not _inspection_is_clean_complete(self.inspection)
                or inspected_class is None
                or type(self.request) is not AuthorizationRequest
                or type(self.policy) is not PolicyBundle
                or type(self.decision) is not AuthorizationDecision
            ):
                raise ValidationError(_INVALID_RESULT_MESSAGE)
            expected_request = _build_request(
                inspection=self.inspection,
                inspection_digest=self.inspection_digest,
                evaluated_at=float(self.evaluated_at),
                permission_class=inspected_class,
            )
            expected_policy = _build_policy(inspected_class)
            expected_decision = _expected_permit_decision(
                expected_request,
                expected_policy,
                inspected_class,
            )
            if (
                self.request != expected_request
                or self.policy != expected_policy
                or self.decision != expected_decision
                or self.block_reason_codes
                != _evaluated_block_reason_codes(
                    self.decision,
                    evaluated_at=float(self.evaluated_at),
                    requested_permission_class=inspected_class,
                )
            ):
                raise ValidationError(_INVALID_RESULT_MESSAGE)
            return

        if any(value is not None for value in values):
            raise ValidationError(_INVALID_RESULT_MESSAGE)
        if self.evaluation_status == "not_evaluated":
            if (
                self.run_ref != self.inspection.run_ref
                or _inspection_is_clean_complete(self.inspection)
                or self.block_reason_codes
                != ("inspection_not_clean_complete",)
            ):
                raise ValidationError(_INVALID_RESULT_MESSAGE)
            return

        if self.block_reason_codes == (
            "inspection_run_binding_mismatch",
        ):
            if self.run_ref == self.inspection.run_ref:
                raise ValidationError(_INVALID_RESULT_MESSAGE)
        elif (
            self.run_ref != self.inspection.run_ref
            or not _inspection_is_clean_complete(self.inspection)
            or self.block_reason_codes
            not in {
                ("authorization_evaluation_failed",),
                ("authorization_replay_mismatch",),
            }
        ):
            raise ValidationError(_INVALID_RESULT_MESSAGE)

    @property
    def decision_current_at_evaluation(self) -> bool:
        return bool(
            self.decision is not None
            and self.decision.issued_at <= self.evaluated_at
            < self.decision.expires_at
        )

    @property
    def permission_class_matches(self) -> bool:
        return bool(
            self.decision is not None
            and self.requested_permission_class is not None
            and self.decision.derived_permission_class
            is self.requested_permission_class
            and self.decision.derived_permission_class
            <= PermissionClass.LOCAL_DRAFT
        )

    @property
    def obligations_exact(self) -> bool:
        if (
            self.decision is None
            or self.requested_permission_class is None
        ):
            return False
        return self.decision.obligations == _expected_obligations(
            self.requested_permission_class
        )

    @property
    def shadow_eligible(self) -> bool:
        if (
            self.evaluation_status != "evaluated"
            or self.block_reason_codes
        ):
            return False
        try:
            self.__post_init__()
        except Exception:
            return False
        return True

    @property
    def effect(self) -> AuthorizationEffect:
        if self.decision is None:
            return AuthorizationEffect.INDETERMINATE
        return self.decision.effect

    def to_mapping(self) -> dict[str, Any]:
        """Return a fresh privacy-safe mapping with explicit no-effect facts."""

        return {
            "schema_version": (
                REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION
            ),
            "kind": REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND,
            "mode": "shadow",
            "action_scope": (
                REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE
            ),
            "decision_authoritative": False,
            "enforcement_enabled": False,
            "authority_granted": False,
            "admission_performed": False,
            "action_performed": False,
            "action_receipt_created": False,
            "evidence_persisted": False,
            "repair_performed": False,
            "dispatch_enabled": False,
            "route_selected": False,
            "billing_assessed": False,
            "obligations_enforced": False,
            "run_ref": self.run_ref,
            "inspection": _BUILTIN_INSPECTION_TO_MAPPING(self.inspection),
            "inspection_digest": self.inspection_digest,
            "requested_permission_class": (
                int(self.requested_permission_class)
                if self.requested_permission_class is not None
                else None
            ),
            "evaluation_status": self.evaluation_status,
            "request": (
                self.request.to_canonical()
                if self.request is not None
                else None
            ),
            "request_digest": (
                self.request.digest if self.request is not None else None
            ),
            "policy": (
                self.policy.to_canonical()
                if self.policy is not None
                else None
            ),
            "policy_digest": (
                self.policy.digest if self.policy is not None else None
            ),
            "decision": (
                self.decision.to_canonical()
                if self.decision is not None
                else None
            ),
            "decision_digest": (
                self.decision.digest
                if self.decision is not None
                else None
            ),
            "effect": self.effect.value,
            "derived_permission_class": (
                int(self.decision.derived_permission_class)
                if self.decision is not None
                else None
            ),
            "decision_current_at_evaluation": (
                self.decision_current_at_evaluation
            ),
            "permission_class_matches": self.permission_class_matches,
            "obligations_exact": self.obligations_exact,
            "shadow_eligible": self.shadow_eligible,
            "block_reason_codes": list(self.block_reason_codes),
            "evaluated_at": float(self.evaluated_at),
        }


def evaluate_repository_proposal_admission_shadow(
    database_path: str | os.PathLike[str],
    *,
    run_id: str,
    evaluated_at: float,
) -> RepositoryProposalAdmissionShadow:
    """Freshly inspect and observe one fixed repository-proposal admission.

    A returned shadow permit is descriptive only.  It cannot authorize an
    admission, state mutation, repository operation, command, worker, route,
    billing assessment, harness invocation, or dispatch.
    """

    timestamp = _validate_evaluated_at(evaluated_at)
    inspection = _BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE(
        database_path,
        run_id=run_id,
    )
    if type(inspection) is not RepositoryProposalInspectionReport:
        raise ValidationError(_INVALID_INSPECTION_MESSAGE)

    inspection_mapping = _BUILTIN_INSPECTION_TO_MAPPING(inspection)
    inspection_digest = canonical_digest(inspection_mapping)
    expected_run_ref = _expected_run_ref(run_id)
    requested_permission_class = _inspection_permission_class(inspection)

    if inspection.run_ref != expected_run_ref:
        return _new_shadow(
            run_ref=expected_run_ref,
            inspection=inspection,
            inspection_digest=inspection_digest,
            evaluated_at=timestamp,
            requested_permission_class=requested_permission_class,
            evaluation_status="failed",
            request=None,
            policy=None,
            decision=None,
            block_reason_codes=("inspection_run_binding_mismatch",),
        )

    if not _inspection_is_clean_complete(inspection):
        return _new_shadow(
            run_ref=expected_run_ref,
            inspection=inspection,
            inspection_digest=inspection_digest,
            evaluated_at=timestamp,
            requested_permission_class=requested_permission_class,
            evaluation_status="not_evaluated",
            request=None,
            policy=None,
            decision=None,
            block_reason_codes=("inspection_not_clean_complete",),
        )

    if requested_permission_class is None:
        return _evaluation_failure(
            run_ref=expected_run_ref,
            inspection=inspection,
            inspection_digest=inspection_digest,
            evaluated_at=timestamp,
            requested_permission_class=None,
        )

    try:
        request = _build_request(
            inspection=inspection,
            inspection_digest=inspection_digest,
            evaluated_at=timestamp,
            permission_class=requested_permission_class,
        )
        policy = _build_policy(requested_permission_class)
        if derive_permission_class(request) is not requested_permission_class:
            raise ValueError("fixed admission projection changed class")

        candidate = ShadowAuthorizationEvaluator().evaluate(request, policy)
        replayed = _BUILTIN_SHADOW_AUTHORIZATION_EVALUATE(
            _BUILTIN_SHADOW_AUTHORIZATION_EVALUATOR(),
            request,
            policy,
        )
        expected = _expected_permit_decision(
            request,
            policy,
            requested_permission_class,
        )
    except Exception:
        return _evaluation_failure(
            run_ref=expected_run_ref,
            inspection=inspection,
            inspection_digest=inspection_digest,
            evaluated_at=timestamp,
            requested_permission_class=requested_permission_class,
        )

    if (
        type(candidate) is not AuthorizationDecision
        or type(replayed) is not AuthorizationDecision
        or candidate != replayed
        or replayed != expected
    ):
        return _evaluation_failure(
            run_ref=expected_run_ref,
            inspection=inspection,
            inspection_digest=inspection_digest,
            evaluated_at=timestamp,
            requested_permission_class=requested_permission_class,
            replay_mismatch=True,
        )

    return _new_shadow(
        run_ref=expected_run_ref,
        inspection=inspection,
        inspection_digest=inspection_digest,
        evaluated_at=timestamp,
        requested_permission_class=requested_permission_class,
        evaluation_status="evaluated",
        request=request,
        policy=policy,
        decision=expected,
        block_reason_codes=_evaluated_block_reason_codes(
            expected,
            evaluated_at=timestamp,
            requested_permission_class=requested_permission_class,
        ),
    )


def _evaluation_failure(
    *,
    run_ref: str,
    inspection: RepositoryProposalInspectionReport,
    inspection_digest: str,
    evaluated_at: float,
    requested_permission_class: PermissionClass | None,
    replay_mismatch: bool = False,
) -> RepositoryProposalAdmissionShadow:
    return _new_shadow(
        run_ref=run_ref,
        inspection=inspection,
        inspection_digest=inspection_digest,
        evaluated_at=evaluated_at,
        requested_permission_class=requested_permission_class,
        evaluation_status="failed",
        request=None,
        policy=None,
        decision=None,
        block_reason_codes=(
            "authorization_replay_mismatch"
            if replay_mismatch
            else "authorization_evaluation_failed",
        ),
    )


def _new_shadow(
    *,
    run_ref: str,
    inspection: RepositoryProposalInspectionReport,
    inspection_digest: str,
    evaluated_at: float,
    requested_permission_class: PermissionClass | None,
    evaluation_status: str,
    request: AuthorizationRequest | None,
    policy: PolicyBundle | None,
    decision: AuthorizationDecision | None,
    block_reason_codes: tuple[str, ...],
) -> RepositoryProposalAdmissionShadow:
    """Create one validated result without exposing a report-taking API."""

    result = object.__new__(RepositoryProposalAdmissionShadow)
    for name, value in (
        ("run_ref", run_ref),
        ("inspection", inspection),
        ("inspection_digest", inspection_digest),
        ("evaluated_at", evaluated_at),
        ("requested_permission_class", requested_permission_class),
        ("evaluation_status", evaluation_status),
        ("request", request),
        ("policy", policy),
        ("decision", decision),
        ("block_reason_codes", block_reason_codes),
    ):
        object.__setattr__(result, name, value)
    result.__post_init__()
    return result


def _build_request(
    *,
    inspection: RepositoryProposalInspectionReport,
    inspection_digest: str,
    evaluated_at: float,
    permission_class: PermissionClass,
) -> AuthorizationRequest:
    projection = _PROJECTIONS[permission_class]
    lineage = {
        "admission_shadow_schema_version": (
            REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION
        ),
        "binding_sequence": inspection.binding_sequence,
        "inspection_digest": inspection_digest,
        "permission_class": int(permission_class),
        "proposal_digest": inspection.proposal_digest,
        "proposal_ref": inspection.proposal_ref,
        "proposal_version_ref": inspection.proposal_version_ref,
        "registration_digest": inspection.registration_digest,
        "registration_ref": inspection.registration_ref,
        "registration_selection_digest": (
            inspection.registration_selection_digest
        ),
        "registration_version": inspection.registration_version,
        "repository_proposal_binding_digest": (
            inspection.repository_proposal_binding_digest
        ),
        "repository_ref": inspection.repository_ref,
        "run_ref": inspection.run_ref,
        "selection_sequence": inspection.selection_sequence,
    }
    environment = EnvironmentAttributes(
        evaluated_at=evaluated_at,
        isolation_state=IsolationState.VERIFIED,
        network_state=NetworkState.DISABLED,
        billing_route=BillingRoute.LOCAL_NON_AI,
        capacity_state=CapacityState.NOT_APPLICABLE,
        paid_continuation_protection=(
            PaidContinuationProtection.NOT_APPLICABLE
        ),
        circuit_state=CircuitState.CLOSED,
        flow_state=_FLOW_STATE,
    )
    request = AuthorizationRequest(
        request_id=(
            f"{REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE}:"
            f"{inspection.run_ref}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:repository-proposal-admission-shadow",
            controller_id="ordomata:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id="profile:not-applicable-local-non-ai",
            runner_id=_RUNNER_ID,
            session_id=f"repository-proposal:{inspection.run_ref}",
        ),
        action=ActionAttributes(
            verb=projection.verb,
            operation=projection.operation,
            parameters_digest=canonical_digest(lineage),
            intended_effect=projection.intended_effect,
        ),
        resource=ResourceAttributes(
            resource_type=projection.resource_type,
            identifier=canonical_digest(
                {
                    "inspection_digest": inspection_digest,
                    "repository_proposal_binding_digest": (
                        inspection.repository_proposal_binding_digest
                    ),
                    "resource_type": projection.resource_type,
                    "run_ref": inspection.run_ref,
                }
            ),
            version=str(inspection.repository_proposal_binding_digest),
            owner="operator:local",
            trust_boundary=_TRUST_BOUNDARY,
            protected=False,
            sensitivity=ImpactLevel.LOW,
            repository_id=inspection.repository_ref,
            content_digest=inspection_digest,
        ),
        environment=environment,
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
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=(
                f"{REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE}:"
                f"{inspection.run_ref}:{attribute}"
            ),
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id=source_id,
            observed_at=evaluated_at,
            expires_at=evaluated_at + _EVIDENCE_LIFETIME_SECONDS,
            authenticated=True,
        )
        for attribute, source, source_id in (
            (
                "subject",
                EvidenceSource.CONTROLLER,
                "ordomata:local-controller",
            ),
            (
                "action",
                EvidenceSource.CONTROLLER,
                "ordomata:local-controller",
            ),
            (
                "resource",
                EvidenceSource.LOCAL_REGISTRY,
                "ordomata:repository-proposal-inspection",
            ),
            (
                "environment",
                EvidenceSource.CONTROLLER,
                "ordomata:local-controller",
            ),
            (
                "consequences",
                EvidenceSource.CONTROLLER,
                "ordomata:local-controller",
            ),
        )
    )
    return replace(request, evidence=evidence)


def _build_policy(permission_class: PermissionClass) -> PolicyBundle:
    projection = _PROJECTIONS[permission_class]
    return PolicyBundle(
        bundle_id=(
            f"{REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID}."
            f"class-{int(permission_class)}"
        ),
        version=REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION,
        issued_at=0.0,
        evidence_requirements=(
            EvidenceRequirement(
                "subject",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "action",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "resource",
                (EvidenceSource.LOCAL_REGISTRY,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "environment",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "consequences",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
        ),
        enabled_classes=(permission_class,),
        allowed_verbs=(projection.verb,),
        allowed_roles=(Role.CONTROLLER,),
        allowed_operations=(projection.operation,),
        allowed_resource_types=(projection.resource_type,),
        allowed_trust_boundaries=(_TRUST_BOUNDARY,),
        allowed_flow_states=(_FLOW_STATE,),
        allowed_network_states=(NetworkState.DISABLED,),
        allowed_billing_routes=(BillingRoute.LOCAL_NON_AI,),
        approval_requirements=(),
        decision_ttl_seconds=_DECISION_TTL_SECONDS,
    )


def _expected_permit_decision(
    request: AuthorizationRequest,
    policy: PolicyBundle,
    permission_class: PermissionClass,
) -> AuthorizationDecision:
    evaluated_at = float(request.environment.evaluated_at)
    return AuthorizationDecision(
        request_id=request.request_id,
        request_digest=request.digest,
        policy_bundle_id=policy.bundle_id,
        policy_version=policy.version,
        policy_digest=policy.digest,
        effect=AuthorizationEffect.PERMIT,
        derived_permission_class=permission_class,
        reason_codes=(DecisionReason.CURRENT_STAGE_PERMIT,),
        reason_details=(
            f"derived Class {int(permission_class)} is enabled in shadow policy",
        ),
        matched_rule_ids=(
            f"phase-1c-class-{int(permission_class)}",
        ),
        evidence_refs=tuple(
            sorted(record.evidence_id for record in request.evidence)
        ),
        issued_at=evaluated_at,
        expires_at=evaluated_at + _DECISION_TTL_SECONDS,
        obligations=_expected_obligations(permission_class),
    )


def _expected_obligations(
    permission_class: PermissionClass,
) -> tuple[DecisionObligation, ...]:
    projection = _PROJECTIONS[permission_class]
    return (
        DecisionObligation(
            ObligationKind.AUDIT_RECEIPT,
            "append_after_action",
        ),
        DecisionObligation(projection.obligation_kind, "required"),
    )


def _evaluated_block_reason_codes(
    decision: AuthorizationDecision,
    *,
    evaluated_at: float,
    requested_permission_class: PermissionClass,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if decision.effect is not AuthorizationEffect.PERMIT:
        reasons.append("authorization_effect_not_permit")
    if not decision.issued_at <= evaluated_at < decision.expires_at:
        reasons.append("authorization_decision_not_current")
    if (
        decision.derived_permission_class is not requested_permission_class
        or decision.derived_permission_class > PermissionClass.LOCAL_DRAFT
    ):
        reasons.append("authorization_permission_class_mismatch")
    if decision.obligations != _expected_obligations(
        requested_permission_class
    ):
        reasons.append("authorization_obligations_unexpected")
    return tuple(reasons)


def _inspection_permission_class(
    inspection: RepositoryProposalInspectionReport,
) -> PermissionClass | None:
    if inspection.permission_class not in (0, 1):
        return None
    return PermissionClass(inspection.permission_class)


def _inspection_is_clean_complete(
    inspection: RepositoryProposalInspectionReport,
) -> bool:
    required_values = (
        inspection.proposal_digest,
        inspection.proposal_ref,
        inspection.proposal_version_ref,
        inspection.registration_digest,
        inspection.registration_ref,
        inspection.registration_version,
        inspection.repository_ref,
        inspection.registration_selection_digest,
        inspection.repository_proposal_binding_digest,
        inspection.selection_sequence,
        inspection.binding_sequence,
    )
    return bool(
        inspection.clean
        and inspection.evidence_complete
        and inspection.coverage == "complete"
        and not inspection.truncated
        and inspection.inspected_event_count == 3
        and inspection.permission_class in (0, 1)
        and inspection.current_status == "created"
        and not inspection.findings
        and all(value is not None for value in required_values)
        and inspection.selection_sequence < inspection.binding_sequence
    )


def _expected_run_ref(run_id: Any) -> str:
    if type(run_id) is not str:
        raise ValidationError(_INVALID_REQUEST_MESSAGE)
    try:
        return canonical_digest({"run_id": run_id})
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise ValidationError(_INVALID_REQUEST_MESSAGE) from None


def _validate_evaluated_at(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        raise ValidationError(_INVALID_REQUEST_MESSAGE)
    try:
        timestamp = float(value)
    except (OverflowError, TypeError, ValueError):
        raise ValidationError(_INVALID_REQUEST_MESSAGE) from None
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValidationError(_INVALID_REQUEST_MESSAGE)
    return timestamp


def _is_timestamp(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        timestamp = float(value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(timestamp) and timestamp >= 0


def _is_digest(value: Any) -> bool:
    return bool(
        type(value) is str
        and _DIGEST_PATTERN.fullmatch(value) is not None
    )


__all__ = [
    "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE",
    "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND",
    "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID",
    "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION",
    "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION",
    "REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION",
    "REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE",
    "REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION",
    "REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE",
    "RepositoryProposalAdmissionShadow",
    "evaluate_repository_proposal_admission_shadow",
]
