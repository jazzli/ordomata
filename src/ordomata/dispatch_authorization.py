"""First authoritative ABAC enforcement point for ordinary mock dispatch.

This module is deliberately narrow.  It authorizes only a profile-backed,
deterministic in-memory mock attempt at the exact ``runner.execute`` boundary.
It cannot authorize a live harness, comparison trial, supervisor claim,
repository worker, mediated tool, external effect, or Permission Class 2/3.
The existing numeric Class 0/1 gate remains an independent prerequisite.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import re
from typing import Any

from .authorization import (
    ActionAttributes,
    ActionReceipt,
    ActionVerb,
    ApprovalRequirement,
    AttributeEvidence,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationEvaluator,
    AuthorizationRequest,
    CircuitState,
    ConsequenceVector,
    EnvironmentAttributes,
    EvidenceSource,
    IsolationState,
    NetworkState,
    ObligationKind,
    ObligationResult,
    PolicyBundle,
    ReceiptOutcome,
    ResourceAttributes,
    Role,
    SubjectAttributes,
    canonical_digest,
)
from .contracts import TaskContract
from .errors import AuthorizationBlocked, ValidationError
from .models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    PermissionClass,
    RunRequest,
)
from .shadow_authorization import resolve_task_authorization_intent
from .task_evidence import (
    TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
)


MOCK_DISPATCH_DECISION_EVENT_TYPE = (
    "task_attempt_mock_dispatch_authorization_decision"
)
MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE = (
    "task_attempt_mock_dispatch_action_receipt"
)
MOCK_DISPATCH_ACTION_SCOPE = "ordinary_mock_runner_dispatch_only"
MOCK_DISPATCH_OPERATION = "runner.execute_mock_attempt"
MOCK_DISPATCH_RESOURCE_TYPE = "mock_runner_attempt"
MOCK_DISPATCH_POLICY_ID = "ordomata.phase-1c.mock-dispatch-enforcement"
MOCK_DISPATCH_POLICY_VERSION = "1.0.0"
MOCK_DISPATCH_EXECUTOR_ID = "ordomata:in-memory-mock-executor"
MOCK_DISPATCH_EVENT_SCHEMA_VERSION = 1

_EVIDENCE_LIFETIME_SECONDS = 120.0
_PRE_RUN_APPROVAL_REQUIREMENT = "task_contract_pre_run_operator_approval"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_PROFILE_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
_BILLING_ASSESSMENT_PAYLOAD_KEYS = frozenset(
    {
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
    }
)
_FIXED_PERMIT_OBLIGATIONS = frozenset(
    {
        (ObligationKind.AUDIT_RECEIPT, "append_after_action"),
        (ObligationKind.ISOLATED_LOCAL_ONLY, "required"),
    }
)

# Retain the shipped evaluator implementation for the final independent replay.
# Runtime tests and integrations may patch the public evaluator entry point, but
# a patchable first-pass decision must never become its own authority.
_BUILTIN_AUTHORIZATION_EVALUATOR = AuthorizationEvaluator
_BUILTIN_AUTHORIZATION_EVALUATE = AuthorizationEvaluator.evaluate


@dataclass(frozen=True, slots=True)
class MockDispatchAuthorization:
    """Typed request, fixed policy, and immutable decision at the mock PEP."""

    request: AuthorizationRequest
    policy: PolicyBundle
    decision: AuthorizationDecision
    task_attempt_binding_digest: str
    execution_selection_digest: str
    billing_assessment_digest: str
    task_authorization_intent_digest: str
    requested_permission_class: PermissionClass
    legacy_executable: bool
    authority_ceiling_satisfied: bool
    obligations_supported: bool
    decision_current_at_evaluation: bool
    block_reason_codes: tuple[str, ...]

    @property
    def authorized_at_evaluation(self) -> bool:
        return not self.block_reason_codes

    def to_event_payload(self) -> dict[str, Any]:
        """Return the strict privacy-safe decision wrapper for durable append."""

        return _mock_dispatch_event_payload(self)


def _mock_dispatch_event_payload(
    authorization: MockDispatchAuthorization,
) -> dict[str, Any]:
    """Construct the fixed durable wrapper without invoking a patchable method."""

    return {
        "schema_version": MOCK_DISPATCH_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": MOCK_DISPATCH_ACTION_SCOPE,
        "enforcement_coverage": (
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
        ),
        "task_attempt_binding_digest": (
            authorization.task_attempt_binding_digest
        ),
        "execution_selection_digest": (
            authorization.execution_selection_digest
        ),
        "billing_assessment_digest": (
            authorization.billing_assessment_digest
        ),
        "task_authorization_intent_digest": (
            authorization.task_authorization_intent_digest
        ),
        "requested_permission_class": int(
            authorization.requested_permission_class
        ),
        "legacy_executable": authorization.legacy_executable,
        "request": authorization.request.to_canonical(),
        "request_digest": authorization.request.digest,
        "policy": authorization.policy.to_canonical(),
        "policy_digest": authorization.policy.digest,
        "decision": authorization.decision.to_canonical(),
        "decision_digest": authorization.decision.digest,
        "effect": authorization.decision.effect.value,
        "derived_permission_class": int(
            authorization.decision.derived_permission_class
        ),
        "decision_current_at_evaluation": (
            authorization.decision_current_at_evaluation
        ),
        "authority_ceiling_satisfied": (
            authorization.authority_ceiling_satisfied
        ),
        "obligations_supported": authorization.obligations_supported,
        "authorization_eligible": authorization.authorized_at_evaluation,
        "block_reason_codes": list(authorization.block_reason_codes),
        "evaluated_at": float(
            authorization.request.environment.evaluated_at
        ),
    }


def evaluate_mock_dispatch_authorization(
    *,
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    context_digest: str,
    prompt_digest: str,
    billing_assessment: BillingRouteAssessment,
    billing_assessment_payload: Mapping[str, Any],
    billing_assessment_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> MockDispatchAuthorization:
    """Evaluate the exact deterministic mock invocation under a fixed policy."""

    return _evaluate_mock_dispatch_authorization(
        contract=contract,
        request=request,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        task_attempt_binding_digest=task_attempt_binding_digest,
        execution_selection_digest=execution_selection_digest,
        context_digest=context_digest,
        prompt_digest=prompt_digest,
        billing_assessment=billing_assessment,
        billing_assessment_payload=billing_assessment_payload,
        billing_assessment_digest=billing_assessment_digest,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
    )


def _evaluate_mock_dispatch_authorization(
    *,
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    context_digest: str,
    prompt_digest: str,
    billing_assessment: BillingRouteAssessment,
    billing_assessment_payload: Mapping[str, Any],
    billing_assessment_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> MockDispatchAuthorization:
    """Authoritative implementation used directly by the final PEP rebuild."""

    _validate_evaluation_inputs(
        contract=contract,
        request=request,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        digests=(
            ("task attempt binding", task_attempt_binding_digest),
            ("execution selection", execution_selection_digest),
            ("context", context_digest),
            ("prompt", prompt_digest),
            ("billing assessment", billing_assessment_digest),
        ),
        prompt_digest=prompt_digest,
        billing_assessment=billing_assessment,
        billing_assessment_payload=billing_assessment_payload,
        billing_assessment_digest=billing_assessment_digest,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
    )

    task_intent, _ = resolve_task_authorization_intent(contract)
    task_intent_digest = task_intent.digest
    profile_ref = canonical_digest({"profile_id": profile_id})
    repository_ref = canonical_digest({"project_root": str(project_root)})
    workspace_ref = canonical_digest({"workspace": str(request.workspace)})
    run_ref = canonical_digest({"run_id": request.run_id})
    environment = EnvironmentAttributes(
        evaluated_at=evaluated_at,
        isolation_state=IsolationState.VERIFIED,
        network_state=NetworkState.DISABLED,
        billing_route=BillingRoute.MOCK,
        capacity_state=billing_assessment.capacity_state,
        paid_continuation_protection=(
            billing_assessment.paid_continuation_protection
        ),
        circuit_state=CircuitState.CLOSED,
        flow_state="runner_dispatch_proposed",
    )
    authorization_request = AuthorizationRequest(
        request_id=f"{MOCK_DISPATCH_ACTION_SCOPE}:{request.run_id}",
        subject=SubjectAttributes(
            principal_id="agent:task-attempt",
            controller_id="ordomata:local-controller",
            role=Role.IMPLEMENTER,
            role_version="1",
            profile_id=profile_ref,
            runner_id="mock",
            session_id=f"attempt:{request.run_id}",
        ),
        action=ActionAttributes(
            verb=ActionVerb.EXECUTE,
            operation=MOCK_DISPATCH_OPERATION,
            parameters_digest=canonical_digest(
                {
                    "attempt": request.attempt,
                    "billing_assessment_digest": billing_assessment_digest,
                    "context_digest": context_digest,
                    "execution_selection_digest": execution_selection_digest,
                    "output_schema_digest": canonical_digest(
                        request.output_schema
                    ),
                    "profile_ref": profile_ref,
                    "prompt_digest": prompt_digest,
                    "run_ref": run_ref,
                    "runner_overrides_digest": canonical_digest(
                        dict(request.runner_overrides)
                    ),
                    "task_attempt_binding_digest": (
                        task_attempt_binding_digest
                    ),
                    "task_authorization_intent_digest": task_intent_digest,
                    "task_definition_digest": contract.definition_hash,
                    "timeout_seconds": request.timeout_seconds,
                    "workspace_ref": workspace_ref,
                }
            ),
            intended_effect="execute_deterministic_in_memory_mock_attempt",
        ),
        resource=ResourceAttributes(
            resource_type=MOCK_DISPATCH_RESOURCE_TYPE,
            identifier=canonical_digest(
                {
                    "resource_type": MOCK_DISPATCH_RESOURCE_TYPE,
                    "run_ref": run_ref,
                    "workspace_ref": workspace_ref,
                }
            ),
            version=contract.definition_hash,
            owner="operator:local",
            trust_boundary="isolated_run_workspace",
            protected=task_intent.resource.protected,
            sensitivity=task_intent.resource.sensitivity,
            repository_id=repository_ref,
            content_digest=prompt_digest,
        ),
        environment=environment,
        consequences=ConsequenceVector(
            confidentiality=task_intent.consequences.confidentiality,
            integrity=task_intent.consequences.integrity,
            availability=task_intent.consequences.availability,
            reach=task_intent.consequences.reach,
            destructive=task_intent.consequences.destructive,
            reversible=task_intent.consequences.reversible,
            sensitivity=task_intent.consequences.sensitivity,
            blast_radius=task_intent.consequences.blast_radius,
        ),
    )
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=f"{MOCK_DISPATCH_ACTION_SCOPE}:{attribute}",
            attribute=attribute,
            value=authorization_request.attribute_value(attribute),
            source=source,
            source_id=f"ordomata:{source.value}",
            observed_at=evaluated_at,
            expires_at=evaluated_at + _EVIDENCE_LIFETIME_SECONDS,
            authenticated=True,
        )
        for attribute, source in (
            ("subject", EvidenceSource.CONTROLLER),
            ("action", EvidenceSource.LOCAL_REGISTRY),
            ("resource", EvidenceSource.LOCAL_REGISTRY),
            ("environment", EvidenceSource.CONTROLLER),
            ("consequences", EvidenceSource.LOCAL_REGISTRY),
        )
    )
    authorization_request = replace(
        authorization_request,
        evidence=evidence,
    )

    policy = _mock_dispatch_policy(
        contract=contract,
        requested_permission_class=request.permission_class,
    )
    decision = AuthorizationEvaluator().evaluate(
        authorization_request,
        policy,
    )
    if not isinstance(decision, AuthorizationDecision):
        raise ValidationError("authorization evaluator returned an invalid decision")

    policy_matches = _policy_and_decision_match(
        authorization_request,
        policy,
        decision,
        evaluated_at=evaluated_at,
    )
    decision_current = (
        decision.issued_at <= evaluated_at < decision.expires_at
    )
    authority_ceiling_satisfied = (
        decision.derived_permission_class <= request.permission_class
        and decision.derived_permission_class
        <= PermissionClass.LOCAL_DRAFT
    )
    obligations_supported = _obligations_supported(decision)
    block_reasons: list[str] = []
    if not legacy_executable:
        block_reasons.append("legacy_gate_not_executable")
    if not policy_matches:
        block_reasons.append("authorization_policy_mismatch")
    if decision.effect is not AuthorizationEffect.PERMIT:
        block_reasons.append("authorization_effect_not_permit")
    if not decision_current:
        block_reasons.append("authorization_decision_not_current")
    if not authority_ceiling_satisfied:
        block_reasons.append("authorization_class_ceiling_exceeded")
    if not obligations_supported:
        block_reasons.append("authorization_obligation_unsupported")

    return MockDispatchAuthorization(
        request=authorization_request,
        policy=policy,
        decision=decision,
        task_attempt_binding_digest=task_attempt_binding_digest,
        execution_selection_digest=execution_selection_digest,
        billing_assessment_digest=billing_assessment_digest,
        task_authorization_intent_digest=task_intent_digest,
        requested_permission_class=request.permission_class,
        legacy_executable=legacy_executable,
        authority_ceiling_satisfied=authority_ceiling_satisfied,
        obligations_supported=obligations_supported,
        decision_current_at_evaluation=decision_current,
        block_reason_codes=tuple(block_reasons),
    )


def build_mock_dispatch_failure_payload(
    *,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    billing_assessment_digest: str,
    task_authorization_intent_digest: str,
    requested_permission_class: PermissionClass,
    legacy_executable: bool,
    evaluated_at: float,
) -> dict[str, Any]:
    """Return a fixed, redacted indeterminate record after build/eval failure."""

    return {
        "schema_version": MOCK_DISPATCH_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": MOCK_DISPATCH_ACTION_SCOPE,
        "enforcement_coverage": (
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
        ),
        "task_attempt_binding_digest": task_attempt_binding_digest,
        "execution_selection_digest": execution_selection_digest,
        "billing_assessment_digest": billing_assessment_digest,
        "task_authorization_intent_digest": (
            task_authorization_intent_digest
        ),
        "requested_permission_class": int(requested_permission_class),
        "legacy_executable": legacy_executable,
        "request": None,
        "request_digest": None,
        "policy": None,
        "policy_digest": None,
        "decision": None,
        "decision_digest": None,
        "effect": AuthorizationEffect.INDETERMINATE.value,
        "derived_permission_class": None,
        "decision_current_at_evaluation": False,
        "authority_ceiling_satisfied": False,
        "obligations_supported": False,
        "authorization_eligible": False,
        "block_reason_codes": ["authorization_evaluation_failed"],
        "evaluated_at": float(evaluated_at),
        "failure_stage": "request_or_evaluation",
    }


def assert_mock_dispatch_authorized(
    authorization: MockDispatchAuthorization,
    *,
    action_started_at: float,
    persisted_payload: Mapping[str, Any],
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    controller_owned_mock_runner: bool,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    context_digest: str,
    prompt_digest: str,
    billing_assessment: BillingRouteAssessment,
    billing_assessment_payload: Mapping[str, Any],
    billing_assessment_digest: str,
    legacy_executable: bool,
) -> None:
    """Rebuild and require the exact persisted permit at runner invocation."""

    if not isinstance(authorization, MockDispatchAuthorization):
        raise AuthorizationBlocked(
            "mock dispatch requires a typed authorization permit"
        )
    try:
        rebuilt = _evaluate_mock_dispatch_authorization(
            contract=contract,
            request=request,
            runner_id=runner_id,
            profile_id=profile_id,
            project_root=project_root,
            task_attempt_binding_digest=task_attempt_binding_digest,
            execution_selection_digest=execution_selection_digest,
            context_digest=context_digest,
            prompt_digest=prompt_digest,
            billing_assessment=billing_assessment,
            billing_assessment_payload=billing_assessment_payload,
            billing_assessment_digest=billing_assessment_digest,
            evaluated_at=authorization.request.environment.evaluated_at,
            legacy_executable=legacy_executable,
        )
        exact_binding = bool(
            controller_owned_mock_runner is True
            and authorization == rebuilt
            and _mock_dispatch_event_payload(rebuilt)
            == dict(persisted_payload)
        )
    except Exception:
        exact_binding = False
    if not exact_binding:
        raise AuthorizationBlocked(
            "mock dispatch requires an exact persisted authorization permit"
        )

    _assert_mock_dispatch_permit_current(
        authorization,
        action_started_at=action_started_at,
        contract=contract,
    )


def assert_mock_dispatch_fresh_at_action_start(
    authorization: MockDispatchAuthorization,
    *,
    action_started_at: float,
) -> None:
    """Recheck only immutable permit freshness at the actual effect boundary."""

    if (
        not isinstance(authorization, MockDispatchAuthorization)
        or not authorization.authorized_at_evaluation
        or not authorization.decision_current_at_evaluation
        or not _valid_timestamp(action_started_at)
        or action_started_at < authorization.decision.issued_at
        or action_started_at >= authorization.decision.expires_at
    ):
        raise AuthorizationBlocked(
            "mock dispatch permit is not current at the action boundary"
        )


def _assert_mock_dispatch_permit_current(
    authorization: MockDispatchAuthorization,
    *,
    action_started_at: float,
    contract: TaskContract,
) -> None:
    """Independently re-evaluate fixed policy and require a current permit."""

    if (
        not isinstance(authorization, MockDispatchAuthorization)
        or not isinstance(authorization.request, AuthorizationRequest)
        or not isinstance(authorization.policy, PolicyBundle)
        or not isinstance(authorization.decision, AuthorizationDecision)
        or not isinstance(contract, TaskContract)
    ):
        raise AuthorizationBlocked(
            "mock dispatch requires a typed authorization permit"
        )

    request = authorization.request
    decision = authorization.decision
    policy = authorization.policy
    try:
        task_intent, _ = resolve_task_authorization_intent(contract)
        expected_consequences = ConsequenceVector(
            confidentiality=task_intent.consequences.confidentiality,
            integrity=task_intent.consequences.integrity,
            availability=task_intent.consequences.availability,
            reach=task_intent.consequences.reach,
            destructive=task_intent.consequences.destructive,
            reversible=task_intent.consequences.reversible,
            sensitivity=task_intent.consequences.sensitivity,
            blast_radius=task_intent.consequences.blast_radius,
        )
        fixed_policy = _mock_dispatch_policy(
            contract=contract,
            requested_permission_class=authorization.requested_permission_class,
        )
        reevaluated_decision = _BUILTIN_AUTHORIZATION_EVALUATE(
            _BUILTIN_AUTHORIZATION_EVALUATOR(),
            request,
            fixed_policy,
        )
    except Exception:
        task_intent = None
        expected_consequences = None
        fixed_policy = None
        reevaluated_decision = None
    obligation_pairs = tuple(
        (obligation.kind, obligation.value)
        for obligation in decision.obligations
    )
    if (
        not authorization.authorized_at_evaluation
        or not authorization.legacy_executable
        or not authorization.authority_ceiling_satisfied
        or not authorization.obligations_supported
        or not authorization.decision_current_at_evaluation
        or authorization.requested_permission_class
        is not contract.permission_class
        or task_intent is None
        or authorization.task_authorization_intent_digest != task_intent.digest
        or policy != fixed_policy
        or decision != reevaluated_decision
        or policy.bundle_id != MOCK_DISPATCH_POLICY_ID
        or policy.version != MOCK_DISPATCH_POLICY_VERSION
        or decision.effect is not AuthorizationEffect.PERMIT
        or decision.request_id != request.request_id
        or decision.request_digest != request.digest
        or decision.policy_bundle_id != policy.bundle_id
        or decision.policy_version != policy.version
        or decision.policy_digest != policy.digest
        or request.subject.runner_id != "mock"
        or request.subject.role is not Role.IMPLEMENTER
        or request.action.verb is not ActionVerb.EXECUTE
        or request.action.operation != MOCK_DISPATCH_OPERATION
        or request.action.intended_effect
        != "execute_deterministic_in_memory_mock_attempt"
        or request.resource.resource_type != MOCK_DISPATCH_RESOURCE_TYPE
        or request.resource.version != contract.definition_hash
        or request.resource.trust_boundary != "isolated_run_workspace"
        or request.resource.protected != task_intent.resource.protected
        or request.resource.sensitivity is not task_intent.resource.sensitivity
        or request.consequences != expected_consequences
        or request.environment.isolation_state is not IsolationState.VERIFIED
        or request.environment.network_state is not NetworkState.DISABLED
        or request.environment.billing_route is not BillingRoute.MOCK
        or request.environment.circuit_state is not CircuitState.CLOSED
        or request.environment.flow_state != "runner_dispatch_proposed"
        or len(obligation_pairs) != len(_FIXED_PERMIT_OBLIGATIONS)
        or len(set(obligation_pairs)) != len(obligation_pairs)
        or frozenset(obligation_pairs) != _FIXED_PERMIT_OBLIGATIONS
        or decision.derived_permission_class
        > authorization.requested_permission_class
        or decision.derived_permission_class > PermissionClass.LOCAL_DRAFT
        or not _valid_timestamp(action_started_at)
        or action_started_at < decision.issued_at
        or action_started_at >= decision.expires_at
    ):
        raise AuthorizationBlocked(
            "mock dispatch requires a fresh exact Class 0/1 authorization permit"
        )


def build_mock_dispatch_action_receipt(
    *,
    authorization: MockDispatchAuthorization,
    contract: TaskContract,
    action_started_at: float,
    completed_at: float,
    outcome: ReceiptOutcome,
    result_digest: str | None,
) -> dict[str, Any]:
    """Build the exact terminal receipt whose durable append satisfies audit."""

    _assert_mock_dispatch_permit_current(
        authorization,
        action_started_at=action_started_at,
        contract=contract,
    )
    if not _valid_timestamp(completed_at) or completed_at < action_started_at:
        raise ValidationError("mock dispatch completion time is invalid")
    obligation_results = tuple(
        ObligationResult(
            kind=obligation.kind,
            value=obligation.value,
            satisfied=True,
        )
        for obligation in authorization.decision.obligations
    )
    receipt_id = canonical_digest(
        {
            "decision_digest": authorization.decision.digest,
            "request_digest": authorization.request.digest,
            "task_attempt_binding_digest": (
                authorization.task_attempt_binding_digest
            ),
            "receipt_kind": "mock_dispatch_action",
        }
    )
    receipt = ActionReceipt.record(
        receipt_id=receipt_id,
        decision=authorization.decision,
        request=authorization.request,
        executor_id=MOCK_DISPATCH_EXECUTOR_ID,
        started_at=action_started_at,
        completed_at=completed_at,
        outcome=outcome,
        obligation_results=obligation_results,
        result_digest=result_digest,
    )
    return {
        "schema_version": MOCK_DISPATCH_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": MOCK_DISPATCH_ACTION_SCOPE,
        "enforcement_coverage": (
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
        ),
        "task_attempt_binding_digest": (
            authorization.task_attempt_binding_digest
        ),
        "execution_selection_digest": (
            authorization.execution_selection_digest
        ),
        "request_digest": authorization.request.digest,
        "decision_digest": authorization.decision.digest,
        "receipt": receipt.to_canonical(),
        "receipt_digest": receipt.digest,
    }


def _mock_dispatch_policy(
    *,
    contract: TaskContract,
    requested_permission_class: PermissionClass,
) -> PolicyBundle:
    """Build the only policy bundle valid at the mock-dispatch boundary."""

    if not isinstance(contract, TaskContract):
        raise ValidationError("mock dispatch policy requires a task contract")
    if requested_permission_class not in {
        PermissionClass.READ_ONLY,
        PermissionClass.LOCAL_DRAFT,
    }:
        raise ValidationError("mock dispatch policy supports only Class 0/1")
    approval_requirements: tuple[ApprovalRequirement, ...] = ()
    if contract.approval_requirements.required_before_run:
        approval_requirements = (
            ApprovalRequirement(
                requirement_id=_PRE_RUN_APPROVAL_REQUIREMENT,
                verbs=(ActionVerb.EXECUTE,),
                resource_types=(MOCK_DISPATCH_RESOURCE_TYPE,),
                allowed_approver_ids=(
                    canonical_digest(
                        {
                            "approver": (
                                contract.approval_requirements.approver
                            )
                        }
                    ),
                ),
            ),
        )
    enabled_classes = tuple(
        permission_class
        for permission_class in (
            PermissionClass.READ_ONLY,
            PermissionClass.LOCAL_DRAFT,
        )
        if permission_class <= requested_permission_class
    )
    return replace(
        PolicyBundle.current_stage(
            issued_at=0.0,
            approval_requirements=approval_requirements,
        ),
        bundle_id=MOCK_DISPATCH_POLICY_ID,
        version=MOCK_DISPATCH_POLICY_VERSION,
        enabled_classes=enabled_classes,
        allowed_verbs=(ActionVerb.EXECUTE,),
        allowed_operations=(MOCK_DISPATCH_OPERATION,),
        allowed_resource_types=(MOCK_DISPATCH_RESOURCE_TYPE,),
        allowed_trust_boundaries=("isolated_run_workspace",),
        allowed_flow_states=("runner_dispatch_proposed",),
        allowed_network_states=(NetworkState.DISABLED,),
        allowed_billing_routes=(BillingRoute.MOCK,),
    )


def _validate_evaluation_inputs(
    *,
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    digests: tuple[tuple[str, str], ...],
    prompt_digest: str,
    billing_assessment: BillingRouteAssessment,
    billing_assessment_payload: Mapping[str, Any],
    billing_assessment_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> None:
    if not isinstance(contract, TaskContract) or not isinstance(
        request,
        RunRequest,
    ):
        raise ValidationError("mock dispatch authorization inputs are invalid")
    if runner_id != "mock":
        raise ValidationError("mock dispatch authorization requires the mock runner")
    if not isinstance(profile_id, str) or _PROFILE_PATTERN.fullmatch(
        profile_id
    ) is None:
        raise ValidationError("mock dispatch authorization requires a safe profile")
    if not isinstance(project_root, Path) or not project_root.is_absolute():
        raise ValidationError("mock dispatch project root must be absolute")
    if (
        not isinstance(request.workspace, Path)
        or not request.workspace.is_absolute()
        or not isinstance(request.run_directory, Path)
        or not request.run_directory.is_absolute()
    ):
        raise ValidationError("mock dispatch paths must be absolute")
    try:
        request.run_directory.relative_to(project_root)
        request.workspace.relative_to(request.run_directory)
    except ValueError as error:
        raise ValidationError("mock dispatch paths are not contained") from error
    if request.workspace.parent != request.run_directory:
        raise ValidationError("mock dispatch workspace layout is invalid")
    if (
        request.task_id != contract.task_id
        or request.task_version != contract.version
    ):
        raise ValidationError("mock dispatch request identity is inconsistent")
    if request.permission_class is not contract.permission_class:
        raise ValidationError("mock dispatch permission class is inconsistent")
    if request.timeout_seconds != contract.timeout_seconds or request.attempt != 1:
        raise ValidationError("mock dispatch attempt limits are inconsistent")
    try:
        output_schema_matches = canonical_digest(
            request.output_schema
        ) == canonical_digest(contract.output_schema)
        prompt_matches = (
            "sha256:"
            + hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()
            == prompt_digest
        )
    except (AttributeError, TypeError, ValueError):
        output_schema_matches = False
        prompt_matches = False
    if not output_schema_matches:
        raise ValidationError("mock dispatch output schema is inconsistent")
    if not prompt_matches:
        raise ValidationError("mock dispatch prompt digest is inconsistent")
    if request.permission_class not in {
        PermissionClass.READ_ONLY,
        PermissionClass.LOCAL_DRAFT,
    }:
        raise ValidationError("mock dispatch authorization supports only Class 0/1")
    for name, value in digests:
        if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
            raise ValidationError(f"{name} digest is invalid")
    if not isinstance(legacy_executable, bool):
        raise ValidationError("legacy executable evidence must be a boolean")
    if not _valid_timestamp(evaluated_at):
        raise ValidationError("mock dispatch evaluation time is invalid")
    if not isinstance(billing_assessment, BillingRouteAssessment):
        raise ValidationError("mock dispatch billing assessment is invalid")
    if billing_assessment.runner_id != "mock":
        raise ValidationError("mock dispatch billing runner is inconsistent")
    if (
        billing_assessment.route is not BillingRoute.MOCK
        or billing_assessment.confidence is not AssessmentConfidence.HIGH
    ):
        raise ValidationError(
            "mock dispatch authorization requires verified mock billing evidence"
        )
    if not _billing_assessment_payload_matches(
        billing_assessment,
        billing_assessment_payload,
        billing_assessment_digest,
    ):
        raise ValidationError("mock dispatch billing evidence is inconsistent")


def _billing_assessment_payload_matches(
    assessment: BillingRouteAssessment,
    payload: Mapping[str, Any],
    expected_digest: str,
) -> bool:
    try:
        candidate = dict(payload)
        if frozenset(candidate) != _BILLING_ASSESSMENT_PAYLOAD_KEYS:
            return False
        if (
            isinstance(candidate["schema_version"], bool)
            or candidate["schema_version"] != 1
            or not isinstance(candidate["account_identity_verified"], bool)
            or not isinstance(candidate["attestation_present"], bool)
        ):
            return False
        embedded_digest = candidate.pop("assessment_digest")
        if (
            not isinstance(embedded_digest, str)
            or _DIGEST_PATTERN.fullmatch(embedded_digest) is None
            or embedded_digest != expected_digest
            or canonical_digest(candidate) != embedded_digest
        ):
            return False
        return candidate == _billing_assessment_projection(assessment)
    except (AttributeError, TypeError, ValueError):
        return False


def _billing_assessment_projection(
    assessment: BillingRouteAssessment,
) -> dict[str, Any]:
    safe_subscription_name = {
        "ChatGPT": "ChatGPT",
        "Claude": "Claude",
    }.get(assessment.subscription_name or "")
    fingerprint = assessment.account_identity_fingerprint
    account_identity_verified = bool(
        isinstance(fingerprint, str)
        and len(fingerprint) == 64
        and all(character in "0123456789abcdef" for character in fingerprint)
    )
    return {
        "schema_version": 1,
        "runner_id": assessment.runner_id,
        "route": assessment.route.value,
        "confidence": assessment.confidence.value,
        "subscription_name": safe_subscription_name,
        "capacity_state": assessment.capacity_state.value,
        "paid_continuation_protection": (
            assessment.paid_continuation_protection.value
        ),
        "paid_credit_balance": assessment.paid_credit_balance.value,
        "account_identity_verified": account_identity_verified,
        "attestation_present": assessment.attestation is not None,
    }


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
    obligation_pairs = tuple(
        (obligation.kind, obligation.value)
        for obligation in decision.obligations
    )
    return bool(
        len(obligation_pairs) == len(_FIXED_PERMIT_OBLIGATIONS)
        and len(set(obligation_pairs)) == len(obligation_pairs)
        and frozenset(obligation_pairs) == _FIXED_PERMIT_OBLIGATIONS
    )


def _valid_timestamp(value: Any) -> bool:
    return bool(
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and float(value) >= 0.0
        and float(value) != float("inf")
        and float(value) != float("-inf")
        and float(value) == float(value)
    )


__all__ = [
    "MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE",
    "MOCK_DISPATCH_ACTION_SCOPE",
    "MOCK_DISPATCH_DECISION_EVENT_TYPE",
    "MOCK_DISPATCH_EVENT_SCHEMA_VERSION",
    "MOCK_DISPATCH_EXECUTOR_ID",
    "MOCK_DISPATCH_OPERATION",
    "MOCK_DISPATCH_POLICY_ID",
    "MOCK_DISPATCH_POLICY_VERSION",
    "MOCK_DISPATCH_RESOURCE_TYPE",
    "MockDispatchAuthorization",
    "assert_mock_dispatch_authorized",
    "assert_mock_dispatch_fresh_at_action_start",
    "build_mock_dispatch_action_receipt",
    "build_mock_dispatch_failure_payload",
    "evaluate_mock_dispatch_authorization",
]
