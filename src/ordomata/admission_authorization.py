"""Authoritative ABAC gate for one ordinary mock task admission.

This module is deliberately narrow.  It can authorize only the controller's
local, reversible admission of a new profile-backed attempt that will use the
exact built-in in-memory mock runner.  Admission is a controller bookkeeping
action; it is not authority to dispatch a runner or publish an artifact.  The
separate dispatch and publication PEPs, and the existing Class 0/1 gate,
remain independent prerequisites.
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
    BlastRadius,
    CircuitState,
    ConsequenceVector,
    EnvironmentAttributes,
    EvidenceSource,
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
from .contracts import (
    TaskActionIntent,
    TaskAuthorizationIntent,
    TaskConsequenceIntent,
    TaskContract,
    TaskResourceIntent,
)
from .errors import AuthorizationBlocked, ValidationError
from .models import (
    BillingRoute,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
    RunRequest,
)
from .shadow_authorization import resolve_task_authorization_intent
from .task_evidence import TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE


TASK_ADMISSION_DECISION_EVENT_TYPE = (
    "task_attempt_admission_authorization_decision"
)
TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE = (
    "task_attempt_admission_action_receipt"
)
TASK_ADMISSION_ACTION_SCOPE = (
    "ordinary_profile_backed_mock_task_admission_only"
)
TASK_ADMISSION_ENFORCEMENT_COVERAGE = (
    TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE
)
_PRE_RUN_APPROVAL_REQUIREMENT = "task_contract_pre_run_operator_approval"
TASK_ADMISSION_OPERATION = "task_attempt_admission"
TASK_ADMISSION_RESOURCE_TYPE = "isolated_worktree"
TASK_ADMISSION_POLICY_ID = "ordomata.phase-1c.mock-task-admission-enforcement"
TASK_ADMISSION_POLICY_VERSION = "1.0.0"
TASK_ADMISSION_EXECUTOR_ID = "ordomata:local-controller"
TASK_ADMISSION_EVENT_SCHEMA_VERSION = 1

_EVIDENCE_LIFETIME_SECONDS = 120.0
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_PROFILE_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
_FIXED_PERMIT_OBLIGATIONS = frozenset(
    {
        (ObligationKind.AUDIT_RECEIPT, "append_after_action"),
        (ObligationKind.ISOLATED_LOCAL_ONLY, "required"),
    }
)


@dataclass(frozen=True, slots=True)
class TaskAdmissionAuthorization:
    """Exact request, fixed policy, and decision at the admission PEP."""

    request: AuthorizationRequest
    policy: PolicyBundle
    decision: AuthorizationDecision
    run_ref: str
    profile_ref: str
    task_attempt_binding_digest: str
    execution_selection_digest: str
    profile_version_ref: str
    profile_configuration_digest: str
    context_digest: str
    prompt_digest: str
    task_authorization_intent_digest: str
    admission_authorization_intent_digest: str
    requested_permission_class: PermissionClass
    controller_owned_mock_runner: bool
    legacy_executable: bool
    pre_run_approval_required: bool
    pre_run_approver_ref: str
    authority_ceiling_satisfied: bool
    obligations_supported: bool
    decision_current_at_evaluation: bool
    block_reason_codes: tuple[str, ...]

    @property
    def authorized_at_evaluation(self) -> bool:
        return not self.block_reason_codes

    def to_event_payload(self) -> dict[str, Any]:
        """Return the strict, privacy-safe decision wrapper for persistence."""

        return {
            "schema_version": TASK_ADMISSION_EVENT_SCHEMA_VERSION,
            "mode": "enforcing",
            "action_scope": TASK_ADMISSION_ACTION_SCOPE,
            "enforcement_coverage": TASK_ADMISSION_ENFORCEMENT_COVERAGE,
            "run_ref": self.run_ref,
            "profile_ref": self.profile_ref,
            "task_attempt_binding_digest": self.task_attempt_binding_digest,
            "execution_selection_digest": self.execution_selection_digest,
            "profile_version_ref": self.profile_version_ref,
            "profile_configuration_digest": (
                self.profile_configuration_digest
            ),
            "context_digest": self.context_digest,
            "prompt_digest": self.prompt_digest,
            "task_authorization_intent_digest": (
                self.task_authorization_intent_digest
            ),
            "admission_authorization_intent_digest": (
                self.admission_authorization_intent_digest
            ),
            "requested_permission_class": int(
                self.requested_permission_class
            ),
            "controller_owned_mock_runner": (
                self.controller_owned_mock_runner
            ),
            "legacy_executable": self.legacy_executable,
            "pre_run_approval_required": self.pre_run_approval_required,
            "pre_run_approver_ref": self.pre_run_approver_ref,
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
            "decision_current_at_evaluation": (
                self.decision_current_at_evaluation
            ),
            "authority_ceiling_satisfied": (
                self.authority_ceiling_satisfied
            ),
            "obligations_supported": self.obligations_supported,
            "authorization_eligible": self.authorized_at_evaluation,
            "block_reason_codes": list(self.block_reason_codes),
            "evaluated_at": float(self.request.environment.evaluated_at),
        }


def evaluate_task_admission_authorization(
    *,
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    controller_owned_mock_runner: bool,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    profile_version_ref: str,
    profile_configuration_digest: str,
    context_digest: str,
    prompt_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> TaskAdmissionAuthorization:
    """Evaluate one exact internal admission under a fixed Class 1 policy."""

    _validate_evaluation_inputs(
        contract=contract,
        request=request,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        controller_owned_mock_runner=controller_owned_mock_runner,
        digests=(
            ("task attempt binding", task_attempt_binding_digest),
            ("execution selection", execution_selection_digest),
            ("profile version", profile_version_ref),
            ("profile configuration", profile_configuration_digest),
            ("context", context_digest),
            ("prompt", prompt_digest),
        ),
        prompt_digest=prompt_digest,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
    )

    task_intent, _ = resolve_task_authorization_intent(contract)
    admission_intent = _task_admission_intent(task_intent)
    task_intent_digest = task_intent.digest
    admission_intent_digest = admission_intent.digest
    run_ref = canonical_digest({"run_id": request.run_id})
    profile_ref = canonical_digest({"profile_id": profile_id})
    repository_ref = canonical_digest({"project_root": str(project_root)})
    workspace_ref = canonical_digest({"workspace": str(request.workspace)})
    run_directory_ref = canonical_digest(
        {"run_directory": str(request.run_directory)}
    )
    pre_run_approver_ref = canonical_digest(
        {"approver": contract.approval_requirements.approver}
    )
    approval_requirements_digest = canonical_digest(
        {
            "approver": contract.approval_requirements.approver,
            "required_before_run": (
                contract.approval_requirements.required_before_run
            ),
        }
    )

    environment = EnvironmentAttributes(
        evaluated_at=evaluated_at,
        isolation_state=IsolationState.VERIFIED,
        network_state=NetworkState.DISABLED,
        billing_route=BillingRoute.MOCK,
        capacity_state=CapacityState.NOT_APPLICABLE,
        paid_continuation_protection=(
            PaidContinuationProtection.NOT_APPLICABLE
        ),
        circuit_state=CircuitState.CLOSED,
        flow_state="admission_proposed",
    )
    authorization_request = AuthorizationRequest(
        request_id=f"{TASK_ADMISSION_ACTION_SCOPE}:{run_ref}",
        subject=SubjectAttributes(
            principal_id="agent:task-attempt",
            controller_id="ordomata:local-controller",
            role=Role.IMPLEMENTER,
            role_version="1",
            profile_id=profile_ref,
            runner_id="mock",
            session_id=f"attempt:{run_ref}",
        ),
        action=ActionAttributes(
            verb=ActionVerb.CREATE,
            operation=TASK_ADMISSION_OPERATION,
            parameters_digest=canonical_digest(
                {
                    "admission_authorization_intent_digest": (
                        admission_intent_digest
                    ),
                    "attempt": request.attempt,
                    "context_digest": context_digest,
                    "controller_owned_mock_runner": (
                        controller_owned_mock_runner
                    ),
                    "execution_selection_digest": execution_selection_digest,
                    "legacy_permission_class": int(request.permission_class),
                    "output_schema_digest": canonical_digest(
                        request.output_schema
                    ),
                    "pre_run_approval_requirements_digest": (
                        approval_requirements_digest
                    ),
                    "profile_configuration_digest": (
                        profile_configuration_digest
                    ),
                    "profile_ref": profile_ref,
                    "profile_version_ref": profile_version_ref,
                    "prompt_digest": prompt_digest,
                    "repository_ref": repository_ref,
                    "run_directory_ref": run_directory_ref,
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
            intended_effect="admit_profile_backed_mock_task_attempt",
        ),
        resource=ResourceAttributes(
            resource_type=TASK_ADMISSION_RESOURCE_TYPE,
            identifier=canonical_digest(
                {
                    "execution_selection_digest": execution_selection_digest,
                    "resource_type": TASK_ADMISSION_RESOURCE_TYPE,
                    "run_ref": run_ref,
                    "task_attempt_binding_digest": (
                        task_attempt_binding_digest
                    ),
                    "workspace_ref": workspace_ref,
                }
            ),
            version=contract.definition_hash,
            owner="operator:local",
            trust_boundary="isolated_run_workspace",
            protected=admission_intent.resource.protected,
            sensitivity=admission_intent.resource.sensitivity,
            repository_id=repository_ref,
            content_digest=context_digest,
        ),
        environment=environment,
        consequences=ConsequenceVector(
            confidentiality=admission_intent.consequences.confidentiality,
            integrity=admission_intent.consequences.integrity,
            availability=admission_intent.consequences.availability,
            reach=admission_intent.consequences.reach,
            destructive=admission_intent.consequences.destructive,
            reversible=admission_intent.consequences.reversible,
            sensitivity=admission_intent.consequences.sensitivity,
            blast_radius=admission_intent.consequences.blast_radius,
        ),
    )
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=f"{TASK_ADMISSION_ACTION_SCOPE}:{attribute}",
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
    authorization_request = replace(authorization_request, evidence=evidence)
    pre_run_approval_required = (
        contract.approval_requirements.required_before_run
    )
    policy = _task_admission_policy(
        pre_run_approval_required=pre_run_approval_required,
        pre_run_approver_ref=pre_run_approver_ref,
    )
    decision = AuthorizationEvaluator().evaluate(authorization_request, policy)
    if not isinstance(decision, AuthorizationDecision):
        raise ValidationError("authorization evaluator returned an invalid decision")

    policy_matches = _policy_and_decision_match(
        authorization_request,
        policy,
        decision,
        evaluated_at=evaluated_at,
    )
    decision_current = decision.issued_at <= evaluated_at < decision.expires_at
    authority_ceiling_satisfied = (
        decision.derived_permission_class <= request.permission_class
        and decision.derived_permission_class <= PermissionClass.LOCAL_DRAFT
    )
    obligations_supported = _obligations_supported(decision)
    block_reasons: list[str] = []
    if not controller_owned_mock_runner:
        block_reasons.append("controller_owned_mock_runner_not_verified")
    if request.permission_class is not PermissionClass.LOCAL_DRAFT:
        block_reasons.append("task_permission_class_not_local_draft")
    if not legacy_executable:
        block_reasons.append("legacy_gate_not_executable")
    if pre_run_approval_required:
        block_reasons.append("pre_run_approval_not_supported")
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

    return TaskAdmissionAuthorization(
        request=authorization_request,
        policy=policy,
        decision=decision,
        run_ref=run_ref,
        profile_ref=profile_ref,
        task_attempt_binding_digest=task_attempt_binding_digest,
        execution_selection_digest=execution_selection_digest,
        profile_version_ref=profile_version_ref,
        profile_configuration_digest=profile_configuration_digest,
        context_digest=context_digest,
        prompt_digest=prompt_digest,
        task_authorization_intent_digest=task_intent_digest,
        admission_authorization_intent_digest=admission_intent_digest,
        requested_permission_class=request.permission_class,
        controller_owned_mock_runner=controller_owned_mock_runner,
        legacy_executable=legacy_executable,
        pre_run_approval_required=pre_run_approval_required,
        pre_run_approver_ref=pre_run_approver_ref,
        authority_ceiling_satisfied=authority_ceiling_satisfied,
        obligations_supported=obligations_supported,
        decision_current_at_evaluation=decision_current,
        block_reason_codes=tuple(block_reasons),
    )


def task_admission_authorization_intent_digest(contract: TaskContract) -> str:
    """Return the fixed admission projection digest for failure evidence."""

    if not isinstance(contract, TaskContract):
        raise ValidationError("task admission contract is invalid")
    task_intent, _ = resolve_task_authorization_intent(contract)
    return _task_admission_intent(task_intent).digest


def build_task_admission_failure_payload(
    *,
    run_ref: str,
    profile_ref: str,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    profile_version_ref: str,
    profile_configuration_digest: str,
    context_digest: str,
    prompt_digest: str,
    task_authorization_intent_digest: str,
    admission_authorization_intent_digest: str,
    requested_permission_class: PermissionClass,
    controller_owned_mock_runner: bool,
    legacy_executable: bool,
    pre_run_approval_required: bool,
    pre_run_approver_ref: str,
    evaluated_at: float,
) -> dict[str, Any]:
    """Return a fixed redacted indeterminate record after build/eval failure."""

    return {
        "schema_version": TASK_ADMISSION_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": TASK_ADMISSION_ACTION_SCOPE,
        "enforcement_coverage": TASK_ADMISSION_ENFORCEMENT_COVERAGE,
        "run_ref": _optional_digest(run_ref),
        "profile_ref": _optional_digest(profile_ref),
        "task_attempt_binding_digest": _optional_digest(
            task_attempt_binding_digest
        ),
        "execution_selection_digest": _optional_digest(
            execution_selection_digest
        ),
        "profile_version_ref": _optional_digest(profile_version_ref),
        "profile_configuration_digest": _optional_digest(
            profile_configuration_digest
        ),
        "context_digest": _optional_digest(context_digest),
        "prompt_digest": _optional_digest(prompt_digest),
        "task_authorization_intent_digest": _optional_digest(
            task_authorization_intent_digest
        ),
        "admission_authorization_intent_digest": _optional_digest(
            admission_authorization_intent_digest
        ),
        "requested_permission_class": (
            int(requested_permission_class)
            if isinstance(requested_permission_class, PermissionClass)
            else None
        ),
        "controller_owned_mock_runner": (
            controller_owned_mock_runner is True
        ),
        "legacy_executable": legacy_executable is True,
        "pre_run_approval_required": pre_run_approval_required is True,
        "pre_run_approver_ref": _optional_digest(pre_run_approver_ref),
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
        "evaluated_at": _optional_timestamp(evaluated_at),
        "failure_stage": "request_or_evaluation",
    }


def assert_task_admission_authorized(
    authorization: TaskAdmissionAuthorization,
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
    profile_version_ref: str,
    profile_configuration_digest: str,
    context_digest: str,
    prompt_digest: str,
    legacy_executable: bool,
) -> None:
    """Rebuild and require the exact permit at the admission state change."""

    if not isinstance(authorization, TaskAdmissionAuthorization):
        raise AuthorizationBlocked(
            "task admission requires a typed authorization permit"
        )
    try:
        rebuilt = evaluate_task_admission_authorization(
            contract=contract,
            request=request,
            runner_id=runner_id,
            profile_id=profile_id,
            project_root=project_root,
            controller_owned_mock_runner=controller_owned_mock_runner,
            task_attempt_binding_digest=task_attempt_binding_digest,
            execution_selection_digest=execution_selection_digest,
            profile_version_ref=profile_version_ref,
            profile_configuration_digest=profile_configuration_digest,
            context_digest=context_digest,
            prompt_digest=prompt_digest,
            evaluated_at=authorization.request.environment.evaluated_at,
            legacy_executable=legacy_executable,
        )
        exact_binding = bool(
            authorization == rebuilt
            and authorization.to_event_payload() == dict(persisted_payload)
        )
    except Exception:
        exact_binding = False
    if not exact_binding:
        raise AuthorizationBlocked(
            "task admission requires an exact persisted authorization permit"
        )

    _assert_task_admission_permit_current(
        authorization,
        action_started_at=action_started_at,
    )


def build_task_admission_action_receipt(
    *,
    authorization: TaskAdmissionAuthorization,
    action_started_at: float,
    completed_at: float,
) -> dict[str, Any]:
    """Build the deterministic succeeded receipt that marks durable admission."""

    _assert_task_admission_permit_current(
        authorization,
        action_started_at=action_started_at,
    )
    if (
        not _valid_timestamp(completed_at)
        or completed_at < action_started_at
    ):
        raise ValidationError("task admission completion time is invalid")
    obligation_results = tuple(
        ObligationResult(
            kind=obligation.kind,
            value=obligation.value,
            satisfied=True,
        )
        for obligation in authorization.decision.obligations
    )
    admission_result_digest = canonical_digest(
        {
            "admission_state": "admitted",
            "execution_selection_digest": (
                authorization.execution_selection_digest
            ),
            "run_ref": authorization.run_ref,
            "task_attempt_binding_digest": (
                authorization.task_attempt_binding_digest
            ),
        }
    )
    receipt_id = canonical_digest(
        {
            "decision_digest": authorization.decision.digest,
            "execution_selection_digest": (
                authorization.execution_selection_digest
            ),
            "request_digest": authorization.request.digest,
            "task_attempt_binding_digest": (
                authorization.task_attempt_binding_digest
            ),
            "receipt_kind": "task_admission_action",
        }
    )
    receipt = ActionReceipt.record(
        receipt_id=receipt_id,
        decision=authorization.decision,
        request=authorization.request,
        executor_id=TASK_ADMISSION_EXECUTOR_ID,
        started_at=action_started_at,
        completed_at=completed_at,
        outcome=ReceiptOutcome.SUCCEEDED,
        obligation_results=obligation_results,
        result_digest=admission_result_digest,
    )
    return {
        "schema_version": TASK_ADMISSION_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": TASK_ADMISSION_ACTION_SCOPE,
        "enforcement_coverage": TASK_ADMISSION_ENFORCEMENT_COVERAGE,
        "run_ref": authorization.run_ref,
        "profile_ref": authorization.profile_ref,
        "task_attempt_binding_digest": (
            authorization.task_attempt_binding_digest
        ),
        "execution_selection_digest": (
            authorization.execution_selection_digest
        ),
        "request_digest": authorization.request.digest,
        "decision_digest": authorization.decision.digest,
        "admission_result_digest": admission_result_digest,
        "receipt": receipt.to_canonical(),
        "receipt_digest": receipt.digest,
    }


def _assert_task_admission_permit_current(
    authorization: TaskAdmissionAuthorization,
    *,
    action_started_at: float,
) -> None:
    """Independently re-evaluate policy and require a current typed permit."""

    if not isinstance(authorization, TaskAdmissionAuthorization):
        raise AuthorizationBlocked(
            "task admission requires a typed authorization permit"
        )
    request = authorization.request
    policy = authorization.policy
    decision = authorization.decision
    try:
        fixed_policy = _task_admission_policy(
            pre_run_approval_required=(
                authorization.pre_run_approval_required
            ),
            pre_run_approver_ref=authorization.pre_run_approver_ref,
        )
        reevaluated_decision = AuthorizationEvaluator().evaluate(
            request,
            fixed_policy,
        )
    except Exception:
        fixed_policy = None
        reevaluated_decision = None
    obligation_pairs = tuple(
        (obligation.kind, obligation.value)
        for obligation in decision.obligations
    )
    if (
        not authorization.authorized_at_evaluation
        or not authorization.controller_owned_mock_runner
        or not authorization.legacy_executable
        or authorization.pre_run_approval_required
        or _optional_digest(authorization.pre_run_approver_ref)
        != authorization.pre_run_approver_ref
        or authorization.requested_permission_class
        is not PermissionClass.LOCAL_DRAFT
        or not authorization.authority_ceiling_satisfied
        or not authorization.obligations_supported
        or policy != fixed_policy
        or decision != reevaluated_decision
        or decision.effect is not AuthorizationEffect.PERMIT
        or decision.request_id != request.request_id
        or decision.request_digest != request.digest
        or decision.policy_bundle_id != policy.bundle_id
        or decision.policy_version != policy.version
        or decision.policy_digest != policy.digest
        or request.subject.runner_id != "mock"
        or request.subject.role is not Role.IMPLEMENTER
        or request.action.verb is not ActionVerb.CREATE
        or request.action.operation != TASK_ADMISSION_OPERATION
        or request.action.intended_effect
        != "admit_profile_backed_mock_task_attempt"
        or request.resource.resource_type != TASK_ADMISSION_RESOURCE_TYPE
        or request.resource.trust_boundary != "isolated_run_workspace"
        or request.environment.isolation_state is not IsolationState.VERIFIED
        or request.environment.network_state is not NetworkState.DISABLED
        or request.environment.billing_route is not BillingRoute.MOCK
        or request.environment.capacity_state is not CapacityState.NOT_APPLICABLE
        or request.environment.paid_continuation_protection
        is not PaidContinuationProtection.NOT_APPLICABLE
        or request.environment.circuit_state is not CircuitState.CLOSED
        or request.environment.flow_state != "admission_proposed"
        or request.consequences.reach is not Reach.LOCAL
        or request.consequences.destructive
        or not request.consequences.reversible
        or request.consequences.blast_radius is not BlastRadius.SINGLE_RESOURCE
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
            "task admission requires a fresh exact Class 1 authorization permit"
        )


def _task_admission_intent(
    task_intent: TaskAuthorizationIntent,
) -> TaskAuthorizationIntent:
    return TaskAuthorizationIntent(
        action=TaskActionIntent(
            verb=ActionVerb.CREATE,
            operation=TASK_ADMISSION_OPERATION,
            intended_effect="admit_profile_backed_mock_task_attempt",
        ),
        resource=TaskResourceIntent(
            resource_type=TASK_ADMISSION_RESOURCE_TYPE,
            trust_boundary="isolated_run_workspace",
            protected=task_intent.resource.protected,
            sensitivity=task_intent.resource.sensitivity,
        ),
        consequences=TaskConsequenceIntent(
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


def _task_admission_policy(
    *,
    pre_run_approval_required: bool,
    pre_run_approver_ref: str,
) -> PolicyBundle:
    if not isinstance(pre_run_approval_required, bool):
        raise ValidationError(
            "task admission approval requirement must be a boolean"
        )
    if _optional_digest(pre_run_approver_ref) != pre_run_approver_ref:
        raise ValidationError("task admission approver reference is invalid")
    approval_requirements: tuple[ApprovalRequirement, ...] = ()
    if pre_run_approval_required:
        approval_requirements = (
            ApprovalRequirement(
                requirement_id=_PRE_RUN_APPROVAL_REQUIREMENT,
                verbs=(ActionVerb.CREATE,),
                resource_types=(TASK_ADMISSION_RESOURCE_TYPE,),
                allowed_approver_ids=(pre_run_approver_ref,),
            ),
        )
    return replace(
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


def _validate_evaluation_inputs(
    *,
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    controller_owned_mock_runner: bool,
    digests: tuple[tuple[str, str], ...],
    prompt_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> None:
    if not isinstance(contract, TaskContract) or not isinstance(
        request,
        RunRequest,
    ):
        raise ValidationError("task admission authorization inputs are invalid")
    if runner_id != "mock":
        raise ValidationError("task admission requires the mock runner")
    if not isinstance(profile_id, str) or _PROFILE_PATTERN.fullmatch(
        profile_id
    ) is None:
        raise ValidationError("task admission requires a safe profile")
    if not isinstance(project_root, Path) or not project_root.is_absolute():
        raise ValidationError("task admission project root must be absolute")
    if (
        not isinstance(request.workspace, Path)
        or not request.workspace.is_absolute()
        or not isinstance(request.run_directory, Path)
        or not request.run_directory.is_absolute()
    ):
        raise ValidationError("task admission paths must be absolute")
    try:
        request.run_directory.relative_to(project_root)
        request.workspace.relative_to(request.run_directory)
    except ValueError as error:
        raise ValidationError("task admission paths are not contained") from error
    if request.workspace.parent != request.run_directory:
        raise ValidationError("task admission workspace layout is invalid")
    if (
        request.task_id != contract.task_id
        or request.task_version != contract.version
    ):
        raise ValidationError("task admission request identity is inconsistent")
    if request.permission_class is not contract.permission_class:
        raise ValidationError("task admission permission class is inconsistent")
    if request.timeout_seconds != contract.timeout_seconds or request.attempt != 1:
        raise ValidationError("task admission attempt limits are inconsistent")
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
        raise ValidationError("task admission output schema is inconsistent")
    if not prompt_matches:
        raise ValidationError("task admission prompt digest is inconsistent")
    if request.permission_class not in {
        PermissionClass.READ_ONLY,
        PermissionClass.LOCAL_DRAFT,
    }:
        raise ValidationError("task admission supports only Class 0/1 inputs")
    for name, value in digests:
        if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
            raise ValidationError(f"{name} digest is invalid")
    for name, value in (
        ("controller-owned mock runner", controller_owned_mock_runner),
        ("legacy executable", legacy_executable),
    ):
        if not isinstance(value, bool):
            raise ValidationError(f"{name} evidence must be a boolean")
    if not _valid_timestamp(evaluated_at):
        raise ValidationError("task admission evaluation time is invalid")


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
    values = tuple(
        (obligation.kind, obligation.value)
        for obligation in decision.obligations
    )
    return bool(
        len(values) == len(_FIXED_PERMIT_OBLIGATIONS)
        and len(set(values)) == len(values)
        and frozenset(values) == _FIXED_PERMIT_OBLIGATIONS
    )


def _optional_digest(value: Any) -> str | None:
    return (
        value
        if isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None
        else None
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


def _optional_timestamp(value: Any) -> float | None:
    return float(value) if _valid_timestamp(value) else None


__all__ = [
    "TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE",
    "TASK_ADMISSION_ACTION_SCOPE",
    "TASK_ADMISSION_DECISION_EVENT_TYPE",
    "TASK_ADMISSION_ENFORCEMENT_COVERAGE",
    "TASK_ADMISSION_EVENT_SCHEMA_VERSION",
    "TASK_ADMISSION_EXECUTOR_ID",
    "TASK_ADMISSION_OPERATION",
    "TASK_ADMISSION_POLICY_ID",
    "TASK_ADMISSION_POLICY_VERSION",
    "TASK_ADMISSION_RESOURCE_TYPE",
    "TaskAdmissionAuthorization",
    "assert_task_admission_authorized",
    "build_task_admission_action_receipt",
    "build_task_admission_failure_payload",
    "evaluate_task_admission_authorization",
    "task_admission_authorization_intent_digest",
]
