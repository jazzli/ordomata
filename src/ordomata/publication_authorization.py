"""Authoritative ABAC gate for one ordinary mock candidate publication.

This module is deliberately narrow.  It can authorize only the controller's
local, reversible creation of an owner-private candidate produced by a
profile-backed exact built-in mock attempt.  It cannot authorize dispatch,
live or comparison execution, shared promotion, repository mutation,
deployment, an external action, or Permission Class 2/3.  The existing Class
0/1 gate and the controller's deterministic publication prerequisites remain
independent requirements.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
import re
from typing import Any

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
from .task_evidence import (
    TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
)


LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE = (
    "task_attempt_local_candidate_publication_authorization_decision"
)
LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE = (
    "ordinary_profile_backed_mock_local_candidate_publication_only"
)
LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE = (
    TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
)
LOCAL_CANDIDATE_PUBLICATION_OPERATION = "artifact.publish_local_candidate"
LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE = "local_candidate_artifact"
LOCAL_CANDIDATE_PUBLICATION_POLICY_ID = (
    "ordomata.phase-1c.mock-local-candidate-publication-enforcement"
)
LOCAL_CANDIDATE_PUBLICATION_POLICY_VERSION = "1.0.0"
LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID = "ordomata:local-controller"
LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION = 1

_EVIDENCE_LIFETIME_SECONDS = 120.0
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_PROFILE_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,160}")
_ARTIFACT_KIND_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}")
_FIXED_PERMIT_OBLIGATIONS = frozenset(
    {
        (ObligationKind.AUDIT_RECEIPT, "append_after_action"),
        (ObligationKind.ISOLATED_LOCAL_ONLY, "required"),
    }
)


@dataclass(frozen=True, slots=True)
class LocalCandidatePublicationAuthorization:
    """Exact request, fixed policy, and decision at the publication PEP."""

    request: AuthorizationRequest
    policy: PolicyBundle
    decision: AuthorizationDecision
    task_attempt_binding_digest: str
    execution_selection_digest: str
    task_authorization_intent_digest: str
    publication_authorization_intent_digest: str
    dispatch_request_digest: str
    dispatch_decision_digest: str
    dispatch_action_receipt_digest: str
    execution_accounting_digest: str
    billing_disposition_digest: str
    artifact_digest: str
    destination_digest: str
    artifact_metadata_digest: str
    requested_permission_class: PermissionClass
    controller_owned_mock_runner: bool
    legacy_executable: bool
    safe_publication_prerequisites: bool
    evaluation_accepted: bool
    credential_scan_passed: bool
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
            "schema_version": LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION,
            "mode": "enforcing",
            "action_scope": LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE,
            "enforcement_coverage": (
                LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
            ),
            "task_attempt_binding_digest": self.task_attempt_binding_digest,
            "execution_selection_digest": self.execution_selection_digest,
            "task_authorization_intent_digest": (
                self.task_authorization_intent_digest
            ),
            "publication_authorization_intent_digest": (
                self.publication_authorization_intent_digest
            ),
            "dispatch_request_digest": self.dispatch_request_digest,
            "dispatch_decision_digest": self.dispatch_decision_digest,
            "dispatch_action_receipt_digest": (
                self.dispatch_action_receipt_digest
            ),
            "execution_accounting_digest": self.execution_accounting_digest,
            "billing_disposition_digest": self.billing_disposition_digest,
            "artifact_digest": self.artifact_digest,
            "destination_digest": self.destination_digest,
            "artifact_metadata_digest": self.artifact_metadata_digest,
            "requested_permission_class": int(
                self.requested_permission_class
            ),
            "controller_owned_mock_runner": (
                self.controller_owned_mock_runner
            ),
            "legacy_executable": self.legacy_executable,
            "safe_publication_prerequisites": (
                self.safe_publication_prerequisites
            ),
            "evaluation_accepted": self.evaluation_accepted,
            "credential_scan_passed": self.credential_scan_passed,
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


def evaluate_local_candidate_publication_authorization(
    *,
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    controller_owned_mock_runner: bool,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    dispatch_request_digest: str,
    dispatch_decision_digest: str,
    dispatch_action_receipt_digest: str,
    execution_accounting_digest: str,
    billing_disposition_digest: str,
    artifact_digest: str,
    destination_digest: str,
    artifact_metadata_digest: str,
    artifact_kind: str,
    artifact_size_bytes: int,
    evaluation_accepted: bool,
    credential_scan_passed: bool,
    safe_publication_prerequisites: bool,
    evaluated_at: float,
    legacy_executable: bool,
) -> LocalCandidatePublicationAuthorization:
    """Evaluate one exact local candidate create under a fixed Class 1 policy."""

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
            ("dispatch request", dispatch_request_digest),
            ("dispatch decision", dispatch_decision_digest),
            ("dispatch action receipt", dispatch_action_receipt_digest),
            ("execution accounting", execution_accounting_digest),
            ("billing disposition", billing_disposition_digest),
            ("artifact", artifact_digest),
            ("destination", destination_digest),
            ("artifact metadata", artifact_metadata_digest),
        ),
        artifact_kind=artifact_kind,
        artifact_size_bytes=artifact_size_bytes,
        evaluation_accepted=evaluation_accepted,
        credential_scan_passed=credential_scan_passed,
        safe_publication_prerequisites=safe_publication_prerequisites,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
    )

    task_intent, _ = resolve_task_authorization_intent(contract)
    publication_intent = _local_candidate_publication_intent(task_intent)
    task_intent_digest = task_intent.digest
    publication_intent_digest = publication_intent.digest
    profile_ref = canonical_digest({"profile_id": profile_id})
    repository_ref = canonical_digest({"project_root": str(project_root)})
    workspace_ref = canonical_digest({"workspace": str(request.workspace)})
    run_ref = canonical_digest({"run_id": request.run_id})

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
        flow_state="local_candidate_publication_proposed",
    )
    authorization_request = AuthorizationRequest(
        request_id=(
            f"{LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE}:{run_ref}"
        ),
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
            operation=LOCAL_CANDIDATE_PUBLICATION_OPERATION,
            parameters_digest=canonical_digest(
                {
                    "artifact_digest": artifact_digest,
                    "artifact_kind": artifact_kind,
                    "artifact_metadata_digest": artifact_metadata_digest,
                    "artifact_size_bytes": artifact_size_bytes,
                    "billing_disposition_digest": (
                        billing_disposition_digest
                    ),
                    "controller_owned_mock_runner": (
                        controller_owned_mock_runner
                    ),
                    "credential_scan_passed": credential_scan_passed,
                    "destination_digest": destination_digest,
                    "dispatch_action_receipt_digest": (
                        dispatch_action_receipt_digest
                    ),
                    "dispatch_decision_digest": dispatch_decision_digest,
                    "dispatch_request_digest": dispatch_request_digest,
                    "evaluation_accepted": evaluation_accepted,
                    "execution_accounting_digest": (
                        execution_accounting_digest
                    ),
                    "execution_selection_digest": (
                        execution_selection_digest
                    ),
                    "legacy_permission_class": int(
                        request.permission_class
                    ),
                    "output_schema_digest": canonical_digest(
                        request.output_schema
                    ),
                    "profile_ref": profile_ref,
                    "publication_authorization_intent_digest": (
                        publication_intent_digest
                    ),
                    "repository_ref": repository_ref,
                    "run_ref": run_ref,
                    "safe_publication_prerequisites": (
                        safe_publication_prerequisites
                    ),
                    "task_attempt_binding_digest": (
                        task_attempt_binding_digest
                    ),
                    "task_authorization_intent_digest": task_intent_digest,
                    "task_definition_digest": contract.definition_hash,
                    "workspace_ref": workspace_ref,
                }
            ),
            intended_effect="create_isolated_local_candidate",
        ),
        resource=ResourceAttributes(
            resource_type=LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE,
            identifier=canonical_digest(
                {
                    "artifact_metadata_digest": artifact_metadata_digest,
                    "destination_digest": destination_digest,
                    "resource_type": (
                        LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE
                    ),
                    "run_ref": run_ref,
                }
            ),
            version=artifact_digest,
            owner="operator:local",
            trust_boundary="isolated_run_workspace",
            protected=publication_intent.resource.protected,
            sensitivity=publication_intent.resource.sensitivity,
            repository_id=repository_ref,
            content_digest=artifact_digest,
        ),
        environment=environment,
        consequences=ConsequenceVector(
            confidentiality=(
                publication_intent.consequences.confidentiality
            ),
            integrity=publication_intent.consequences.integrity,
            availability=publication_intent.consequences.availability,
            reach=Reach.LOCAL,
            destructive=False,
            reversible=True,
            sensitivity=publication_intent.consequences.sensitivity,
            blast_radius=BlastRadius.SINGLE_RESOURCE,
        ),
    )
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=(
                f"{LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE}:{attribute}"
            ),
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
    policy = _local_candidate_publication_policy()
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
    decision_current = decision.issued_at <= evaluated_at < decision.expires_at
    authority_ceiling_satisfied = (
        decision.derived_permission_class <= request.permission_class
        and decision.derived_permission_class <= PermissionClass.LOCAL_DRAFT
    )
    obligations_supported = _obligations_supported(decision)
    block_reasons: list[str] = []
    if not controller_owned_mock_runner:
        block_reasons.append("controller_owned_mock_runner_not_verified")
    if not legacy_executable:
        block_reasons.append("legacy_gate_not_executable")
    if not safe_publication_prerequisites:
        block_reasons.append("safe_publication_prerequisites_not_satisfied")
    if not evaluation_accepted:
        block_reasons.append("evaluation_not_accepted")
    if not credential_scan_passed:
        block_reasons.append("credential_scan_not_passed")
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

    return LocalCandidatePublicationAuthorization(
        request=authorization_request,
        policy=policy,
        decision=decision,
        task_attempt_binding_digest=task_attempt_binding_digest,
        execution_selection_digest=execution_selection_digest,
        task_authorization_intent_digest=task_intent_digest,
        publication_authorization_intent_digest=(
            publication_intent_digest
        ),
        dispatch_request_digest=dispatch_request_digest,
        dispatch_decision_digest=dispatch_decision_digest,
        dispatch_action_receipt_digest=dispatch_action_receipt_digest,
        execution_accounting_digest=execution_accounting_digest,
        billing_disposition_digest=billing_disposition_digest,
        artifact_digest=artifact_digest,
        destination_digest=destination_digest,
        artifact_metadata_digest=artifact_metadata_digest,
        requested_permission_class=request.permission_class,
        controller_owned_mock_runner=controller_owned_mock_runner,
        legacy_executable=legacy_executable,
        safe_publication_prerequisites=safe_publication_prerequisites,
        evaluation_accepted=evaluation_accepted,
        credential_scan_passed=credential_scan_passed,
        authority_ceiling_satisfied=authority_ceiling_satisfied,
        obligations_supported=obligations_supported,
        decision_current_at_evaluation=decision_current,
        block_reason_codes=tuple(block_reasons),
    )


def build_local_candidate_publication_failure_payload(
    *,
    task_attempt_binding_digest: str,
    execution_selection_digest: str,
    task_authorization_intent_digest: str,
    publication_authorization_intent_digest: str,
    dispatch_request_digest: str,
    dispatch_decision_digest: str,
    dispatch_action_receipt_digest: str,
    execution_accounting_digest: str,
    billing_disposition_digest: str,
    artifact_digest: str,
    destination_digest: str,
    artifact_metadata_digest: str,
    requested_permission_class: PermissionClass,
    controller_owned_mock_runner: bool,
    legacy_executable: bool,
    safe_publication_prerequisites: bool,
    evaluation_accepted: bool,
    credential_scan_passed: bool,
    evaluated_at: float,
) -> dict[str, Any]:
    """Return a fixed redacted indeterminate record after build/eval failure."""

    return {
        "schema_version": LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE,
        "enforcement_coverage": (
            LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
        ),
        "task_attempt_binding_digest": _optional_digest(
            task_attempt_binding_digest
        ),
        "execution_selection_digest": _optional_digest(
            execution_selection_digest
        ),
        "task_authorization_intent_digest": _optional_digest(
            task_authorization_intent_digest
        ),
        "publication_authorization_intent_digest": _optional_digest(
            publication_authorization_intent_digest
        ),
        "dispatch_request_digest": _optional_digest(dispatch_request_digest),
        "dispatch_decision_digest": _optional_digest(dispatch_decision_digest),
        "dispatch_action_receipt_digest": _optional_digest(
            dispatch_action_receipt_digest
        ),
        "execution_accounting_digest": _optional_digest(
            execution_accounting_digest
        ),
        "billing_disposition_digest": _optional_digest(
            billing_disposition_digest
        ),
        "artifact_digest": _optional_digest(artifact_digest),
        "destination_digest": _optional_digest(destination_digest),
        "artifact_metadata_digest": _optional_digest(
            artifact_metadata_digest
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
        "safe_publication_prerequisites": (
            safe_publication_prerequisites is True
        ),
        "evaluation_accepted": evaluation_accepted is True,
        "credential_scan_passed": credential_scan_passed is True,
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


def assert_local_candidate_publication_authorized(
    authorization: LocalCandidatePublicationAuthorization,
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
    dispatch_request_digest: str,
    dispatch_decision_digest: str,
    dispatch_action_receipt_digest: str,
    execution_accounting_digest: str,
    billing_disposition_digest: str,
    artifact_digest: str,
    destination_digest: str,
    artifact_metadata_digest: str,
    artifact_kind: str,
    artifact_size_bytes: int,
    evaluation_accepted: bool,
    credential_scan_passed: bool,
    safe_publication_prerequisites: bool,
    legacy_executable: bool,
) -> None:
    """Rebuild and require the exact permit at the first filesystem effect."""

    if not isinstance(authorization, LocalCandidatePublicationAuthorization):
        raise AuthorizationBlocked(
            "local candidate publication requires a typed authorization permit"
        )
    try:
        rebuilt = evaluate_local_candidate_publication_authorization(
            contract=contract,
            request=request,
            runner_id=runner_id,
            profile_id=profile_id,
            project_root=project_root,
            controller_owned_mock_runner=controller_owned_mock_runner,
            task_attempt_binding_digest=task_attempt_binding_digest,
            execution_selection_digest=execution_selection_digest,
            dispatch_request_digest=dispatch_request_digest,
            dispatch_decision_digest=dispatch_decision_digest,
            dispatch_action_receipt_digest=dispatch_action_receipt_digest,
            execution_accounting_digest=execution_accounting_digest,
            billing_disposition_digest=billing_disposition_digest,
            artifact_digest=artifact_digest,
            destination_digest=destination_digest,
            artifact_metadata_digest=artifact_metadata_digest,
            artifact_kind=artifact_kind,
            artifact_size_bytes=artifact_size_bytes,
            evaluation_accepted=evaluation_accepted,
            credential_scan_passed=credential_scan_passed,
            safe_publication_prerequisites=safe_publication_prerequisites,
            evaluated_at=authorization.request.environment.evaluated_at,
            legacy_executable=legacy_executable,
        )
        persisted = dict(persisted_payload)
        exact_binding = bool(
            authorization == rebuilt
            and authorization.to_event_payload() == persisted
        )
    except Exception:
        exact_binding = False
    if not exact_binding:
        raise AuthorizationBlocked(
            "local candidate publication requires an exact persisted authorization permit"
        )

    _assert_local_candidate_publication_permit_current(
        authorization,
        action_started_at=action_started_at,
    )


def _assert_local_candidate_publication_permit_current(
    authorization: LocalCandidatePublicationAuthorization,
    *,
    action_started_at: float,
) -> None:
    """Independently re-evaluate policy and require a current typed permit."""

    if not isinstance(authorization, LocalCandidatePublicationAuthorization):
        raise AuthorizationBlocked(
            "local candidate publication requires a typed authorization permit"
        )
    request = authorization.request
    policy = authorization.policy
    decision = authorization.decision
    fixed_policy = _local_candidate_publication_policy()
    try:
        reevaluated_decision = AuthorizationEvaluator().evaluate(
            request,
            fixed_policy,
        )
    except Exception:
        reevaluated_decision = None
    obligation_pairs = tuple(
        (obligation.kind, obligation.value)
        for obligation in decision.obligations
    )
    if (
        not authorization.authorized_at_evaluation
        or not authorization.controller_owned_mock_runner
        or not authorization.legacy_executable
        or not authorization.safe_publication_prerequisites
        or not authorization.evaluation_accepted
        or not authorization.credential_scan_passed
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
        or request.action.operation != LOCAL_CANDIDATE_PUBLICATION_OPERATION
        or request.resource.resource_type
        != LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE
        or request.resource.trust_boundary != "isolated_run_workspace"
        or request.environment.isolation_state is not IsolationState.VERIFIED
        or request.environment.network_state is not NetworkState.DISABLED
        or request.environment.billing_route is not BillingRoute.LOCAL_NON_AI
        or request.environment.capacity_state is not CapacityState.NOT_APPLICABLE
        or request.environment.paid_continuation_protection
        is not PaidContinuationProtection.NOT_APPLICABLE
        or request.environment.circuit_state is not CircuitState.CLOSED
        or request.environment.flow_state
        != "local_candidate_publication_proposed"
        or request.consequences.reach is not Reach.LOCAL
        or request.consequences.destructive
        or not request.consequences.reversible
        or request.consequences.blast_radius
        is not BlastRadius.SINGLE_RESOURCE
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
            "local candidate publication requires a fresh exact Class 1 "
            "authorization permit"
        )


def build_local_candidate_publication_enforcement_receipt(
    *,
    authorization: LocalCandidatePublicationAuthorization,
    action_started_at: float,
    completed_at: float,
    outcome: ReceiptOutcome,
    result_digest: str | None,
) -> dict[str, Any]:
    """Build the canonical receipt wrapper for existing reconciliation evidence."""

    _assert_local_candidate_publication_permit_current(
        authorization,
        action_started_at=action_started_at,
    )
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
            "destination_digest": authorization.destination_digest,
            "request_digest": authorization.request.digest,
            "task_attempt_binding_digest": (
                authorization.task_attempt_binding_digest
            ),
            "receipt_kind": "local_candidate_publication_action",
        }
    )
    receipt = ActionReceipt.record(
        receipt_id=receipt_id,
        decision=authorization.decision,
        request=authorization.request,
        executor_id=LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID,
        started_at=action_started_at,
        completed_at=max(action_started_at, completed_at),
        outcome=outcome,
        obligation_results=obligation_results,
        result_digest=result_digest,
    )
    return {
        "schema_version": LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION,
        "mode": "enforcing",
        "action_scope": LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE,
        "enforcement_coverage": (
            LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
        ),
        "task_attempt_binding_digest": (
            authorization.task_attempt_binding_digest
        ),
        "execution_selection_digest": (
            authorization.execution_selection_digest
        ),
        "dispatch_request_digest": authorization.dispatch_request_digest,
        "dispatch_decision_digest": authorization.dispatch_decision_digest,
        "dispatch_action_receipt_digest": (
            authorization.dispatch_action_receipt_digest
        ),
        "execution_accounting_digest": (
            authorization.execution_accounting_digest
        ),
        "billing_disposition_digest": (
            authorization.billing_disposition_digest
        ),
        "artifact_digest": authorization.artifact_digest,
        "destination_digest": authorization.destination_digest,
        "artifact_metadata_digest": authorization.artifact_metadata_digest,
        "request_digest": authorization.request.digest,
        "decision_digest": authorization.decision.digest,
        "receipt": receipt.to_canonical(),
        "receipt_digest": receipt.digest,
    }


def _local_candidate_publication_intent(
    task_intent: TaskAuthorizationIntent,
) -> TaskAuthorizationIntent:
    return TaskAuthorizationIntent(
        action=TaskActionIntent(
            verb=ActionVerb.CREATE,
            operation=LOCAL_CANDIDATE_PUBLICATION_OPERATION,
            intended_effect="create_isolated_local_candidate",
        ),
        resource=TaskResourceIntent(
            resource_type=LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE,
            trust_boundary="isolated_run_workspace",
            protected=task_intent.resource.protected,
            sensitivity=task_intent.resource.sensitivity,
        ),
        consequences=TaskConsequenceIntent(
            confidentiality=task_intent.consequences.confidentiality,
            integrity=task_intent.consequences.integrity,
            availability=task_intent.consequences.availability,
            reach=Reach.LOCAL,
            destructive=False,
            reversible=True,
            sensitivity=task_intent.consequences.sensitivity,
            blast_radius=BlastRadius.SINGLE_RESOURCE,
        ),
    )


def _local_candidate_publication_policy() -> PolicyBundle:
    return replace(
        PolicyBundle.current_stage(issued_at=0.0),
        bundle_id=LOCAL_CANDIDATE_PUBLICATION_POLICY_ID,
        version=LOCAL_CANDIDATE_PUBLICATION_POLICY_VERSION,
        enabled_classes=(PermissionClass.LOCAL_DRAFT,),
        allowed_verbs=(ActionVerb.CREATE,),
        allowed_roles=(Role.IMPLEMENTER,),
        allowed_operations=(LOCAL_CANDIDATE_PUBLICATION_OPERATION,),
        allowed_resource_types=(
            LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE,
        ),
        allowed_trust_boundaries=("isolated_run_workspace",),
        allowed_flow_states=("local_candidate_publication_proposed",),
        allowed_network_states=(NetworkState.DISABLED,),
        allowed_billing_routes=(BillingRoute.LOCAL_NON_AI,),
        approval_requirements=(),
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
    artifact_kind: str,
    artifact_size_bytes: int,
    evaluation_accepted: bool,
    credential_scan_passed: bool,
    safe_publication_prerequisites: bool,
    evaluated_at: float,
    legacy_executable: bool,
) -> None:
    if not isinstance(contract, TaskContract) or not isinstance(
        request, RunRequest
    ):
        raise ValidationError("publication authorization inputs are invalid")
    if runner_id != "mock":
        raise ValidationError("publication authorization requires the mock runner")
    if not isinstance(profile_id, str) or _PROFILE_PATTERN.fullmatch(
        profile_id
    ) is None:
        raise ValidationError("publication authorization requires a safe profile")
    if not isinstance(project_root, Path) or not project_root.is_absolute():
        raise ValidationError("publication project root must be absolute")
    if not isinstance(request.workspace, Path) or not request.workspace.is_absolute():
        raise ValidationError("publication workspace must be absolute")
    if request.task_id != contract.task_id or request.task_version != contract.version:
        raise ValidationError("publication request task identity is inconsistent")
    try:
        output_schema_matches = canonical_digest(
            request.output_schema
        ) == canonical_digest(contract.output_schema)
    except (TypeError, ValueError):
        output_schema_matches = False
    if not output_schema_matches:
        raise ValidationError("publication output schema is inconsistent")
    if request.permission_class not in {
        PermissionClass.READ_ONLY,
        PermissionClass.LOCAL_DRAFT,
    }:
        raise ValidationError("publication authorization supports only Class 0/1")
    for name, value in digests:
        if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
            raise ValidationError(f"{name} digest is invalid")
    if not isinstance(artifact_kind, str) or _ARTIFACT_KIND_PATTERN.fullmatch(
        artifact_kind
    ) is None:
        raise ValidationError("artifact kind is invalid")
    if (
        isinstance(artifact_size_bytes, bool)
        or not isinstance(artifact_size_bytes, int)
        or artifact_size_bytes <= 0
    ):
        raise ValidationError("artifact size must be a positive integer")
    for name, value in (
        ("controller-owned mock runner", controller_owned_mock_runner),
        ("evaluation accepted", evaluation_accepted),
        ("credential scan passed", credential_scan_passed),
        ("safe publication prerequisites", safe_publication_prerequisites),
        ("legacy executable", legacy_executable),
    ):
        if not isinstance(value, bool):
            raise ValidationError(f"{name} evidence must be a boolean")
    if not _valid_timestamp(evaluated_at):
        raise ValidationError("publication evaluation time is invalid")


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
    "LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE",
    "LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE",
    "LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE",
    "LOCAL_CANDIDATE_PUBLICATION_EVENT_SCHEMA_VERSION",
    "LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID",
    "LOCAL_CANDIDATE_PUBLICATION_OPERATION",
    "LOCAL_CANDIDATE_PUBLICATION_POLICY_ID",
    "LOCAL_CANDIDATE_PUBLICATION_POLICY_VERSION",
    "LOCAL_CANDIDATE_PUBLICATION_RESOURCE_TYPE",
    "LocalCandidatePublicationAuthorization",
    "assert_local_candidate_publication_authorized",
    "build_local_candidate_publication_enforcement_receipt",
    "build_local_candidate_publication_failure_payload",
    "evaluate_local_candidate_publication_authorization",
]
