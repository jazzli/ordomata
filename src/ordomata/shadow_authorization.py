"""Non-authoritative ABAC observations for the Phase 1C migration.

The current :class:`~ordomata.approval.ApprovalPolicy` remains authoritative.
This module evaluates typed task effects at Chief-of-Staff controller
boundaries and at controlled-comparison admission, dispatch, and private-review
publication. It returns bounded, secret-free audit payloads. A shadow result
can neither enable nor block execution or local candidate publication.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

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
    EvidenceSource,
    ImpactLevel,
    IsolationState,
    NetworkState,
    PolicyBundle,
    Reach,
    ResourceAttributes,
    Role,
    ShadowAuthorizationEvaluator,
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
from .models import (
    BillingRoute,
    BillingRouteAssessment,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
)


SHADOW_EVENT_SCHEMA_VERSION = 2
COMPARISON_SHADOW_EVENT_SCHEMA_VERSION = 3
COMPARISON_REVIEW_ARTIFACT_SHADOW_EVENT_SCHEMA_VERSION = 4
TASK_CANDIDATE_ARTIFACT_SHADOW_EVENT_SCHEMA_VERSION = 5
ADMISSION_ACTION_SCOPE = "task_attempt_admission_only"
DISPATCH_ACTION_SCOPE = "runner_model_dispatch_only"
PUBLICATION_ACTION_SCOPE = "local_candidate_publication_only"
# Compatibility alias for callers of the first admission-only slice.
SHADOW_ACTION_SCOPE = ADMISSION_ACTION_SCOPE

_EVIDENCE_LIFETIME_SECONDS = 120.0
_PRE_RUN_APPROVAL_REQUIREMENT = "task_contract_pre_run_operator_approval"

_FLOW_STATE_BY_SCOPE = {
    ADMISSION_ACTION_SCOPE: "admission_proposed",
    DISPATCH_ACTION_SCOPE: "runner_dispatch_proposed",
    PUBLICATION_ACTION_SCOPE: "local_candidate_publication_proposed",
}


def build_task_admission_shadow_event(
    *,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    context_digest: str,
    prompt_digest: str,
    project_root: Path,
    task_attempt_binding_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> dict[str, Any]:
    """Observe whether the exact task effect is eligible at admission."""

    return _build_shadow_event(
        action_scope=ADMISSION_ACTION_SCOPE,
        contract=contract,
        run_id=run_id,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
        resource_version=contract.definition_hash,
        content_digest=context_digest,
        billing_assessment=None,
        local_only_environment=False,
        apply_pre_run_approval=True,
        parameters={
            "context_digest": context_digest,
            "prompt_digest": prompt_digest,
            "task_attempt_binding_digest": task_attempt_binding_digest,
        },
        task_attempt_binding_digest=task_attempt_binding_digest,
    )


def build_runner_model_dispatch_shadow_event(
    *,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    context_digest: str,
    prompt_digest: str,
    project_root: Path,
    task_attempt_binding_digest: str,
    runner_overrides: Mapping[str, Any],
    timeout_seconds: int,
    attempt: int,
    billing_assessment: BillingRouteAssessment,
    billing_assessment_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> dict[str, Any]:
    """Observe dispatch intent immediately before ``runner.execute``.

    This is not evidence that a harness process or live model call occurred.
    Those facts remain in the later execution-accounting event.
    """

    return _build_shadow_event(
        action_scope=DISPATCH_ACTION_SCOPE,
        contract=contract,
        run_id=run_id,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
        resource_version=contract.definition_hash,
        content_digest=prompt_digest,
        billing_assessment=billing_assessment,
        local_only_environment=False,
        apply_pre_run_approval=True,
        parameters={
            "attempt": attempt,
            "billing_assessment_digest": billing_assessment_digest,
            "context_digest": context_digest,
            "prompt_digest": prompt_digest,
            "runner_overrides_digest": canonical_digest(
                dict(runner_overrides)
            ),
            "task_attempt_binding_digest": task_attempt_binding_digest,
            "timeout_seconds": timeout_seconds,
        },
        task_attempt_binding_digest=task_attempt_binding_digest,
    )


def build_comparison_trial_admission_shadow_event(
    *,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    project_root: Path,
    comparison_binding_digest: str,
    snapshot_digest: str,
    context_digest: str,
    billing_assessment: BillingRouteAssessment,
    evaluated_at: float,
    legacy_executable: bool,
) -> dict[str, Any]:
    """Observe admission of one immutable Class 0 comparison trial."""

    return _build_shadow_event(
        action_scope=ADMISSION_ACTION_SCOPE,
        contract=contract,
        intent_override=_comparison_trial_intent(contract),
        intent_source_override="comparison_trial_projection",
        run_id=run_id,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
        resource_version=snapshot_digest,
        content_digest=context_digest,
        billing_assessment=billing_assessment,
        local_only_environment=False,
        apply_pre_run_approval=True,
        parameters={
            "comparison_binding_digest": comparison_binding_digest,
            "context_digest": context_digest,
            "snapshot_digest": snapshot_digest,
        },
        requested_permission_class=PermissionClass.READ_ONLY,
        schema_version=COMPARISON_SHADOW_EVENT_SCHEMA_VERSION,
        comparison_binding_digest=comparison_binding_digest,
        use_comparison_policy=True,
    )


def build_comparison_trial_dispatch_shadow_event(
    *,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    project_root: Path,
    comparison_binding_digest: str,
    snapshot_digest: str,
    prompt_digest: str,
    billing_assessment: BillingRouteAssessment,
    evaluated_at: float,
    legacy_executable: bool,
) -> dict[str, Any]:
    """Observe dispatch of one immutable Class 0 comparison trial."""

    return _build_shadow_event(
        action_scope=DISPATCH_ACTION_SCOPE,
        contract=contract,
        intent_override=_comparison_trial_intent(contract),
        intent_source_override="comparison_trial_projection",
        run_id=run_id,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
        resource_version=snapshot_digest,
        content_digest=prompt_digest,
        billing_assessment=billing_assessment,
        local_only_environment=False,
        apply_pre_run_approval=True,
        parameters={
            "comparison_binding_digest": comparison_binding_digest,
            "prompt_digest": prompt_digest,
            "snapshot_digest": snapshot_digest,
        },
        requested_permission_class=PermissionClass.READ_ONLY,
        schema_version=COMPARISON_SHADOW_EVENT_SCHEMA_VERSION,
        comparison_binding_digest=comparison_binding_digest,
        use_comparison_policy=True,
    )


def build_comparison_review_artifact_publication_shadow_event(
    *,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    project_root: Path,
    comparison_binding_digest: str,
    destination_digest: str,
    artifact_digest: str,
    artifact_size_bytes: int,
    artifact_kind: str,
    output_withheld: bool,
    billing_disposition_digest: str,
    evaluated_at: float,
    legacy_executable: bool,
) -> dict[str, Any]:
    """Observe the separate Class 1 private-review publication boundary.

    The controller supplies every effect-bearing attribute. The comparison
    runner remains confined to the Class 0 immutable-snapshot action, and this
    non-authoritative observation cannot enable or block the legacy local write.
    """

    return _build_shadow_event(
        action_scope=PUBLICATION_ACTION_SCOPE,
        contract=contract,
        intent_override=_comparison_review_artifact_publication_intent(contract),
        intent_source_override="comparison_review_artifact_projection",
        run_id=run_id,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
        resource_version=artifact_digest,
        content_digest=artifact_digest,
        billing_assessment=None,
        local_only_environment=True,
        apply_pre_run_approval=False,
        parameters={
            "artifact_digest": artifact_digest,
            "artifact_kind": artifact_kind,
            "artifact_size_bytes": artifact_size_bytes,
            "billing_disposition_digest": billing_disposition_digest,
            "comparison_binding_digest": comparison_binding_digest,
            "destination_digest": destination_digest,
            "output_withheld": output_withheld,
        },
        requested_permission_class=PermissionClass.LOCAL_DRAFT,
        schema_version=(
            COMPARISON_REVIEW_ARTIFACT_SHADOW_EVENT_SCHEMA_VERSION
        ),
        comparison_binding_digest=comparison_binding_digest,
        use_comparison_publication_policy=True,
    )


def build_local_candidate_publication_shadow_event(
    *,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    project_root: Path,
    artifact_digest: str,
    artifact_size_bytes: int,
    artifact_kind: str,
    destination_digest: str,
    task_attempt_binding_digest: str,
    evaluation_accepted: bool,
    credential_scan_passed: bool,
    billing_disposition: Mapping[str, Any],
    evaluated_at: float,
    legacy_executable: bool,
) -> dict[str, Any]:
    """Observe intent before the first local candidate filesystem mutation.

    This owner-private candidate boundary is deliberately distinct from a
    future shared, remote, active-policy, deployment, or Git promotion action.
    ``required_before_promotion`` therefore does not apply here.
    """

    return _build_shadow_event(
        action_scope=PUBLICATION_ACTION_SCOPE,
        contract=contract,
        intent_override=_local_candidate_publication_intent(contract),
        intent_source_override="controller_boundary_projection",
        run_id=run_id,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        evaluated_at=evaluated_at,
        legacy_executable=legacy_executable,
        resource_version=artifact_digest,
        content_digest=artifact_digest,
        billing_assessment=None,
        local_only_environment=True,
        apply_pre_run_approval=False,
        parameters={
            "artifact_digest": artifact_digest,
            "artifact_kind": artifact_kind,
            "artifact_size_bytes": artifact_size_bytes,
            "billing_disposition": billing_disposition,
            "credential_scan_passed": credential_scan_passed,
            "destination_digest": destination_digest,
            "evaluation_accepted": evaluation_accepted,
            "task_attempt_binding_digest": task_attempt_binding_digest,
        },
        schema_version=TASK_CANDIDATE_ARTIFACT_SHADOW_EVENT_SCHEMA_VERSION,
        task_attempt_binding_digest=task_attempt_binding_digest,
    )


def _build_shadow_event(
    *,
    action_scope: str,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    project_root: Path,
    evaluated_at: float,
    legacy_executable: bool,
    resource_version: str,
    content_digest: str,
    billing_assessment: BillingRouteAssessment | None,
    local_only_environment: bool,
    apply_pre_run_approval: bool,
    parameters: Mapping[str, Any],
    intent_override: TaskAuthorizationIntent | None = None,
    intent_source_override: str | None = None,
    requested_permission_class: PermissionClass | None = None,
    schema_version: int = SHADOW_EVENT_SCHEMA_VERSION,
    comparison_binding_digest: str | None = None,
    task_attempt_binding_digest: str | None = None,
    use_comparison_policy: bool = False,
    use_comparison_publication_policy: bool = False,
) -> dict[str, Any]:
    """Construct and evaluate one observation, sanitizing every failure."""

    selected_permission_class = (
        contract.permission_class
        if requested_permission_class is None
        else requested_permission_class
    )
    request: AuthorizationRequest | None = None
    policy: PolicyBundle | None = None
    intent: TaskAuthorizationIntent | None = None
    intent_source: str | None = None
    try:
        if intent_override is None:
            intent, intent_source = _resolve_intent(contract)
        else:
            intent = intent_override
            intent_source = intent_source_override
            if intent_source is None:
                raise ValueError("an overridden intent requires a source")
        request = _build_request(
            action_scope=action_scope,
            contract=contract,
            intent=intent,
            intent_source=intent_source,
            run_id=run_id,
            runner_id=runner_id,
            profile_id=profile_id,
            project_root=project_root,
            evaluated_at=evaluated_at,
            resource_version=resource_version,
            content_digest=content_digest,
            billing_assessment=billing_assessment,
            local_only_environment=local_only_environment,
            parameters=parameters,
            requested_permission_class=selected_permission_class,
        )
        policy = _build_policy(
            contract,
            intent=intent,
            apply_pre_run_approval=apply_pre_run_approval,
            use_comparison_policy=use_comparison_policy,
            use_comparison_publication_policy=(
                use_comparison_publication_policy
            ),
        )
    except Exception:
        return _failure_payload(
            action_scope=action_scope,
            contract=contract,
            intent=intent,
            intent_source=intent_source,
            legacy_executable=legacy_executable,
            failure_stage="request_construction",
            requested_permission_class=selected_permission_class,
            schema_version=schema_version,
            comparison_binding_digest=comparison_binding_digest,
            task_attempt_binding_digest=task_attempt_binding_digest,
        )

    try:
        decision = ShadowAuthorizationEvaluator().evaluate(request, policy)
    except Exception:
        return _failure_payload(
            action_scope=action_scope,
            contract=contract,
            intent=intent,
            intent_source=intent_source,
            legacy_executable=legacy_executable,
            failure_stage="evaluation",
            request=request,
            policy=policy,
            requested_permission_class=selected_permission_class,
            schema_version=schema_version,
            comparison_binding_digest=comparison_binding_digest,
            task_attempt_binding_digest=task_attempt_binding_digest,
        )

    shadow_executable = decision.effect is AuthorizationEffect.PERMIT
    authority_ceiling_parity = (
        decision.derived_permission_class <= selected_permission_class
    )
    payload = {
        "schema_version": schema_version,
        "mode": "shadow",
        "action_scope": action_scope,
        "intent_source": intent_source,
        "intent_digest": intent.digest,
        "task_authorization_intent": intent.to_canonical(),
        "request": request.to_canonical(),
        "request_digest": request.digest,
        "decision": decision.to_canonical(),
        "decision_digest": decision.digest,
        "policy_bundle_id": decision.policy_bundle_id,
        "policy_version": decision.policy_version,
        "policy_digest": decision.policy_digest,
        "effect": decision.effect.value,
        "reason_codes": [item.value for item in decision.reason_codes],
        "matched_rule_ids": list(decision.matched_rule_ids),
        "evidence_refs": list(decision.evidence_refs),
        "obligations": [item.to_canonical() for item in decision.obligations],
        "derived_permission_class": int(decision.derived_permission_class),
        "requested_permission_class": int(selected_permission_class),
        "legacy_executable": legacy_executable,
        "execution_parity": shadow_executable == legacy_executable,
        "authority_ceiling_parity": authority_ceiling_parity,
    }
    if comparison_binding_digest is not None:
        payload["comparison_binding_digest"] = comparison_binding_digest
    if task_attempt_binding_digest is not None:
        payload["task_attempt_binding_digest"] = task_attempt_binding_digest
    return payload


def _resolve_intent(
    contract: TaskContract,
) -> tuple[TaskAuthorizationIntent, str]:
    if contract.authorization_intent is not None:
        return contract.authorization_intent, "task_contract"
    if contract.permission_class is PermissionClass.READ_ONLY:
        return (
            TaskAuthorizationIntent(
                action=TaskActionIntent(
                    verb=ActionVerb.READ,
                    operation="repository.inspect",
                    intended_effect="inspect_registered_task_inputs",
                ),
                resource=TaskResourceIntent(
                    resource_type="isolated_worktree",
                    trust_boundary="repository_run_workspace",
                    protected=False,
                    sensitivity=ImpactLevel.LOW,
                ),
                consequences=_low_consequence_intent(),
            ),
            "legacy_permission_class_fallback",
        )
    return (
        TaskAuthorizationIntent(
            action=TaskActionIntent(
                verb=ActionVerb.CREATE,
                operation="artifact.publish_local_candidate",
                intended_effect="create_isolated_local_candidate",
            ),
            resource=TaskResourceIntent(
                resource_type="local_candidate_artifact",
                trust_boundary="isolated_run_workspace",
                protected=False,
                sensitivity=ImpactLevel.LOW,
            ),
            consequences=_low_consequence_intent(),
        ),
        "legacy_permission_class_fallback",
    )


def task_authorization_intent_digest(contract: TaskContract) -> str:
    """Return the resolved task intent digest used at task boundaries."""

    intent, _ = _resolve_intent(contract)
    return intent.digest


def _low_consequence_intent() -> TaskConsequenceIntent:
    return TaskConsequenceIntent(
        confidentiality=ImpactLevel.LOW,
        integrity=ImpactLevel.LOW,
        availability=ImpactLevel.LOW,
        reach=Reach.LOCAL,
        destructive=False,
        reversible=True,
        sensitivity=ImpactLevel.LOW,
        blast_radius=BlastRadius.SINGLE_RESOURCE,
    )


def _local_candidate_publication_intent(
    contract: TaskContract,
) -> TaskAuthorizationIntent:
    """Return the controller-owned effect at the publication boundary.

    A task-level read intent cannot truthfully describe creation of the local
    review candidate.  The projection remains local and non-destructive but
    conservatively inherits the task's resource protection/sensitivity and
    consequence vector, so sensitive content cannot be relabeled as low risk.
    """

    task_intent, _ = _resolve_intent(contract)
    return TaskAuthorizationIntent(
        action=TaskActionIntent(
            verb=ActionVerb.CREATE,
            operation="artifact.publish_local_candidate",
            intended_effect="create_isolated_local_candidate",
        ),
        resource=TaskResourceIntent(
            resource_type="local_candidate_artifact",
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


def _comparison_trial_intent(contract: TaskContract) -> TaskAuthorizationIntent:
    """Project the immutable comparison effect without lowering task impacts."""

    task_intent, _ = _resolve_intent(contract)
    return TaskAuthorizationIntent(
        action=TaskActionIntent(
            verb=ActionVerb.READ,
            operation="comparison.evaluate_immutable_snapshot",
            intended_effect="evaluate_immutable_comparison_snapshot",
        ),
        resource=TaskResourceIntent(
            resource_type="comparison_snapshot",
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


def _comparison_review_artifact_publication_intent(
    contract: TaskContract,
) -> TaskAuthorizationIntent:
    """Project the controller-owned owner-private comparison artifact effect."""

    task_intent, _ = _resolve_intent(contract)
    return TaskAuthorizationIntent(
        action=TaskActionIntent(
            verb=ActionVerb.CREATE,
            operation="artifact.publish_private_review",
            intended_effect="create_owner_private_review_artifact",
        ),
        resource=TaskResourceIntent(
            resource_type="private_review_artifact",
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


def _build_request(
    *,
    action_scope: str,
    contract: TaskContract,
    intent: TaskAuthorizationIntent,
    intent_source: str,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    project_root: Path,
    evaluated_at: float,
    resource_version: str,
    content_digest: str,
    billing_assessment: BillingRouteAssessment | None,
    local_only_environment: bool,
    parameters: Mapping[str, Any],
    requested_permission_class: PermissionClass,
) -> AuthorizationRequest:
    profile_ref = canonical_digest(
        {"profile_id": profile_id if profile_id is not None else "implicit"}
    )
    repository_ref = canonical_digest({"project_root": str(project_root)})
    environment, environment_window = _build_environment(
        action_scope=action_scope,
        runner_id=runner_id,
        billing_assessment=billing_assessment,
        evaluated_at=evaluated_at,
        local_only_environment=local_only_environment,
    )
    request = AuthorizationRequest(
        request_id=f"{action_scope}:{run_id}",
        subject=SubjectAttributes(
            principal_id="agent:task-attempt",
            controller_id="agentops:local-controller",
            role=Role.IMPLEMENTER,
            role_version="1",
            profile_id=profile_ref,
            runner_id=runner_id,
            session_id=f"attempt:{run_id}",
        ),
        action=ActionAttributes(
            verb=intent.action.verb,
            operation=intent.action.operation,
            parameters_digest=canonical_digest(
                {
                    "action_scope": action_scope,
                    "intent_digest": intent.digest,
                    "intent_source": intent_source,
                    "legacy_permission_class": int(requested_permission_class),
                    "output_schema_digest": canonical_digest(contract.output_schema),
                    "parameters": parameters,
                    "profile_ref": profile_ref,
                    "runner_id": runner_id,
                    "task_definition_digest": contract.definition_hash,
                    "task_id": contract.task_id,
                    "task_version": contract.version,
                }
            ),
            intended_effect=intent.action.intended_effect,
        ),
        resource=ResourceAttributes(
            resource_type=intent.resource.resource_type,
            identifier=canonical_digest(
                {
                    "action_scope": action_scope,
                    "resource_type": intent.resource.resource_type,
                    "run_id": run_id,
                }
            ),
            version=resource_version,
            owner="operator:local",
            trust_boundary=intent.resource.trust_boundary,
            protected=intent.resource.protected,
            sensitivity=intent.resource.sensitivity,
            repository_id=repository_ref,
            content_digest=content_digest,
        ),
        environment=environment,
        consequences=ConsequenceVector(
            confidentiality=intent.consequences.confidentiality,
            integrity=intent.consequences.integrity,
            availability=intent.consequences.availability,
            reach=intent.consequences.reach,
            destructive=intent.consequences.destructive,
            reversible=intent.consequences.reversible,
            sensitivity=intent.consequences.sensitivity,
            blast_radius=intent.consequences.blast_radius,
        ),
    )
    evidence_sources = {
        "subject": EvidenceSource.CONTROLLER,
        "action": EvidenceSource.LOCAL_REGISTRY,
        "resource": EvidenceSource.LOCAL_REGISTRY,
        "consequences": EvidenceSource.LOCAL_REGISTRY,
    }
    evidence = [
        AttributeEvidence.bind(
            evidence_id=f"{action_scope}:{attribute}",
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id=f"agentops:{source.value}",
            observed_at=evaluated_at,
            expires_at=evaluated_at + _EVIDENCE_LIFETIME_SECONDS,
            authenticated=True,
        )
        for attribute, source in evidence_sources.items()
    ]
    if environment_window is not None:
        observed_at, expires_at = environment_window
        evidence.append(
            AttributeEvidence.bind(
                evidence_id=f"{action_scope}:environment",
                attribute="environment",
                value=request.attribute_value("environment"),
                source=EvidenceSource.CONTROLLER,
                source_id="agentops:controller",
                observed_at=observed_at,
                expires_at=expires_at,
                authenticated=True,
            )
        )
    return replace(request, evidence=tuple(evidence))


def _build_environment(
    *,
    action_scope: str,
    runner_id: str,
    billing_assessment: BillingRouteAssessment | None,
    evaluated_at: float,
    local_only_environment: bool,
) -> tuple[EnvironmentAttributes, tuple[float, float] | None]:
    if action_scope not in _FLOW_STATE_BY_SCOPE:
        raise ValueError("unsupported shadow authorization action scope")
    if local_only_environment:
        return (
            EnvironmentAttributes(
                evaluated_at=evaluated_at,
                isolation_state=IsolationState.VERIFIED,
                network_state=NetworkState.DISABLED,
                billing_route=BillingRoute.LOCAL_NON_AI,
                capacity_state=CapacityState.NOT_APPLICABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.NOT_APPLICABLE
                ),
                circuit_state=CircuitState.CLOSED,
                flow_state=_FLOW_STATE_BY_SCOPE[action_scope],
            ),
            (evaluated_at, evaluated_at + _EVIDENCE_LIFETIME_SECONDS),
        )
    if runner_id == "mock":
        return (
            EnvironmentAttributes(
                evaluated_at=evaluated_at,
                isolation_state=IsolationState.VERIFIED,
                network_state=NetworkState.DISABLED,
                billing_route=BillingRoute.MOCK,
                capacity_state=CapacityState.NOT_APPLICABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.NOT_APPLICABLE
                ),
                circuit_state=CircuitState.CLOSED,
                flow_state=_FLOW_STATE_BY_SCOPE[action_scope],
            ),
            (evaluated_at, evaluated_at + _EVIDENCE_LIFETIME_SECONDS),
        )
    if billing_assessment is None:
        return (
            EnvironmentAttributes(
                evaluated_at=evaluated_at,
                isolation_state=IsolationState.VERIFIED,
                network_state=NetworkState.UNKNOWN,
                billing_route=BillingRoute.UNKNOWN,
                capacity_state=CapacityState.UNKNOWN,
                paid_continuation_protection=PaidContinuationProtection.UNKNOWN,
                circuit_state=CircuitState.UNKNOWN,
                flow_state=_FLOW_STATE_BY_SCOPE[action_scope],
            ),
            (evaluated_at, evaluated_at + _EVIDENCE_LIFETIME_SECONDS),
        )

    environment = EnvironmentAttributes(
        evaluated_at=evaluated_at,
        isolation_state=IsolationState.VERIFIED,
        network_state=NetworkState.UNKNOWN,
        billing_route=billing_assessment.route,
        capacity_state=billing_assessment.capacity_state,
        paid_continuation_protection=(
            billing_assessment.paid_continuation_protection
        ),
        circuit_state=CircuitState.UNKNOWN,
        flow_state=_FLOW_STATE_BY_SCOPE[action_scope],
    )
    observations: list[float] = []
    expiries: list[float] = []
    if billing_assessment.capacity_observed_at is not None:
        observations.append(billing_assessment.capacity_observed_at)
    if billing_assessment.capacity_expires_at is not None:
        expiries.append(billing_assessment.capacity_expires_at)
    if billing_assessment.attestation is not None:
        observations.append(billing_assessment.attestation.observed_at)
        expiries.append(billing_assessment.attestation.expires_at)
    window = (
        (min(observations), min(expiries))
        if observations and expiries
        else None
    )
    return environment, window


def _build_policy(
    contract: TaskContract,
    *,
    intent: TaskAuthorizationIntent,
    apply_pre_run_approval: bool,
    use_comparison_policy: bool = False,
    use_comparison_publication_policy: bool = False,
) -> PolicyBundle:
    if use_comparison_policy and use_comparison_publication_policy:
        raise ValueError("comparison shadow policies are mutually exclusive")
    requirements: tuple[ApprovalRequirement, ...] = ()
    if (
        apply_pre_run_approval
        and contract.approval_requirements.required_before_run
    ):
        requirements = (
            ApprovalRequirement(
                requirement_id=_PRE_RUN_APPROVAL_REQUIREMENT,
                verbs=(intent.action.verb,),
                resource_types=(intent.resource.resource_type,),
                allowed_approver_ids=(contract.approval_requirements.approver,),
            ),
        )
    policy = PolicyBundle.current_stage(
        issued_at=0.0,
        approval_requirements=requirements,
    )
    if use_comparison_publication_policy:
        return replace(
            policy,
            bundle_id=(
                "ordomata.phase-1c.comparison-review-publication-shadow"
            ),
            version="1.0.0",
            enabled_classes=(PermissionClass.LOCAL_DRAFT,),
            allowed_verbs=(ActionVerb.CREATE,),
            allowed_operations=("artifact.publish_private_review",),
            allowed_resource_types=("private_review_artifact",),
            allowed_trust_boundaries=("isolated_run_workspace",),
            allowed_flow_states=("local_candidate_publication_proposed",),
            allowed_billing_routes=(BillingRoute.LOCAL_NON_AI,),
        )
    if not use_comparison_policy:
        return policy
    return replace(
        policy,
        bundle_id="agentops.phase-1c.comparison-shadow",
        version="1.0.0",
        enabled_classes=(PermissionClass.READ_ONLY,),
        allowed_verbs=(ActionVerb.READ,),
        allowed_operations=("comparison.evaluate_immutable_snapshot",),
        allowed_resource_types=("comparison_snapshot",),
        allowed_trust_boundaries=("isolated_run_workspace",),
        allowed_flow_states=(
            "admission_proposed",
            "runner_dispatch_proposed",
        ),
    )


def _failure_payload(
    *,
    action_scope: str,
    contract: TaskContract,
    intent: TaskAuthorizationIntent | None,
    intent_source: str | None,
    legacy_executable: bool,
    failure_stage: str,
    requested_permission_class: PermissionClass,
    schema_version: int,
    comparison_binding_digest: str | None,
    task_attempt_binding_digest: str | None = None,
    request: AuthorizationRequest | None = None,
    policy: PolicyBundle | None = None,
) -> dict[str, Any]:
    shadow_executable = False
    payload = {
        "schema_version": schema_version,
        "mode": "shadow",
        "action_scope": action_scope,
        "intent_source": intent_source,
        "intent_digest": None if intent is None else intent.digest,
        "task_authorization_intent": (
            None if intent is None else intent.to_canonical()
        ),
        "request": None if request is None else request.to_canonical(),
        "request_digest": None if request is None else request.digest,
        "decision": None,
        "decision_digest": None,
        "policy_bundle_id": None if policy is None else policy.bundle_id,
        "policy_version": None if policy is None else policy.version,
        "policy_digest": None if policy is None else policy.digest,
        "effect": AuthorizationEffect.INDETERMINATE.value,
        "reason_codes": ["shadow_evaluation_failed"],
        "matched_rule_ids": [],
        "evidence_refs": [],
        "obligations": [],
        "derived_permission_class": None,
        "requested_permission_class": int(requested_permission_class),
        "legacy_executable": legacy_executable,
        "execution_parity": shadow_executable == legacy_executable,
        "authority_ceiling_parity": None,
        "failure_stage": failure_stage,
    }
    if comparison_binding_digest is not None:
        payload["comparison_binding_digest"] = comparison_binding_digest
    if task_attempt_binding_digest is not None:
        payload["task_attempt_binding_digest"] = task_attempt_binding_digest
    return payload


__all__ = [
    "ADMISSION_ACTION_SCOPE",
    "COMPARISON_REVIEW_ARTIFACT_SHADOW_EVENT_SCHEMA_VERSION",
    "COMPARISON_SHADOW_EVENT_SCHEMA_VERSION",
    "DISPATCH_ACTION_SCOPE",
    "PUBLICATION_ACTION_SCOPE",
    "SHADOW_ACTION_SCOPE",
    "SHADOW_EVENT_SCHEMA_VERSION",
    "TASK_CANDIDATE_ARTIFACT_SHADOW_EVENT_SCHEMA_VERSION",
    "build_comparison_review_artifact_publication_shadow_event",
    "build_comparison_trial_admission_shadow_event",
    "build_comparison_trial_dispatch_shadow_event",
    "build_local_candidate_publication_shadow_event",
    "build_runner_model_dispatch_shadow_event",
    "build_task_admission_shadow_event",
    "task_authorization_intent_digest",
]
