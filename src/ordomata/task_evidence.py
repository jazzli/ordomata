"""Digest-only controller evidence for ordinary task attempts.

Bindings and publication receipts are evidence, never authorization grants.
Schema-v3 bindings additionally declare that a separate mock-dispatch decision
and action receipt are required.  Schema-v4 retains that exact binding shape
and declares a second, local-candidate publication enforcement chain.  In both
cases authority comes from the typed runtime decision plus the independent
legacy Class 0/1 gate.
"""

from __future__ import annotations

from collections.abc import Mapping
import math
from typing import Any

from .authorization import canonical_digest
from .billing import BillingPostRunDisposition
from .contracts import TaskContract
from .errors import ValidationError
from .execution_selection import TASK_EXECUTION_SELECTION_EVENT_TYPE
from .models import (
    BillingRoute,
    PermissionClass,
    RunRequest,
    RunnerExecutionResult,
)
from .state import ArtifactRecord


TASK_ATTEMPT_AUTHORIZATION_BINDING_EVENT_TYPE = (
    "task_attempt_authorization_binding"
)
TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE = (
    "task_attempt_candidate_artifact_intent"
)
TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE = (
    "task_attempt_candidate_artifact_action_receipt"
)
TASK_ATTEMPT_AUTHORIZATION_SHADOW_COVERAGE = (
    "task_attempt_admission_dispatch_publication_shadow"
)
TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE = (
    "task_attempt_candidate_artifact_pre_effect_action_receipt"
)
TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE = (
    "task_attempt_mock_dispatch_decision_action_receipt"
)
TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE = (
    "task_attempt_local_candidate_publication_decision_action_receipt"
)

_TASK_EXECUTION_MODES = {
    "mock": "in_memory_mock",
    "codex": "codex_exec_jsonl_read_only_ephemeral",
    "claude": "claude_print_stream_json_safe_no_tools",
}


def build_task_attempt_binding_event(
    *,
    contract: TaskContract,
    request: RunRequest,
    runner_id: str,
    context_digest: str,
    prompt_digest: str,
    project_root: str,
    profile_id: str | None,
    authorization_intent_digest: str,
    execution_selection_digest: str | None = None,
    profile_version_ref: str | None = None,
    profile_configuration_digest: str | None = None,
    enforce_mock_dispatch: bool = False,
    enforce_local_candidate_publication: bool = False,
) -> dict[str, Any]:
    """Bind later evidence to immutable, controller-authored attempt inputs."""

    selection_values = (
        execution_selection_digest,
        profile_version_ref,
        profile_configuration_digest,
    )
    selection_bound = all(value is not None for value in selection_values)
    if any(value is not None for value in selection_values) and not selection_bound:
        raise ValidationError(
            "execution selection binding fields must be provided together"
        )
    if selection_bound and profile_id is None:
        raise ValidationError("execution selection requires a named profile")
    if not isinstance(enforce_mock_dispatch, bool):
        raise ValidationError("mock dispatch enforcement flag must be a boolean")
    if not isinstance(enforce_local_candidate_publication, bool):
        raise ValidationError(
            "local candidate publication enforcement flag must be a boolean"
        )
    if enforce_mock_dispatch and (not selection_bound or runner_id != "mock"):
        raise ValidationError(
            "mock dispatch enforcement requires a selected mock profile"
        )
    if enforce_local_candidate_publication and not enforce_mock_dispatch:
        raise ValidationError(
            "local candidate publication enforcement requires mock dispatch enforcement"
        )

    binding: dict[str, Any] = {
        "kind": "task_attempt",
        "run_ref": canonical_digest({"run_id": request.run_id}),
        "task_id": contract.task_id,
        "task_version": contract.version,
        "task_definition_digest": _normalized_digest(
            contract.definition_hash,
            "task definition digest",
        ),
        "authorization_intent_digest": _normalized_digest(
            authorization_intent_digest,
            "authorization intent digest",
        ),
        "context_digest": _normalized_digest(
            context_digest,
            "context digest",
        ),
        "prompt_digest": _normalized_digest(prompt_digest, "prompt digest"),
        "output_schema_digest": canonical_digest(contract.output_schema),
        "repository_ref": canonical_digest({"project_root": project_root}),
        "profile_ref": canonical_digest(
            {"profile_id": profile_id if profile_id is not None else "implicit"}
        ),
        "runner_overrides_digest": canonical_digest(
            dict(request.runner_overrides)
        ),
        "runner_id": runner_id,
        "timeout_seconds": request.timeout_seconds,
        "attempt": request.attempt,
        "permission_class": int(request.permission_class),
    }
    if selection_bound:
        assert execution_selection_digest is not None
        assert profile_version_ref is not None
        assert profile_configuration_digest is not None
        binding.update(
            {
                "execution_selection_digest": _normalized_digest(
                    execution_selection_digest,
                    "execution selection digest",
                ),
                "profile_version_ref": _normalized_digest(
                    profile_version_ref,
                    "profile version reference",
                ),
                "profile_configuration_digest": _normalized_digest(
                    profile_configuration_digest,
                    "profile configuration digest",
                ),
            }
        )
    if enforce_mock_dispatch:
        binding.update(
            {
                "workspace_ref": canonical_digest(
                    {"workspace": str(request.workspace)}
                ),
                "pre_run_approval_requirements_digest": canonical_digest(
                    {
                        "approver": contract.approval_requirements.approver,
                        "required_before_run": (
                            contract.approval_requirements.required_before_run
                        ),
                    }
                ),
            }
        )
    payload = {
        "schema_version": (
            4
            if enforce_local_candidate_publication
            else 3
            if enforce_mock_dispatch
            else 2
            if selection_bound
            else 1
        ),
        "authorization_shadow_coverage": (
            TASK_ATTEMPT_AUTHORIZATION_SHADOW_COVERAGE
        ),
        "authorization_action_receipt_coverage": (
            TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE
        ),
        "binding": binding,
        "binding_digest": canonical_digest(binding),
    }
    if enforce_mock_dispatch:
        payload["authorization_enforcement_coverage"] = (
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE
        )
    if enforce_local_candidate_publication:
        payload["publication_authorization_enforcement_coverage"] = (
            TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
        )
    return payload


def task_publication_billing_projection(
    *,
    identity_matches: bool,
    billing_matches: bool,
    billing_disposition: BillingPostRunDisposition,
) -> dict[str, Any]:
    """Project only independently inspectable post-run billing semantics."""

    return {
        "identity_matches": identity_matches is True,
        "billing_matches": billing_matches is True,
        "capacity_state": billing_disposition.capacity_state.value,
        "paid_capacity_consumed": (
            billing_disposition.paid_capacity_consumed.value
        ),
        "incremental_ai_charge": (
            billing_disposition.incremental_ai_charge.value
        ),
        "quarantine_required": billing_disposition.quarantine_required,
        "circuit_breaker_required": (
            billing_disposition.circuit_breaker_required
        ),
        "reason_codes": list(billing_disposition.reasons),
    }


def task_publication_billing_digest(
    *,
    identity_matches: bool,
    billing_matches: bool,
    billing_disposition: BillingPostRunDisposition,
) -> str:
    return canonical_digest(
        task_publication_billing_projection(
            identity_matches=identity_matches,
            billing_matches=billing_matches,
            billing_disposition=billing_disposition,
        )
    )


def build_task_execution_accounting(
    *,
    result: RunnerExecutionResult,
    billing_matches: bool,
    billing_disposition: BillingPostRunDisposition,
    runner_event_count: int,
    incremental_api_charge: str,
) -> dict[str, Any]:
    """Return the schema-v2 accounting record consumed by the inspector."""

    billing_digest = task_publication_billing_digest(
        identity_matches=True,
        billing_matches=billing_matches,
        billing_disposition=billing_disposition,
    )
    return {
        "schema_version": 2,
        "result_observed": True,
        "identity_matches": True,
        "billing_matches": billing_matches,
        "runner_event_count": runner_event_count,
        "result_status": result.status.value,
        "harness_process_started": result.harness_process_started,
        "live_model_execution_occurred": (
            result.live_model_execution_occurred
        ),
        "subscription_capacity_consumed": (
            result.subscription_capacity_consumed if billing_matches else None
        ),
        "paid_capacity_consumed": (
            billing_disposition.paid_capacity_consumed.value
        ),
        "incremental_ai_charge": (
            billing_disposition.incremental_ai_charge.value
        ),
        "capacity_state": billing_disposition.capacity_state.value,
        "billing_disposition_reason_codes": list(
            billing_disposition.reasons
        ),
        "billing_disposition_digest": billing_digest,
        "usage_observation": result.usage_observation.value,
        "billing_quarantine_required": (
            billing_disposition.quarantine_required
        ),
        "billing_circuit_breaker_required": (
            billing_disposition.circuit_breaker_required
        ),
        "failure_code": None,
        "wall_seconds": result.wall_seconds,
        # Adapter diagnostics are untrusted descriptive input.  Preserve a
        # bounded reference to a version without persisting the raw string,
        # and retain an execution-mode label only when it matches a fixed
        # controller-owned route/runner vocabulary.
        "runner_version": task_runner_version_reference(
            result.runner_version
        ),
        "execution_mode": task_execution_mode(result),
        "incremental_api_charge": incremental_api_charge,
    }


def task_runner_version_reference(value: Any) -> str | None:
    """Return a content reference without retaining adapter-provided text."""

    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    return canonical_digest({"runner_version": value})


def task_execution_mode(result: RunnerExecutionResult) -> str | None:
    """Project only a runner/route-consistent controller-owned mode label."""

    expected = _TASK_EXECUTION_MODES.get(result.runner_id)
    billing_assessment = result.billing_assessment
    if (
        expected is None
        and getattr(billing_assessment, "route", None)
        is BillingRoute.LOCAL_NON_AI
    ):
        expected = "local_non_ai"
    return expected if result.execution_mode == expected else None


def artifact_record_digest(record: ArtifactRecord) -> str:
    """Bind an immutable metadata row without exposing its path or identifier."""

    return canonical_digest(
        {
            "artifact_id_ref": canonical_digest(
                {"artifact_id": record.artifact_id}
            ),
            "run_ref": canonical_digest({"run_id": record.run_id}),
            "artifact_kind": record.kind,
            "destination_digest": canonical_digest(
                {"artifact_path": record.path}
            ),
            "artifact_digest": "sha256:" + record.sha256,
            "media_type": record.media_type,
            "size_bytes": record.size_bytes,
        }
    )


def build_candidate_artifact_pre_effect_receipt(
    *,
    task_attempt_binding_digest: str,
    publication_shadow: Mapping[str, Any],
    publication_shadow_persisted: bool,
    requested_permission_class: PermissionClass,
    artifact_kind: str,
    destination_digest: str,
    artifact_digest: str,
    artifact_size_bytes: int,
    artifact_metadata_digest: str,
    billing_disposition_digest: str,
    started_at: float,
    publication_authorization: Mapping[str, Any] | None = None,
    publication_authorization_event_id: str | None = None,
) -> dict[str, Any]:
    enforcement = _publication_authorization_links(
        publication_authorization,
        publication_authorization_event_id,
    )
    if enforcement is not None:
        request_digest, decision_digest, action_digest, _ = enforcement
        if (
            not isinstance(publication_shadow_persisted, bool)
            or not isinstance(requested_permission_class, PermissionClass)
            or not isinstance(artifact_kind, str)
            or not artifact_kind
            or not _is_digest(task_attempt_binding_digest)
            or not _is_digest(destination_digest)
            or not _is_digest(artifact_digest)
            or not isinstance(artifact_size_bytes, int)
            or isinstance(artifact_size_bytes, bool)
            or artifact_size_bytes <= 0
            or not _is_digest(artifact_metadata_digest)
            or not _is_digest(billing_disposition_digest)
            or not _is_timestamp(started_at)
        ):
            raise ValidationError(
                "candidate enforcing pre-effect inputs are invalid"
            )
        payload = {
            "schema_version": 3,
            "mode": "enforcing",
            "receipt_kind": "pre_effect",
            "authorization_enforced": True,
            "authority_basis": (
                "abac_exact_permit_and_legacy_permission_class_gate"
            ),
            "task_attempt_binding_digest": task_attempt_binding_digest,
            "publication_shadow_persisted": publication_shadow_persisted,
            "publication_shadow_request_digest": _shadow_link_digest(
                publication_shadow,
                "request_digest",
            ),
            "publication_shadow_decision_digest": _shadow_link_digest(
                publication_shadow,
                "decision_digest",
            ),
            "publication_authorization_event_id": (
                publication_authorization_event_id
            ),
            "publication_enforcement_coverage": (
                TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
            ),
            "publication_request_digest": request_digest,
            "publication_decision_digest": decision_digest,
            "action_digest": action_digest,
            "requested_permission_class": int(requested_permission_class),
            "artifact_kind": artifact_kind,
            "destination_digest": destination_digest,
            "artifact_digest": artifact_digest,
            "artifact_size_bytes": artifact_size_bytes,
            "artifact_record_digest": artifact_metadata_digest,
            "billing_disposition_digest": billing_disposition_digest,
            "evaluation_accepted": True,
            "credential_scan_passed": True,
            "started_at": started_at,
        }
        payload["receipt_digest"] = canonical_digest(payload)
        return payload

    payload: dict[str, Any] = {
        "schema_version": 2,
        "mode": "shadow",
        "receipt_kind": "pre_effect",
        "authorization_enforced": False,
        "authority_basis": "legacy_permission_class_gate",
        "task_attempt_binding_digest": task_attempt_binding_digest,
        "publication_shadow_persisted": publication_shadow_persisted,
        "publication_request_digest": _shadow_link_digest(
            publication_shadow,
            "request_digest",
        ),
        "publication_decision_digest": _shadow_link_digest(
            publication_shadow,
            "decision_digest",
        ),
        "action_digest": _shadow_action_digest(publication_shadow),
        "requested_permission_class": int(requested_permission_class),
        "artifact_kind": artifact_kind,
        "destination_digest": destination_digest,
        "artifact_digest": artifact_digest,
        "artifact_size_bytes": artifact_size_bytes,
        "artifact_record_digest": artifact_metadata_digest,
        "billing_disposition_digest": billing_disposition_digest,
        "evaluation_accepted": True,
        "credential_scan_passed": True,
        "started_at": started_at,
    }
    payload["receipt_digest"] = canonical_digest(payload)
    return payload


def build_candidate_artifact_action_receipt(
    *,
    task_attempt_binding_digest: str,
    pre_effect_receipt: Mapping[str, Any],
    publication_shadow: Mapping[str, Any],
    publication_shadow_persisted: bool,
    requested_permission_class: PermissionClass,
    artifact_kind: str,
    destination_digest: str,
    intended_artifact_digest: str,
    intended_artifact_size_bytes: int,
    artifact_metadata_digest: str,
    billing_disposition_digest: str,
    started_at: float,
    completed_at: float,
    outcome: str,
    result_digest: str | None,
    observed_artifact_size_bytes: int | None,
    failure_code: str | None,
    publication_authorization: Mapping[str, Any] | None = None,
    publication_authorization_event_id: str | None = None,
    effect_started_at: float | None = None,
    enforcement_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    pre_effect_receipt_digest = pre_effect_receipt.get("receipt_digest")
    if not isinstance(pre_effect_receipt_digest, str):
        raise ValidationError("candidate pre-effect receipt digest is missing")
    enforcement = _publication_authorization_links(
        publication_authorization,
        publication_authorization_event_id,
    )
    enforcing_action = any(
        value is not None
        for value in (
            publication_authorization,
            publication_authorization_event_id,
            effect_started_at,
            enforcement_receipt,
        )
    )
    if enforcing_action:
        if (
            enforcement is None
            or effect_started_at is None
            or enforcement_receipt is None
        ):
            raise ValidationError(
                "candidate enforcing receipt inputs must be provided together"
            )
        request_digest, decision_digest, action_digest, obligations = (
            enforcement
        )
        _validate_enforcing_artifact_outcome(
            started_at=started_at,
            effect_started_at=effect_started_at,
            completed_at=completed_at,
            outcome=outcome,
            intended_artifact_digest=intended_artifact_digest,
            intended_artifact_size_bytes=intended_artifact_size_bytes,
            result_digest=result_digest,
            observed_artifact_size_bytes=observed_artifact_size_bytes,
            failure_code=failure_code,
        )
        _validate_enforcing_pre_effect_receipt(
            pre_effect_receipt,
            task_attempt_binding_digest=task_attempt_binding_digest,
            publication_authorization_event_id=(
                publication_authorization_event_id
            ),
            publication_shadow_persisted=publication_shadow_persisted,
            publication_shadow_request_digest=_shadow_link_digest(
                publication_shadow,
                "request_digest",
            ),
            publication_shadow_decision_digest=_shadow_link_digest(
                publication_shadow,
                "decision_digest",
            ),
            request_digest=request_digest,
            decision_digest=decision_digest,
            action_digest=action_digest,
            requested_permission_class=requested_permission_class,
            artifact_kind=artifact_kind,
            destination_digest=destination_digest,
            intended_artifact_digest=intended_artifact_digest,
            intended_artifact_size_bytes=intended_artifact_size_bytes,
            artifact_metadata_digest=artifact_metadata_digest,
            billing_disposition_digest=billing_disposition_digest,
            started_at=started_at,
        )
        enforcement_receipt_mapping = dict(enforcement_receipt)
        _validate_enforcement_action_receipt(
            enforcement_receipt_mapping,
            task_attempt_binding_digest=task_attempt_binding_digest,
            destination_digest=destination_digest,
            request_digest=request_digest,
            decision_digest=decision_digest,
            action_digest=action_digest,
            obligations=obligations,
            effect_started_at=effect_started_at,
            completed_at=completed_at,
            outcome=outcome,
            result_digest=result_digest,
        )
        payload = {
            "schema_version": 3,
            "mode": "enforcing",
            "receipt_kind": "action",
            "authorization_enforced": True,
            "authority_basis": (
                "abac_exact_permit_and_legacy_permission_class_gate"
            ),
            "receipt_id": canonical_digest(
                {
                    "task_attempt_binding_digest": (
                        task_attempt_binding_digest
                    ),
                    "destination_digest": destination_digest,
                    "pre_effect_receipt_digest": pre_effect_receipt_digest,
                }
            ),
            "task_attempt_binding_digest": task_attempt_binding_digest,
            "pre_effect_receipt_digest": pre_effect_receipt_digest,
            "publication_shadow_persisted": publication_shadow_persisted,
            "publication_shadow_request_digest": _shadow_link_digest(
                publication_shadow,
                "request_digest",
            ),
            "publication_shadow_decision_digest": _shadow_link_digest(
                publication_shadow,
                "decision_digest",
            ),
            "publication_authorization_event_id": (
                publication_authorization_event_id
            ),
            "publication_enforcement_coverage": (
                TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
            ),
            "publication_request_digest": request_digest,
            "publication_decision_digest": decision_digest,
            "action_digest": action_digest,
            "executor_id": "ordomata:local-controller",
            "started_at": started_at,
            "effect_started_at": effect_started_at,
            "completed_at": completed_at,
            "outcome": outcome,
            "obligation_results": _obligation_result_projection(
                obligations
            ),
            "requested_permission_class": int(requested_permission_class),
            "artifact_kind": artifact_kind,
            "destination_digest": destination_digest,
            "intended_artifact_digest": intended_artifact_digest,
            "intended_artifact_size_bytes": intended_artifact_size_bytes,
            "artifact_record_digest": artifact_metadata_digest,
            "billing_disposition_digest": billing_disposition_digest,
            "evaluation_accepted": True,
            "credential_scan_passed": True,
            "result_digest": result_digest,
            "observed_artifact_size_bytes": observed_artifact_size_bytes,
            "failure_code": failure_code,
            "enforcement_receipt": enforcement_receipt_mapping,
            "enforcement_receipt_digest": canonical_digest(
                enforcement_receipt_mapping
            ),
        }
        payload["receipt_digest"] = canonical_digest(payload)
        return payload

    payload: dict[str, Any] = {
        "schema_version": 2,
        "mode": "shadow",
        "receipt_kind": "action",
        "authorization_enforced": False,
        "authority_basis": "legacy_permission_class_gate",
        "receipt_id": canonical_digest(
            {
                "task_attempt_binding_digest": task_attempt_binding_digest,
                "destination_digest": destination_digest,
                "pre_effect_receipt_digest": pre_effect_receipt_digest,
            }
        ),
        "task_attempt_binding_digest": task_attempt_binding_digest,
        "pre_effect_receipt_digest": pre_effect_receipt_digest,
        "publication_shadow_persisted": publication_shadow_persisted,
        "publication_request_digest": _shadow_link_digest(
            publication_shadow,
            "request_digest",
        ),
        "publication_decision_digest": _shadow_link_digest(
            publication_shadow,
            "decision_digest",
        ),
        "action_digest": _shadow_action_digest(publication_shadow),
        "executor_id": "ordomata:local-controller",
        "started_at": started_at,
        "completed_at": completed_at,
        "outcome": outcome,
        "obligation_results": _shadow_obligation_results(
            publication_shadow
        ),
        "requested_permission_class": int(requested_permission_class),
        "artifact_kind": artifact_kind,
        "destination_digest": destination_digest,
        "intended_artifact_digest": intended_artifact_digest,
        "intended_artifact_size_bytes": intended_artifact_size_bytes,
        "artifact_record_digest": artifact_metadata_digest,
        "billing_disposition_digest": billing_disposition_digest,
        "evaluation_accepted": True,
        "credential_scan_passed": True,
        "result_digest": result_digest,
        "observed_artifact_size_bytes": observed_artifact_size_bytes,
        "failure_code": failure_code,
    }
    payload["receipt_digest"] = canonical_digest(payload)
    return payload


def _publication_authorization_links(
    publication_authorization: Mapping[str, Any] | None,
    publication_authorization_event_id: str | None,
) -> tuple[
    str,
    str,
    str,
    tuple[tuple[str, str], ...],
] | None:
    supplied = (
        publication_authorization is not None,
        publication_authorization_event_id is not None,
    )
    if not any(supplied):
        return None
    if not all(supplied) or not isinstance(publication_authorization, Mapping):
        raise ValidationError(
            "candidate publication authorization inputs must be provided together"
        )
    if not _is_digest(publication_authorization_event_id):
        raise ValidationError(
            "candidate publication authorization event identifier is invalid"
        )
    if (
        publication_authorization.get("mode") != "enforcing"
        or publication_authorization.get("enforcement_coverage")
        != TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
        or publication_authorization.get("effect") != "permit"
        or publication_authorization.get("authorization_eligible") is not True
    ):
        raise ValidationError(
            "candidate publication authorization is not an exact permit"
        )
    request = publication_authorization.get("request")
    decision = publication_authorization.get("decision")
    request_digest = publication_authorization.get("request_digest")
    decision_digest = publication_authorization.get("decision_digest")
    if (
        not isinstance(request, Mapping)
        or not isinstance(decision, Mapping)
        or set(request)
        != {
            "action",
            "consequences",
            "environment",
            "evidence",
            "request_id",
            "resource",
            "subject",
        }
        or set(decision)
        != {
            "derived_permission_class",
            "effect",
            "evidence_refs",
            "expires_at",
            "issued_at",
            "matched_rule_ids",
            "obligations",
            "policy_bundle_id",
            "policy_digest",
            "policy_version",
            "reason_codes",
            "reason_details",
            "request_digest",
            "request_id",
        }
        or not _is_digest(request_digest)
        or not _is_digest(decision_digest)
        or request_digest != canonical_digest(request)
        or decision_digest != canonical_digest(decision)
        or decision.get("effect") != "permit"
        or decision.get("request_digest") != request_digest
    ):
        raise ValidationError(
            "candidate publication authorization digests are inconsistent"
        )
    action = request.get("action")
    resource = request.get("resource")
    if (
        not isinstance(action, Mapping)
        or not isinstance(resource, Mapping)
        or action.get("verb") != "create"
        or action.get("operation") != "artifact.publish_local_candidate"
        or resource.get("resource_type") != "local_candidate_artifact"
        or resource.get("trust_boundary") != "isolated_run_workspace"
    ):
        raise ValidationError(
            "candidate publication authorization action is invalid"
        )
    obligations = decision.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        raise ValidationError(
            "candidate publication authorization obligations are invalid"
        )
    obligation_pairs: list[tuple[str, str]] = []
    for obligation in obligations:
        if not isinstance(obligation, Mapping):
            raise ValidationError(
                "candidate publication authorization obligations are invalid"
            )
        kind = obligation.get("kind")
        value = obligation.get("value")
        if (
            not isinstance(kind, str)
            or not kind
            or not isinstance(value, str)
            or not value
        ):
            raise ValidationError(
                "candidate publication authorization obligations are invalid"
            )
        obligation_pairs.append((kind, value))
    if (
        obligation_pairs != sorted(obligation_pairs)
        or len(obligation_pairs) != len(set(obligation_pairs))
    ):
        raise ValidationError(
            "candidate publication authorization obligations are invalid"
        )
    return (
        request_digest,
        decision_digest,
        canonical_digest({"action": action, "resource": resource}),
        tuple(obligation_pairs),
    )


def _validate_enforcing_pre_effect_receipt(
    payload: Mapping[str, Any],
    *,
    task_attempt_binding_digest: str,
    publication_authorization_event_id: str | None,
    publication_shadow_persisted: bool,
    publication_shadow_request_digest: str | None,
    publication_shadow_decision_digest: str | None,
    request_digest: str,
    decision_digest: str,
    action_digest: str,
    requested_permission_class: PermissionClass,
    artifact_kind: str,
    destination_digest: str,
    intended_artifact_digest: str,
    intended_artifact_size_bytes: int,
    artifact_metadata_digest: str,
    billing_disposition_digest: str,
    started_at: float,
) -> None:
    expected_keys = {
        "action_digest",
        "artifact_digest",
        "artifact_kind",
        "artifact_record_digest",
        "artifact_size_bytes",
        "authority_basis",
        "authorization_enforced",
        "billing_disposition_digest",
        "credential_scan_passed",
        "destination_digest",
        "evaluation_accepted",
        "mode",
        "publication_authorization_event_id",
        "publication_decision_digest",
        "publication_enforcement_coverage",
        "publication_request_digest",
        "publication_shadow_decision_digest",
        "publication_shadow_persisted",
        "publication_shadow_request_digest",
        "receipt_digest",
        "receipt_kind",
        "requested_permission_class",
        "schema_version",
        "started_at",
        "task_attempt_binding_digest",
    }
    receipt_digest = payload.get("receipt_digest")
    receipt_body = dict(payload)
    receipt_body.pop("receipt_digest", None)
    if (
        set(payload) != expected_keys
        or not _is_digest(receipt_digest)
        or receipt_digest != canonical_digest(receipt_body)
        or payload.get("schema_version") != 3
        or payload.get("mode") != "enforcing"
        or payload.get("receipt_kind") != "pre_effect"
        or payload.get("authorization_enforced") is not True
        or payload.get("authority_basis")
        != "abac_exact_permit_and_legacy_permission_class_gate"
        or payload.get("publication_enforcement_coverage")
        != TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
        or payload.get("task_attempt_binding_digest")
        != task_attempt_binding_digest
        or payload.get("publication_authorization_event_id")
        != publication_authorization_event_id
        or payload.get("publication_shadow_persisted")
        is not publication_shadow_persisted
        or payload.get("publication_shadow_request_digest")
        != publication_shadow_request_digest
        or payload.get("publication_shadow_decision_digest")
        != publication_shadow_decision_digest
        or payload.get("publication_request_digest") != request_digest
        or payload.get("publication_decision_digest") != decision_digest
        or payload.get("action_digest") != action_digest
        or payload.get("requested_permission_class")
        != int(requested_permission_class)
        or payload.get("artifact_kind") != artifact_kind
        or payload.get("destination_digest") != destination_digest
        or payload.get("artifact_digest") != intended_artifact_digest
        or payload.get("artifact_size_bytes")
        != intended_artifact_size_bytes
        or payload.get("artifact_record_digest")
        != artifact_metadata_digest
        or payload.get("billing_disposition_digest")
        != billing_disposition_digest
        or payload.get("evaluation_accepted") is not True
        or payload.get("credential_scan_passed") is not True
        or payload.get("started_at") != started_at
    ):
        raise ValidationError(
            "candidate enforcing pre-effect receipt is inconsistent"
        )


def _validate_enforcement_action_receipt(
    receipt: Mapping[str, Any],
    *,
    task_attempt_binding_digest: str,
    destination_digest: str,
    request_digest: str,
    decision_digest: str,
    action_digest: str,
    obligations: tuple[tuple[str, str], ...],
    effect_started_at: float,
    completed_at: float,
    outcome: str,
    result_digest: str | None,
) -> None:
    expected_keys = {
        "completed_at",
        "decision_digest",
        "enforced_action_digest",
        "executor_id",
        "obligation_results",
        "outcome",
        "receipt_id",
        "request_digest",
        "result_digest",
        "started_at",
    }
    obligation_results = receipt.get("obligation_results")
    expected_obligation_results = [
        {"kind": kind, "satisfied": True, "value": value}
        for kind, value in obligations
    ]
    expected_receipt_id = canonical_digest(
        {
            "decision_digest": decision_digest,
            "destination_digest": destination_digest,
            "request_digest": request_digest,
            "task_attempt_binding_digest": task_attempt_binding_digest,
            "receipt_kind": "local_candidate_publication_action",
        }
    )
    if (
        set(receipt) != expected_keys
        or receipt.get("receipt_id") != expected_receipt_id
        or receipt.get("request_digest") != request_digest
        or receipt.get("decision_digest") != decision_digest
        or receipt.get("enforced_action_digest") != action_digest
        or receipt.get("executor_id") != "ordomata:local-controller"
        or receipt.get("started_at") != effect_started_at
        or receipt.get("completed_at") != completed_at
        or receipt.get("outcome") != outcome
        or receipt.get("result_digest") != result_digest
        or obligation_results != expected_obligation_results
        or not _is_timestamp(effect_started_at)
        or not _is_timestamp(completed_at)
        or completed_at < effect_started_at
    ):
        raise ValidationError(
            "candidate publication enforcement receipt is inconsistent"
        )


def _validate_enforcing_artifact_outcome(
    *,
    started_at: float,
    effect_started_at: float,
    completed_at: float,
    outcome: str,
    intended_artifact_digest: str,
    intended_artifact_size_bytes: int,
    result_digest: str | None,
    observed_artifact_size_bytes: int | None,
    failure_code: str | None,
) -> None:
    timestamps_valid = (
        _is_timestamp(started_at)
        and _is_timestamp(effect_started_at)
        and _is_timestamp(completed_at)
        and started_at <= effect_started_at <= completed_at
    )
    if outcome == "succeeded":
        outcome_valid = (
            failure_code is None
            and result_digest == intended_artifact_digest
            and observed_artifact_size_bytes == intended_artifact_size_bytes
        )
    else:
        failure_codes = {
            "failed": "artifact_persistence_failed",
            "cancelled": "artifact_persistence_interrupted",
            "unknown": "artifact_publication_outcome_unknown",
        }
        outcome_valid = (
            outcome in failure_codes
            and failure_code == failure_codes.get(outcome)
            and result_digest is None
            and observed_artifact_size_bytes is None
        )
    if not timestamps_valid or not outcome_valid:
        raise ValidationError(
            "candidate enforcing artifact outcome is inconsistent"
        )


def _obligation_result_projection(
    obligations: tuple[tuple[str, str], ...],
) -> list[dict[str, Any]]:
    return [
        {
            "kind": kind,
            "satisfied": True,
            "value_digest": canonical_digest({"value": value}),
        }
        for kind, value in obligations
    ]


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_timestamp(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and value >= 0
    )


def _normalized_digest(value: str, field_name: str) -> str:
    if (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    ):
        return value
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return "sha256:" + value
    raise ValidationError(f"{field_name} must be a canonical SHA-256 digest")


def _shadow_link_digest(
    payload: Mapping[str, Any],
    key: str,
) -> str | None:
    value = payload.get(key)
    if (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    ):
        return value
    return None


def _shadow_action_digest(payload: Mapping[str, Any]) -> str | None:
    request = payload.get("request")
    if not isinstance(request, Mapping):
        return None
    action = request.get("action")
    resource = request.get("resource")
    if not isinstance(action, Mapping) or not isinstance(resource, Mapping):
        return None
    return canonical_digest({"action": action, "resource": resource})


def _shadow_obligation_results(
    payload: Mapping[str, Any],
) -> list[dict[str, Any]]:
    decision = payload.get("decision")
    if not isinstance(decision, Mapping):
        return []
    obligations = decision.get("obligations")
    if not isinstance(obligations, list):
        return []
    projected: list[dict[str, Any]] = []
    for obligation in obligations:
        if not isinstance(obligation, Mapping):
            return []
        kind = obligation.get("kind")
        value = obligation.get("value")
        if not isinstance(kind, str) or not isinstance(value, str):
            return []
        projected.append(
            {
                "kind": kind,
                "satisfied": True,
                "value_digest": canonical_digest({"value": value}),
            }
        )
    return sorted(
        projected,
        key=lambda item: (item["kind"], item["value_digest"]),
    )


__all__ = [
    "TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE",
    "TASK_ATTEMPT_AUTHORIZATION_BINDING_EVENT_TYPE",
    "TASK_ATTEMPT_AUTHORIZATION_SHADOW_COVERAGE",
    "TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE",
    "TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE",
    "TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE",
    "TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE",
    "artifact_record_digest",
    "build_candidate_artifact_action_receipt",
    "build_candidate_artifact_pre_effect_receipt",
    "build_task_attempt_binding_event",
    "build_task_execution_accounting",
    "task_publication_billing_digest",
    "task_publication_billing_projection",
    "task_execution_mode",
    "task_runner_version_reference",
]
