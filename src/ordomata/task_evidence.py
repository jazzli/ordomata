"""Digest-only controller evidence for ordinary task-attempt publication.

The records in this module are audit evidence, not authorization grants.  The
legacy Class 0/1 gate remains authoritative while Phase 1C shadows the richer
ABAC contract and makes local candidate publication crash-reconcilable.
"""

from __future__ import annotations

from collections.abc import Mapping
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
    return {
        "schema_version": 2 if selection_bound else 1,
        "authorization_shadow_coverage": (
            TASK_ATTEMPT_AUTHORIZATION_SHADOW_COVERAGE
        ),
        "authorization_action_receipt_coverage": (
            TASK_ATTEMPT_ACTION_RECEIPT_COVERAGE
        ),
        "binding": binding,
        "binding_digest": canonical_digest(binding),
    }


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
) -> dict[str, Any]:
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
) -> dict[str, Any]:
    pre_effect_receipt_digest = pre_effect_receipt.get("receipt_digest")
    if not isinstance(pre_effect_receipt_digest, str):
        raise ValidationError("candidate pre-effect receipt digest is missing")
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
