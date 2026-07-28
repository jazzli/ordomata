"""Privacy-safe, content-addressed evidence for execution-profile selection.

Selection records are controller evidence, not authorization grants.  They
describe the deterministic profile-router inputs and result while omitting raw
model names, settings, account identifiers, diagnostics, and local paths.
Every dispatch still has to pass the independent legacy permission, billing,
environment, isolation, and circuit gates.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import json
import math
import re
from typing import Any

from .authorization import canonical_digest
from .billing import BillingPolicy
from .errors import ValidationError
from .models import BillingRoute, BillingRouteAssessment, PermissionClass
from .routing import (
    ExecutionProfile,
    ProfileRouter,
    ROUTING_POLICY_ID,
    ROUTING_POLICY_VERSION,
    RuntimeProfileState,
    TaskRoutingFeatures,
    runner_overrides_for_profile,
)


TASK_EXECUTION_SELECTION_EVENT_TYPE = "task_execution_selection"
EXECUTION_SELECTION_SCHEMA_VERSION = 1
EXECUTION_SELECTION_KIND = "task_execution_selection"
EXECUTION_SELECTION_MODES = frozenset(
    {"operator_explicit", "controller_default", "routed"}
)
MAX_EXECUTION_SELECTION_CANDIDATES = 64

_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SELECTION_KEYS = frozenset(
    {
        "authorization_intent_digest",
        "candidate_set_digest",
        "candidates",
        "context_digest",
        "evaluated_at",
        "kind",
        "routing_policy_digest",
        "routing_policy_id",
        "routing_policy_version",
        "required_valid_until",
        "run_ref",
        "selected",
        "selection_mode",
        "task",
        "task_definition_digest",
        "task_features_digest",
    }
)
_TASK_KEYS = frozenset(
    {
        "allowed_billing_routes",
        "allowed_roles",
        "context_bytes",
        "permission_class",
        "required_capabilities",
        "risk",
        "task_kind",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "allowed_billing_routes",
        "billing",
        "billing_projection_digest",
        "candidate_order",
        "capabilities",
        "disposition",
        "latency_prior_seconds",
        "max_context_bytes",
        "max_permission_class",
        "model_ref",
        "profile_id",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "quality_prior",
        "rank",
        "rejection_codes",
        "role",
        "runner_id",
        "runner_overrides_digest",
        "runtime",
        "score_vector",
        "settings_digest",
        "task_kinds",
    }
)
_RUNTIME_KEYS = frozenset(
    {
        "accepted_result_rate",
        "available",
        "cooldown_active",
        "evidence_count",
        "median_latency_seconds",
        "recent_failure_rate",
        "subscription_capacity_available",
        "subscription_efficiency",
        "verified_success_rate",
    }
)
_BILLING_KEYS = frozenset(
    {
        "account_identity_ref",
        "attestation_ref",
        "capacity_expires_at",
        "capacity_observed_at",
        "capacity_state",
        "confidence",
        "evidence_ref",
        "paid_continuation_protection",
        "paid_credit_balance",
        "policy_allowed",
        "policy_blocker_codes",
        "risky_environment_names_ref",
        "route",
        "runner_id",
        "subscription_ref",
        "warnings_ref",
    }
)
_SELECTED_KEYS = frozenset(
    {
        "model_ref",
        "profile_id",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "rank",
        "runner_id",
        "runner_overrides_digest",
        "settings_digest",
    }
)


@dataclass(frozen=True, slots=True)
class ExecutionSelection:
    """Deeply immutable canonical selection snapshot."""

    _selection_json: str
    selection_digest: str
    _source_run_id: str | None = field(default=None, repr=False, compare=False)
    _source_task: TaskRoutingFeatures | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _source_candidates: tuple[RuntimeProfileState, ...] = field(
        default=(),
        repr=False,
        compare=False,
    )

    @property
    def selection(self) -> dict[str, Any]:
        value = json.loads(self._selection_json)
        assert isinstance(value, dict)
        return value

    def to_event_payload(self) -> dict[str, Any]:
        return {
            "schema_version": EXECUTION_SELECTION_SCHEMA_VERSION,
            "selection": self.selection,
            "selection_digest": self.selection_digest,
        }

    @property
    def run_ref(self) -> str:
        return self.selection["run_ref"]

    @property
    def selection_mode(self) -> str:
        return self.selection["selection_mode"]

    @property
    def task_features_digest(self) -> str:
        return self.selection["task_features_digest"]

    @property
    def task_definition_digest(self) -> str:
        return self.selection["task_definition_digest"]

    @property
    def context_digest(self) -> str:
        return self.selection["context_digest"]

    @property
    def authorization_intent_digest(self) -> str:
        return self.selection["authorization_intent_digest"]

    @property
    def permission_class(self) -> int:
        return self.selection["task"]["permission_class"]

    @property
    def candidate_set_digest(self) -> str:
        return self.selection["candidate_set_digest"]

    @property
    def required_valid_until(self) -> float:
        return self.selection["required_valid_until"]

    @property
    def evaluated_at(self) -> float:
        return self.selection["evaluated_at"]

    @property
    def selected_profile_ref(self) -> str:
        return self._selected_value("profile_ref")

    @property
    def selected_profile_id(self) -> str:
        return self._selected_value("profile_id")

    @property
    def selected_profile_version_ref(self) -> str:
        return self._selected_value("profile_version_ref")

    @property
    def selected_profile_configuration_digest(self) -> str:
        return self._selected_value("profile_configuration_digest")

    @property
    def selected_runner_id(self) -> str:
        return self._selected_value("runner_id")

    @property
    def selected_runner_overrides_digest(self) -> str:
        return self._selected_value("runner_overrides_digest")

    def _selected_value(self, key: str) -> Any:
        selected = self.selection.get("selected")
        if not isinstance(selected, dict):
            raise ValidationError("execution selection has no selected profile")
        return selected[key]

    def rebuild_from_controller_sources(self) -> ExecutionSelection:
        """Recompute a selection from the non-persisted controller snapshot."""

        if (
            self._source_run_id is None
            or self._source_task is None
            or not self._source_candidates
        ):
            raise ValidationError(
                "execution selection lacks controller-owned source evidence"
            )
        return build_execution_selection(
            run_id=self._source_run_id,
            selection_mode=self.selection_mode,
            task=self._source_task,
            candidates=self._source_candidates,
            task_definition_digest=self.task_definition_digest,
            context_digest=self.context_digest,
            authorization_intent_digest=self.authorization_intent_digest,
            evaluated_at=self.selection["evaluated_at"],
            required_valid_until=self.required_valid_until,
        )

    @property
    def selected_source_profile(self) -> ExecutionProfile:
        for state in self._source_candidates:
            if state.profile.profile_id == self.selected_profile_id:
                return state.profile
        raise ValidationError(
            "execution selection lacks the selected controller profile"
        )

    @property
    def controller_source_profiles(self) -> tuple[ExecutionProfile, ...]:
        """Return the non-persisted, immutable profile inputs to the router."""

        if not self._source_candidates:
            raise ValidationError(
                "execution selection lacks controller profile sources"
            )
        return tuple(state.profile for state in self._source_candidates)

    @property
    def selected_source_billing_assessment(self) -> BillingRouteAssessment:
        """Return the non-persisted assessment that made the selection eligible."""

        selected_profile_id = self.selected_profile_id
        for state in self._source_candidates:
            if state.profile.profile_id == selected_profile_id:
                return state.billing_assessment
        raise ValidationError(
            "execution selection lacks the selected billing assessment"
        )


def build_execution_selection(
    *,
    run_id: str,
    selection_mode: str,
    task: TaskRoutingFeatures,
    candidates: Iterable[RuntimeProfileState],
    task_definition_digest: str,
    context_digest: str,
    authorization_intent_digest: str,
    evaluated_at: float,
    required_valid_until: float | None = None,
) -> ExecutionSelection:
    """Recompute routing and return one immutable, safe selection record."""

    _safe_identifier(run_id, "run_id")
    if selection_mode not in EXECUTION_SELECTION_MODES:
        raise ValidationError("selection_mode is invalid")
    if not isinstance(task, TaskRoutingFeatures):
        raise ValidationError("task must be TaskRoutingFeatures")
    _finite_number(evaluated_at, "evaluated_at", minimum=0.0)
    validity_horizon = (
        float(evaluated_at)
        if required_valid_until is None
        else _finite_number(
            required_valid_until,
            "required_valid_until",
            minimum=float(evaluated_at),
        )
    )
    states = tuple(candidates)
    if not states or len(states) > MAX_EXECUTION_SELECTION_CANDIDATES:
        raise ValidationError("execution selection candidate count is invalid")
    if selection_mode in {"operator_explicit", "controller_default"} and len(
        states
    ) != 1:
        raise ValidationError("explicit/default selection requires one candidate")

    decision = ProfileRouter().route(
        task,
        states,
        evaluated_at=float(evaluated_at),
        required_valid_until=validity_horizon,
    )
    if decision.selected is None:
        raise ValidationError("execution selection has no eligible profile")

    ranked = {
        item.state.profile.profile_id: (rank, item.score_vector)
        for rank, item in enumerate(decision.ranked)
    }
    rejected = {
        item.profile_id: item.reason_codes for item in decision.rejected
    }
    candidate_rows: list[dict[str, Any]] = []
    ordered_states = sorted(
        states,
        key=lambda item: item.profile.profile_id,
    )
    for candidate_order, state in enumerate(ordered_states):
        profile = state.profile
        _safe_identifier(profile.profile_id, "profile_id")
        _safe_identifier(profile.runner_id, "runner_id")
        overrides = runner_overrides_for_profile(profile)
        rank_and_score = ranked.get(profile.profile_id)
        candidate_rows.append(
            _candidate_projection(
                state,
                task=task,
                candidate_order=candidate_order,
                rank=(None if rank_and_score is None else rank_and_score[0]),
                score_vector=(
                    None if rank_and_score is None else rank_and_score[1]
                ),
                rejection_codes=rejected.get(profile.profile_id, ()),
                runner_overrides=overrides,
                evaluated_at=float(evaluated_at),
                required_valid_until=validity_horizon,
            )
        )

    selected_profile = decision.selected.profile
    selected_candidate = next(
        row
        for row, state in zip(
            candidate_rows,
            ordered_states,
            strict=True,
        )
        if state.profile.profile_id == selected_profile.profile_id
    )
    selected = {
        key: selected_candidate[key]
        for key in (
            "model_ref",
            "profile_id",
            "profile_configuration_digest",
            "profile_ref",
            "profile_version_ref",
            "rank",
            "runner_id",
            "runner_overrides_digest",
            "settings_digest",
        )
    }
    task_projection = task_routing_features_projection(task)
    selection: dict[str, Any] = {
        "authorization_intent_digest": _normalized_digest(
            authorization_intent_digest,
            "authorization_intent_digest",
        ),
        "candidate_set_digest": canonical_digest(candidate_rows),
        "candidates": candidate_rows,
        "context_digest": _normalized_digest(context_digest, "context_digest"),
        "evaluated_at": float(evaluated_at),
        "kind": EXECUTION_SELECTION_KIND,
        "routing_policy_digest": routing_policy_digest(),
        "routing_policy_id": ROUTING_POLICY_ID,
        "routing_policy_version": ROUTING_POLICY_VERSION,
        "required_valid_until": validity_horizon,
        "run_ref": canonical_digest({"run_id": run_id}),
        "selected": selected,
        "selection_mode": selection_mode,
        "task": task_projection,
        "task_definition_digest": _normalized_digest(
            task_definition_digest,
            "task_definition_digest",
        ),
        "task_features_digest": canonical_digest(task_projection),
    }
    payload = {
        "schema_version": EXECUTION_SELECTION_SCHEMA_VERSION,
        "selection": selection,
        "selection_digest": canonical_digest(selection),
    }
    validated = validate_execution_selection_payload(payload)
    return ExecutionSelection(
        validated._selection_json,
        validated.selection_digest,
        run_id,
        task,
        states,
    )


def validate_execution_selection_payload(
    payload: Mapping[str, Any],
) -> ExecutionSelection:
    """Strictly validate an event payload and return an immutable snapshot."""

    document = _canonical_json_copy(payload, "execution selection payload")
    if set(document) != {"schema_version", "selection", "selection_digest"}:
        raise ValidationError("execution selection payload shape is invalid")
    if document.get("schema_version") != EXECUTION_SELECTION_SCHEMA_VERSION:
        raise ValidationError("execution selection schema version is invalid")
    selection = document.get("selection")
    if not isinstance(selection, dict) or set(selection) != _SELECTION_KEYS:
        raise ValidationError("execution selection shape is invalid")
    selection_digest = document.get("selection_digest")
    if not _is_digest(selection_digest) or selection_digest != canonical_digest(
        selection
    ):
        raise ValidationError("execution selection digest is invalid")
    if selection.get("kind") != EXECUTION_SELECTION_KIND:
        raise ValidationError("execution selection kind is invalid")
    if selection.get("selection_mode") not in EXECUTION_SELECTION_MODES:
        raise ValidationError("execution selection mode is invalid")
    if (
        selection.get("routing_policy_id") != ROUTING_POLICY_ID
        or selection.get("routing_policy_version") != ROUTING_POLICY_VERSION
        or selection.get("routing_policy_digest") != routing_policy_digest()
    ):
        raise ValidationError("execution selection policy is invalid")
    _finite_number(selection.get("evaluated_at"), "evaluated_at", minimum=0.0)
    _finite_number(
        selection.get("required_valid_until"),
        "required_valid_until",
        minimum=float(selection["evaluated_at"]),
    )
    for field_name in (
        "authorization_intent_digest",
        "candidate_set_digest",
        "context_digest",
        "routing_policy_digest",
        "run_ref",
        "task_definition_digest",
        "task_features_digest",
    ):
        if not _is_digest(selection.get(field_name)):
            raise ValidationError(f"execution selection {field_name} is invalid")

    task = selection.get("task")
    if not isinstance(task, dict) or set(task) != _TASK_KEYS:
        raise ValidationError("execution selection task shape is invalid")
    _validate_task_projection(task)
    if selection["task_features_digest"] != canonical_digest(task):
        raise ValidationError("execution selection task digest is invalid")

    candidates = selection.get("candidates")
    if (
        not isinstance(candidates, list)
        or not candidates
        or len(candidates) > MAX_EXECUTION_SELECTION_CANDIDATES
    ):
        raise ValidationError("execution selection candidates are invalid")
    for order, candidate in enumerate(candidates):
        _validate_candidate(candidate, order=order)
        expected_codes = _recomputed_rejection_codes(task, candidate)
        if candidate["rejection_codes"] != list(expected_codes):
            raise ValidationError(
                "execution selection rejection codes do not match inputs"
            )
        expected_score = (
            None
            if expected_codes
            else list(_recomputed_score_vector(task, candidate))
        )
        if candidate["score_vector"] != expected_score:
            raise ValidationError(
                "execution selection score vector does not match inputs"
            )
    if len({candidate["profile_ref"] for candidate in candidates}) != len(
        candidates
    ):
        raise ValidationError("execution selection candidates are duplicated")
    if [candidate["profile_id"] for candidate in candidates] != sorted(
        candidate["profile_id"] for candidate in candidates
    ):
        raise ValidationError("execution selection candidate order is invalid")
    if selection["candidate_set_digest"] != canonical_digest(candidates):
        raise ValidationError("execution selection candidate digest is invalid")
    eligible = [
        candidate for candidate in candidates if candidate["disposition"] == "eligible"
    ]
    ranks = sorted(candidate["rank"] for candidate in eligible)
    if ranks != list(range(len(eligible))):
        raise ValidationError("execution selection ranks are invalid")
    expected_ranking = _rank_candidate_rows(eligible)
    actual_ranking = sorted(eligible, key=lambda candidate: candidate["rank"])
    if [candidate["profile_ref"] for candidate in actual_ranking] != [
        candidate["profile_ref"] for candidate in expected_ranking
    ]:
        raise ValidationError("execution selection ranking does not match inputs")

    selected = selection.get("selected")
    if not isinstance(selected, dict) or set(selected) != _SELECTED_KEYS:
        raise ValidationError("execution selection selected shape is invalid")
    matches = [
        candidate
        for candidate in candidates
        if candidate["profile_ref"] == selected["profile_ref"]
    ]
    if len(matches) != 1:
        raise ValidationError("execution selection selected candidate is invalid")
    expected_selected = {
        key: matches[0][key] for key in _SELECTED_KEYS
    }
    if selected != expected_selected or selected.get("rank") != 0:
        raise ValidationError("execution selection selected candidate is invalid")
    if matches[0].get("disposition") != "eligible":
        raise ValidationError("execution selection selected candidate is ineligible")

    encoded = json.dumps(
        selection,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert isinstance(selection_digest, str)
    return ExecutionSelection(encoded, selection_digest)


def execution_profile_configuration_mapping(
    profile: ExecutionProfile,
) -> dict[str, Any]:
    if not isinstance(profile, ExecutionProfile):
        raise ValidationError("profile must be an ExecutionProfile")
    return {
        "allowed_billing_routes": sorted(
            route.value for route in profile.allowed_billing_routes
        ),
        "capabilities": sorted(profile.capabilities),
        "latency_prior_seconds": profile.latency_prior_seconds,
        "max_context_bytes": profile.max_context_bytes,
        "max_permission_class": int(profile.max_permission_class),
        "model_id": profile.model_id,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "quality_prior": profile.quality_prior,
        "role": profile.role,
        "runner_id": profile.runner_id,
        "settings": dict(profile.settings),
        "task_kinds": sorted(profile.task_kinds),
    }


def execution_profile_configuration_digest(profile: ExecutionProfile) -> str:
    return canonical_digest(execution_profile_configuration_mapping(profile))


def task_routing_features_projection(task: TaskRoutingFeatures) -> dict[str, Any]:
    if not isinstance(task, TaskRoutingFeatures):
        raise ValidationError("task must be TaskRoutingFeatures")
    return {
        "allowed_billing_routes": sorted(
            route.value for route in task.allowed_billing_routes
        ),
        "allowed_roles": sorted(_opaque_ref("role", item) for item in task.allowed_roles),
        "context_bytes": task.context_bytes,
        "permission_class": int(task.permission_class),
        "required_capabilities": sorted(
            _opaque_ref("capability", item) for item in task.required_capabilities
        ),
        "risk": task.risk,
        "task_kind": _opaque_ref("task_kind", task.task_kind),
    }


def task_routing_features_digest(task: TaskRoutingFeatures) -> str:
    return canonical_digest(task_routing_features_projection(task))


def routing_policy_digest() -> str:
    return canonical_digest(
        {
            "objective_order": ["quality_and_risk", "included_efficiency", "latency"],
            "policy_id": ROUTING_POLICY_ID,
            "policy_version": ROUTING_POLICY_VERSION,
            "rejection_codes": list(ProfileRouter.rejection_codes()),
            "score_dimensions": list(ProfileRouter.score_dimensions()),
            "tie_break": "stable_profile_id",
        }
    )


def _candidate_projection(
    state: RuntimeProfileState,
    *,
    task: TaskRoutingFeatures,
    candidate_order: int,
    rank: int | None,
    score_vector: tuple[float | None, ...] | None,
    rejection_codes: tuple[str, ...],
    runner_overrides: Mapping[str, Any],
    evaluated_at: float,
    required_valid_until: float,
) -> dict[str, Any]:
    profile = state.profile
    assessment = state.billing_assessment
    billing = _billing_projection(
        assessment,
        evaluated_at=evaluated_at,
        required_valid_until=required_valid_until,
    )
    efficiency = state.subscription_efficiency
    runtime = {
        "accepted_result_rate": _metric_projection(
            state.accepted_result_rate,
            prior=profile.quality_prior,
        ),
        "available": state.available,
        "cooldown_active": state.cooldown_active,
        "evidence_count": state.evidence_count,
        "median_latency_seconds": _metric_projection(
            state.median_latency_seconds,
            prior=profile.latency_prior_seconds,
        ),
        "recent_failure_rate": state.recent_failure_rate,
        "subscription_capacity_available": state.subscription_capacity_available,
        "subscription_efficiency": (
            {
                "pool_ref": None,
                "source": "unavailable",
                "unit_ref": None,
                "value": None,
            }
            if efficiency is None
            else {
                "pool_ref": _opaque_ref(
                    "included_capacity_pool", efficiency.included_capacity_pool
                ),
                "source": "observed",
                "unit_ref": _opaque_ref(
                    "included_capacity_unit", efficiency.included_capacity_unit
                ),
                "value": round(
                    efficiency.accepted_results_per_included_capacity_unit, 6
                ),
            }
        ),
        "verified_success_rate": _metric_projection(
            state.verified_success_rate,
            prior=profile.quality_prior,
        ),
    }
    return {
        "allowed_billing_routes": sorted(
            route.value for route in profile.allowed_billing_routes
        ),
        "billing": billing,
        "billing_projection_digest": canonical_digest(billing),
        "candidate_order": candidate_order,
        "capabilities": sorted(
            _opaque_ref("capability", item) for item in profile.capabilities
        ),
        "disposition": "eligible" if rank is not None else "rejected",
        "latency_prior_seconds": profile.latency_prior_seconds,
        "max_context_bytes": profile.max_context_bytes,
        "max_permission_class": int(profile.max_permission_class),
        "model_ref": (
            None
            if profile.model_id is None
            else _opaque_ref("model_id", profile.model_id)
        ),
        "profile_id": profile.profile_id,
        "profile_configuration_digest": execution_profile_configuration_digest(
            profile
        ),
        "profile_ref": canonical_digest({"profile_id": profile.profile_id}),
        "profile_version_ref": canonical_digest(
            {"profile_version": profile.version}
        ),
        "quality_prior": profile.quality_prior,
        "rank": rank,
        "rejection_codes": list(rejection_codes),
        "role": _opaque_ref("role", profile.role),
        "runner_id": profile.runner_id,
        "runner_overrides_digest": canonical_digest(dict(runner_overrides)),
        "runtime": runtime,
        "score_vector": None if score_vector is None else list(score_vector),
        "settings_digest": canonical_digest(dict(profile.settings)),
        "task_kinds": sorted(
            _opaque_ref("task_kind", item) for item in profile.task_kinds
        ),
    }


def _billing_projection(
    assessment: Any,
    *,
    evaluated_at: float,
    required_valid_until: float,
) -> dict[str, Any]:
    allowed = BillingPolicy.route_is_allowed(
        assessment,
        now=evaluated_at,
        required_valid_until=required_valid_until,
    )
    blockers: tuple[str, ...]
    if allowed:
        blockers = ()
    elif assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
        blockers = BillingPolicy.subscription_blockers(
            assessment,
            now=evaluated_at,
            required_valid_until=required_valid_until,
        )
    else:
        blockers = ("billing_route_prohibited",)
    attestation = assessment.attestation
    attestation_ref = (
        None
        if attestation is None
        else canonical_digest(
            {
                "account_identity_fingerprint": (
                    attestation.account_identity_fingerprint
                ),
                "billing_route": attestation.billing_route.value,
                "capacity_state": attestation.capacity_state.value,
                "confidence": attestation.confidence.value,
                "evidence": list(attestation.evidence),
                "expires_at": attestation.expires_at,
                "observed_at": attestation.observed_at,
                "paid_continuation_protection": (
                    attestation.paid_continuation_protection.value
                ),
                "runner_id": attestation.runner_id,
            }
        )
    )
    return {
        "account_identity_ref": _optional_opaque_ref(
            "account_identity", assessment.account_identity_fingerprint
        ),
        "attestation_ref": attestation_ref,
        "capacity_expires_at": assessment.capacity_expires_at,
        "capacity_observed_at": assessment.capacity_observed_at,
        "capacity_state": assessment.capacity_state.value,
        "confidence": assessment.confidence.value,
        "evidence_ref": canonical_digest(list(assessment.evidence)),
        "paid_continuation_protection": (
            assessment.paid_continuation_protection.value
        ),
        "paid_credit_balance": assessment.paid_credit_balance.value,
        "policy_allowed": allowed,
        "policy_blocker_codes": list(blockers),
        "risky_environment_names_ref": canonical_digest(
            sorted(assessment.risky_environment_names)
        ),
        "route": assessment.route.value,
        "runner_id": assessment.runner_id,
        "subscription_ref": _optional_opaque_ref(
            "subscription", assessment.subscription_name
        ),
        "warnings_ref": canonical_digest(list(assessment.warnings)),
    }


def _validate_task_projection(task: Mapping[str, Any]) -> None:
    if not _is_digest(task.get("task_kind")):
        raise ValidationError("execution selection task kind is invalid")
    permission_class = task.get("permission_class")
    if permission_class not in {
        int(PermissionClass.READ_ONLY),
        int(PermissionClass.LOCAL_DRAFT),
    }:
        raise ValidationError("execution selection permission class is invalid")
    for field_name in ("required_capabilities", "allowed_roles"):
        values = task.get(field_name)
        if (
            not isinstance(values, list)
            or values != sorted(values)
            or any(not _is_digest(item) for item in values)
        ):
            raise ValidationError("execution selection task references are invalid")
    routes = task.get("allowed_billing_routes")
    if (
        not isinstance(routes, list)
        or routes != sorted(routes)
        or any(not isinstance(item, str) for item in routes)
    ):
        raise ValidationError("execution selection billing routes are invalid")
    _non_negative_integer(task.get("context_bytes"), "context_bytes")
    risk = task.get("risk")
    if isinstance(risk, bool) or not isinstance(risk, int) or not 0 <= risk <= 3:
        raise ValidationError("execution selection risk is invalid")


def _validate_candidate(candidate: Any, *, order: int) -> None:
    if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_KEYS:
        raise ValidationError("execution selection candidate shape is invalid")
    if candidate.get("candidate_order") != order:
        raise ValidationError("execution selection candidate order is invalid")
    profile_id = _safe_identifier(candidate.get("profile_id"), "profile_id")
    if candidate.get("profile_ref") != canonical_digest(
        {"profile_id": profile_id}
    ):
        raise ValidationError("execution selection profile reference is invalid")
    for field_name in (
        "billing_projection_digest",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "role",
        "runner_overrides_digest",
        "settings_digest",
    ):
        if not _is_digest(candidate.get(field_name)):
            raise ValidationError("execution selection candidate digest is invalid")
    if candidate.get("model_ref") is not None and not _is_digest(
        candidate.get("model_ref")
    ):
        raise ValidationError("execution selection model reference is invalid")
    _safe_identifier(candidate.get("runner_id"), "runner_id")
    if candidate.get("max_permission_class") not in {0, 1}:
        raise ValidationError("execution selection profile class is invalid")
    max_context = candidate.get("max_context_bytes")
    if max_context is not None:
        _non_negative_integer(max_context, "max_context_bytes")
        if max_context == 0:
            raise ValidationError("execution selection context limit is invalid")
    _finite_number(candidate.get("quality_prior"), "quality_prior", 0.0, 1.0)
    _finite_number(
        candidate.get("latency_prior_seconds"),
        "latency_prior_seconds",
        minimum=0.0,
    )
    for field_name in ("capabilities", "task_kinds"):
        values = candidate.get(field_name)
        if (
            not isinstance(values, list)
            or values != sorted(values)
            or any(not _is_digest(item) for item in values)
        ):
            raise ValidationError("execution selection profile refs are invalid")
    routes = candidate.get("allowed_billing_routes")
    if not isinstance(routes, list) or routes != sorted(routes):
        raise ValidationError("execution selection profile routes are invalid")
    runtime = candidate.get("runtime")
    billing = candidate.get("billing")
    if not isinstance(runtime, dict) or set(runtime) != _RUNTIME_KEYS:
        raise ValidationError("execution selection runtime shape is invalid")
    if not isinstance(billing, dict) or set(billing) != _BILLING_KEYS:
        raise ValidationError("execution selection billing shape is invalid")
    if candidate["billing_projection_digest"] != canonical_digest(billing):
        raise ValidationError("execution selection billing digest is invalid")
    _safe_identifier(billing.get("runner_id"), "billing runner_id")
    if not isinstance(billing.get("policy_allowed"), bool):
        raise ValidationError("execution selection billing policy marker is invalid")
    for field_name in (
        "account_identity_ref",
        "attestation_ref",
        "subscription_ref",
    ):
        if billing.get(field_name) is not None and not _is_digest(
            billing.get(field_name)
        ):
            raise ValidationError("execution selection billing reference is invalid")
    for field_name in (
        "evidence_ref",
        "risky_environment_names_ref",
        "warnings_ref",
    ):
        if not _is_digest(billing.get(field_name)):
            raise ValidationError("execution selection billing reference is invalid")
    for field_name in ("capacity_observed_at", "capacity_expires_at"):
        if billing.get(field_name) is not None:
            _finite_number(billing.get(field_name), field_name, minimum=0.0)
    blockers = billing.get("policy_blocker_codes")
    if (
        not isinstance(blockers, list)
        or any(not isinstance(code, str) or len(code) > 80 for code in blockers)
    ):
        raise ValidationError("execution selection billing blockers are invalid")
    for field_name in ("available", "subscription_capacity_available", "cooldown_active"):
        if not isinstance(runtime.get(field_name), bool):
            raise ValidationError("execution selection runtime marker is invalid")
    _non_negative_integer(runtime.get("evidence_count"), "evidence_count")
    _finite_number(runtime.get("recent_failure_rate"), "recent_failure_rate", 0.0, 1.0)
    for field_name in (
        "verified_success_rate",
        "accepted_result_rate",
        "median_latency_seconds",
    ):
        metric = runtime.get(field_name)
        if (
            not isinstance(metric, dict)
            or set(metric) != {"source", "value"}
            or metric.get("source") not in {"observed", "profile_prior"}
        ):
            raise ValidationError("execution selection metric is invalid")
        _finite_number(metric.get("value"), field_name, minimum=0.0)
    efficiency = runtime.get("subscription_efficiency")
    if (
        not isinstance(efficiency, dict)
        or set(efficiency) != {"pool_ref", "source", "unit_ref", "value"}
        or efficiency.get("source") not in {"observed", "unavailable"}
    ):
        raise ValidationError("execution selection efficiency is invalid")
    if efficiency["source"] == "observed":
        if not _is_digest(efficiency.get("pool_ref")) or not _is_digest(
            efficiency.get("unit_ref")
        ):
            raise ValidationError("execution selection efficiency refs are invalid")
        _finite_number(efficiency.get("value"), "efficiency", minimum=0.0)
    elif any(efficiency.get(key) is not None for key in ("pool_ref", "unit_ref", "value")):
        raise ValidationError("execution selection unavailable efficiency is invalid")
    codes = candidate.get("rejection_codes")
    if (
        not isinstance(codes, list)
        or len(codes) != len(set(codes))
        or any(code not in ProfileRouter.rejection_codes() for code in codes)
    ):
        raise ValidationError("execution selection rejection codes are invalid")
    disposition = candidate.get("disposition")
    rank = candidate.get("rank")
    score = candidate.get("score_vector")
    if disposition == "eligible":
        _non_negative_integer(rank, "rank")
        if (
            not isinstance(score, list)
            or len(score) != len(ProfileRouter.score_dimensions())
        ):
            raise ValidationError("execution selection score vector is invalid")
        for value in score:
            if value is not None:
                _finite_number(value, "score_vector")
        if codes:
            raise ValidationError("eligible execution selection has rejections")
    elif disposition == "rejected":
        if rank is not None or score is not None or not codes:
            raise ValidationError("rejected execution selection is invalid")
    else:
        raise ValidationError("execution selection disposition is invalid")


def _metric_projection(value: float | None, *, prior: float) -> dict[str, Any]:
    return {
        "source": "profile_prior" if value is None else "observed",
        "value": prior if value is None else value,
    }


def _recomputed_rejection_codes(
    task: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[str, ...]:
    runtime = candidate["runtime"]
    billing = candidate["billing"]
    codes: list[str] = []
    if billing["runner_id"] != candidate["runner_id"]:
        codes.append("billing_runner_identity_mismatch")
    if billing["confidence"] != "high":
        codes.append("billing_confidence_not_high")
    if billing["policy_allowed"] is not True:
        codes.append("billing_route_prohibited")
    profile_routes = candidate["allowed_billing_routes"]
    if not profile_routes:
        codes.append("profile_billing_route_allowlist_missing")
    elif billing["route"] not in profile_routes:
        codes.append("profile_billing_route_not_allowed")
    if runtime["available"] is not True:
        codes.append("profile_unavailable")
    if runtime["cooldown_active"] is True:
        codes.append("profile_cooldown_active")
    if runtime["subscription_capacity_available"] is not True:
        codes.append("subscription_capacity_unavailable")
    if task["permission_class"] > candidate["max_permission_class"]:
        codes.append("permission_class_exceeds_profile_limit")
    if candidate["task_kinds"] and task["task_kind"] not in candidate["task_kinds"]:
        codes.append("task_kind_unsupported")
    if task["allowed_roles"] and candidate["role"] not in task["allowed_roles"]:
        codes.append("profile_role_not_enabled")
    if (
        task["allowed_billing_routes"]
        and billing["route"] not in task["allowed_billing_routes"]
    ):
        codes.append("lane_billing_route_not_enabled")
    if not set(task["required_capabilities"]).issubset(candidate["capabilities"]):
        codes.append("required_capability_missing")
    if (
        candidate["max_context_bytes"] is not None
        and task["context_bytes"] > candidate["max_context_bytes"]
    ):
        codes.append("context_exceeds_profile_limit")
    return tuple(codes)


def _recomputed_score_vector(
    task: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[float | None, ...]:
    runtime = candidate["runtime"]
    success = runtime["verified_success_rate"]["value"]
    accepted = runtime["accepted_result_rate"]["value"]
    latency = runtime["median_latency_seconds"]["value"]
    efficiency = runtime["subscription_efficiency"]
    permission_headroom = (
        candidate["max_permission_class"] - task["permission_class"]
    )
    return (
        round(success * (1.0 - runtime["recent_failure_rate"]), 6),
        round(accepted, 6),
        round(min(runtime["evidence_count"] / 20.0, 1.0), 6),
        -float(task["risk"]) - float(permission_headroom),
        None if efficiency["source"] == "unavailable" else efficiency["value"],
        -round(latency, 6),
    )


def _rank_candidate_rows(
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    quality_groups: dict[tuple[float, ...], list[dict[str, Any]]] = {}
    for candidate in candidates:
        score = candidate["score_vector"]
        assert isinstance(score, list)
        quality_groups.setdefault(tuple(score[:4]), []).append(candidate)

    ranked: list[dict[str, Any]] = []
    for quality_key in sorted(quality_groups, reverse=True):
        buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for candidate in sorted(
            quality_groups[quality_key],
            key=lambda item: item["profile_id"],
        ):
            efficiency = candidate["runtime"]["subscription_efficiency"]
            if efficiency["source"] == "unavailable":
                key = ("unavailable", candidate["profile_id"])
            else:
                key = (
                    "comparable",
                    candidate["runner_id"],
                    efficiency["pool_ref"],
                    efficiency["unit_ref"],
                )
            buckets.setdefault(key, []).append(candidate)
        for key, bucket in buckets.items():
            if key[0] == "comparable":
                bucket.sort(
                    key=lambda item: (
                        -item["runtime"]["subscription_efficiency"]["value"],
                        item["runtime"]["median_latency_seconds"]["value"],
                        item["profile_id"],
                    )
                )
        while buckets:
            selected_key = min(
                buckets,
                key=lambda key: (
                    buckets[key][0]["runtime"]["median_latency_seconds"]["value"],
                    buckets[key][0]["profile_id"],
                ),
            )
            bucket = buckets[selected_key]
            ranked.append(bucket.pop(0))
            if not bucket:
                del buckets[selected_key]
    return ranked


def _opaque_ref(kind: str, value: str) -> str:
    return canonical_digest({kind: value})


def _optional_opaque_ref(kind: str, value: str | None) -> str | None:
    return None if value is None else _opaque_ref(kind, value)


def _normalized_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a SHA-256 digest")
    normalized = value if value.startswith("sha256:") else f"sha256:{value}"
    if not _is_digest(normalized):
        raise ValidationError(f"{field_name} must be a SHA-256 digest")
    return normalized


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _safe_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValidationError(f"{field_name} is not a safe identifier")
    return value


def _finite_number(
    value: Any,
    field_name: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ValidationError(f"{field_name} must be a finite number")
    if minimum is not None and numeric < minimum:
        raise ValidationError(f"{field_name} is below its minimum")
    if maximum is not None and numeric > maximum:
        raise ValidationError(f"{field_name} exceeds its maximum")
    return numeric


def _non_negative_integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(f"{field_name} must be a non-negative integer")
    return value


def _canonical_json_copy(value: Any, field_name: str) -> dict[str, Any]:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError(f"{field_name} must be canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise ValidationError(f"{field_name} must be a JSON object")
    return decoded
