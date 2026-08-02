"""Provider-neutral model, harness, and execution-profile routing."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import time
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .errors import ConfigurationError, ValidationError
from .billing import BillingPolicy
from .environment import is_sensitive_environment_value
from .models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    PermissionClass,
)


ALLOWED_ROUTES = frozenset(
    {
        BillingRoute.SUBSCRIPTION_INCLUDED,
        BillingRoute.LOCAL_NON_AI,
        BillingRoute.MOCK,
    }
)

ROUTING_POLICY_ID = "profile-router"
ROUTING_POLICY_VERSION = "1"
ROUTING_REJECTION_CODES = (
    "billing_runner_identity_mismatch",
    "billing_confidence_not_high",
    "billing_route_prohibited",
    "profile_billing_route_allowlist_missing",
    "profile_billing_route_not_allowed",
    "profile_unavailable",
    "profile_cooldown_active",
    "subscription_capacity_unavailable",
    "permission_class_exceeds_profile_limit",
    "task_kind_unsupported",
    "profile_role_not_enabled",
    "lane_billing_route_not_enabled",
    "required_capability_missing",
    "context_exceeds_profile_limit",
)


def _validate_non_negative_integer(value: Any, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(f"{field_name} must be a non-negative integer")


def _validate_finite_number(
    value: Any,
    field_name: str,
    *,
    minimum: float = 0.0,
    maximum: float | None = None,
) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < minimum:
        raise ValidationError(f"{field_name} must be a finite number >= {minimum:g}")
    if maximum is not None and numeric > maximum:
        raise ValidationError(
            f"{field_name} must be a finite number between {minimum:g} and {maximum:g}"
        )


@dataclass(frozen=True, slots=True)
class TaskRoutingFeatures:
    task_kind: str
    permission_class: PermissionClass
    required_capabilities: frozenset[str] = frozenset()
    allowed_roles: frozenset[str] = frozenset()
    allowed_billing_routes: frozenset[BillingRoute] = frozenset()
    context_bytes: int = 0
    risk: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.task_kind, str) or not self.task_kind.strip():
            raise ValidationError("task_kind must be a non-empty string")
        if not isinstance(self.permission_class, PermissionClass):
            raise ValidationError("permission_class must be a PermissionClass")
        _validate_non_negative_integer(self.context_bytes, "context_bytes")
        if (
            isinstance(self.risk, bool)
            or not isinstance(self.risk, int)
            or not 0 <= self.risk <= 3
        ):
            raise ValidationError("risk must be an integer between 0 and 3")


@dataclass(frozen=True, slots=True)
class ExecutionProfile:
    """A versioned bundle of runner, model, role, and provider settings."""

    profile_id: str
    version: str
    runner_id: str
    model_id: str | None
    role: str
    settings: Mapping[str, Any] = field(default_factory=dict)
    capabilities: frozenset[str] = frozenset()
    task_kinds: frozenset[str] = frozenset()
    allowed_billing_routes: frozenset[BillingRoute] = frozenset()
    max_permission_class: PermissionClass = PermissionClass.READ_ONLY
    max_context_bytes: int | None = None
    quality_prior: float = 0.5
    latency_prior_seconds: float = 60.0

    def __post_init__(self) -> None:
        for field_name in ("profile_id", "version", "runner_id", "role"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{field_name} must be a non-empty string")
        if self.model_id is not None and (
            not isinstance(self.model_id, str) or not self.model_id.strip()
        ):
            raise ValidationError("model_id must be a non-empty string or None")
        if not isinstance(self.max_permission_class, PermissionClass):
            raise ValidationError("max_permission_class must be a PermissionClass")
        if self.max_permission_class > PermissionClass.LOCAL_DRAFT:
            raise ValidationError("max_permission_class may enable only Classes 0 and 1")
        if self.max_context_bytes is not None:
            _validate_non_negative_integer(self.max_context_bytes, "max_context_bytes")
            if self.max_context_bytes == 0:
                raise ValidationError("max_context_bytes must be positive when provided")
        _validate_finite_number(
            self.quality_prior, "quality_prior", minimum=0.0, maximum=1.0
        )
        _validate_finite_number(
            self.latency_prior_seconds, "latency_prior_seconds", minimum=0.0
        )
        if not isinstance(self.settings, Mapping):
            raise ValidationError("settings must be a mapping")
        try:
            settings = json.loads(
                json.dumps(
                    dict(self.settings),
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError("settings must be canonical JSON") from exc
        if not isinstance(settings, dict):
            raise ValidationError("settings must be a JSON object")
        object.__setattr__(self, "settings", MappingProxyType(settings))


@dataclass(frozen=True, slots=True)
class SubscriptionEfficiencyObservation:
    """One comparable observation of included-subscription efficiency.

    The ratio is meaningful only inside the named capacity pool and unit. A
    missing observation is represented by ``None`` on ``RuntimeProfileState``;
    it is never coerced to zero or to a provider-independent estimate.
    """

    included_capacity_pool: str
    included_capacity_unit: str
    accepted_results_per_included_capacity_unit: float

    def __post_init__(self) -> None:
        for field_name in ("included_capacity_pool", "included_capacity_unit"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{field_name} must be a non-empty string")
        _validate_finite_number(
            self.accepted_results_per_included_capacity_unit,
            "accepted_results_per_included_capacity_unit",
            minimum=0.0,
        )

    @property
    def compatibility_key(self) -> tuple[str, str]:
        return (self.included_capacity_pool, self.included_capacity_unit)


@dataclass(frozen=True, slots=True)
class RuntimeProfileState:
    profile: ExecutionProfile
    billing_assessment: BillingRouteAssessment
    available: bool
    subscription_capacity_available: bool = True
    cooldown_active: bool = False
    verified_success_rate: float | None = None
    accepted_result_rate: float | None = None
    median_latency_seconds: float | None = None
    recent_failure_rate: float = 0.0
    evidence_count: int = 0
    subscription_efficiency: SubscriptionEfficiencyObservation | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.profile, ExecutionProfile):
            raise ValidationError("profile must be an ExecutionProfile")
        if not isinstance(self.billing_assessment, BillingRouteAssessment):
            raise ValidationError(
                "billing_assessment must be a BillingRouteAssessment"
            )
        for field_name in (
            "available",
            "subscription_capacity_available",
            "cooldown_active",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise ValidationError(f"{field_name} must be boolean")
        for field_name in ("verified_success_rate", "accepted_result_rate"):
            value = getattr(self, field_name)
            if value is not None:
                _validate_finite_number(value, field_name, minimum=0.0, maximum=1.0)
        if self.median_latency_seconds is not None:
            _validate_finite_number(
                self.median_latency_seconds,
                "median_latency_seconds",
                minimum=0.0,
            )
        _validate_finite_number(
            self.recent_failure_rate,
            "recent_failure_rate",
            minimum=0.0,
            maximum=1.0,
        )
        _validate_non_negative_integer(self.evidence_count, "evidence_count")
        if self.subscription_efficiency is not None:
            if not isinstance(
                self.subscription_efficiency, SubscriptionEfficiencyObservation
            ):
                raise ValidationError(
                    "subscription_efficiency must be a "
                    "SubscriptionEfficiencyObservation or None"
                )
            if (
                self.billing_assessment.route
                is not BillingRoute.SUBSCRIPTION_INCLUDED
            ):
                raise ValidationError(
                    "subscription_efficiency requires a subscription_included route"
                )

    @property
    def billing_route(self) -> BillingRoute:
        return self.billing_assessment.route


@dataclass(frozen=True, slots=True)
class RoutingRejection:
    profile_id: str
    reasons: tuple[str, ...]
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RankedProfile:
    state: RuntimeProfileState
    score_vector: tuple[float | None, ...]


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    selected: RuntimeProfileState | None
    ranked: tuple[RankedProfile, ...]
    rejected: tuple[RoutingRejection, ...]
    evaluated_at: float | None = None

    @property
    def blocked(self) -> bool:
        return self.selected is None


class ProfileRouter:
    """Hard-filter unsafe profiles, then rank eligible profiles lexicographically.

    The default objective deliberately puts verified quality and risk fit first,
    included-subscription efficiency second, and latency third. Efficiency is
    compared only inside a matching capacity-pool and unit group. It does not
    compare provider settings as if they were semantically identical; each
    versioned profile owns its translation.
    """

    def route(
        self,
        task: TaskRoutingFeatures,
        candidates: Iterable[RuntimeProfileState],
        *,
        evaluated_at: float | None = None,
        required_valid_until: float | None = None,
    ) -> RoutingDecision:
        if not isinstance(task, TaskRoutingFeatures):
            raise ValidationError("task must be TaskRoutingFeatures")
        policy_time = time.time() if evaluated_at is None else evaluated_at
        _validate_finite_number(policy_time, "evaluated_at", minimum=0.0)
        validity_horizon = (
            policy_time
            if required_valid_until is None
            else required_valid_until
        )
        _validate_finite_number(
            validity_horizon,
            "required_valid_until",
            minimum=float(policy_time),
        )
        materialized = tuple(candidates)
        if any(not isinstance(state, RuntimeProfileState) for state in materialized):
            raise ValidationError("candidates must contain RuntimeProfileState values")
        profile_ids = tuple(state.profile.profile_id for state in materialized)
        if len(set(profile_ids)) != len(profile_ids):
            raise ValidationError("routing candidates contain duplicate profile IDs")

        eligible: list[RankedProfile] = []
        rejected: list[RoutingRejection] = []

        for state in sorted(
            materialized,
            key=lambda item: item.profile.profile_id,
        ):
            reason_pairs = self._ineligible_reason_pairs(
                task,
                state,
                evaluated_at=float(policy_time),
                required_valid_until=float(validity_horizon),
            )
            if reason_pairs:
                rejected.append(
                    RoutingRejection(
                        state.profile.profile_id,
                        tuple(message for _, message in reason_pairs),
                        tuple(code for code, _ in reason_pairs),
                    )
                )
                continue
            eligible.append(RankedProfile(state, self._score(task, state)))

        eligible = self._rank_eligible(eligible)
        return RoutingDecision(
            selected=eligible[0].state if eligible else None,
            ranked=tuple(eligible),
            rejected=tuple(rejected),
            evaluated_at=float(policy_time),
        )

    @staticmethod
    def score_dimensions() -> tuple[str, ...]:
        return (
            "verified_success_adjusted_for_recent_failures",
            "accepted_result_rate",
            "evidence_confidence",
            "least_privilege_and_risk_fit",
            "accepted_results_per_included_capacity_unit_when_comparable",
            "negative_latency_seconds",
        )

    @staticmethod
    def rejection_codes() -> tuple[str, ...]:
        return ROUTING_REJECTION_CODES

    @classmethod
    def _rank_eligible(
        cls, eligible: Iterable[RankedProfile]
    ) -> list[RankedProfile]:
        """Apply the reviewed objective tiers without inventing unit conversions."""

        quality_groups: dict[tuple[float, ...], list[RankedProfile]] = {}
        for item in eligible:
            quality_groups.setdefault(item.score_vector[:4], []).append(item)

        ranked: list[RankedProfile] = []
        for quality_key in sorted(quality_groups, reverse=True):
            ranked.extend(cls._rank_equal_quality_group(quality_groups[quality_key]))
        return ranked

    @classmethod
    def _rank_equal_quality_group(
        cls, candidates: Iterable[RankedProfile]
    ) -> list[RankedProfile]:
        """Rank equal-quality candidates with only compatible efficiency data.

        Each compatible pool/unit group is ordered by efficiency before latency.
        The heads of distinct groups (and candidates without observations) are
        merged by latency, so an efficiency value from one provider can never
        rank against a value from an incompatible or unknown quota pool.
        """

        buckets: dict[tuple[str, ...], list[RankedProfile]] = {}
        for item in sorted(
            candidates,
            key=lambda candidate: candidate.state.profile.profile_id,
        ):
            observation = item.state.subscription_efficiency
            if observation is None:
                key = ("unavailable", item.state.profile.profile_id)
            else:
                key = (
                    "comparable",
                    item.state.profile.runner_id,
                    *observation.compatibility_key,
                )
            buckets.setdefault(key, []).append(item)

        for key, bucket in buckets.items():
            if key[0] == "comparable":
                bucket.sort(
                    key=lambda item: (
                        -cls._efficiency_value(item.state),
                        cls._latency_seconds(item.state),
                        item.state.profile.profile_id,
                    )
                )

        ranked: list[RankedProfile] = []
        while buckets:
            selected_key = min(
                buckets,
                key=lambda key: (
                    cls._latency_seconds(buckets[key][0].state),
                    buckets[key][0].state.profile.profile_id,
                ),
            )
            bucket = buckets[selected_key]
            ranked.append(bucket.pop(0))
            if not bucket:
                del buckets[selected_key]
        return ranked

    @staticmethod
    def _ineligible_reason_pairs(
        task: TaskRoutingFeatures,
        state: RuntimeProfileState,
        *,
        evaluated_at: float,
        required_valid_until: float,
    ) -> list[tuple[str, str]]:
        profile = state.profile
        reasons: list[tuple[str, str]] = []
        assessment = state.billing_assessment
        if assessment.runner_id != profile.runner_id:
            reasons.append(
                (
                    "billing_runner_identity_mismatch",
                    "billing assessment runner identity does not match profile",
                )
            )
        if assessment.confidence is not AssessmentConfidence.HIGH:
            reasons.append(
                (
                    "billing_confidence_not_high",
                    "billing assessment confidence is not high",
                )
            )
        if not BillingPolicy.route_is_allowed(
            assessment,
            now=evaluated_at,
            required_valid_until=required_valid_until,
        ):
            reasons.append(
                (
                    "billing_route_prohibited",
                    f"billing route {assessment.route.value} is prohibited",
                )
            )
        if not profile.allowed_billing_routes:
            reasons.append(
                (
                    "profile_billing_route_allowlist_missing",
                    "profile has no explicit billing-route allowlist",
                )
            )
        elif assessment.route not in profile.allowed_billing_routes:
            reasons.append(
                (
                    "profile_billing_route_not_allowed",
                    "billing route is not allowed by the profile",
                )
            )
        if not state.available:
            reasons.append(("profile_unavailable", "profile is unavailable"))
        if state.cooldown_active:
            reasons.append(("profile_cooldown_active", "profile is cooling down"))
        if not state.subscription_capacity_available:
            reasons.append(
                (
                    "subscription_capacity_unavailable",
                    "subscription capacity is unavailable",
                )
            )
        if task.permission_class > profile.max_permission_class:
            reasons.append(
                (
                    "permission_class_exceeds_profile_limit",
                    "permission class exceeds profile limit",
                )
            )
        if profile.task_kinds and task.task_kind not in profile.task_kinds:
            reasons.append(("task_kind_unsupported", "task kind is unsupported"))
        if task.allowed_roles and profile.role not in task.allowed_roles:
            reasons.append(
                (
                    "profile_role_not_enabled",
                    "profile role is not enabled for this routing lane",
                )
            )
        if (
            task.allowed_billing_routes
            and assessment.route not in task.allowed_billing_routes
        ):
            reasons.append(
                (
                    "lane_billing_route_not_enabled",
                    "billing route is not enabled for this routing lane",
                )
            )
        missing = task.required_capabilities - profile.capabilities
        if missing:
            reasons.append(
                (
                    "required_capability_missing",
                    f"missing capabilities: {', '.join(sorted(missing))}",
                )
            )
        if (
            profile.max_context_bytes is not None
            and task.context_bytes > profile.max_context_bytes
        ):
            reasons.append(
                (
                    "context_exceeds_profile_limit",
                    "context exceeds profile limit",
                )
            )
        return reasons

    @staticmethod
    def _score(
        task: TaskRoutingFeatures, state: RuntimeProfileState
    ) -> tuple[float | None, ...]:
        quality_and_risk = ProfileRouter._quality_and_risk_score(task, state)
        observation = state.subscription_efficiency
        efficiency = (
            None
            if observation is None
            else round(
                observation.accepted_results_per_included_capacity_unit, 6
            )
        )
        return (
            *quality_and_risk,
            efficiency,
            -round(ProfileRouter._latency_seconds(state), 6),
        )

    @staticmethod
    def _quality_and_risk_score(
        task: TaskRoutingFeatures, state: RuntimeProfileState
    ) -> tuple[float, ...]:
        profile = state.profile
        success = (
            state.verified_success_rate
            if state.verified_success_rate is not None
            else profile.quality_prior
        )
        accepted = (
            state.accepted_result_rate
            if state.accepted_result_rate is not None
            else profile.quality_prior
        )
        evidence_confidence = min(state.evidence_count / 20.0, 1.0)
        permission_headroom = float(profile.max_permission_class - task.permission_class)
        return (
            round(success * (1.0 - state.recent_failure_rate), 6),
            round(accepted, 6),
            round(evidence_confidence, 6),
            -float(task.risk) - permission_headroom,
        )

    @staticmethod
    def _efficiency_value(state: RuntimeProfileState) -> float:
        observation = state.subscription_efficiency
        if observation is None:
            raise ValidationError("subscription efficiency observation is unavailable")
        return round(
            observation.accepted_results_per_included_capacity_unit, 6
        )

    @staticmethod
    def _latency_seconds(state: RuntimeProfileState) -> float:
        return round(
            (
                state.median_latency_seconds
                if state.median_latency_seconds is not None
                else state.profile.latency_prior_seconds
            ),
            6,
        )


_SECRET_SETTING_FRAGMENTS = (
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "credential",
    "secret",
    "endpoint",
    "base_url",
    "billing",
    "bedrock",
    "vertex",
    "foundry",
    "openrouter",
    "allow_api",
)


def load_execution_profiles(path: Path) -> tuple[ExecutionProfile, ...]:
    """Load versioned profiles while rejecting embedded credential material."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot load routing profiles: {exc}") from exc
    raw_profiles = document.get("profiles") if isinstance(document, dict) else None
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise ConfigurationError("routing profile document requires a non-empty profiles list")

    profiles: list[ExecutionProfile] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_profiles):
        if not isinstance(raw, dict):
            raise ConfigurationError(f"profile {index} must be an object")
        profile_id = _required_text(raw, "profile_id", index)
        if profile_id in seen:
            raise ConfigurationError(f"duplicate profile_id: {profile_id}")
        seen.add(profile_id)
        settings = raw.get("settings", {})
        if not isinstance(settings, dict):
            raise ConfigurationError(f"profile {profile_id} settings must be an object")
        prohibited = tuple(_find_secret_setting_names(settings))
        if prohibited:
            raise ConfigurationError(
                f"profile {profile_id} contains prohibited setting names: "
                + ", ".join(prohibited)
            )
        prohibited_values = tuple(_find_secret_setting_values(settings))
        if prohibited_values:
            raise ConfigurationError(
                f"profile {profile_id} contains credential-shaped setting values at: "
                + ", ".join(prohibited_values)
            )
        raw_routes = raw.get("allowed_billing_routes")
        if not isinstance(raw_routes, list) or not raw_routes:
            raise ConfigurationError(
                f"profile {profile_id} requires an explicit allowed_billing_routes list"
            )
        try:
            allowed_routes = frozenset(BillingRoute(value) for value in raw_routes)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"profile {profile_id} contains an invalid billing route"
            ) from exc
        if not allowed_routes.issubset(ALLOWED_ROUTES):
            raise ConfigurationError(
                f"profile {profile_id} enables a prohibited billing route"
            )
        raw_max_permission = raw.get("max_permission_class", 0)
        if isinstance(raw_max_permission, bool) or not isinstance(
            raw_max_permission, int
        ):
            raise ConfigurationError(
                f"profile {profile_id} has invalid max_permission_class"
            )
        try:
            max_permission = PermissionClass(raw_max_permission)
        except ValueError as exc:
            raise ConfigurationError(
                f"profile {profile_id} has invalid max_permission_class"
            ) from exc
        if max_permission > PermissionClass.LOCAL_DRAFT:
            raise ConfigurationError(
                f"profile {profile_id} exceeds current Class 1 execution boundary"
            )
        model_id = raw.get("model_id")
        if model_id is not None and (
            not isinstance(model_id, str) or not model_id.strip()
        ):
            raise ConfigurationError(
                f"profile {profile_id} model_id must be a non-empty string or null"
            )
        max_context_bytes = raw.get("max_context_bytes")
        if max_context_bytes is not None and (
            isinstance(max_context_bytes, bool)
            or not isinstance(max_context_bytes, int)
        ):
            raise ConfigurationError(
                f"profile {profile_id} max_context_bytes must be an integer or null"
            )
        quality_prior = raw.get("quality_prior", 0.5)
        latency_prior_seconds = raw.get("latency_prior_seconds", 60.0)
        try:
            profile = ExecutionProfile(
                profile_id=profile_id,
                version=_required_text(raw, "version", index),
                runner_id=_required_text(raw, "runner_id", index),
                model_id=model_id,
                role=_required_text(raw, "role", index),
                settings=settings,
                capabilities=frozenset(_string_list(raw, "capabilities")),
                task_kinds=frozenset(_string_list(raw, "task_kinds")),
                allowed_billing_routes=allowed_routes,
                max_permission_class=max_permission,
                max_context_bytes=max_context_bytes,
                quality_prior=quality_prior,
                latency_prior_seconds=latency_prior_seconds,
            )
        except ValidationError as exc:
            raise ConfigurationError(f"profile {profile_id} is invalid: {exc}") from exc
        profiles.append(profile)
    return tuple(profiles)


def _required_text(raw: Mapping[str, Any], key: str, index: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"profile {index} requires non-empty {key}")
    return value.strip()


def _string_list(raw: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigurationError(f"{key} must be a list of strings")
    return tuple(value)


def _find_secret_setting_names(value: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            normalized = str(key).lower().replace("-", "_")
            if any(fragment in normalized for fragment in _SECRET_SETTING_FRAGMENTS):
                yield name
            yield from _find_secret_setting_names(nested, name)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _find_secret_setting_names(nested, f"{prefix}[{index}]")


def _find_secret_setting_values(value: Any, prefix: str = "settings") -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            yield from _find_secret_setting_values(nested, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _find_secret_setting_values(nested, f"{prefix}[{index}]")
    elif isinstance(value, str) and is_sensitive_environment_value(value):
        yield prefix


def runner_overrides_for_profile(profile: ExecutionProfile) -> dict[str, Any]:
    """Translate a provider-neutral profile into bounded adapter settings."""

    allowed_by_runner = {
        "codex": frozenset({"reasoning_effort"}),
        "claude": frozenset({"effort", "max_turns"}),
        "mock": frozenset({"fixture"}),
    }
    allowed = allowed_by_runner.get(profile.runner_id)
    if allowed is None:
        raise ConfigurationError(
            f"no settings translator exists for runner {profile.runner_id!r}"
        )
    unknown = sorted(set(profile.settings) - allowed)
    if unknown:
        raise ConfigurationError(
            f"profile {profile.profile_id} has unsupported settings: "
            + ", ".join(unknown)
        )
    settings = dict(profile.settings)
    if profile.runner_id == "codex":
        effort = settings.get("reasoning_effort")
        if effort is not None and effort not in {
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh",
        }:
            raise ConfigurationError(
                f"profile {profile.profile_id} has invalid reasoning_effort"
            )
    elif profile.runner_id == "claude":
        effort = settings.get("effort")
        if effort is not None and effort not in {"low", "medium", "high"}:
            raise ConfigurationError(
                f"profile {profile.profile_id} has invalid effort"
            )
        max_turns = settings.get("max_turns")
        if max_turns is not None and (
            isinstance(max_turns, bool)
            or not isinstance(max_turns, int)
            or not 1 <= max_turns <= 100
        ):
            raise ConfigurationError(
                f"profile {profile.profile_id} has invalid max_turns"
            )
    elif profile.runner_id == "mock":
        if profile.model_id is not None:
            raise ConfigurationError(
                f"profile {profile.profile_id} cannot select a model"
            )
        fixture = settings.get("fixture")
        if fixture is not None and fixture != "chief_of_staff.valid":
            raise ConfigurationError(
                f"profile {profile.profile_id} has unsupported fixture"
            )
    overrides = {
        key: value
        for key, value in settings.items()
        if key != "fixture"
    }
    if profile.model_id is not None:
        overrides["model"] = profile.model_id
    return overrides
