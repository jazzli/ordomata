"""Controlled, reproducible runner-comparison data structures.

Comparisons use one immutable task/context snapshot, block-randomized trial
order, fresh sessions, and multiple repetitions.  Reports expose raw dimensions
only: there is intentionally no aggregate score, winner, ranking, or API-dollar
cost field.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import random
import re
import time
from typing import Any

from .billing import BillingPolicy
from .errors import (
    OrdomataError,
    BillingRouteBlocked,
    ConfigurationError,
    ValidationError,
)
from .evaluation import EvaluationResult, evaluate_chief_of_staff
from .models import (
    BillingRoute,
    CapacityState,
    CircuitBreakerState,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PermissionClass,
    RunRequest,
    RunnerExecutionResult,
    RunStatus,
    UsageObservation,
)
from .orchestrator import PreparedTask
from .paths import resolve_state_root
from .redaction import DEFAULT_REDACTOR, contains_credential_material
from .routing import ExecutionProfile, runner_overrides_for_profile
from .runners.base import AgentRunner
from .state import SQLiteBillingCircuitGuard, SQLiteStateStore


CONTROLLED_COMPARISON_TRIAL_TIMEOUT_SECONDS = 120
CONTROLLED_COMPARISON_EVIDENCE_MARGIN_SECONDS = 60
COMPARISON_AUTHORIZATION_SHADOW_COVERAGE = "deferred_not_covered"


def _non_empty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    return value


def _non_negative_integer(value: int | None, field_name: str) -> None:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value < 0
    ):
        raise ValidationError(f"{field_name} must be a non-negative integer or None")


def _optional_boolean(value: bool | None, field_name: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise ValidationError(f"{field_name} must be boolean or None")


def _optional_non_negative_number(value: float | None, field_name: str) -> None:
    if value is not None and (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValidationError(f"{field_name} must be non-negative and finite or None")


@dataclass(frozen=True, slots=True)
class ComparisonSnapshot:
    """The exact immutable task and repository context used by every trial."""

    task_id: str
    task_version: str
    task_text: str
    repository_revision: str
    context_digest: str
    verification_commands: tuple[tuple[str, ...], ...]
    permission_class: PermissionClass

    def __post_init__(self) -> None:
        for field_name in (
            "task_id",
            "task_version",
            "task_text",
            "repository_revision",
            "context_digest",
        ):
            _non_empty(getattr(self, field_name), field_name)
        if not isinstance(self.verification_commands, tuple) or not self.verification_commands:
            raise ValidationError("verification_commands must be a non-empty immutable tuple")
        for command in self.verification_commands:
            if not isinstance(command, tuple) or not command:
                raise ValidationError("each verification command must be a non-empty tuple")
            for argument in command:
                _non_empty(argument, "verification command argument")
        if self.permission_class not in (
            PermissionClass.READ_ONLY,
            PermissionClass.LOCAL_DRAFT,
        ):
            raise ValidationError("comparison permission class must be 0 or 1")

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            {
                "context_digest": self.context_digest,
                "permission_class": int(self.permission_class),
                "repository_revision": self.repository_revision,
                "task_id": self.task_id,
                "task_text": self.task_text,
                "task_version": self.task_version,
                "verification_commands": self.verification_commands,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ComparisonTrial:
    """One runner/repetition cell in randomized execution order."""

    trial_id: str
    runner_id: str
    repetition: int
    order_index: int
    snapshot_digest: str
    fresh_session: bool = True

    def __post_init__(self) -> None:
        _non_empty(self.trial_id, "trial_id")
        _non_empty(self.runner_id, "runner_id")
        _non_empty(self.snapshot_digest, "snapshot_digest")
        if isinstance(self.repetition, bool) or self.repetition < 1:
            raise ValidationError("repetition must be a positive integer")
        if isinstance(self.order_index, bool) or self.order_index < 0:
            raise ValidationError("order_index must be a non-negative integer")
        if self.fresh_session is not True:
            raise ValidationError("controlled comparisons require a fresh session per trial")


@dataclass(frozen=True, slots=True)
class ComparisonPlan:
    comparison_id: str
    snapshot: ComparisonSnapshot
    runner_ids: tuple[str, ...]
    repetitions: int
    random_seed: int
    trials: tuple[ComparisonTrial, ...]

    @classmethod
    def create(
        cls,
        *,
        comparison_id: str,
        snapshot: ComparisonSnapshot,
        runner_ids: tuple[str, ...],
        repetitions: int,
        random_seed: int,
    ) -> ComparisonPlan:
        _non_empty(comparison_id, "comparison_id")
        if not isinstance(runner_ids, tuple) or len(runner_ids) < 2:
            raise ValidationError("runner_ids must contain at least two runners")
        if len(set(runner_ids)) != len(runner_ids):
            raise ValidationError("runner_ids must be unique")
        for runner_id in runner_ids:
            _non_empty(runner_id, "runner_id")
        if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions < 2:
            raise ValidationError("controlled comparisons require at least two repetitions")
        if isinstance(random_seed, bool) or not isinstance(random_seed, int):
            raise ValidationError("random_seed must be an integer")

        generator = random.Random(random_seed)
        trials: list[ComparisonTrial] = []
        order_index = 0
        for repetition in range(1, repetitions + 1):
            block = list(runner_ids)
            generator.shuffle(block)
            for runner_id in block:
                trials.append(
                    ComparisonTrial(
                        trial_id=f"{comparison_id}:r{repetition}:{runner_id}",
                        runner_id=runner_id,
                        repetition=repetition,
                        order_index=order_index,
                        snapshot_digest=snapshot.digest,
                    )
                )
                order_index += 1
        return cls(
            comparison_id=comparison_id,
            snapshot=snapshot,
            runner_ids=runner_ids,
            repetitions=repetitions,
            random_seed=random_seed,
            trials=tuple(trials),
        )

    def __post_init__(self) -> None:
        _non_empty(self.comparison_id, "comparison_id")
        if not isinstance(self.snapshot, ComparisonSnapshot):
            raise ValidationError("snapshot must be a ComparisonSnapshot")
        if not isinstance(self.runner_ids, tuple) or len(self.runner_ids) < 2:
            raise ValidationError("runner_ids must contain at least two runners")
        if len(set(self.runner_ids)) != len(self.runner_ids):
            raise ValidationError("runner_ids must be unique")
        for runner_id in self.runner_ids:
            _non_empty(runner_id, "runner_id")
        if (
            isinstance(self.repetitions, bool)
            or not isinstance(self.repetitions, int)
            or self.repetitions < 2
        ):
            raise ValidationError(
                "controlled comparisons require at least two repetitions"
            )
        if isinstance(self.random_seed, bool) or not isinstance(self.random_seed, int):
            raise ValidationError("random_seed must be an integer")
        if not isinstance(self.trials, tuple):
            raise ValidationError("trials must be an immutable tuple")
        expected = len(self.runner_ids) * self.repetitions
        if len(self.trials) != expected:
            raise ValidationError("comparison plan does not contain a complete trial matrix")
        if any(not isinstance(trial, ComparisonTrial) for trial in self.trials):
            raise ValidationError("trials must contain ComparisonTrial values")
        if tuple(trial.order_index for trial in self.trials) != tuple(range(expected)):
            raise ValidationError("trial order_index values must be contiguous")
        seen_cells: set[tuple[str, int]] = set()
        seen_trial_ids: set[str] = set()
        for trial in self.trials:
            if trial.snapshot_digest != self.snapshot.digest:
                raise ValidationError("every trial must use the plan's exact snapshot")
            if trial.trial_id in seen_trial_ids:
                raise ValidationError("comparison trial identifiers must be unique")
            seen_trial_ids.add(trial.trial_id)
            cell = (trial.runner_id, trial.repetition)
            if cell in seen_cells:
                raise ValidationError("runner/repetition cell appears more than once")
            seen_cells.add(cell)
        expected_cells = {
            (runner_id, repetition)
            for runner_id in self.runner_ids
            for repetition in range(1, self.repetitions + 1)
        }
        if seen_cells != expected_cells:
            raise ValidationError(
                "comparison plan must contain the exact runner/repetition matrix"
            )


@dataclass(frozen=True, slots=True)
class TrialMetrics:
    """Raw measurements; none combines unlike dimensions into a score."""

    verification_passed: bool
    checks_total: int
    checks_passed: int
    wall_time_seconds: float
    attempt_count: int
    files_changed: int
    lines_added: int
    lines_deleted: int
    reviewer_findings: int
    regressions: int
    human_interventions: int
    process_exit_code: int | None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_input_tokens: int | None = None
    usage_observation: UsageObservation = UsageObservation.UNAVAILABLE
    schema_valid: bool | None = None
    correctness_passed: bool | None = None
    grounding_passed: bool | None = None
    completeness_passed: bool | None = None
    prioritization_passed: bool | None = None
    actionability_passed: bool | None = None
    safety_passed: bool | None = None
    uncertainty_handled_passed: bool | None = None
    context_bytes: int | None = None
    approximate_context_tokens: int | None = None
    turn_count: int | None = None
    tool_activity_count: int | None = None
    human_setup_minutes: float | None = None
    human_review_minutes: float | None = None
    corrections_required: int | None = None
    maximum_correction_severity: str | None = None
    human_quality_assessment: str | None = None
    human_safety_assessment: str | None = None
    subscription_capacity_observation: str | None = None
    billing_route: BillingRoute = BillingRoute.UNKNOWN
    subscription_name: str | None = None
    included_capacity_state: CapacityState = CapacityState.UNKNOWN
    subscription_capacity_consumed: bool | None = None
    subscription_limit_encountered: bool | None = None
    run_delayed_by_limit: bool | None = None
    paid_capacity_consumed: PaidCapacityConsumed = PaidCapacityConsumed.UNKNOWN
    incremental_ai_charge: IncrementalAICharge = IncrementalAICharge.UNKNOWN
    billing_quarantine_required: bool = False
    billing_circuit_breaker_required: bool = False
    local_compute_resources: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.verification_passed, bool):
            raise ValidationError("verification_passed must be boolean")
        for field_name in (
            "checks_total",
            "checks_passed",
            "attempt_count",
            "files_changed",
            "lines_added",
            "lines_deleted",
            "reviewer_findings",
            "regressions",
            "human_interventions",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValidationError(f"{field_name} must be a non-negative integer")
        if self.attempt_count < 1:
            raise ValidationError("attempt_count must be at least one")
        if self.checks_passed > self.checks_total:
            raise ValidationError("checks_passed cannot exceed checks_total")
        if (
            isinstance(self.wall_time_seconds, bool)
            or not isinstance(self.wall_time_seconds, (int, float))
            or not math.isfinite(float(self.wall_time_seconds))
            or self.wall_time_seconds < 0
        ):
            raise ValidationError("wall_time_seconds must be non-negative and finite")
        if self.process_exit_code is not None and (
            isinstance(self.process_exit_code, bool)
            or not isinstance(self.process_exit_code, int)
        ):
            raise ValidationError("process_exit_code must be an integer or None")
        for field_name in ("input_tokens", "output_tokens", "cached_input_tokens"):
            _non_negative_integer(getattr(self, field_name), field_name)
        if not isinstance(self.usage_observation, UsageObservation):
            raise ValidationError("usage_observation must be a UsageObservation")
        for field_name in (
            "schema_valid",
            "correctness_passed",
            "grounding_passed",
            "completeness_passed",
            "prioritization_passed",
            "actionability_passed",
            "safety_passed",
            "uncertainty_handled_passed",
            "subscription_capacity_consumed",
            "subscription_limit_encountered",
            "run_delayed_by_limit",
            "billing_quarantine_required",
            "billing_circuit_breaker_required",
        ):
            _optional_boolean(getattr(self, field_name), field_name)
        for field_name in (
            "context_bytes",
            "approximate_context_tokens",
            "turn_count",
            "tool_activity_count",
            "corrections_required",
        ):
            _non_negative_integer(getattr(self, field_name), field_name)
        for field_name in ("human_setup_minutes", "human_review_minutes"):
            _optional_non_negative_number(getattr(self, field_name), field_name)
        if self.maximum_correction_severity not in {
            None,
            "none",
            "low",
            "medium",
            "high",
            "critical",
        }:
            raise ValidationError("maximum_correction_severity is invalid")
        if self.human_quality_assessment not in {
            None,
            "unacceptable",
            "major_corrections",
            "minor_corrections",
            "acceptable",
            "excellent",
        }:
            raise ValidationError("human_quality_assessment is invalid")
        if self.human_safety_assessment not in {
            None,
            "unsafe",
            "needs_review",
            "acceptable",
        }:
            raise ValidationError("human_safety_assessment is invalid")
        if self.subscription_capacity_observation not in {
            None,
            "not_observed",
            "consumed",
            "limit_encountered",
            "delayed_by_limit",
            "uncertain",
        }:
            raise ValidationError("subscription_capacity_observation is invalid")
        if not isinstance(self.billing_route, BillingRoute):
            raise ValidationError("billing_route must be a BillingRoute")
        if not isinstance(self.included_capacity_state, CapacityState):
            raise ValidationError("included_capacity_state must be a CapacityState")
        if not isinstance(self.paid_capacity_consumed, PaidCapacityConsumed):
            raise ValidationError(
                "paid_capacity_consumed must be a PaidCapacityConsumed"
            )
        if not isinstance(self.incremental_ai_charge, IncrementalAICharge):
            raise ValidationError(
                "incremental_ai_charge must be an IncrementalAICharge"
            )
        for field_name in (
            "subscription_name",
            "local_compute_resources",
        ):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, str) or not value.strip() or len(value) > 200
            ):
                raise ValidationError(f"{field_name} must be a short non-empty string or None")


@dataclass(frozen=True, slots=True)
class TrialOutcome:
    trial_id: str
    run_id: str
    runner_id: str
    snapshot_digest: str
    session_id: str
    status: RunStatus
    metrics: TrialMetrics

    def __post_init__(self) -> None:
        for field_name in (
            "trial_id",
            "run_id",
            "runner_id",
            "snapshot_digest",
            "session_id",
        ):
            _non_empty(getattr(self, field_name), field_name)
        if not isinstance(self.status, RunStatus):
            raise ValidationError("status must be a RunStatus")


@dataclass(frozen=True, slots=True)
class ComparisonRow:
    comparison_id: str
    trial_id: str
    runner_id: str
    repetition: int
    order_index: int
    run_id: str
    session_id: str
    status: RunStatus
    metrics: TrialMetrics


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    """A validated matrix of raw outcomes without ranking or aggregation."""

    plan: ComparisonPlan
    rows: tuple[ComparisonRow, ...]

    @classmethod
    def build(
        cls, plan: ComparisonPlan, outcomes: tuple[TrialOutcome, ...]
    ) -> ComparisonReport:
        if not isinstance(outcomes, tuple):
            raise ValidationError("outcomes must be an immutable tuple")
        by_trial: dict[str, TrialOutcome] = {}
        sessions: set[str] = set()
        for outcome in outcomes:
            if outcome.trial_id in by_trial:
                raise ValidationError(f"duplicate outcome for trial {outcome.trial_id}")
            if outcome.session_id in sessions:
                raise ValidationError("each comparison trial must use a fresh session ID")
            by_trial[outcome.trial_id] = outcome
            sessions.add(outcome.session_id)
        expected_ids = {trial.trial_id for trial in plan.trials}
        if set(by_trial) != expected_ids:
            missing = len(expected_ids - set(by_trial))
            unexpected = len(set(by_trial) - expected_ids)
            raise ValidationError(
                f"outcomes must exactly cover the plan (missing={missing}, unexpected={unexpected})"
            )

        rows: list[ComparisonRow] = []
        for trial in plan.trials:
            outcome = by_trial[trial.trial_id]
            if outcome.runner_id != trial.runner_id:
                raise ValidationError(f"runner mismatch for trial {trial.trial_id}")
            if outcome.snapshot_digest != plan.snapshot.digest:
                raise ValidationError(f"snapshot mismatch for trial {trial.trial_id}")
            rows.append(
                ComparisonRow(
                    comparison_id=plan.comparison_id,
                    trial_id=trial.trial_id,
                    runner_id=trial.runner_id,
                    repetition=trial.repetition,
                    order_index=trial.order_index,
                    run_id=outcome.run_id,
                    session_id=outcome.session_id,
                    status=outcome.status,
                    metrics=outcome.metrics,
                )
            )
        return cls(plan=plan, rows=tuple(rows))

    def for_runner(self, runner_id: str) -> tuple[ComparisonRow, ...]:
        _non_empty(runner_id, "runner_id")
        return tuple(row for row in self.rows if row.runner_id == runner_id)

    @staticmethod
    def metric_dimensions() -> tuple[str, ...]:
        """Expose the auditable dimensions; useful for stable report columns."""

        return tuple(field.name for field in fields(TrialMetrics))


_CONTROLLED_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError("comparison metadata must be canonical JSON") from exc
    return "sha256:" + sha256(encoded).hexdigest()


def _controlled_identifier(value: str, field_name: str) -> str:
    _non_empty(value, field_name)
    if _CONTROLLED_IDENTIFIER.fullmatch(value) is None:
        raise ValidationError(
            f"{field_name} must contain only letters, numbers, '.', '_', or '-'"
        )
    return value


@dataclass(frozen=True, slots=True)
class ComparisonProfile:
    """Immutable identity of one named, versioned comparison candidate."""

    profile_id: str
    profile_version: str
    runner_id: str
    configuration_digest: str

    def __post_init__(self) -> None:
        _controlled_identifier(self.profile_id, "profile_id")
        _non_empty(self.profile_version, "profile_version")
        _non_empty(self.runner_id, "runner_id")
        if not isinstance(self.configuration_digest, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.configuration_digest
        ):
            raise ValidationError("configuration_digest must be a SHA-256 digest")

    @classmethod
    def from_execution_profile(
        cls, profile: ExecutionProfile
    ) -> ComparisonProfile:
        if not isinstance(profile, ExecutionProfile):
            raise ValidationError("profile must be an ExecutionProfile")
        digest = _canonical_digest(
            {
                "model_id": profile.model_id,
                "profile_id": profile.profile_id,
                "profile_version": profile.version,
                "runner_id": profile.runner_id,
                "settings": dict(profile.settings),
                "role": profile.role,
                "capabilities": sorted(profile.capabilities),
                "task_kinds": sorted(profile.task_kinds),
                "allowed_billing_routes": sorted(
                    route.value for route in profile.allowed_billing_routes
                ),
                "max_permission_class": int(profile.max_permission_class),
                "max_context_bytes": profile.max_context_bytes,
                "quality_prior": profile.quality_prior,
                "latency_prior_seconds": profile.latency_prior_seconds,
            }
        )
        return cls(
            profile_id=profile.profile_id,
            profile_version=profile.version,
            runner_id=profile.runner_id,
            configuration_digest=digest,
        )


@dataclass(frozen=True, slots=True)
class ControlledComparisonTrial:
    """One named-profile cell in the predetermined comparison order."""

    trial_id: str
    profile_id: str
    runner_id: str
    repetition: int
    order_index: int
    snapshot_digest: str
    fresh_session: bool = True

    def __post_init__(self) -> None:
        _controlled_identifier(self.trial_id, "trial_id")
        _controlled_identifier(self.profile_id, "profile_id")
        _non_empty(self.runner_id, "runner_id")
        _non_empty(self.snapshot_digest, "snapshot_digest")
        if (
            isinstance(self.repetition, bool)
            or not isinstance(self.repetition, int)
            or self.repetition < 1
        ):
            raise ValidationError("repetition must be a positive integer")
        if (
            isinstance(self.order_index, bool)
            or not isinstance(self.order_index, int)
            or self.order_index < 0
        ):
            raise ValidationError("order_index must be a non-negative integer")
        if self.fresh_session is not True:
            raise ValidationError("controlled comparisons require fresh sessions")


@dataclass(frozen=True, slots=True)
class ControlledComparisonPlan:
    """Fully determined randomized order for named execution profiles."""

    comparison_id: str
    snapshot: ComparisonSnapshot
    profiles: tuple[ComparisonProfile, ...]
    repetitions: int
    random_seed: int
    trials: tuple[ControlledComparisonTrial, ...]

    @classmethod
    def create(
        cls,
        *,
        comparison_id: str,
        snapshot: ComparisonSnapshot,
        profiles: tuple[ComparisonProfile, ...],
        repetitions: int = 3,
        random_seed: int = 20260726,
    ) -> ControlledComparisonPlan:
        _controlled_identifier(comparison_id, "comparison_id")
        if not isinstance(snapshot, ComparisonSnapshot):
            raise ValidationError("snapshot must be a ComparisonSnapshot")
        if snapshot.permission_class is not PermissionClass.READ_ONLY:
            raise ValidationError(
                "controlled compare-run snapshots must use read-only permission Class 0"
            )
        if not isinstance(profiles, tuple) or len(profiles) < 2:
            raise ValidationError("profiles must contain at least two named profiles")
        if any(not isinstance(profile, ComparisonProfile) for profile in profiles):
            raise ValidationError("profiles must contain ComparisonProfile values")
        profile_ids = tuple(profile.profile_id for profile in profiles)
        if len(set(profile_ids)) != len(profile_ids):
            raise ValidationError("comparison profile identifiers must be unique")
        if (
            isinstance(repetitions, bool)
            or not isinstance(repetitions, int)
            or repetitions < 2
        ):
            raise ValidationError(
                "controlled comparisons require at least two repetitions"
            )
        if isinstance(random_seed, bool) or not isinstance(random_seed, int):
            raise ValidationError("random_seed must be an integer")

        generator = random.Random(random_seed)
        trials: list[ControlledComparisonTrial] = []
        order_index = 0
        for repetition in range(1, repetitions + 1):
            block = list(profiles)
            generator.shuffle(block)
            for profile in block:
                trials.append(
                    ControlledComparisonTrial(
                        trial_id=f"trial-{order_index + 1:03d}",
                        profile_id=profile.profile_id,
                        runner_id=profile.runner_id,
                        repetition=repetition,
                        order_index=order_index,
                        snapshot_digest=snapshot.digest,
                    )
                )
                order_index += 1
        return cls(
            comparison_id=comparison_id,
            snapshot=snapshot,
            profiles=profiles,
            repetitions=repetitions,
            random_seed=random_seed,
            trials=tuple(trials),
        )

    def __post_init__(self) -> None:
        _controlled_identifier(self.comparison_id, "comparison_id")
        if not isinstance(self.snapshot, ComparisonSnapshot):
            raise ValidationError("snapshot must be a ComparisonSnapshot")
        if self.snapshot.permission_class is not PermissionClass.READ_ONLY:
            raise ValidationError(
                "controlled compare-run snapshots must use read-only permission Class 0"
            )
        if not isinstance(self.profiles, tuple) or len(self.profiles) < 2:
            raise ValidationError("profiles must contain at least two named profiles")
        if any(not isinstance(profile, ComparisonProfile) for profile in self.profiles):
            raise ValidationError("profiles must contain ComparisonProfile values")
        profile_ids = tuple(profile.profile_id for profile in self.profiles)
        if len(set(profile_ids)) != len(profile_ids):
            raise ValidationError("comparison profile identifiers must be unique")
        if (
            isinstance(self.repetitions, bool)
            or not isinstance(self.repetitions, int)
            or self.repetitions < 2
        ):
            raise ValidationError(
                "controlled comparisons require at least two repetitions"
            )
        if isinstance(self.random_seed, bool) or not isinstance(self.random_seed, int):
            raise ValidationError("random_seed must be an integer")
        if not isinstance(self.trials, tuple):
            raise ValidationError("trials must be an immutable tuple")
        expected_count = len(self.profiles) * self.repetitions
        if len(self.trials) != expected_count:
            raise ValidationError("controlled plan has an incomplete trial matrix")
        if tuple(trial.order_index for trial in self.trials) != tuple(
            range(expected_count)
        ):
            raise ValidationError("controlled trial order must be contiguous")
        profile_by_id = {profile.profile_id: profile for profile in self.profiles}
        cells: set[tuple[str, int]] = set()
        trial_ids: set[str] = set()
        for trial in self.trials:
            if not isinstance(trial, ControlledComparisonTrial):
                raise ValidationError(
                    "trials must contain ControlledComparisonTrial values"
                )
            profile = profile_by_id.get(trial.profile_id)
            if profile is None or profile.runner_id != trial.runner_id:
                raise ValidationError("controlled trial profile identity is inconsistent")
            if trial.snapshot_digest != self.snapshot.digest:
                raise ValidationError("every controlled trial must use the exact snapshot")
            if trial.trial_id in trial_ids:
                raise ValidationError("controlled trial identifiers must be unique")
            trial_ids.add(trial.trial_id)
            cell = (trial.profile_id, trial.repetition)
            if cell in cells:
                raise ValidationError("profile/repetition cell appears more than once")
            cells.add(cell)
        expected_cells = {
            (profile.profile_id, repetition)
            for profile in self.profiles
            for repetition in range(1, self.repetitions + 1)
        }
        if cells != expected_cells:
            raise ValidationError(
                "controlled plan must contain the exact profile/repetition matrix"
            )


@dataclass(frozen=True, slots=True)
class ComparisonControls:
    """Controller-owned conditions that are identical for every trial."""

    context_digest: str
    output_schema_digest: str
    timeout_seconds: int
    permission_class: PermissionClass = PermissionClass.READ_ONLY
    fresh_session_per_trial: bool = True
    outputs_shared_between_trials: bool = False
    external_actions_allowed: bool = False

    def __post_init__(self) -> None:
        _non_empty(self.context_digest, "context_digest")
        if not isinstance(self.output_schema_digest, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.output_schema_digest
        ):
            raise ValidationError("output_schema_digest must be a SHA-256 digest")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or self.timeout_seconds < 1
        ):
            raise ValidationError("timeout_seconds must be a positive integer")
        if self.permission_class is not PermissionClass.READ_ONLY:
            raise ValidationError("controlled comparisons require read-only Class 0")
        if self.fresh_session_per_trial is not True:
            raise ValidationError("controlled comparisons require fresh sessions")
        if self.outputs_shared_between_trials is not False:
            raise ValidationError("comparison outputs must not be shared between trials")
        if self.external_actions_allowed is not False:
            raise ValidationError("controlled comparisons prohibit external actions")


@dataclass(frozen=True, slots=True)
class ControlledTrialOutcome:
    trial_id: str
    profile_id: str
    runner_id: str
    run_id: str
    snapshot_digest: str
    session_id: str
    session_id_observed: bool
    status: RunStatus
    metrics: TrialMetrics
    review_artifact_path: str | None = None
    review_artifact_sha256: str | None = None
    failure_type: str | None = None
    error_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "trial_id",
            "profile_id",
            "runner_id",
            "run_id",
            "snapshot_digest",
            "session_id",
        ):
            _non_empty(getattr(self, field_name), field_name)
        if not isinstance(self.session_id_observed, bool):
            raise ValidationError("session_id_observed must be boolean")
        if not isinstance(self.status, RunStatus):
            raise ValidationError("status must be a RunStatus")
        if not isinstance(self.metrics, TrialMetrics):
            raise ValidationError("metrics must be TrialMetrics")
        if (self.review_artifact_path is None) != (
            self.review_artifact_sha256 is None
        ):
            raise ValidationError("review artifact path and digest must appear together")
        if self.review_artifact_sha256 is not None and re.fullmatch(
            r"[0-9a-f]{64}", self.review_artifact_sha256
        ) is None:
            raise ValidationError("review_artifact_sha256 must be a SHA-256 digest")
        if self.failure_type is not None and re.fullmatch(
            r"[a-z][a-z0-9_]{0,79}", self.failure_type
        ) is None:
            raise ValidationError("failure_type must be a normalized code or None")
        if any(
            not isinstance(code, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code) is None
            for code in self.error_codes
        ):
            raise ValidationError("error_codes must contain normalized fixed codes")


@dataclass(frozen=True, slots=True)
class ControlledComparisonRow:
    comparison_id: str
    trial_id: str
    profile_id: str
    runner_id: str
    repetition: int
    order_index: int
    run_id: str
    session_id: str
    session_id_observed: bool
    status: RunStatus
    metrics: TrialMetrics
    review_artifact_path: str | None
    review_artifact_sha256: str | None
    failure_type: str | None
    error_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControlledComparisonReport:
    """Completed raw comparison matrix without ranking or model outputs."""

    plan: ControlledComparisonPlan
    controls: ComparisonControls
    rows: tuple[ControlledComparisonRow, ...]
    report_path: str
    review_template_path: str

    @classmethod
    def build(
        cls,
        plan: ControlledComparisonPlan,
        controls: ComparisonControls,
        outcomes: tuple[ControlledTrialOutcome, ...],
        *,
        report_path: Path,
        review_template_path: Path,
    ) -> ControlledComparisonReport:
        if not isinstance(outcomes, tuple):
            raise ValidationError("outcomes must be an immutable tuple")
        by_trial: dict[str, ControlledTrialOutcome] = {}
        sessions: set[str] = set()
        for outcome in outcomes:
            if not isinstance(outcome, ControlledTrialOutcome):
                raise ValidationError("outcomes must contain controlled outcomes")
            if outcome.trial_id in by_trial:
                raise ValidationError(f"duplicate outcome for {outcome.trial_id}")
            if outcome.session_id in sessions:
                raise ValidationError("each controlled trial must use a fresh session")
            by_trial[outcome.trial_id] = outcome
            sessions.add(outcome.session_id)
        expected_ids = {trial.trial_id for trial in plan.trials}
        unexpected_ids = set(by_trial) - expected_ids
        if unexpected_ids:
            raise ValidationError("outcomes contain trials outside the controlled plan")

        rows: list[ControlledComparisonRow] = []
        for trial in plan.trials:
            outcome = by_trial.get(trial.trial_id)
            if outcome is None:
                continue
            if (
                outcome.profile_id != trial.profile_id
                or outcome.runner_id != trial.runner_id
                or outcome.snapshot_digest != plan.snapshot.digest
            ):
                raise ValidationError(
                    f"controlled outcome identity mismatch for {trial.trial_id}"
                )
            rows.append(
                ControlledComparisonRow(
                    comparison_id=plan.comparison_id,
                    trial_id=trial.trial_id,
                    profile_id=trial.profile_id,
                    runner_id=trial.runner_id,
                    repetition=trial.repetition,
                    order_index=trial.order_index,
                    run_id=outcome.run_id,
                    session_id=outcome.session_id,
                    session_id_observed=outcome.session_id_observed,
                    status=outcome.status,
                    metrics=outcome.metrics,
                    review_artifact_path=outcome.review_artifact_path,
                    review_artifact_sha256=outcome.review_artifact_sha256,
                    failure_type=outcome.failure_type,
                    error_codes=outcome.error_codes,
                )
            )
        return cls(
            plan=plan,
            controls=controls,
            rows=tuple(rows),
            report_path=str(report_path),
            review_template_path=str(review_template_path),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "comparison_id": self.plan.comparison_id,
            "snapshot_digest": self.plan.snapshot.digest,
            "profiles": [
                {
                    "profile_id": profile.profile_id,
                    "profile_version": profile.profile_version,
                    "runner_id": profile.runner_id,
                    "configuration_digest": profile.configuration_digest,
                }
                for profile in self.plan.profiles
            ],
            "repetitions": self.plan.repetitions,
            "random_seed": self.plan.random_seed,
            "controls": {
                "context_digest": self.controls.context_digest,
                "output_schema_digest": self.controls.output_schema_digest,
                "timeout_seconds": self.controls.timeout_seconds,
                "permission_class": int(self.controls.permission_class),
                "fresh_session_per_trial": self.controls.fresh_session_per_trial,
                "outputs_shared_between_trials": self.controls.outputs_shared_between_trials,
                "external_actions_allowed": self.controls.external_actions_allowed,
            },
            "metric_dimensions": list(ComparisonReport.metric_dimensions()),
            "authorization_shadow_coverage": (
                COMPARISON_AUTHORIZATION_SHADOW_COVERAGE
            ),
            "raw_results_only": True,
            "ranking_performed": False,
            "report_path": self.report_path,
            "review_template_path": self.review_template_path,
            "planned_trial_count": len(self.plan.trials),
            "completed_trial_count": len(self.rows),
            "execution_complete": len(self.rows) == len(self.plan.trials),
            "automated_checks_succeeded": (
                len(self.rows) == len(self.plan.trials)
                and all(
                    row.status is RunStatus.SUCCEEDED
                    and row.metrics.verification_passed
                    for row in self.rows
                )
            ),
            "human_review_status": "pending",
            "trials": [
                {
                    "trial_id": row.trial_id,
                    "profile_id": row.profile_id,
                    "runner_id": row.runner_id,
                    "repetition": row.repetition,
                    "order_index": row.order_index,
                    "run_id": row.run_id,
                    "session_id": row.session_id,
                    "session_id_observed": row.session_id_observed,
                    "status": row.status.value,
                    "review_artifact_path": row.review_artifact_path,
                    "review_artifact_sha256": row.review_artifact_sha256,
                    "failure_type": row.failure_type,
                    "error_codes": list(row.error_codes),
                    "metrics": _metrics_mapping(row.metrics),
                    "human_scoring": {
                        "status": "pending_human_review",
                        "review_time_minutes": row.metrics.human_review_minutes,
                        "corrections_required": row.metrics.corrections_required,
                        "maximum_correction_severity": row.metrics.maximum_correction_severity,
                        "quality_assessment": row.metrics.human_quality_assessment,
                        "safety_assessment": row.metrics.human_safety_assessment,
                        "subscription_capacity_observation": row.metrics.subscription_capacity_observation,
                    },
                }
                for row in self.rows
            ],
        }


def comparison_snapshot_from_prepared(prepared: PreparedTask) -> ComparisonSnapshot:
    """Bind the existing sanitized task/context to a Class 0 compare snapshot."""

    if not isinstance(prepared, PreparedTask):
        raise ValidationError("prepared must be a PreparedTask")
    if not prepared.context_pack.verify_snapshot_hash():
        raise ValidationError("comparison context snapshot failed its integrity check")
    return ComparisonSnapshot(
        task_id=prepared.contract.task_id,
        task_version=prepared.contract.version,
        task_text=prepared.prompt,
        repository_revision=(
            f"local-fixture:{prepared.contract.definition_hash}"
        ),
        context_digest=prepared.context_pack.snapshot_hash,
        verification_commands=(
            ("deterministic-evaluator", "chief-of-staff-lite"),
        ),
        permission_class=PermissionClass.READ_ONLY,
    )


async def run_controlled_comparison(
    project_root: str | Path,
    *,
    prepared: PreparedTask,
    plan: ControlledComparisonPlan,
    profiles: Sequence[ExecutionProfile],
    runner_factory: Callable[[ExecutionProfile], AgentRunner],
    comparison_root: str | Path | None = None,
) -> ControlledComparisonReport:
    """Execute a predetermined profile matrix without sharing trial outputs.

    The controller passes every runner the same prompt, schema, timeout, and
    Class 0 permission. A new adapter instance and empty workspace are created
    for every trial. Redacted output is written only to a private per-trial
    review artifact; it is never added to a later prompt or embedded in the
    manifest/report.
    """

    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ConfigurationError(f"project root is not a directory: {root}")
    state_root = resolve_state_root(root)
    expected_snapshot = comparison_snapshot_from_prepared(prepared)
    if expected_snapshot.digest != plan.snapshot.digest:
        raise ValidationError("controlled plan does not match the prepared snapshot")
    if expected_snapshot.context_digest != plan.snapshot.context_digest:
        raise ValidationError("controlled plan context digest changed before execution")

    profile_by_id = {profile.profile_id: profile for profile in profiles}
    if len(profile_by_id) != len(tuple(profiles)):
        raise ValidationError("execution profiles must be unique")
    if set(profile_by_id) != {profile.profile_id for profile in plan.profiles}:
        raise ValidationError("execution profiles must exactly match the plan")
    for planned in plan.profiles:
        actual = profile_by_id[planned.profile_id]
        if ComparisonProfile.from_execution_profile(actual) != planned:
            raise ValidationError(
                f"profile {planned.profile_id} changed after the order was planned"
            )

    comparison_timeout_seconds = min(
        prepared.contract.timeout_seconds,
        CONTROLLED_COMPARISON_TRIAL_TIMEOUT_SECONDS,
    )
    controls = ComparisonControls(
        context_digest=prepared.context_pack.snapshot_hash,
        output_schema_digest=_canonical_digest(prepared.contract.output_schema),
        timeout_seconds=comparison_timeout_seconds,
    )

    # Preflight every fresh trial adapter before creating comparison records.
    # Missing attestations, unsafe routes, and open circuits therefore fail
    # before a trial starts or a plan/report is written.
    prepared_trials: list[
        tuple[ControlledComparisonTrial, ExecutionProfile, AgentRunner, Any]
    ] = []
    runner_instances: list[AgentRunner] = []
    required_billing_valid_until = (
        time.time()
        + len(plan.trials) * comparison_timeout_seconds
        + CONTROLLED_COMPARISON_EVIDENCE_MARGIN_SECONDS
    )
    for trial in plan.trials:
        profile = profile_by_id[trial.profile_id]
        runner = runner_factory(profile)
        if not isinstance(runner, AgentRunner):
            raise ValidationError("runner_factory returned an invalid runner")
        if any(runner is previous for previous in runner_instances):
            raise ValidationError("runner_factory must create a fresh adapter per trial")
        runner_instances.append(runner)
        if runner.runner_id != trial.runner_id:
            raise ValidationError("runner factory identity does not match the plan")
        assessment = await runner.inspect_billing_route()
        if assessment.runner_id != runner.runner_id:
            raise BillingRouteBlocked(
                "comparison billing assessment identity does not match the runner"
            )
        if assessment.route not in profile.allowed_billing_routes:
            raise BillingRouteBlocked(
                f"profile {profile.profile_id} does not allow the observed billing route"
            )
        BillingPolicy.assert_route_allowed(
            assessment,
            required_valid_until=required_billing_valid_until,
        )
        prepared_trials.append((trial, profile, runner, assessment))

    state_path = state_root / "state.sqlite3"
    if state_path.is_symlink():
        raise ConfigurationError("comparison state database must not be a symlink")
    if state_path.exists():
        with SQLiteStateStore(state_path) as state:
            checked_profiles: set[str] = set()
            for _trial, profile, _runner, assessment in prepared_trials:
                if profile.profile_id in checked_profiles:
                    continue
                checked_profiles.add(profile.profile_id)
                guard = SQLiteBillingCircuitGuard(
                    state,
                    profile_id=profile.profile_id,
                )
                try:
                    guard.assert_closed(assessment)
                except BillingRouteBlocked as exc:
                    raise BillingRouteBlocked(
                        f"profile {profile.profile_id} has blocking durable billing state"
                    ) from exc

    base = (
        state_root / "comparisons"
        if comparison_root is None
        else Path(comparison_root).resolve()
    )
    try:
        base.resolve().relative_to(root)
    except ValueError as exc:
        raise ConfigurationError("comparison root must remain inside the project") from exc
    base.mkdir(parents=True, exist_ok=True)
    comparison_directory = base / plan.comparison_id
    try:
        comparison_directory.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise ConfigurationError(
            f"comparison already exists: {plan.comparison_id}"
        ) from exc
    trials_directory = comparison_directory / "trials"
    trials_directory.mkdir(mode=0o700)
    manifest_path = comparison_directory / "plan.json"
    report_path = comparison_directory / "report.json"
    review_template_path = comparison_directory / "human-review-template.json"
    _write_exclusive_json(
        manifest_path,
        _controlled_plan_mapping(plan, controls),
    )

    outcomes: list[ControlledTrialOutcome] = []
    stop_remaining = False
    with SQLiteStateStore(state_path) as state:
        for trial, profile, runner, assessment in prepared_trials:
            if stop_remaining:
                break
            if comparison_snapshot_from_prepared(prepared).digest != plan.snapshot.digest:
                raise ValidationError("immutable comparison snapshot changed between trials")
            run_id = f"compare-{plan.snapshot.digest[:10]}-{trial.order_index + 1:03d}"
            run_directory = trials_directory / f"{trial.order_index + 1:03d}"
            workspace = run_directory / "workspace"
            run_directory.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            request = RunRequest(
                run_id=run_id,
                task_id=prepared.contract.task_id,
                task_version=prepared.contract.version,
                prompt=prepared.prompt,
                workspace=workspace,
                run_directory=run_directory,
                output_schema=prepared.contract.output_schema,
                permission_class=PermissionClass.READ_ONLY,
                timeout_seconds=comparison_timeout_seconds,
                attempt=1,
                runner_overrides=runner_overrides_for_profile(profile),
            )
            events_seen = 0

            async def event_sink(_event: Any) -> None:
                nonlocal events_seen
                events_seen += 1

            started_at = time.monotonic()
            try:
                result = await runner.execute(request, event_sink)
                if not isinstance(result, RunnerExecutionResult):
                    raise ValidationError("runner returned an invalid result type")
                identity_matches = (
                    result.run_id == run_id and result.runner_id == runner.runner_id
                )
                billing_matches = _billing_assessment_matches(
                    assessment, result.billing_assessment
                )
                workspace_entries = tuple(workspace.rglob("*"))
                credential_detected = (
                    result.credential_material_detected
                    or contains_credential_material(result.output)
                )
                redacted_output = DEFAULT_REDACTOR.redact(result.output)
                review_artifact_path = run_directory / "review-output.json"
                artifact_digest = _persist_review_artifact(
                    review_artifact_path,
                    trial=trial,
                    output=(None if credential_detected else redacted_output),
                    withheld_reason=(
                        "credential_material_detected"
                        if credential_detected
                        else None
                    ),
                )
                evaluation = evaluate_chief_of_staff(
                    redacted_output,
                    prepared.contract.output_schema,
                    prepared.context_pack,
                    prepared.expectations,
                )
                final_status = result.status
                if (
                    not identity_matches
                    or not billing_matches
                    or credential_detected
                    or workspace_entries
                    or result.billing_quarantine_required
                    or result.billing_circuit_breaker_required
                ):
                    final_status = RunStatus.QUARANTINED
                failure_type, error_codes = _result_failure_summary(
                    result=result,
                    evaluation=evaluation,
                    identity_matches=identity_matches,
                    billing_matches=billing_matches,
                    credential_detected=credential_detected,
                    workspace_entries=workspace_entries,
                )
                session_id, session_observed = _safe_session_id(result, run_id)
                outcomes.append(
                    ControlledTrialOutcome(
                        trial_id=trial.trial_id,
                        profile_id=trial.profile_id,
                        runner_id=trial.runner_id,
                        run_id=run_id,
                        snapshot_digest=plan.snapshot.digest,
                        session_id=session_id,
                        session_id_observed=session_observed,
                        status=final_status,
                        metrics=_trial_metrics(
                            result=result,
                            evaluation=evaluation,
                            prepared=prepared,
                            billing_matches=billing_matches and identity_matches,
                            credential_material_detected=credential_detected,
                            workspace_entries=workspace_entries,
                            events_seen=events_seen,
                        ),
                        review_artifact_path=str(review_artifact_path),
                        review_artifact_sha256=artifact_digest,
                        failure_type=failure_type,
                        error_codes=error_codes,
                    )
                )
                stop_remaining = _record_billing_observations(
                    state,
                    result=result,
                    profile_id=profile.profile_id,
                    run_id=run_id,
                )
                del result, evaluation, redacted_output
            except Exception as exc:
                failure_type = _exception_failure_type(exc)
                outcomes.append(
                    ControlledTrialOutcome(
                        trial_id=trial.trial_id,
                        profile_id=trial.profile_id,
                        runner_id=trial.runner_id,
                        run_id=run_id,
                        snapshot_digest=plan.snapshot.digest,
                        session_id=f"controller-{run_id}",
                        session_id_observed=False,
                        status=(
                            RunStatus.BLOCKED
                            if isinstance(exc, OrdomataError)
                            else RunStatus.FAILED
                        ),
                        metrics=_failed_trial_metrics(
                            prepared=prepared,
                            assessment=assessment,
                            wall_time_seconds=max(0.0, time.monotonic() - started_at),
                        ),
                        failure_type=failure_type,
                        error_codes=(failure_type,),
                    )
                )
                # Exception text can contain provider or credential material;
                # retain only the fixed code and fail closed on later trials.
                stop_remaining = True

    _write_exclusive_json(
        review_template_path,
        _review_template_mapping(
            plan,
            outcomes,
            report_path=report_path,
        ),
    )
    report = ControlledComparisonReport.build(
        plan,
        controls,
        tuple(outcomes),
        report_path=report_path,
        review_template_path=review_template_path,
    )
    _write_exclusive_json(report_path, report.to_mapping())
    return report


def _controlled_plan_mapping(
    plan: ControlledComparisonPlan, controls: ComparisonControls
) -> dict[str, Any]:
    return {
        "comparison_id": plan.comparison_id,
        "snapshot_digest": plan.snapshot.digest,
        "profiles": [
            {
                "profile_id": profile.profile_id,
                "profile_version": profile.profile_version,
                "runner_id": profile.runner_id,
                "configuration_digest": profile.configuration_digest,
            }
            for profile in plan.profiles
        ],
        "repetitions": plan.repetitions,
        "random_seed": plan.random_seed,
        "controls": {
            "context_digest": controls.context_digest,
            "output_schema_digest": controls.output_schema_digest,
            "timeout_seconds": controls.timeout_seconds,
            "permission_class": int(controls.permission_class),
            "fresh_session_per_trial": controls.fresh_session_per_trial,
            "outputs_shared_between_trials": controls.outputs_shared_between_trials,
            "external_actions_allowed": controls.external_actions_allowed,
        },
        "trials": [
            {
                "trial_id": trial.trial_id,
                "profile_id": trial.profile_id,
                "runner_id": trial.runner_id,
                "repetition": trial.repetition,
                "order_index": trial.order_index,
                "snapshot_digest": trial.snapshot_digest,
            }
            for trial in plan.trials
        ],
    }


def _persist_review_artifact(
    path: Path,
    *,
    trial: ControlledComparisonTrial,
    output: Any,
    withheld_reason: str | None = None,
) -> str:
    if withheld_reason is not None:
        return _write_exclusive_json(
            path,
            {
                "schema_version": 1,
                "trial_id": trial.trial_id,
                "profile_id": trial.profile_id,
                "runner_id": trial.runner_id,
                "output": None,
                "output_withheld_reason": withheld_reason,
            },
        )
    try:
        json.dumps(output, ensure_ascii=False, allow_nan=False)
        payload = {
            "schema_version": 1,
            "trial_id": trial.trial_id,
            "profile_id": trial.profile_id,
            "runner_id": trial.runner_id,
            "output": output,
        }
    except (TypeError, ValueError):
        payload = {
            "schema_version": 1,
            "trial_id": trial.trial_id,
            "profile_id": trial.profile_id,
            "runner_id": trial.runner_id,
            "output": None,
            "output_withheld_reason": "non_json_output",
        }
    return _write_exclusive_json(path, payload)


def _review_template_mapping(
    plan: ControlledComparisonPlan,
    outcomes: Sequence[ControlledTrialOutcome],
    *,
    report_path: Path,
) -> dict[str, Any]:
    by_trial = {outcome.trial_id: outcome for outcome in outcomes}
    return {
        "schema_version": 1,
        "comparison_id": plan.comparison_id,
        "raw_report_path": str(report_path),
        "instructions": (
            "Fill operator_fields after reviewing each private artifact. "
            "Do not copy model output into this template."
        ),
        "allowed_values": {
            "maximum_correction_severity": [
                "none",
                "low",
                "medium",
                "high",
                "critical",
            ],
            "quality_assessment": [
                "unacceptable",
                "major_corrections",
                "minor_corrections",
                "acceptable",
                "excellent",
            ],
            "safety_assessment": ["unsafe", "needs_review", "acceptable"],
            "subscription_capacity_observation": [
                "not_observed",
                "consumed",
                "limit_encountered",
                "delayed_by_limit",
                "uncertain",
            ],
        },
        "trials": [
            {
                "trial_id": trial.trial_id,
                "profile_id": trial.profile_id,
                "runner_id": trial.runner_id,
                "execution_status": (
                    "not_run"
                    if trial.trial_id not in by_trial
                    else by_trial[trial.trial_id].status.value
                ),
                "review_artifact_path": (
                    None
                    if trial.trial_id not in by_trial
                    else by_trial[trial.trial_id].review_artifact_path
                ),
                "review_artifact_sha256": (
                    None
                    if trial.trial_id not in by_trial
                    else by_trial[trial.trial_id].review_artifact_sha256
                ),
                "operator_fields": {
                    "setup_minutes": None,
                    "review_minutes": None,
                    "corrections_required": None,
                    "maximum_correction_severity": None,
                    "quality_assessment": None,
                    "safety_assessment": None,
                    "subscription_capacity_observation": None,
                },
            }
            for trial in plan.trials
        ],
    }


def _result_failure_summary(
    *,
    result: RunnerExecutionResult,
    evaluation: EvaluationResult,
    identity_matches: bool,
    billing_matches: bool,
    credential_detected: bool,
    workspace_entries: tuple[Path, ...],
) -> tuple[str | None, tuple[str, ...]]:
    codes: list[str] = []
    if not identity_matches:
        codes.append("runner_identity_mismatch")
    if not billing_matches:
        codes.append("billing_preflight_mismatch")
    if result.billing_quarantine_required:
        codes.append("billing_quarantine_required")
    if result.billing_circuit_breaker_required:
        codes.append("billing_circuit_breaker_required")
    if credential_detected:
        codes.append("credential_material_redacted")
    if workspace_entries:
        codes.append("read_only_workspace_changed")
    if result.errors:
        codes.append("runner_reported_error")
    failed_criteria = [
        metric.criterion_id for metric in evaluation.metrics if not metric.passed
    ]
    codes.extend(f"criterion_{criterion}_failed" for criterion in failed_criteria)

    if result.billing_quarantine_required or result.billing_circuit_breaker_required:
        failure_type = "billing_quarantined"
    elif not identity_matches:
        failure_type = "runner_identity_mismatch"
    elif not billing_matches:
        failure_type = "billing_preflight_mismatch"
    elif credential_detected:
        failure_type = "credential_quarantined"
    elif workspace_entries:
        failure_type = "read_only_violation"
    elif result.status is RunStatus.BLOCKED:
        failure_type = "runner_blocked"
    elif result.status is not RunStatus.SUCCEEDED:
        failure_type = "runner_failed"
    elif failed_criteria:
        failure_type = "verification_failed"
    else:
        failure_type = None
    return failure_type, tuple(dict.fromkeys(codes))


def _exception_failure_type(exc: Exception) -> str:
    if isinstance(exc, BillingRouteBlocked):
        return "billing_execution_blocked"
    if isinstance(exc, ValidationError):
        return "runner_validation_failed"
    if isinstance(exc, TimeoutError):
        return "runner_timeout"
    if isinstance(exc, OSError):
        return "runner_process_error"
    if isinstance(exc, OrdomataError):
        return "controller_blocked"
    return "runner_execution_error"


def _effective_capacity(result: RunnerExecutionResult) -> CapacityState:
    if result.postflight_billing_assessment is not None:
        return result.postflight_billing_assessment.capacity_state
    if (
        result.billing_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
        and result.harness_process_started
    ):
        return CapacityState.UNKNOWN
    return result.billing_assessment.capacity_state


def _safe_fingerprint(value: str | None) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    return None


def _record_billing_observations(
    state: SQLiteStateStore,
    *,
    result: RunnerExecutionResult,
    profile_id: str,
    run_id: str,
) -> bool:
    if result.billing_assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
        return False
    capacity = _effective_capacity(result)
    postflight = result.postflight_billing_assessment
    trusted_fingerprint = _safe_fingerprint(
        result.billing_assessment.account_identity_fingerprint
    )
    if capacity is CapacityState.AVAILABLE:
        capacity_reason = "post_run_capacity_available"
    elif capacity in {
        CapacityState.LIMIT_REACHED,
        CapacityState.BLOCKED_UNTIL_RESET,
    }:
        capacity_reason = "included_capacity_exhausted"
    elif capacity is CapacityState.COOLDOWN:
        capacity_reason = "post_run_capacity_cooldown"
    else:
        capacity_reason = "post_run_billing_unknown"
    state.append_billing_capacity_event(
        runner_id=result.runner_id,
        capacity_state=capacity,
        reason_code=capacity_reason,
        account_identity_fingerprint=trusted_fingerprint,
        profile_id=profile_id,
        run_id=run_id,
    )
    if result.billing_circuit_breaker_required:
        circuit_reason = (
            "post_run_paid_route_possible"
            if result.incremental_ai_charge
            in {IncrementalAICharge.POSSIBLE, IncrementalAICharge.CONFIRMED}
            else "post_run_billing_unknown"
        )
        postflight_fingerprint = _safe_fingerprint(
            None
            if postflight is None
            else postflight.account_identity_fingerprint
        )
        circuit_scopes: list[str | None] = [trusted_fingerprint]
        if (
            trusted_fingerprint is None
            or postflight_fingerprint is None
            or postflight_fingerprint != trusted_fingerprint
        ):
            circuit_scopes.append(None)
        for scope_fingerprint in tuple(dict.fromkeys(circuit_scopes)):
            state.append_billing_circuit_event(
                runner_id=result.runner_id,
                state=CircuitBreakerState.OPEN,
                reason_code=circuit_reason,
                account_identity_fingerprint=scope_fingerprint,
                profile_id=profile_id,
                run_id=run_id,
            )
        return True
    return capacity in {
        CapacityState.LIMIT_REACHED,
        CapacityState.BLOCKED_UNTIL_RESET,
        CapacityState.COOLDOWN,
        CapacityState.UNKNOWN,
    }


def _write_exclusive_json(path: Path, payload: Mapping[str, Any]) -> str:
    try:
        document = (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("comparison record is not canonical JSON") from exc
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ConfigurationError(f"cannot create immutable comparison record {path}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(document)
        path.chmod(0o600)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return sha256(document.encode("utf-8")).hexdigest()


def _billing_assessment_matches(first: Any, second: Any) -> bool:
    return all(
        getattr(first, field_name, None) == getattr(second, field_name, None)
        for field_name in (
            "runner_id",
            "route",
            "confidence",
            "subscription_name",
            "capacity_state",
            "paid_continuation_protection",
            "paid_credit_balance",
            "account_identity_fingerprint",
        )
    )


def _safe_session_id(
    result: RunnerExecutionResult, run_id: str
) -> tuple[str, bool]:
    if isinstance(result.session_id, str) and result.session_id:
        digest = sha256(result.session_id.encode("utf-8")).hexdigest()
        return f"observed-sha256-{digest}", True
    return f"controller-{run_id}", False


def _evaluation_passed(evaluation: EvaluationResult, criterion_id: str) -> bool:
    try:
        return evaluation.metric(criterion_id).passed
    except KeyError:
        return False


def _usage_integer(usage: Mapping[str, Any], *names: str) -> int | None:
    for name in names:
        value = usage.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _tool_activity_count(result: RunnerExecutionResult) -> int:
    tool_types = {
        "command_execution",
        "file_change",
        "mcp_tool_call",
        "tool_use",
        "tool_result",
    }
    count = 0
    for event in result.events:
        item = event.payload.get("item")
        item_type = item.get("type") if isinstance(item, Mapping) else None
        if event.event_type in tool_types or item_type in tool_types:
            count += 1
    return count


def _turn_count(result: RunnerExecutionResult) -> int | None:
    value = _usage_integer(result.usage, "turn_count", "num_turns", "turns")
    if value is not None:
        return value
    terminal_types = {"turn.completed", "result"}
    count = sum(event.event_type in terminal_types for event in result.events)
    return count or None


def _failed_trial_metrics(
    *,
    prepared: PreparedTask,
    assessment: Any,
    wall_time_seconds: float,
) -> TrialMetrics:
    return TrialMetrics(
        verification_passed=False,
        checks_total=1,
        checks_passed=0,
        wall_time_seconds=wall_time_seconds,
        attempt_count=1,
        files_changed=0,
        lines_added=0,
        lines_deleted=0,
        reviewer_findings=1,
        regressions=0,
        human_interventions=0,
        process_exit_code=None,
        usage_observation=UsageObservation.UNAVAILABLE,
        context_bytes=prepared.context_pack.raw_bytes,
        approximate_context_tokens=prepared.context_pack.approximate_context_tokens,
        billing_route=getattr(assessment, "route", BillingRoute.UNKNOWN),
        subscription_name=getattr(assessment, "subscription_name", None),
        included_capacity_state=getattr(
            assessment, "capacity_state", CapacityState.UNKNOWN
        ),
        subscription_capacity_consumed=None,
        subscription_limit_encountered=None,
        paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
        incremental_ai_charge=IncrementalAICharge.UNKNOWN,
    )


def _trial_metrics(
    *,
    result: RunnerExecutionResult,
    evaluation: EvaluationResult,
    prepared: PreparedTask,
    billing_matches: bool,
    credential_material_detected: bool,
    workspace_entries: tuple[Path, ...],
    events_seen: int,
) -> TrialMetrics:
    del events_seen  # event payloads are deliberately not persisted as metrics.
    automated_passes = sum(metric.passed for metric in evaluation.metrics)
    invariant_passes = sum(
        (
            billing_matches,
            not credential_material_detected,
            not workspace_entries,
            not result.billing_quarantine_required,
            not result.billing_circuit_breaker_required,
        )
    )
    checks_total = len(evaluation.metrics) + 5
    checks_passed = automated_passes + invariant_passes
    correctness = all(
        _evaluation_passed(evaluation, criterion)
        for criterion in ("schema_valid", "snapshot_match", "grounded", "complete")
    )
    safety = (
        _evaluation_passed(evaluation, "safe")
        and not credential_material_detected
        and not workspace_entries
        and not result.billing_quarantine_required
        and not result.billing_circuit_breaker_required
    )
    effective_capacity = _effective_capacity(result)
    if effective_capacity in {
        CapacityState.LIMIT_REACHED,
        CapacityState.BLOCKED_UNTIL_RESET,
    }:
        limit_encountered: bool | None = True
    elif effective_capacity in {
        CapacityState.AVAILABLE,
        CapacityState.NOT_APPLICABLE,
    }:
        limit_encountered = False
    else:
        limit_encountered = None
    return TrialMetrics(
        verification_passed=(
            result.status is RunStatus.SUCCEEDED
            and checks_passed == checks_total
        ),
        checks_total=checks_total,
        checks_passed=checks_passed,
        wall_time_seconds=float(result.wall_seconds or 0.0),
        attempt_count=1,
        files_changed=len(workspace_entries),
        lines_added=0,
        lines_deleted=0,
        reviewer_findings=sum(not metric.passed for metric in evaluation.metrics),
        regressions=0,
        human_interventions=0,
        process_exit_code=result.exit_code,
        input_tokens=_usage_integer(
            result.usage, "input_tokens", "inputTokens", "input"
        ),
        output_tokens=_usage_integer(
            result.usage, "output_tokens", "outputTokens", "output"
        ),
        cached_input_tokens=_usage_integer(
            result.usage,
            "cached_input_tokens",
            "cache_read_input_tokens",
            "cacheReadInputTokens",
        ),
        usage_observation=result.usage_observation,
        schema_valid=_evaluation_passed(evaluation, "schema_valid"),
        correctness_passed=correctness,
        grounding_passed=_evaluation_passed(evaluation, "grounded"),
        completeness_passed=_evaluation_passed(evaluation, "complete"),
        prioritization_passed=_evaluation_passed(evaluation, "prioritized"),
        actionability_passed=_evaluation_passed(evaluation, "actionable"),
        safety_passed=safety,
        uncertainty_handled_passed=_evaluation_passed(
            evaluation, "uncertainty_handled"
        ),
        context_bytes=prepared.context_pack.raw_bytes,
        approximate_context_tokens=prepared.context_pack.approximate_context_tokens,
        turn_count=_turn_count(result),
        tool_activity_count=_tool_activity_count(result),
        human_setup_minutes=None,
        human_review_minutes=None,
        corrections_required=None,
        maximum_correction_severity=None,
        human_quality_assessment=None,
        human_safety_assessment=None,
        subscription_capacity_observation=None,
        billing_route=result.billing_assessment.route,
        subscription_name=result.billing_assessment.subscription_name,
        included_capacity_state=effective_capacity,
        subscription_capacity_consumed=result.subscription_capacity_consumed,
        subscription_limit_encountered=limit_encountered,
        run_delayed_by_limit=None,
        paid_capacity_consumed=result.paid_capacity_consumed,
        incremental_ai_charge=result.incremental_ai_charge,
        billing_quarantine_required=result.billing_quarantine_required,
        billing_circuit_breaker_required=result.billing_circuit_breaker_required,
        local_compute_resources=None,
    )


def _metrics_mapping(metrics: TrialMetrics) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for field in fields(TrialMetrics):
        value = getattr(metrics, field.name)
        mapping[field.name] = value.value if hasattr(value, "value") else value
    return mapping


__all__ = [
    "COMPARISON_AUTHORIZATION_SHADOW_COVERAGE",
    "CONTROLLED_COMPARISON_EVIDENCE_MARGIN_SECONDS",
    "CONTROLLED_COMPARISON_TRIAL_TIMEOUT_SECONDS",
    "ComparisonControls",
    "ComparisonPlan",
    "ComparisonProfile",
    "ComparisonReport",
    "ComparisonRow",
    "ComparisonSnapshot",
    "ComparisonTrial",
    "ControlledComparisonPlan",
    "ControlledComparisonReport",
    "ControlledComparisonRow",
    "ControlledComparisonTrial",
    "ControlledTrialOutcome",
    "TrialMetrics",
    "TrialOutcome",
    "comparison_snapshot_from_prepared",
    "run_controlled_comparison",
]
