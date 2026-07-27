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
from uuid import uuid4

from .artifact_filesystem import (
    ARTIFACT_ABSENT as _ARTIFACT_ABSENT,
    ARTIFACT_MATCHES as _ARTIFACT_MATCHES,
    ARTIFACT_UNVERIFIABLE as _ARTIFACT_UNVERIFIABLE,
    StagedArtifact as _ComparisonArtifactStage,
    fsync_artifact_parent as _fsync_artifact_parent,
    published_artifact_state as _published_artifact_state,
    remove_owned_published_artifact as _remove_owned_published_artifact,
    stage_artifact as _stage_artifact,
)
from .billing import BillingPolicy, BillingPostRunDisposition
from .contracts import TaskContract
from .errors import (
    OrdomataError,
    BillingRouteBlocked,
    ConfigurationError,
    ValidationError,
)
from .evaluation import EvaluationResult, evaluate_chief_of_staff
from .models import (
    AgentEvent,
    BillingRoute,
    BillingRouteAssessment,
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
from .orchestrator import (
    PreparedTask,
    _billing_assessments_match,
    _promote_staged_artifact,
    _record_billing_outcome,
    _resolve_billing_disposition,
)
from .paths import resolve_state_root
from .redaction import DEFAULT_REDACTOR, contains_credential_material
from .routing import ExecutionProfile, runner_overrides_for_profile
from .runners.base import AgentRunner
from .shadow_authorization import (
    build_comparison_review_artifact_publication_shadow_event,
    build_comparison_trial_admission_shadow_event,
    build_comparison_trial_dispatch_shadow_event,
)
from .state import SQLiteBillingCircuitGuard, SQLiteStateStore


CONTROLLED_COMPARISON_TRIAL_TIMEOUT_SECONDS = 120
CONTROLLED_COMPARISON_EVIDENCE_MARGIN_SECONDS = 60
COMPARISON_AUTHORIZATION_SHADOW_COVERAGE = (
    "comparison_admission_dispatch_publication_shadow"
)
COMPARISON_ACTION_RECEIPT_COVERAGE = (
    "comparison_private_review_artifact_pre_effect_action_receipt"
)
COMPARISON_TRIAL_BINDING_EVENT_TYPE = "comparison_trial_binding"
COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE = (
    "comparison_review_artifact_intent"
)
COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE = (
    "comparison_review_artifact_observed"
)
COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE = (
    "comparison_review_artifact_action_receipt"
)


class _ComparisonArtifactPublicationUncertain(ConfigurationError):
    """The private effect may exist without a complete durable audit chain."""

    def __init__(
        self,
        message: str,
        *,
        artifact_observed: bool = True,
    ) -> None:
        super().__init__(message)
        self.artifact_observed = artifact_observed


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
            "authorization_action_receipt_coverage": (
                COMPARISON_ACTION_RECEIPT_COVERAGE
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


def _comparison_controls_mapping(controls: ComparisonControls) -> dict[str, Any]:
    return {
        "context_digest": controls.context_digest,
        "output_schema_digest": controls.output_schema_digest,
        "timeout_seconds": controls.timeout_seconds,
        "permission_class": int(controls.permission_class),
        "fresh_session_per_trial": controls.fresh_session_per_trial,
        "outputs_shared_between_trials": controls.outputs_shared_between_trials,
        "external_actions_allowed": controls.external_actions_allowed,
    }


def _comparison_run_id(
    plan: ControlledComparisonPlan,
    trial: ControlledComparisonTrial,
) -> str:
    """Return a collision-resistant identifier without exposing plan labels."""

    run_ref = _canonical_digest(
        {
            "comparison_id": plan.comparison_id,
            "snapshot_digest": plan.snapshot.digest,
            "trial_id": trial.trial_id,
        }
    )
    return "compare-" + run_ref.removeprefix("sha256:")


def _canonical_snapshot_digest(snapshot: ComparisonSnapshot) -> str:
    return "sha256:" + snapshot.digest


def _normalized_digest(value: str, field_name: str) -> str:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return value
    if re.fullmatch(r"[0-9a-f]{64}", value):
        return "sha256:" + value
    raise ValidationError(f"{field_name} must be a canonical SHA-256 digest")


def _safe_optional_timestamp(value: Any) -> float | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        return None
    return float(value)


def _account_identity_ref(value: str | None) -> str | None:
    fingerprint = _safe_fingerprint(value)
    if fingerprint is None:
        return None
    return _canonical_digest({"account_identity_fingerprint": fingerprint})


def _comparison_billing_metadata(
    assessment: BillingRouteAssessment,
) -> dict[str, Any]:
    """Project exact safety semantics without provider text or raw identity."""

    subscription_ref = (
        _canonical_digest({"subscription_name": assessment.subscription_name})
        if isinstance(assessment.subscription_name, str)
        and bool(assessment.subscription_name.strip())
        else None
    )
    attestation = assessment.attestation
    attestation_projection = (
        None
        if attestation is None
        else {
            "runner_id": attestation.runner_id,
            "account_identity_ref": _account_identity_ref(
                attestation.account_identity_fingerprint
            ),
            "billing_route": attestation.billing_route.value,
            "capacity_state": attestation.capacity_state.value,
            "paid_continuation_protection": (
                attestation.paid_continuation_protection.value
            ),
            "observed_at": _safe_optional_timestamp(attestation.observed_at),
            "expires_at": _safe_optional_timestamp(attestation.expires_at),
            "confidence": attestation.confidence.value,
        }
    )
    projection: dict[str, Any] = {
        "schema_version": 1,
        "runner_id": assessment.runner_id,
        "route": assessment.route.value,
        "confidence": assessment.confidence.value,
        "subscription_ref": subscription_ref,
        "capacity_state": assessment.capacity_state.value,
        "paid_continuation_protection": (
            assessment.paid_continuation_protection.value
        ),
        "paid_credit_balance": assessment.paid_credit_balance.value,
        "account_identity_ref": _account_identity_ref(
            assessment.account_identity_fingerprint
        ),
        "capacity_observed_at": _safe_optional_timestamp(
            assessment.capacity_observed_at
        ),
        "capacity_expires_at": _safe_optional_timestamp(
            assessment.capacity_expires_at
        ),
        "attestation": attestation_projection,
    }
    projection["assessment_digest"] = _canonical_digest(projection)
    return projection


def _comparison_trial_binding_event(
    *,
    root: Path,
    prepared: PreparedTask,
    plan: ControlledComparisonPlan,
    controls: ComparisonControls,
    trial: ControlledComparisonTrial,
    profile: ExecutionProfile,
    planned_profile: ComparisonProfile,
    request: RunRequest,
    prompt_digest: str,
    billing_assessment_digest: str,
) -> dict[str, Any]:
    comparison_ref = _canonical_digest({"comparison_id": plan.comparison_id})
    binding: dict[str, Any] = {
        "kind": "controlled_comparison_trial",
        "comparison_ref": comparison_ref,
        "trial_ref": _canonical_digest(
            {
                "comparison_ref": comparison_ref,
                "trial_id": trial.trial_id,
            }
        ),
        "plan_digest": _canonical_digest(_controlled_plan_mapping(plan, controls)),
        "snapshot_digest": _canonical_snapshot_digest(plan.snapshot),
        "controls_digest": _canonical_digest(
            _comparison_controls_mapping(controls)
        ),
        "context_digest": _normalized_digest(
            controls.context_digest, "comparison context digest"
        ),
        "prompt_digest": prompt_digest,
        "task_definition_digest": _normalized_digest(
            prepared.contract.definition_hash, "task definition digest"
        ),
        "output_schema_digest": controls.output_schema_digest,
        "repository_ref": _canonical_digest({"project_root": str(root)}),
        "profile_ref": _canonical_digest({"profile_id": profile.profile_id}),
        "profile_version_ref": _canonical_digest(
            {"profile_version": profile.version}
        ),
        "profile_configuration_digest": (
            planned_profile.configuration_digest
        ),
        "runner_overrides_digest": _canonical_digest(
            dict(request.runner_overrides)
        ),
        "billing_assessment_digest": billing_assessment_digest,
        "runner_id": planned_profile.runner_id,
        "repetition": trial.repetition,
        "order_index": trial.order_index,
        "timeout_seconds": request.timeout_seconds,
        "attempt": request.attempt,
        "permission_class": int(request.permission_class),
    }
    return {
        "schema_version": 2,
        "authorization_shadow_coverage": (
            COMPARISON_AUTHORIZATION_SHADOW_COVERAGE
        ),
        "authorization_action_receipt_coverage": (
            COMPARISON_ACTION_RECEIPT_COVERAGE
        ),
        "binding": binding,
        "binding_digest": _canonical_digest(binding),
    }


def _safe_result_status(value: Any) -> str:
    return value.value if isinstance(value, RunStatus) else "invalid"


def _safe_optional_boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _comparison_execution_accounting(
    result: RunnerExecutionResult | None,
    *,
    identity_matches: bool | None,
    billing_matches: bool | None,
    runner_event_count: int,
    billing_disposition: BillingPostRunDisposition | None = None,
    failure_code: str | None = None,
    billing_unknown: bool = False,
) -> dict[str, Any]:
    if result is None:
        return {
            "schema_version": 2,
            "result_observed": False,
            "identity_matches": identity_matches,
            "billing_matches": billing_matches,
            "runner_event_count": runner_event_count,
            "result_status": "unknown",
            "harness_process_started": None,
            "live_model_execution_occurred": None,
            "subscription_capacity_consumed": None,
            "paid_capacity_consumed": PaidCapacityConsumed.UNKNOWN.value,
            "incremental_ai_charge": IncrementalAICharge.UNKNOWN.value,
            "capacity_state": CapacityState.UNKNOWN.value,
            "billing_disposition_reason_codes": [],
            "billing_disposition_digest": None,
            "usage_observation": UsageObservation.UNAVAILABLE.value,
            "billing_quarantine_required": billing_unknown,
            "billing_circuit_breaker_required": billing_unknown,
            "failure_code": failure_code,
            "wall_seconds": None,
        }
    wall_seconds = _safe_optional_timestamp(result.wall_seconds)
    if billing_unknown:
        paid_capacity_consumed = PaidCapacityConsumed.UNKNOWN.value
        incremental_ai_charge = IncrementalAICharge.UNKNOWN.value
        capacity_state = CapacityState.UNKNOWN.value
        billing_disposition_reason_codes: list[str] = []
        billing_disposition_digest = None
        quarantine_required = True
        circuit_breaker_required = True
    elif billing_disposition is not None:
        paid_capacity_consumed = billing_disposition.paid_capacity_consumed.value
        incremental_ai_charge = billing_disposition.incremental_ai_charge.value
        capacity_state = billing_disposition.capacity_state.value
        billing_disposition_reason_codes = list(billing_disposition.reasons)
        billing_disposition_digest = _comparison_publication_billing_digest(
            identity_matches=identity_matches,
            billing_matches=billing_matches,
            billing_disposition=billing_disposition,
        )
        quarantine_required = billing_disposition.quarantine_required
        circuit_breaker_required = billing_disposition.circuit_breaker_required
    else:
        paid_capacity_consumed = (
            result.paid_capacity_consumed.value
            if isinstance(result.paid_capacity_consumed, PaidCapacityConsumed)
            else PaidCapacityConsumed.UNKNOWN.value
        )
        incremental_ai_charge = (
            result.incremental_ai_charge.value
            if isinstance(result.incremental_ai_charge, IncrementalAICharge)
            else IncrementalAICharge.UNKNOWN.value
        )
        capacity_state = CapacityState.UNKNOWN.value
        billing_disposition_reason_codes = []
        billing_disposition_digest = None
        quarantine_required = _safe_optional_boolean(
            result.billing_quarantine_required
        )
        circuit_breaker_required = _safe_optional_boolean(
            result.billing_circuit_breaker_required
        )
    return {
        "schema_version": 2,
        "result_observed": True,
        "identity_matches": identity_matches,
        "billing_matches": billing_matches,
        "runner_event_count": runner_event_count,
        "result_status": _safe_result_status(result.status),
        "harness_process_started": _safe_optional_boolean(
            result.harness_process_started
        ),
        "live_model_execution_occurred": _safe_optional_boolean(
            result.live_model_execution_occurred
        ),
        "subscription_capacity_consumed": _safe_optional_boolean(
            result.subscription_capacity_consumed
            if (
                identity_matches is True
                and billing_matches is True
                and (
                    billing_disposition is None
                    or (
                        not billing_disposition.quarantine_required
                        and not billing_disposition.circuit_breaker_required
                    )
                )
            )
            else None
        ),
        "paid_capacity_consumed": paid_capacity_consumed,
        "incremental_ai_charge": incremental_ai_charge,
        "capacity_state": capacity_state,
        "billing_disposition_reason_codes": (
            billing_disposition_reason_codes
        ),
        "billing_disposition_digest": billing_disposition_digest,
        "usage_observation": (
            result.usage_observation.value
            if isinstance(result.usage_observation, UsageObservation)
            else UsageObservation.UNAVAILABLE.value
        ),
        "billing_quarantine_required": quarantine_required,
        "billing_circuit_breaker_required": circuit_breaker_required,
        "failure_code": failure_code,
        "wall_seconds": wall_seconds,
    }


def _best_effort_comparison_shadow(
    state: SQLiteStateStore,
    run_id: str,
    builder: Callable[[], dict[str, Any]],
) -> bool:
    try:
        state.append_event(
            run_id,
            "authorization_shadow_decision",
            builder(),
        )
    except Exception:
        return False
    return True


def _shadow_link_digest(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
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
    return _canonical_digest({"action": action, "resource": resource})


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
                "value_digest": _canonical_digest({"value": value}),
            }
        )
    return sorted(
        projected,
        key=lambda item: (item["kind"], item["value_digest"]),
    )


def _comparison_review_artifact_pre_effect_receipt(
    *,
    comparison_binding_digest: str,
    publication_shadow: Mapping[str, Any],
    publication_shadow_persisted: bool,
    artifact_kind: str,
    destination_digest: str,
    artifact_digest: str,
    artifact_size_bytes: int,
    output_withheld: bool,
    billing_disposition_digest: str,
    started_at: float,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 2,
        "mode": "shadow",
        "receipt_kind": "pre_effect",
        "authorization_enforced": False,
        "authority_basis": "legacy_class_1_local_draft_gate",
        "comparison_binding_digest": comparison_binding_digest,
        "publication_shadow_persisted": publication_shadow_persisted,
        "publication_request_digest": _shadow_link_digest(
            publication_shadow, "request_digest"
        ),
        "publication_decision_digest": _shadow_link_digest(
            publication_shadow, "decision_digest"
        ),
        "action_digest": _shadow_action_digest(publication_shadow),
        "requested_permission_class": int(PermissionClass.LOCAL_DRAFT),
        "artifact_kind": artifact_kind,
        "destination_digest": destination_digest,
        "artifact_digest": artifact_digest,
        "artifact_size_bytes": artifact_size_bytes,
        "output_withheld": output_withheld,
        "billing_disposition_digest": billing_disposition_digest,
        "started_at": started_at,
    }
    payload["receipt_digest"] = _canonical_digest(payload)
    return payload


def _comparison_review_artifact_action_receipt(
    *,
    comparison_binding_digest: str,
    pre_effect_receipt: Mapping[str, Any],
    publication_shadow: Mapping[str, Any],
    publication_shadow_persisted: bool,
    artifact_kind: str,
    destination_digest: str,
    intended_artifact_digest: str,
    intended_artifact_size_bytes: int,
    output_withheld: bool,
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
        raise ValidationError("comparison pre-effect receipt digest is missing")
    payload: dict[str, Any] = {
        "schema_version": 2,
        "mode": "shadow",
        "receipt_kind": "action",
        "authorization_enforced": False,
        "authority_basis": "legacy_class_1_local_draft_gate",
        "receipt_id": _canonical_digest(
            {
                "comparison_binding_digest": comparison_binding_digest,
                "destination_digest": destination_digest,
                "pre_effect_receipt_digest": pre_effect_receipt_digest,
            }
        ),
        "comparison_binding_digest": comparison_binding_digest,
        "pre_effect_receipt_digest": pre_effect_receipt_digest,
        "publication_shadow_persisted": publication_shadow_persisted,
        "publication_request_digest": _shadow_link_digest(
            publication_shadow, "request_digest"
        ),
        "publication_decision_digest": _shadow_link_digest(
            publication_shadow, "decision_digest"
        ),
        "action_digest": _shadow_action_digest(publication_shadow),
        "executor_id": "ordomata:local-controller",
        "started_at": started_at,
        "completed_at": completed_at,
        "outcome": outcome,
        "obligation_results": _shadow_obligation_results(publication_shadow),
        "artifact_kind": artifact_kind,
        "destination_digest": destination_digest,
        "intended_artifact_digest": intended_artifact_digest,
        "intended_artifact_size_bytes": intended_artifact_size_bytes,
        "output_withheld": output_withheld,
        "billing_disposition_digest": billing_disposition_digest,
        "result_digest": result_digest,
        "observed_artifact_size_bytes": observed_artifact_size_bytes,
        "failure_code": failure_code,
    }
    payload["receipt_digest"] = _canonical_digest(payload)
    return payload


def _terminalize_comparison_run(
    state: SQLiteStateStore,
    run_id: str,
    *,
    status: RunStatus,
    phase: str,
    details: Mapping[str, Any] | None = None,
) -> None:
    """Durably terminalize a comparison run or fail instead of misreporting it."""

    if state.current_status(run_id) not in {
        RunStatus.CREATED,
        RunStatus.RUNNING,
    }:
        raise ValidationError("comparison run cannot be terminalized from its state")
    payload = {"phase": phase, **dict(details or {})}
    _append_required_comparison_event(
        state,
        run_id,
        "status",
        payload,
        event_id=_comparison_controller_event_id(
            run_id,
            "status",
            payload,
            status=status,
        ),
        status=status,
    )
    if state.current_status(run_id) is not status:
        raise ConfigurationError("comparison terminal status was not persisted")


def _comparison_controller_event_id(
    run_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    *,
    status: RunStatus | None = None,
) -> str:
    material: dict[str, Any] = {
        "event_type": event_type,
        "payload": dict(payload),
        "run_id": run_id,
    }
    if status is not None:
        material["status"] = status.value
    return _canonical_digest(material)


def _append_required_comparison_event(
    state: SQLiteStateStore,
    run_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    *,
    event_id: str,
    status: RunStatus | None = None,
) -> None:
    """Append one content-addressed event with exact ambiguous-write readback."""

    normalized_payload = dict(payload)
    try:
        state.append_event(
            run_id,
            event_type,
            normalized_payload,
            status=status,
            event_id=event_id,
        )
    except BaseException as append_error:
        try:
            matches = tuple(
                event
                for event in state.list_events(run_id)
                if event.event_id == event_id
            )
        except BaseException as readback_error:
            raise ConfigurationError(
                "required comparison evidence persistence is uncertain"
            ) from readback_error
        persisted = bool(
            len(matches) == 1
            and matches[0].event_type == event_type
            and matches[0].status is status
            and matches[0].payload == normalized_payload
        )
        if persisted and isinstance(append_error, Exception):
            return
        if matches:
            raise ConfigurationError(
                "required comparison evidence persistence is uncertain"
            ) from append_error
        raise


def _record_unknown_comparison_billing(
    state: SQLiteStateStore,
    *,
    assessment: BillingRouteAssessment,
    profile_id: str,
    run_id: str,
) -> None:
    if assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
        return
    trusted_fingerprint = _safe_fingerprint(
        assessment.account_identity_fingerprint
    )
    state.append_billing_capacity_event(
        runner_id=assessment.runner_id,
        capacity_state=CapacityState.UNKNOWN,
        reason_code="post_run_billing_unknown",
        account_identity_fingerprint=trusted_fingerprint,
        profile_id=profile_id,
        run_id=run_id,
    )
    scopes = (
        (trusted_fingerprint, profile_id),
        (trusted_fingerprint, None),
        (None, profile_id),
        (None, None),
    )
    for scope_fingerprint, scope_profile_id in tuple(dict.fromkeys(scopes)):
        state.append_billing_circuit_event(
            runner_id=assessment.runner_id,
            state=CircuitBreakerState.OPEN,
            reason_code="post_run_billing_unknown",
            account_identity_fingerprint=scope_fingerprint,
            profile_id=scope_profile_id,
            run_id=run_id,
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
    planned_profile_by_id = {
        profile.profile_id: profile for profile in plan.profiles
    }
    prompt_digest = "sha256:" + sha256(
        prepared.prompt.encode("utf-8")
    ).hexdigest()
    with SQLiteStateStore(state_path) as state:
        for trial, profile, runner, assessment in prepared_trials:
            if stop_remaining:
                break
            if comparison_snapshot_from_prepared(prepared).digest != plan.snapshot.digest:
                raise ValidationError("immutable comparison snapshot changed between trials")
            run_id = _comparison_run_id(plan, trial)
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
            billing_metadata = _comparison_billing_metadata(assessment)
            binding_event = _comparison_trial_binding_event(
                root=root,
                prepared=prepared,
                plan=plan,
                controls=controls,
                trial=trial,
                profile=profile,
                planned_profile=planned_profile_by_id[trial.profile_id],
                request=request,
                prompt_digest=prompt_digest,
                billing_assessment_digest=billing_metadata[
                    "assessment_digest"
                ],
            )
            binding_digest = binding_event["binding_digest"]
            state.create_run_from_request(
                request,
                runner_id=runner.runner_id,
                context_digest=prepared.context_pack.snapshot_hash,
            )
            try:
                _append_required_comparison_event(
                    state,
                    run_id,
                    COMPARISON_TRIAL_BINDING_EVENT_TYPE,
                    binding_event,
                    event_id=binding_digest,
                )
                _best_effort_comparison_shadow(
                    state,
                    run_id,
                    lambda: build_comparison_trial_admission_shadow_event(
                        contract=prepared.contract,
                        run_id=run_id,
                        runner_id=runner.runner_id,
                        profile_id=profile.profile_id,
                        project_root=root,
                        comparison_binding_digest=binding_digest,
                        snapshot_digest=_canonical_snapshot_digest(plan.snapshot),
                        context_digest=_normalized_digest(
                            prepared.context_pack.snapshot_hash,
                            "comparison context digest",
                        ),
                        billing_assessment=assessment,
                        evaluated_at=time.time(),
                        legacy_executable=True,
                    ),
                )
                _append_required_comparison_event(
                    state,
                    run_id,
                    "billing_assessment",
                    billing_metadata,
                    event_id=_comparison_controller_event_id(
                        run_id,
                        "billing_assessment",
                        billing_metadata,
                    ),
                )
                running_payload = {"phase": "comparison_trial_execution"}
                _append_required_comparison_event(
                    state,
                    run_id,
                    "status",
                    running_payload,
                    event_id=_comparison_controller_event_id(
                        run_id,
                        "status",
                        running_payload,
                        status=RunStatus.RUNNING,
                    ),
                    status=RunStatus.RUNNING,
                )
            except BaseException:
                _terminalize_comparison_run(
                    state,
                    run_id,
                    status=RunStatus.BLOCKED,
                    phase="comparison_audit_setup_failure",
                )
                raise
            events_seen = 0

            async def event_sink(_event: AgentEvent) -> None:
                nonlocal events_seen
                events_seen += 1
                # Model-controlled event type and payload are never persisted.
                state.append_event(
                    run_id,
                    "runner_event_observed",
                    {"ordinal": events_seen},
                )

            started_at = time.monotonic()
            result: RunnerExecutionResult | None = None
            identity_matches: bool | None = None
            billing_matches: bool | None = None
            accounting_recorded = False
            billing_disposition: BillingPostRunDisposition | None = None
            subscription_billing_recorded = (
                assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED
            )
            core_audit_persistence_error = False
            review_artifact_path: Path | None = None
            artifact_digest: str | None = None
            _best_effort_comparison_shadow(
                state,
                run_id,
                lambda: build_comparison_trial_dispatch_shadow_event(
                    contract=prepared.contract,
                    run_id=run_id,
                    runner_id=runner.runner_id,
                    profile_id=profile.profile_id,
                    project_root=root,
                    comparison_binding_digest=binding_digest,
                    snapshot_digest=_canonical_snapshot_digest(plan.snapshot),
                    prompt_digest=prompt_digest,
                    billing_assessment=assessment,
                    evaluated_at=time.time(),
                    legacy_executable=True,
                ),
            )
            try:
                observed_result = await runner.execute(request, event_sink)
                if not isinstance(observed_result, RunnerExecutionResult):
                    raise ValidationError("runner returned an invalid result type")
                result = observed_result
                identity_matches = (
                    result.run_id == run_id and result.runner_id == runner.runner_id
                )
                billing_matches = _billing_assessments_match(
                    assessment, result.billing_assessment
                )
                billing_disposition = _resolve_billing_disposition(
                    result=result,
                    preflight_assessment=assessment,
                    billing_matches=(
                        identity_matches is True and billing_matches is True
                    ),
                )
                if assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
                    _record_billing_outcome(
                        state,
                        run_id=run_id,
                        profile_id=profile.profile_id,
                        preflight_assessment=assessment,
                        postflight_assessment=(
                            result.postflight_billing_assessment
                        ),
                        disposition=billing_disposition,
                        billing_matches=(
                            identity_matches is True and billing_matches is True
                        ),
                    )
                    subscription_billing_recorded = True
                accounting_payload = _comparison_execution_accounting(
                    result,
                    identity_matches=identity_matches,
                    billing_matches=billing_matches,
                    runner_event_count=events_seen,
                    billing_disposition=billing_disposition,
                )
                try:
                    _append_required_comparison_event(
                        state,
                        run_id,
                        "execution_accounting",
                        accounting_payload,
                        event_id=_comparison_controller_event_id(
                            run_id,
                            "execution_accounting",
                            accounting_payload,
                        ),
                    )
                except BaseException:
                    core_audit_persistence_error = True
                    raise
                accounting_recorded = True
                stop_remaining = stop_remaining or (
                    identity_matches is not True
                    or billing_matches is not True
                    or (
                        assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
                        and (
                            billing_disposition.quarantine_required
                            or billing_disposition.circuit_breaker_required
                            or billing_disposition.capacity_state
                            in {
                                CapacityState.LIMIT_REACHED,
                                CapacityState.BLOCKED_UNTIL_RESET,
                                CapacityState.COOLDOWN,
                                CapacityState.UNKNOWN,
                            }
                        )
                    )
                )
                workspace_entries = tuple(workspace.rglob("*"))
                billing_or_identity_untrusted = (
                    identity_matches is not True
                    or billing_matches is not True
                    or billing_disposition.quarantine_required
                    or billing_disposition.circuit_breaker_required
                )
                credential_detected = (
                    False
                    if billing_or_identity_untrusted
                    else (
                        result.credential_material_detected
                        or contains_credential_material(result.output)
                    )
                )
                redacted_output = (
                    None
                    if billing_or_identity_untrusted
                    else DEFAULT_REDACTOR.redact(result.output)
                )
                output_withheld = (
                    credential_detected or billing_or_identity_untrusted
                )
                withheld_reason = (
                    "credential_material_detected"
                    if credential_detected
                    else (
                        "billing_or_identity_mismatch"
                        if billing_or_identity_untrusted
                        else None
                    )
                )
                review_artifact_path = run_directory / "review-output.json"
                review_artifact_payload = _review_artifact_payload(
                    trial=trial,
                    output=(None if output_withheld else redacted_output),
                    withheld_reason=withheld_reason,
                )
                review_artifact_bytes = _canonical_json_bytes(
                    review_artifact_payload
                )
                destination_digest = _canonical_digest(
                    {
                        "artifact_kind": "private_review_output",
                        "run_id": run_id,
                    }
                )
                billing_disposition_digest = (
                    _comparison_publication_billing_digest(
                        identity_matches=identity_matches,
                        billing_matches=billing_matches,
                        billing_disposition=billing_disposition,
                    )
                )
                artifact_digest = _publish_comparison_review_artifact(
                    state=state,
                    path=review_artifact_path,
                    content=review_artifact_bytes,
                    contract=prepared.contract,
                    run_id=run_id,
                    runner_id=runner.runner_id,
                    profile_id=profile.profile_id,
                    project_root=root,
                    comparison_binding_digest=binding_digest,
                    artifact_kind="private_review_output",
                    destination_digest=destination_digest,
                    output_withheld=output_withheld,
                    billing_disposition_digest=billing_disposition_digest,
                )
                evaluation = evaluate_chief_of_staff(
                    None if output_withheld else redacted_output,
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
                    or billing_disposition.quarantine_required
                    or billing_disposition.circuit_breaker_required
                    or not isinstance(result.status, RunStatus)
                    or result.status
                    not in {
                        RunStatus.SUCCEEDED,
                        RunStatus.FAILED,
                        RunStatus.BLOCKED,
                        RunStatus.QUARANTINED,
                        RunStatus.CANCELLED,
                    }
                ):
                    final_status = RunStatus.QUARANTINED
                failure_type, error_codes = _result_failure_summary(
                    result=result,
                    evaluation=evaluation,
                    identity_matches=identity_matches,
                    billing_matches=billing_matches,
                    billing_disposition=billing_disposition,
                    credential_detected=credential_detected,
                    workspace_entries=workspace_entries,
                )
                if billing_or_identity_untrusted:
                    session_id, session_observed = (
                        f"controller-{run_id}",
                        False,
                    )
                    outcome_metrics = _failed_trial_metrics(
                        prepared=prepared,
                        assessment=assessment,
                        wall_time_seconds=(
                            _safe_optional_timestamp(result.wall_seconds) or 0.0
                        ),
                    )
                else:
                    session_id, session_observed = _safe_session_id(result, run_id)
                    outcome_metrics = _trial_metrics(
                        result=result,
                        evaluation=evaluation,
                        prepared=prepared,
                        billing_matches=billing_matches and identity_matches,
                        preflight_assessment=assessment,
                        billing_disposition=billing_disposition,
                        credential_material_detected=credential_detected,
                        workspace_entries=workspace_entries,
                        events_seen=events_seen,
                    )
                outcome = ControlledTrialOutcome(
                    trial_id=trial.trial_id,
                    profile_id=trial.profile_id,
                    runner_id=trial.runner_id,
                    run_id=run_id,
                    snapshot_digest=plan.snapshot.digest,
                    session_id=session_id,
                    session_id_observed=session_observed,
                    status=final_status,
                    metrics=outcome_metrics,
                    review_artifact_path=str(review_artifact_path),
                    review_artifact_sha256=artifact_digest,
                    failure_type=failure_type,
                    error_codes=error_codes,
                )
                _terminalize_comparison_run(
                    state,
                    run_id,
                    status=final_status,
                    phase="comparison_trial_complete",
                    details={
                        "artifact_observed": True,
                        "failure_type": failure_type,
                        "error_codes": list(error_codes),
                    },
                )
                outcomes.append(outcome)
                del result, evaluation, redacted_output
            except Exception as exc:
                failure_type = _exception_failure_type(exc)
                publication_state_unknown = isinstance(
                    exc, _ComparisonArtifactPublicationUncertain
                )
                publication_artifact_observed = (
                    exc.artifact_observed
                    if publication_state_unknown
                    else artifact_digest is not None
                )
                subscription_billing_unknown = (
                    assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
                    and not subscription_billing_recorded
                )
                if result is None and assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
                    failure_type = "billing_execution_unknown"
                accounting_recovery_error: BaseException | None = None
                if not accounting_recorded:
                    try:
                        accounting_payload = _comparison_execution_accounting(
                            result,
                            identity_matches=identity_matches,
                            billing_matches=billing_matches,
                            runner_event_count=events_seen,
                            billing_disposition=billing_disposition,
                            failure_code=failure_type,
                            billing_unknown=subscription_billing_unknown,
                        )
                        _append_required_comparison_event(
                            state,
                            run_id,
                            "execution_accounting",
                            accounting_payload,
                            event_id=_comparison_controller_event_id(
                                run_id,
                                "execution_accounting",
                                accounting_payload,
                            ),
                        )
                        accounting_recorded = True
                    except BaseException as accounting_exc:
                        accounting_recovery_error = accounting_exc
                billing_recovery_error: BaseException | None = None
                if subscription_billing_unknown:
                    try:
                        _record_unknown_comparison_billing(
                            state,
                            assessment=assessment,
                            profile_id=profile.profile_id,
                            run_id=run_id,
                        )
                        subscription_billing_recorded = True
                    except BaseException as recovery_exc:
                        billing_recovery_error = recovery_exc
                disposition_quarantines = (
                    billing_disposition is not None
                    and (
                        billing_disposition.quarantine_required
                        or billing_disposition.circuit_breaker_required
                    )
                )
                failure_status = (
                    RunStatus.QUARANTINED
                    if (
                        subscription_billing_unknown
                        or publication_state_unknown
                        or identity_matches is False
                        or billing_matches is False
                        or disposition_quarantines
                    )
                    else (
                        RunStatus.BLOCKED
                        if isinstance(exc, OrdomataError)
                        else RunStatus.FAILED
                    )
                )
                _terminalize_comparison_run(
                    state,
                    run_id,
                    status=failure_status,
                    phase="comparison_trial_failure",
                    details={
                        "artifact_observed": publication_artifact_observed,
                        "failure_type": failure_type,
                        "error_codes": [failure_type],
                    },
                )
                if billing_recovery_error is not None:
                    raise ConfigurationError(
                        "comparison billing recovery could not be persisted"
                    ) from billing_recovery_error
                if core_audit_persistence_error or accounting_recovery_error is not None:
                    raise ConfigurationError(
                        "comparison execution accounting could not be persisted"
                    ) from (accounting_recovery_error or exc)
                outcomes.append(
                    ControlledTrialOutcome(
                        trial_id=trial.trial_id,
                        profile_id=trial.profile_id,
                        runner_id=trial.runner_id,
                        run_id=run_id,
                        snapshot_digest=plan.snapshot.digest,
                        session_id=f"controller-{run_id}",
                        session_id_observed=False,
                        status=failure_status,
                        metrics=_failed_trial_metrics(
                            prepared=prepared,
                            assessment=assessment,
                            wall_time_seconds=max(
                                0.0, time.monotonic() - started_at
                            ),
                        ),
                        review_artifact_path=(
                            None
                            if artifact_digest is None
                            else str(review_artifact_path)
                        ),
                        review_artifact_sha256=artifact_digest,
                        failure_type=failure_type,
                        error_codes=(failure_type,),
                    )
                )
                # Exception text can contain provider or credential material;
                # retain only the fixed code and fail closed on later trials.
                stop_remaining = True
            except BaseException as _interrupted:
                subscription_interrupted = (
                    assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
                )
                publication_interrupted_unknown = isinstance(
                    _interrupted.__cause__,
                    _ComparisonArtifactPublicationUncertain,
                )
                interrupted_artifact_observed = (
                    _interrupted.__cause__.artifact_observed
                    if publication_interrupted_unknown
                    else artifact_digest is not None
                )
                accounting_cleanup_error: BaseException | None = None
                if not accounting_recorded:
                    try:
                        accounting_payload = _comparison_execution_accounting(
                            result,
                            identity_matches=identity_matches,
                            billing_matches=billing_matches,
                            runner_event_count=events_seen,
                            billing_disposition=billing_disposition,
                            failure_code="billing_execution_unknown"
                            if subscription_interrupted
                            else "runner_execution_interrupted",
                            billing_unknown=subscription_interrupted,
                        )
                        _append_required_comparison_event(
                            state,
                            run_id,
                            "execution_accounting",
                            accounting_payload,
                            event_id=_comparison_controller_event_id(
                                run_id,
                                "execution_accounting",
                                accounting_payload,
                            ),
                        )
                    except BaseException as accounting_exc:
                        accounting_cleanup_error = accounting_exc
                billing_cleanup_error: BaseException | None = None
                if subscription_interrupted:
                    try:
                        _record_unknown_comparison_billing(
                            state,
                            assessment=assessment,
                            profile_id=profile.profile_id,
                            run_id=run_id,
                        )
                    except BaseException:
                        try:
                            # Append-only duplicates are safe; one retry closes
                            # a transient persistence gap before interruption
                            # is allowed to leave the controller boundary.
                            _record_unknown_comparison_billing(
                                state,
                                assessment=assessment,
                                profile_id=profile.profile_id,
                                run_id=run_id,
                            )
                        except BaseException as billing_exc:
                            billing_cleanup_error = billing_exc
                terminal_cleanup_error: BaseException | None = None
                try:
                    _terminalize_comparison_run(
                        state,
                        run_id,
                        status=(
                            RunStatus.QUARANTINED
                            if (
                                subscription_interrupted
                                or publication_interrupted_unknown
                            )
                            else RunStatus.CANCELLED
                        ),
                        phase="comparison_trial_interrupted",
                        details={
                            "artifact_observed": interrupted_artifact_observed,
                        },
                    )
                except BaseException as terminal_exc:
                    terminal_cleanup_error = terminal_exc
                cleanup_error = (
                    billing_cleanup_error
                    or accounting_cleanup_error
                    or terminal_cleanup_error
                )
                if cleanup_error is not None:
                    recovery_failure = ConfigurationError(
                        "comparison interruption recovery could not be persisted"
                    )
                    _interrupted.add_note(
                        "Ordomata interruption recovery was not fully persisted."
                    )
                    raise _interrupted from recovery_failure
                raise

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


def _comparison_publication_billing_digest(
    *,
    identity_matches: bool | None,
    billing_matches: bool | None,
    billing_disposition: BillingPostRunDisposition,
) -> str:
    return _canonical_digest(
        {
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
    )


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
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
    return document.encode("utf-8")


def _append_comparison_review_artifact_action_receipt(
    state: SQLiteStateStore,
    run_id: str,
    payload: Mapping[str, Any],
) -> None:
    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str):
        raise ValidationError("comparison action receipt identifier is missing")
    state.append_event(
        run_id,
        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
        payload,
        event_id=receipt_id,
    )


def _comparison_review_artifact_action_receipt_persisted(
    state: SQLiteStateStore,
    run_id: str,
    payload: Mapping[str, Any],
) -> bool | None:
    """Return true/false for an exact readback, or null when unprovable."""

    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str):
        return None
    try:
        matches = tuple(
            event
            for event in state.list_events(run_id)
            if event.event_id == receipt_id
        )
        if not matches:
            return False
        if (
            len(matches) == 1
            and matches[0].event_type
            == COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
            and matches[0].payload == dict(payload)
        ):
            return True
        return None
    except Exception:
        return None


def _safe_comparison_published_state(
    path: Path,
    content: bytes,
    *,
    expected_identity: tuple[int, int] | None,
    expected_parent_identity: tuple[int, int] | None,
    stage: _ComparisonArtifactStage,
) -> str:
    """Classify a comparison effect conservatively under interruption."""

    try:
        return _published_artifact_state(
            path,
            content,
            expected_identity=expected_identity,
            expected_parent_identity=expected_parent_identity,
            stage=stage,
        )
    except BaseException:
        return _ARTIFACT_UNVERIFIABLE


def _safe_remove_comparison_artifact(
    path: Path,
    *,
    staged_identity: tuple[int, int] | None,
    expected_parent_identity: tuple[int, int] | None,
    stage: _ComparisonArtifactStage,
) -> bool:
    """Return false whenever owned cleanup cannot be proven complete."""

    try:
        return _remove_owned_published_artifact(
            path,
            staged_identity=staged_identity,
            expected_parent_identity=expected_parent_identity,
            stage=stage,
        )
    except BaseException:
        return False


def _publish_comparison_review_artifact(
    *,
    state: SQLiteStateStore,
    path: Path,
    content: bytes,
    contract: TaskContract,
    run_id: str,
    runner_id: str,
    profile_id: str,
    project_root: Path,
    comparison_binding_digest: str,
    artifact_kind: str,
    destination_digest: str,
    output_withheld: bool,
    billing_disposition_digest: str,
) -> str:
    """Publish one private review artifact with shadow-mode receipts.

    The legacy Class 1 local-draft gate remains authoritative. The shadow and
    receipts do not authorize or widen the write; required audit persistence
    and effect reconciliation can still fail closed.
    """

    artifact_digest = "sha256:" + sha256(content).hexdigest()
    artifact_size_bytes = len(content)
    publication_shadow = (
        build_comparison_review_artifact_publication_shadow_event(
            contract=contract,
            run_id=run_id,
            runner_id=runner_id,
            profile_id=profile_id,
            project_root=project_root,
            comparison_binding_digest=comparison_binding_digest,
            destination_digest=destination_digest,
            artifact_digest=artifact_digest,
            artifact_size_bytes=artifact_size_bytes,
            artifact_kind=artifact_kind,
            output_withheld=output_withheld,
            billing_disposition_digest=billing_disposition_digest,
            evaluated_at=time.time(),
            legacy_executable=True,
        )
    )
    shadow_persisted = _best_effort_comparison_shadow(
        state,
        run_id,
        lambda: publication_shadow,
    )
    started_at = time.time()
    pre_effect_receipt = _comparison_review_artifact_pre_effect_receipt(
        comparison_binding_digest=comparison_binding_digest,
        publication_shadow=publication_shadow,
        publication_shadow_persisted=shadow_persisted,
        artifact_kind=artifact_kind,
        destination_digest=destination_digest,
        artifact_digest=artifact_digest,
        artifact_size_bytes=artifact_size_bytes,
        output_withheld=output_withheld,
        billing_disposition_digest=billing_disposition_digest,
        started_at=started_at,
    )
    state.append_event(
        run_id,
        COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE,
        pre_effect_receipt,
    )

    stage = _ComparisonArtifactStage(
        path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    )
    staged_path: Path | None = stage.path
    staged_identity: tuple[int, int] | None = None
    try:
        _stage_artifact(path, content, stage=stage)
        staged_identity = stage.identity
        if staged_identity is None:
            raise ConfigurationError(
                "comparison review artifact staging verification failed"
            )
        _promote_staged_artifact(stage, path)
        if not _fsync_artifact_parent(path):
            raise ConfigurationError(
                "comparison review artifact namespace sync failed"
            )
        if _safe_comparison_published_state(
            path,
            content,
            expected_identity=staged_identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        ) != _ARTIFACT_MATCHES:
            raise ConfigurationError(
                "comparison review artifact verification failed"
            )
        # Publication already removes and verifies the staging name while the
        # parent and inode descriptors are leased.  Keep those leases through
        # action-receipt reconciliation; no second pathname cleanup is needed.
    except BaseException as publication_error:
        final_effect_absent = _safe_remove_comparison_artifact(
            path,
            staged_identity=staged_identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        staged_effect_absent = (
            staged_path is None
            or _safe_remove_comparison_artifact(
                staged_path,
                staged_identity=staged_identity,
                expected_parent_identity=stage.parent_identity,
                stage=stage,
            )
        )
        effect_unknown = not (
            final_effect_absent and staged_effect_absent
        )
        stage.close()
        if effect_unknown:
            outcome = "unknown"
            failure_code = "artifact_publication_outcome_unknown"
        elif isinstance(publication_error, Exception):
            outcome = "failed"
            failure_code = "artifact_persistence_failed"
        else:
            outcome = "cancelled"
            failure_code = "artifact_persistence_interrupted"
        try:
            receipt = _comparison_review_artifact_action_receipt(
                comparison_binding_digest=comparison_binding_digest,
                pre_effect_receipt=pre_effect_receipt,
                publication_shadow=publication_shadow,
                publication_shadow_persisted=shadow_persisted,
                artifact_kind=artifact_kind,
                destination_digest=destination_digest,
                intended_artifact_digest=artifact_digest,
                intended_artifact_size_bytes=artifact_size_bytes,
                output_withheld=output_withheld,
                billing_disposition_digest=billing_disposition_digest,
                started_at=started_at,
                completed_at=time.time(),
                outcome=outcome,
                result_digest=None,
                observed_artifact_size_bytes=None,
                failure_code=failure_code,
            )
        except BaseException as receipt_build_error:
            if effect_unknown:
                uncertain = _ComparisonArtifactPublicationUncertain(
                    "comparison artifact failure receipt is unavailable",
                    artifact_observed=True,
                )
                if isinstance(receipt_build_error, Exception):
                    raise uncertain from receipt_build_error
                receipt_build_error.add_note(
                    "Ordomata could not build the interruption receipt."
                )
                raise receipt_build_error from uncertain
            raise
        try:
            _append_comparison_review_artifact_action_receipt(
                state, run_id, receipt
            )
        except BaseException as receipt_error:
            try:
                receipt_persistence = (
                    _comparison_review_artifact_action_receipt_persisted(
                        state,
                        run_id,
                        receipt,
                    )
                )
            except BaseException as readback_error:
                stage.close()
                readback_error.add_note(
                    "Ordomata artifact receipt readback was interrupted."
                )
                raise readback_error from (
                    _ComparisonArtifactPublicationUncertain(
                        "comparison artifact receipt readback is uncertain",
                        artifact_observed=effect_unknown,
                    )
                )
            receipt_persisted = receipt_persistence is True
            receipt_persistence_uncertain = receipt_persistence is None
            recovery_error: ConfigurationError
            if effect_unknown or receipt_persistence_uncertain:
                recovery_error = _ComparisonArtifactPublicationUncertain(
                    "comparison artifact publication evidence is uncertain",
                    artifact_observed=effect_unknown,
                )
            else:
                recovery_error = ConfigurationError(
                    "comparison artifact failure receipt could not be persisted"
                )
            if not isinstance(receipt_error, Exception):
                receipt_error.add_note(
                    "Ordomata reconciled the interrupted artifact receipt."
                    if receipt_persisted
                    else "Ordomata artifact receipt persistence is uncertain."
                )
                raise receipt_error from recovery_error
            if not receipt_persisted and isinstance(publication_error, Exception):
                raise recovery_error from receipt_error
            if not receipt_persisted:
                publication_error.add_note(
                    "Ordomata artifact interruption receipt was not persisted."
                )
                raise publication_error from recovery_error
        if effect_unknown:
            uncertain = _ComparisonArtifactPublicationUncertain(
                "comparison artifact publication outcome is uncertain"
            )
            if isinstance(publication_error, Exception):
                raise uncertain from publication_error
            publication_error.add_note(
                "Ordomata could not reconcile the interrupted artifact effect."
            )
            raise publication_error from uncertain
        raise
    try:
        receipt = _comparison_review_artifact_action_receipt(
            comparison_binding_digest=comparison_binding_digest,
            pre_effect_receipt=pre_effect_receipt,
            publication_shadow=publication_shadow,
            publication_shadow_persisted=shadow_persisted,
            artifact_kind=artifact_kind,
            destination_digest=destination_digest,
            intended_artifact_digest=artifact_digest,
            intended_artifact_size_bytes=artifact_size_bytes,
            output_withheld=output_withheld,
            billing_disposition_digest=billing_disposition_digest,
            started_at=started_at,
            completed_at=time.time(),
            outcome="succeeded",
            result_digest=artifact_digest,
            observed_artifact_size_bytes=artifact_size_bytes,
            failure_code=None,
        )
    except BaseException as receipt_build_error:
        final_effect_absent = _safe_remove_comparison_artifact(
            path,
            staged_identity=staged_identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        staged_effect_absent = _safe_remove_comparison_artifact(
            staged_path,
            staged_identity=staged_identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        stage.close()
        if not (final_effect_absent and staged_effect_absent):
            uncertain = _ComparisonArtifactPublicationUncertain(
                "comparison artifact receipt construction is uncertain",
                artifact_observed=True,
            )
            if isinstance(receipt_build_error, Exception):
                raise uncertain from receipt_build_error
            receipt_build_error.add_note(
                "Ordomata could not reconcile the published artifact."
            )
            raise receipt_build_error from uncertain
        raise
    try:
        _append_comparison_review_artifact_action_receipt(state, run_id, receipt)
    except BaseException as receipt_error:
        try:
            receipt_persistence = (
                _comparison_review_artifact_action_receipt_persisted(
                    state,
                    run_id,
                    receipt,
                )
            )
        except BaseException as readback_error:
            stage.close()
            readback_error.add_note(
                "Ordomata artifact action receipt readback was interrupted."
            )
            raise readback_error from _ComparisonArtifactPublicationUncertain(
                "comparison artifact action receipt readback is uncertain",
                artifact_observed=True,
            )
        receipt_persisted = receipt_persistence is True
        if receipt_persisted:
            published_state = _safe_comparison_published_state(
                path,
                content,
                expected_identity=staged_identity,
                expected_parent_identity=stage.parent_identity,
                stage=stage,
            )
            if published_state != _ARTIFACT_MATCHES:
                stage.close()
                uncertain = _ComparisonArtifactPublicationUncertain(
                    "comparison artifact receipt and effect disagree",
                    artifact_observed=(published_state != _ARTIFACT_ABSENT),
                )
                if isinstance(receipt_error, Exception):
                    raise uncertain from receipt_error
                receipt_error.add_note(
                    "Ordomata reconciled a receipt with an uncertain effect."
                )
                raise receipt_error from uncertain
            if isinstance(receipt_error, Exception):
                stage.close()
                return artifact_digest.removeprefix("sha256:")
            stage.close()
            receipt_error.add_note(
                "Ordomata reconciled the interrupted artifact receipt."
            )
            raise receipt_error from _ComparisonArtifactPublicationUncertain(
                "comparison artifact committed before interruption"
            )
        if receipt_persistence is None:
            published_state = _safe_comparison_published_state(
                path,
                content,
                expected_identity=staged_identity,
                expected_parent_identity=stage.parent_identity,
                stage=stage,
            )
            uncertain = _ComparisonArtifactPublicationUncertain(
                "comparison artifact action receipt is uncertain",
                artifact_observed=(published_state != _ARTIFACT_ABSENT),
            )
            if isinstance(receipt_error, Exception):
                stage.close()
                raise uncertain from receipt_error
            stage.close()
            receipt_error.add_note(
                "Ordomata artifact action receipt persistence is uncertain."
            )
            raise receipt_error from uncertain
        removed = _safe_remove_comparison_artifact(
            path,
            staged_identity=staged_identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        stage.close()
        recovery_error = ConfigurationError(
            "comparison artifact action receipt could not be persisted"
        )
        if isinstance(receipt_error, Exception):
            if not removed:
                raise _ComparisonArtifactPublicationUncertain(
                    "comparison artifact action receipt is missing"
                ) from receipt_error
            raise recovery_error from receipt_error
        if not removed:
            recovery_error = _ComparisonArtifactPublicationUncertain(
                "comparison artifact action receipt is missing"
            )
        receipt_error.add_note(
            "Ordomata artifact action receipt was not persisted."
        )
        raise receipt_error from recovery_error
    if _safe_comparison_published_state(
        path,
        content,
        expected_identity=staged_identity,
        expected_parent_identity=stage.parent_identity,
        stage=stage,
    ) != _ARTIFACT_MATCHES:
        stage.close()
        raise _ComparisonArtifactPublicationUncertain(
            "comparison artifact changed after action receipt"
        )
    stage.close()
    return artifact_digest.removeprefix("sha256:")


def _review_artifact_payload(
    *,
    trial: ControlledComparisonTrial,
    output: Any,
    withheld_reason: str | None = None,
) -> dict[str, Any]:
    if withheld_reason is not None:
        return {
            "schema_version": 1,
            "trial_id": trial.trial_id,
            "profile_id": trial.profile_id,
            "runner_id": trial.runner_id,
            "output": None,
            "output_withheld_reason": withheld_reason,
        }
    try:
        json.dumps(output, ensure_ascii=False, allow_nan=False)
        return {
            "schema_version": 1,
            "trial_id": trial.trial_id,
            "profile_id": trial.profile_id,
            "runner_id": trial.runner_id,
            "output": output,
        }
    except (TypeError, ValueError):
        return {
            "schema_version": 1,
            "trial_id": trial.trial_id,
            "profile_id": trial.profile_id,
            "runner_id": trial.runner_id,
            "output": None,
            "output_withheld_reason": "non_json_output",
        }


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
    billing_disposition: BillingPostRunDisposition,
    credential_detected: bool,
    workspace_entries: tuple[Path, ...],
) -> tuple[str | None, tuple[str, ...]]:
    codes: list[str] = []
    terminal_statuses = {
        RunStatus.SUCCEEDED,
        RunStatus.FAILED,
        RunStatus.BLOCKED,
        RunStatus.QUARANTINED,
        RunStatus.CANCELLED,
    }
    if not isinstance(result.status, RunStatus) or result.status not in terminal_statuses:
        codes.append("runner_status_invalid")
    if not identity_matches:
        codes.append("runner_identity_mismatch")
    if not billing_matches:
        codes.append("billing_preflight_mismatch")
    if billing_disposition.quarantine_required:
        codes.append("billing_quarantine_required")
    if billing_disposition.circuit_breaker_required:
        codes.append("billing_circuit_breaker_required")
    codes.extend(billing_disposition.reasons)
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

    if (
        billing_disposition.quarantine_required
        or billing_disposition.circuit_breaker_required
    ):
        failure_type = "billing_quarantined"
    elif not identity_matches:
        failure_type = "runner_identity_mismatch"
    elif not billing_matches:
        failure_type = "billing_preflight_mismatch"
    elif credential_detected:
        failure_type = "credential_quarantined"
    elif workspace_entries:
        failure_type = "read_only_violation"
    elif not isinstance(result.status, RunStatus) or result.status not in terminal_statuses:
        failure_type = "runner_status_invalid"
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


def _safe_fingerprint(value: str | None) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    return None


def _write_exclusive_json(path: Path, payload: Mapping[str, Any]) -> str:
    document = _canonical_json_bytes(payload)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ConfigurationError(f"cannot create immutable comparison record {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(document)
        path.chmod(0o600)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return sha256(document).hexdigest()


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
    preflight_assessment: BillingRouteAssessment,
    billing_disposition: BillingPostRunDisposition,
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
            not billing_disposition.quarantine_required,
            not billing_disposition.circuit_breaker_required,
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
        and not billing_disposition.quarantine_required
        and not billing_disposition.circuit_breaker_required
    )
    effective_capacity = billing_disposition.capacity_state
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
        billing_route=preflight_assessment.route,
        subscription_name=preflight_assessment.subscription_name,
        included_capacity_state=effective_capacity,
        subscription_capacity_consumed=(
            result.subscription_capacity_consumed
            if (
                billing_matches
                and not billing_disposition.quarantine_required
                and not billing_disposition.circuit_breaker_required
            )
            else None
        ),
        subscription_limit_encountered=limit_encountered,
        run_delayed_by_limit=None,
        paid_capacity_consumed=billing_disposition.paid_capacity_consumed,
        incremental_ai_charge=billing_disposition.incremental_ai_charge,
        billing_quarantine_required=billing_disposition.quarantine_required,
        billing_circuit_breaker_required=(
            billing_disposition.circuit_breaker_required
        ),
        local_compute_resources=None,
    )


def _metrics_mapping(metrics: TrialMetrics) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for field in fields(TrialMetrics):
        value = getattr(metrics, field.name)
        mapping[field.name] = value.value if hasattr(value, "value") else value
    return mapping


__all__ = [
    "COMPARISON_ACTION_RECEIPT_COVERAGE",
    "COMPARISON_AUTHORIZATION_SHADOW_COVERAGE",
    "COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE",
    "COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE",
    "COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE",
    "COMPARISON_TRIAL_BINDING_EVENT_TYPE",
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
