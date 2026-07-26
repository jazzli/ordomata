from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest

from ordomata.comparison import (
    COMPARISON_AUTHORIZATION_SHADOW_COVERAGE,
    CONTROLLED_COMPARISON_TRIAL_TIMEOUT_SECONDS,
    ComparisonPlan,
    ComparisonProfile,
    ComparisonReport,
    ComparisonSnapshot,
    ControlledComparisonPlan,
    TrialMetrics,
    TrialOutcome,
    comparison_snapshot_from_prepared,
    run_controlled_comparison,
)
from ordomata.errors import BillingRouteBlocked, ValidationError
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    CircuitBreakerState,
    EnvironmentValidation,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PaidContinuationProtection,
    PaidCreditBalance,
    PermissionClass,
    RunnerCapabilities,
    RunnerExecutionResult,
    RunStatus,
    UsageObservation,
)
from ordomata.orchestrator import (
    load_mock_chief_of_staff_output,
    prepare_chief_of_staff,
)
from ordomata.routing import ExecutionProfile, load_execution_profiles
from ordomata.runners import MockRunner
from ordomata.state import SQLiteStateStore


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class RecordingMockRunner(MockRunner):
    def __init__(self, *, requests: list, **kwargs) -> None:
        super().__init__(**kwargs)
        self.requests = requests

    async def execute(self, request, event_sink):
        self.requests.append(request)
        return await super().execute(request, event_sink)


class ExplodingMockRunner(MockRunner):
    async def execute(self, request, event_sink):
        del request, event_sink
        raise RuntimeError("secret diagnostic must not be recorded")


class BreakerRunner:
    def __init__(self, *, assessment, output, executions) -> None:
        self.assessment = assessment
        self.output = output
        self.executions = executions

    @property
    def runner_id(self) -> str:
        return "codex"

    async def detect_capabilities(self):
        return RunnerCapabilities(
            runner_id="codex",
            installed=True,
            version="test",
            non_interactive=True,
            structured_output_modes=("jsonl",),
        )

    async def inspect_billing_route(self):
        return self.assessment

    async def validate_environment(self, request):
        del request
        return EnvironmentValidation(valid=True, sanitized_environment={})

    async def execute(self, request, event_sink):
        del event_sink
        self.executions.append(request.run_id)
        return RunnerExecutionResult(
            runner_id="codex",
            run_id=request.run_id,
            status=RunStatus.QUARANTINED,
            billing_assessment=self.assessment,
            output=self.output,
            usage_observation=UsageObservation.UNAVAILABLE,
            harness_process_started=True,
            live_model_execution_occurred=True,
            subscription_capacity_consumed=True,
            paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
            incremental_ai_charge=IncrementalAICharge.POSSIBLE,
            postflight_billing_assessment=None,
            billing_quarantine_required=True,
            billing_circuit_breaker_required=True,
        )

    async def cancel(self, run_id):
        del run_id


class CapacityStopRunner(BreakerRunner):
    def __init__(self, *, capacity_state, assessment, output, executions) -> None:
        super().__init__(assessment=assessment, output=output, executions=executions)
        self.capacity_state = capacity_state

    async def execute(self, request, event_sink):
        del event_sink
        self.executions.append(request.run_id)
        return RunnerExecutionResult(
            runner_id="codex",
            run_id=request.run_id,
            status=RunStatus.QUARANTINED,
            billing_assessment=self.assessment,
            output=self.output,
            usage_observation=UsageObservation.UNAVAILABLE,
            harness_process_started=True,
            live_model_execution_occurred=True,
            subscription_capacity_consumed=True,
            paid_capacity_consumed=PaidCapacityConsumed.NO,
            incremental_ai_charge=IncrementalAICharge.NONE,
            postflight_billing_assessment=replace(
                self.assessment,
                capacity_state=self.capacity_state,
            ),
            billing_quarantine_required=True,
            billing_circuit_breaker_required=False,
        )


class ControlledComparisonTests(unittest.TestCase):
    @staticmethod
    def _snapshot() -> ComparisonSnapshot:
        return ComparisonSnapshot(
            task_id="seeded-lint",
            task_version="v1",
            task_text="Repair the seeded lint failure only.",
            repository_revision="abc123",
            context_digest="c" * 64,
            verification_commands=(("python3", "-m", "unittest"),),
            permission_class=PermissionClass.LOCAL_DRAFT,
        )

    def _plan(self, seed: int = 17) -> ComparisonPlan:
        return ComparisonPlan.create(
            comparison_id="cmp-1",
            snapshot=self._snapshot(),
            runner_ids=("codex", "claude", "cursor"),
            repetitions=3,
            random_seed=seed,
        )

    @staticmethod
    def _metrics() -> TrialMetrics:
        return TrialMetrics(
            verification_passed=True,
            checks_total=4,
            checks_passed=4,
            wall_time_seconds=12.5,
            attempt_count=1,
            files_changed=2,
            lines_added=8,
            lines_deleted=3,
            reviewer_findings=0,
            regressions=0,
            human_interventions=0,
            process_exit_code=0,
            input_tokens=100,
            output_tokens=40,
            usage_observation=UsageObservation.OBSERVED,
        )

    def test_snapshot_is_frozen_and_digest_covers_task_context(self) -> None:
        snapshot = self._snapshot()
        with self.assertRaises(FrozenInstanceError):
            snapshot.task_text = "changed"
        changed = ComparisonSnapshot(
            task_id=snapshot.task_id,
            task_version=snapshot.task_version,
            task_text="Different task",
            repository_revision=snapshot.repository_revision,
            context_digest=snapshot.context_digest,
            verification_commands=snapshot.verification_commands,
            permission_class=snapshot.permission_class,
        )
        self.assertNotEqual(snapshot.digest, changed.digest)
        with self.assertRaises(ValidationError):
            ComparisonSnapshot(
                task_id="x",
                task_version="v1",
                task_text="x",
                repository_revision="r",
                context_digest="d",
                verification_commands=[["pytest"]],
                permission_class=PermissionClass.LOCAL_DRAFT,
            )

    def test_plan_is_repeated_block_randomized_and_reproducible(self) -> None:
        plan = self._plan()
        self.assertEqual(plan.trials, self._plan().trials)
        self.assertEqual(len(plan.trials), 9)
        for repetition in range(1, 4):
            block = [trial for trial in plan.trials if trial.repetition == repetition]
            self.assertEqual({trial.runner_id for trial in block}, set(plan.runner_ids))
            self.assertTrue(all(trial.fresh_session for trial in block))
            self.assertTrue(all(trial.snapshot_digest == plan.snapshot.digest for trial in block))
        with self.assertRaises(ValidationError):
            ComparisonPlan.create(
                comparison_id="bad",
                snapshot=self._snapshot(),
                runner_ids=("codex", "claude"),
                repetitions=1,
                random_seed=1,
            )

    def test_report_requires_fresh_sessions_and_exact_snapshot(self) -> None:
        plan = self._plan()
        outcomes = tuple(
            TrialOutcome(
                trial_id=trial.trial_id,
                run_id=f"run-{trial.order_index}",
                runner_id=trial.runner_id,
                snapshot_digest=plan.snapshot.digest,
                session_id=f"session-{trial.order_index}",
                status=RunStatus.SUCCEEDED,
                metrics=self._metrics(),
            )
            for trial in plan.trials
        )
        report = ComparisonReport.build(plan, outcomes)
        self.assertEqual(len(report.rows), 9)
        self.assertEqual(len(report.for_runner("codex")), 3)

        repeated_session = list(outcomes)
        repeated_session[1] = TrialOutcome(
            trial_id=repeated_session[1].trial_id,
            run_id=repeated_session[1].run_id,
            runner_id=repeated_session[1].runner_id,
            snapshot_digest=repeated_session[1].snapshot_digest,
            session_id=repeated_session[0].session_id,
            status=repeated_session[1].status,
            metrics=repeated_session[1].metrics,
        )
        with self.assertRaisesRegex(ValidationError, "fresh session"):
            ComparisonReport.build(plan, tuple(repeated_session))

    def test_direct_plan_construction_requires_exact_trial_matrix(self) -> None:
        plan = self._plan()
        malformed = list(plan.trials)
        malformed[0] = replace(malformed[0], runner_id="unplanned-runner")
        with self.assertRaisesRegex(ValidationError, "exact runner/repetition matrix"):
            ComparisonPlan(
                comparison_id=plan.comparison_id,
                snapshot=plan.snapshot,
                runner_ids=plan.runner_ids,
                repetitions=plan.repetitions,
                random_seed=plan.random_seed,
                trials=tuple(malformed),
            )

    def test_metrics_are_raw_dimensions_without_cost_or_score(self) -> None:
        names = {field.name for field in fields(TrialMetrics)}
        self.assertGreater(len(names), 8)
        self.assertFalse(any("cost" in name or "price" in name or "score" in name for name in names))
        self.assertTrue(
            {
                "schema_valid",
                "grounding_passed",
                "completeness_passed",
                "prioritization_passed",
                "actionability_passed",
                "safety_passed",
                "uncertainty_handled_passed",
                "human_review_minutes",
                "corrections_required",
                "human_quality_assessment",
                "human_safety_assessment",
                "billing_route",
                "subscription_capacity_consumed",
                "subscription_limit_encountered",
            }.issubset(names)
        )
        with self.assertRaises(ValidationError):
            TrialMetrics(
                verification_passed=False,
                checks_total=1,
                checks_passed=2,
                wall_time_seconds=1,
                attempt_count=1,
                files_changed=0,
                lines_added=0,
                lines_deleted=0,
                reviewer_findings=0,
                regressions=0,
                human_interventions=0,
                process_exit_code=1,
            )

        with self.assertRaises(ValidationError):
            TrialMetrics(
                verification_passed=True,
                checks_total=1,
                checks_passed=1,
                wall_time_seconds=1,
                attempt_count=1,
                files_changed=0,
                lines_added=0,
                lines_deleted=0,
                reviewer_findings=0,
                regressions=0,
                human_interventions=0,
                process_exit_code=0,
                human_review_minutes=float("nan"),
                billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
            )


class ControlledComparisonExecutionTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _project(temporary: str) -> Path:
        root = Path(temporary)
        for name in ("tasks", "schemas", "fixtures", "profiles"):
            shutil.copytree(REPOSITORY_ROOT / name, root / name)
        return root

    async def test_compare_run_uses_one_snapshot_and_fresh_read_only_sessions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            original = next(
                profile
                for profile in load_execution_profiles(root / "profiles/default.json")
                if profile.runner_id == "mock"
            )
            profiles = (
                replace(original, profile_id="mock.control-a"),
                replace(original, profile_id="mock.control-b"),
            )
            snapshot = comparison_snapshot_from_prepared(prepared)
            plan = ControlledComparisonPlan.create(
                comparison_id="controlled-mock",
                snapshot=snapshot,
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=3,
                random_seed=17,
            )
            requests = []
            instances = []

            def factory(_profile):
                runner = RecordingMockRunner(
                    requests=requests,
                    output=load_mock_chief_of_staff_output(root, prepared),
                )
                instances.append(runner)
                return runner

            report = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=plan,
                profiles=profiles,
                runner_factory=factory,
            )
            payload = report.to_mapping()

            self.assertEqual(len(requests), 6)
            self.assertEqual(len({id(instance) for instance in instances}), 6)
            self.assertEqual(
                [row.profile_id for row in report.rows],
                [trial.profile_id for trial in plan.trials],
            )
            self.assertEqual({request.prompt for request in requests}, {prepared.prompt})
            self.assertTrue(
                all(
                    request.permission_class is PermissionClass.READ_ONLY
                    for request in requests
                )
            )
            self.assertEqual(
                {request.timeout_seconds for request in requests},
                {
                    min(
                        prepared.contract.timeout_seconds,
                        CONTROLLED_COMPARISON_TRIAL_TIMEOUT_SECONDS,
                    )
                },
            )
            self.assertEqual(
                {
                    json.dumps(request.output_schema, sort_keys=True)
                    for request in requests
                },
                {json.dumps(prepared.contract.output_schema, sort_keys=True)},
            )
            self.assertEqual(len({request.workspace for request in requests}), 6)
            self.assertTrue(all(not any(request.workspace.iterdir()) for request in requests))
            self.assertEqual(payload["controls"]["permission_class"], 0)
            self.assertFalse(payload["controls"]["outputs_shared_between_trials"])
            self.assertFalse(payload["controls"]["external_actions_allowed"])
            self.assertEqual(
                payload["authorization_shadow_coverage"],
                COMPARISON_AUTHORIZATION_SHADOW_COVERAGE,
            )
            self.assertTrue(all(row.metrics.verification_passed for row in report.rows))
            self.assertTrue(payload["automated_checks_succeeded"])
            self.assertEqual(payload["human_review_status"], "pending")
            artifact_paths = [
                Path(trial["review_artifact_path"])
                for trial in payload["trials"]
            ]
            self.assertEqual(len(set(artifact_paths)), 6)
            self.assertTrue(all(path.is_file() for path in artifact_paths))
            self.assertTrue(
                all(path.stat().st_mode & 0o077 == 0 for path in artifact_paths)
            )
            self.assertTrue(
                all(
                    prepared.prompt not in path.read_text(encoding="utf-8")
                    for path in artifact_paths
                )
            )
            self.assertEqual(
                len(
                    {
                        trial["review_artifact_sha256"]
                        for trial in payload["trials"]
                    }
                ),
                6,
            )
            self.assertTrue(
                all(
                    trial["human_scoring"]
                    == {
                        "status": "pending_human_review",
                        "review_time_minutes": None,
                        "corrections_required": None,
                        "maximum_correction_severity": None,
                        "quality_assessment": None,
                        "safety_assessment": None,
                        "subscription_capacity_observation": None,
                    }
                    for trial in payload["trials"]
                )
            )
            report_path = Path(report.report_path)
            self.assertTrue(report_path.is_file())
            persisted = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted, payload)
            self.assertNotIn("executive_summary", json.dumps(persisted))
            review_template_path = Path(payload["review_template_path"])
            self.assertTrue(review_template_path.is_file())
            self.assertEqual(review_template_path.stat().st_mode & 0o077, 0)
            template = json.loads(
                review_template_path.read_text(encoding="utf-8")
            )
            self.assertEqual(len(template["trials"]), 6)
            self.assertTrue(
                {
                    "setup_minutes",
                    "review_minutes",
                    "corrections_required",
                    "maximum_correction_severity",
                    "quality_assessment",
                    "safety_assessment",
                    "subscription_capacity_observation",
                }.issubset(template["trials"][0]["operator_fields"])
            )
            self.assertNotIn("executive_summary", json.dumps(template))

    async def test_billing_breaker_is_persisted_and_stops_remaining_trials(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            now = time.time()
            fingerprint = "a" * 64
            attestation = BillingSafetyAttestation(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                ),
                observed_at=now - 1,
                expires_at=now + 7200,
                confidence=AssessmentConfidence.HIGH,
                evidence=(
                    "operator_attestation:provider_ui_auto_top_up_disabled",
                ),
            )
            assessment = BillingRouteAssessment(
                runner_id="codex",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                subscription_name="test",
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                ),
                paid_credit_balance=PaidCreditBalance.ZERO,
                account_identity_fingerprint=fingerprint,
                capacity_observed_at=now - 1,
                capacity_expires_at=now + 7200,
                attestation=attestation,
            )
            profiles = tuple(
                ExecutionProfile(
                    profile_id=profile_id,
                    version="1",
                    runner_id="codex",
                    model_id=None,
                    role="synthesis",
                    settings={},
                    capabilities=frozenset(
                        {"structured_output", "isolated_workspace"}
                    ),
                    task_kinds=frozenset({"chief_of_staff"}),
                    allowed_billing_routes=frozenset(
                        {BillingRoute.SUBSCRIPTION_INCLUDED}
                    ),
                    max_permission_class=PermissionClass.READ_ONLY,
                )
                for profile_id in ("codex.breaker-a", "codex.breaker-b")
            )
            snapshot = comparison_snapshot_from_prepared(prepared)
            plan = ControlledComparisonPlan.create(
                comparison_id="breaker-first",
                snapshot=snapshot,
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=3,
                random_seed=17,
            )
            executions = []

            def factory(_profile):
                return BreakerRunner(
                    assessment=assessment,
                    output=load_mock_chief_of_staff_output(root, prepared),
                    executions=executions,
                )

            report = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=plan,
                profiles=profiles,
                runner_factory=factory,
            )
            payload = report.to_mapping()
            self.assertEqual(len(executions), 1)
            self.assertEqual(payload["completed_trial_count"], 1)
            self.assertFalse(payload["execution_complete"])
            self.assertEqual(
                payload["authorization_shadow_coverage"],
                "deferred_not_covered",
            )
            self.assertEqual(payload["trials"][0]["status"], "quarantined")

            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                exact = state.current_billing_circuit(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id=payload["trials"][0]["profile_id"],
                )
                broad = state.current_billing_circuit(
                    runner_id="codex",
                    account_identity_fingerprint=None,
                    profile_id=payload["trials"][0]["profile_id"],
                )
            self.assertEqual(exact.state, CircuitBreakerState.OPEN)
            self.assertEqual(broad.state, CircuitBreakerState.OPEN)

            second = ControlledComparisonPlan.create(
                comparison_id="breaker-second",
                snapshot=snapshot,
                profiles=plan.profiles,
                repetitions=3,
                random_seed=17,
            )
            with self.assertRaises(BillingRouteBlocked):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=second,
                    profiles=profiles,
                    runner_factory=factory,
                )
            self.assertFalse(
                (root / ".ordomata/comparisons/breaker-second").exists()
            )

    async def test_durable_capacity_block_stops_before_comparison_records(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            now = time.time()
            fingerprint = "b" * 64
            attestation = BillingSafetyAttestation(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                ),
                observed_at=now - 10,
                expires_at=now + 7200,
                confidence=AssessmentConfidence.HIGH,
                evidence=(
                    "operator_attestation:provider_ui_auto_top_up_disabled",
                ),
            )
            assessment = BillingRouteAssessment(
                runner_id="codex",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                subscription_name="test",
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                ),
                paid_credit_balance=PaidCreditBalance.ZERO,
                account_identity_fingerprint=fingerprint,
                capacity_observed_at=now - 10,
                capacity_expires_at=now + 7200,
                attestation=attestation,
            )
            profiles = tuple(
                ExecutionProfile(
                    profile_id=profile_id,
                    version="1",
                    runner_id="codex",
                    model_id=None,
                    role="synthesis",
                    settings={},
                    capabilities=frozenset(
                        {"structured_output", "isolated_workspace"}
                    ),
                    task_kinds=frozenset({"chief_of_staff"}),
                    allowed_billing_routes=frozenset(
                        {BillingRoute.SUBSCRIPTION_INCLUDED}
                    ),
                    max_permission_class=PermissionClass.READ_ONLY,
                )
                for profile_id in ("codex.capacity-a", "codex.capacity-b")
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="durable-capacity-blocked",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=3,
                random_seed=17,
            )
            state_path = root / ".ordomata" / "state.sqlite3"
            state_path.parent.mkdir(parents=True)
            with SQLiteStateStore(state_path) as state:
                state.append_billing_capacity_event(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id="codex.capacity-a",
                    capacity_state=CapacityState.BLOCKED_UNTIL_RESET,
                    reason_code="included_capacity_exhausted",
                    reset_at=now + 600,
                    occurred_at=now - 5,
                )
            executions = []

            with self.assertRaisesRegex(
                BillingRouteBlocked, "blocking durable billing state"
            ):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: BreakerRunner(
                        assessment=assessment,
                        output=load_mock_chief_of_staff_output(root, prepared),
                        executions=executions,
                    ),
                )

            self.assertEqual(executions, [])
            self.assertFalse(
                (root / ".ordomata/comparisons/durable-capacity-blocked").exists()
            )

    async def test_cooldown_and_unknown_capacity_stop_remaining_trials(
        self,
    ) -> None:
        for capacity_state in (CapacityState.COOLDOWN, CapacityState.UNKNOWN):
            with (
                self.subTest(capacity_state=capacity_state),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                prepared = prepare_chief_of_staff(root)
                original = next(
                    profile
                    for profile in load_execution_profiles(
                        root / "profiles/default.json"
                    )
                    if profile.runner_id == "codex"
                )
                profiles = (
                    replace(original, profile_id="codex.capacity-stop-a"),
                    replace(original, profile_id="codex.capacity-stop-b"),
                )
                now = time.time()
                fingerprint = "d" * 64
                attestation = BillingSafetyAttestation(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
                    capacity_state=CapacityState.AVAILABLE,
                    paid_continuation_protection=(
                        PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                    ),
                    observed_at=now - 1,
                    expires_at=now + 900,
                    confidence=AssessmentConfidence.HIGH,
                    evidence=(
                        "operator_attestation:provider_ui_auto_top_up_disabled",
                    ),
                )
                assessment = BillingRouteAssessment(
                    runner_id="codex",
                    route=BillingRoute.SUBSCRIPTION_INCLUDED,
                    confidence=AssessmentConfidence.HIGH,
                    subscription_name="test",
                    capacity_state=CapacityState.AVAILABLE,
                    paid_continuation_protection=(
                        PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                    ),
                    paid_credit_balance=PaidCreditBalance.ZERO,
                    account_identity_fingerprint=fingerprint,
                    capacity_observed_at=now - 1,
                    capacity_expires_at=now + 900,
                    attestation=attestation,
                )
                plan = ControlledComparisonPlan.create(
                    comparison_id=f"capacity-stop-{capacity_state.value}",
                    snapshot=comparison_snapshot_from_prepared(prepared),
                    profiles=tuple(
                        ComparisonProfile.from_execution_profile(profile)
                        for profile in profiles
                    ),
                    repetitions=3,
                    random_seed=17,
                )
                executions = []

                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: CapacityStopRunner(
                        capacity_state=capacity_state,
                        assessment=assessment,
                        output=load_mock_chief_of_staff_output(root, prepared),
                        executions=executions,
                    ),
                )

                self.assertEqual(len(executions), 1)
                self.assertEqual(len(report.rows), 1)
                self.assertFalse(report.to_mapping()["execution_complete"])

    async def test_detected_credential_output_is_quarantined_and_withheld(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            original = next(
                profile
                for profile in load_execution_profiles(root / "profiles/default.json")
                if profile.runner_id == "mock"
            )
            profiles = (
                replace(original, profile_id="mock.secret-a"),
                replace(original, profile_id="mock.secret-b"),
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="credential-withheld",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=3,
            )
            secret = "sk-test-credential-material-123456789"
            report = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=plan,
                profiles=profiles,
                runner_factory=lambda _profile: MockRunner(
                    output={"api_key": secret}
                ),
            )

            self.assertTrue(
                all(row.status is RunStatus.QUARANTINED for row in report.rows)
            )
            for row in report.rows:
                artifact = Path(row.review_artifact_path)
                text = artifact.read_text(encoding="utf-8")
                self.assertNotIn(secret, text)
                payload = json.loads(text)
                self.assertIsNone(payload["output"])
                self.assertEqual(
                    payload["output_withheld_reason"],
                    "credential_material_detected",
                )

    async def test_runner_exception_is_recorded_without_diagnostic_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            original = next(
                profile
                for profile in load_execution_profiles(root / "profiles/default.json")
                if profile.runner_id == "mock"
            )
            profiles = (
                replace(original, profile_id="mock.exception-a"),
                replace(original, profile_id="mock.exception-b"),
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="runner-exception",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=3,
            )

            report = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=plan,
                profiles=profiles,
                runner_factory=lambda _profile: ExplodingMockRunner(output={}),
            )
            payload = report.to_mapping()

            self.assertEqual(payload["completed_trial_count"], 1)
            self.assertFalse(payload["execution_complete"])
            self.assertFalse(payload["automated_checks_succeeded"])
            self.assertEqual(payload["trials"][0]["status"], "failed")
            self.assertEqual(
                payload["trials"][0]["failure_type"],
                "runner_execution_error",
            )
            self.assertEqual(
                payload["trials"][0]["error_codes"],
                ["runner_execution_error"],
            )
            self.assertIsNone(payload["trials"][0]["review_artifact_path"])
            persisted_text = Path(report.report_path).read_text(encoding="utf-8")
            review_text = Path(report.review_template_path).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("secret diagnostic", persisted_text)
            self.assertNotIn("secret diagnostic", review_text)

    def test_controlled_plan_rejects_write_capable_snapshot(self) -> None:
        snapshot = ComparisonSnapshot(
            task_id="x",
            task_version="1",
            task_text="fixed",
            repository_revision="r",
            context_digest="d",
            verification_commands=(("check",),),
            permission_class=PermissionClass.LOCAL_DRAFT,
        )
        profiles = (
            ComparisonProfile("profile-a", "1", "mock", "sha256:" + "a" * 64),
            ComparisonProfile("profile-b", "1", "mock", "sha256:" + "b" * 64),
        )
        with self.assertRaisesRegex(ValidationError, "read-only"):
            ControlledComparisonPlan.create(
                comparison_id="write-capable",
                snapshot=snapshot,
                profiles=profiles,
            )


if __name__ == "__main__":
    unittest.main()
