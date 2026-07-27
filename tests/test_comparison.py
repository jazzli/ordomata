from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, fields, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.authorization_inspection import (
    ADMISSION_SCOPE,
    DISPATCH_SCOPE,
    PUBLICATION_SCOPE,
    inspect_authorization_shadows,
)
from ordomata.comparison import (
    COMPARISON_ACTION_RECEIPT_COVERAGE,
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
from ordomata.errors import BillingRouteBlocked, ConfigurationError, ValidationError
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
    _promote_staged_artifact,
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


class ExplodingSubscriptionRunner(BreakerRunner):
    async def execute(self, request, event_sink):
        del event_sink
        self.executions.append(request.run_id)
        raise RuntimeError("private subscription execution diagnostic")


class CancellingSubscriptionRunner(BreakerRunner):
    async def execute(self, request, event_sink):
        del event_sink
        self.executions.append(request.run_id)
        raise asyncio.CancelledError()


class AdversarialResultRunner(BreakerRunner):
    def __init__(
        self,
        *,
        assessment,
        output,
        executions,
        postflight_assessment=None,
        result_runner_id=None,
        result_billing_assessment=None,
    ) -> None:
        super().__init__(
            assessment=assessment,
            output=output,
            executions=executions,
        )
        self.postflight_assessment = postflight_assessment
        self.result_runner_id = result_runner_id
        self.result_billing_assessment = result_billing_assessment

    async def execute(self, request, event_sink):
        del event_sink
        self.executions.append(request.run_id)
        subscription = (
            self.assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
        )
        return RunnerExecutionResult(
            runner_id=self.result_runner_id or self.runner_id,
            run_id=request.run_id,
            status=RunStatus.SUCCEEDED,
            billing_assessment=(
                self.result_billing_assessment or self.assessment
            ),
            postflight_billing_assessment=self.postflight_assessment,
            output=self.output,
            usage_observation=UsageObservation.UNAVAILABLE,
            harness_process_started=subscription,
            live_model_execution_occurred=subscription,
            subscription_capacity_consumed=subscription,
            paid_capacity_consumed=(
                PaidCapacityConsumed.NO
                if subscription
                else PaidCapacityConsumed.NOT_APPLICABLE
            ),
            incremental_ai_charge=IncrementalAICharge.NONE,
            billing_quarantine_required=False,
            billing_circuit_breaker_required=False,
        )


class MismatchedMockResultRunner(MockRunner):
    def __init__(self, *, mismatch: str, executions: list[str], **kwargs) -> None:
        super().__init__(**kwargs)
        self.mismatch = mismatch
        self.executions = executions

    async def execute(self, request, event_sink):
        self.executions.append(request.run_id)
        result = await super().execute(request, event_sink)
        if self.mismatch == "runner":
            return replace(result, runner_id="different-runner")
        if self.mismatch == "billing":
            return replace(
                result,
                billing_assessment=replace(
                    result.billing_assessment,
                    confidence=AssessmentConfidence.LOW,
                ),
            )
        raise AssertionError("unsupported mismatch fixture")


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

    @staticmethod
    def _mock_profiles(root: Path, *profile_ids: str) -> tuple[ExecutionProfile, ...]:
        original = next(
            profile
            for profile in load_execution_profiles(root / "profiles/default.json")
            if profile.runner_id == "mock"
        )
        return tuple(
            replace(original, profile_id=profile_id)
            for profile_id in profile_ids
        )

    def _artifact_recovery_setup(self, temporary: str, comparison_id: str):
        root = self._project(temporary)
        prepared = prepare_chief_of_staff(root)
        profiles = self._mock_profiles(
            root,
            f"mock.{comparison_id}-a",
            f"mock.{comparison_id}-b",
        )
        plan = ControlledComparisonPlan.create(
            comparison_id=comparison_id,
            snapshot=comparison_snapshot_from_prepared(prepared),
            profiles=tuple(
                ComparisonProfile.from_execution_profile(profile)
                for profile in profiles
            ),
            repetitions=2,
            random_seed=17,
        )
        return root, prepared, profiles, plan

    @staticmethod
    def _included_subscription_assessment(
        fingerprint: str,
    ) -> BillingRouteAssessment:
        now = time.time()
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
        return BillingRouteAssessment(
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

    @staticmethod
    def _subscription_profiles(*profile_ids: str) -> tuple[ExecutionProfile, ...]:
        return tuple(
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
            for profile_id in profile_ids
        )

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
            self.assertEqual(
                payload["authorization_action_receipt_coverage"],
                COMPARISON_ACTION_RECEIPT_COVERAGE,
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

            state_path = root / ".ordomata" / "state.sqlite3"
            with SQLiteStateStore(state_path) as state:
                run_records = state.list_runs()
                self.assertEqual(len(run_records), 6)
                self.assertEqual(
                    {record.run_id for record in run_records},
                    {row.run_id for row in report.rows},
                )
                self.assertEqual(
                    len({record.run_id for record in run_records}),
                    6,
                )
                self.assertTrue(
                    all(
                        record.permission_class is PermissionClass.READ_ONLY
                        for record in run_records
                    )
                )
                for row in report.rows:
                    events = state.list_events(row.run_id)
                    self.assertEqual(
                        [
                            (
                                event.event_type,
                                event.status,
                                event.payload.get("action_scope"),
                            )
                            for event in events
                        ],
                        [
                            ("status", RunStatus.CREATED, None),
                            ("comparison_trial_binding", None, None),
                            (
                                "authorization_shadow_decision",
                                None,
                                ADMISSION_SCOPE,
                            ),
                            ("billing_assessment", None, None),
                            ("status", RunStatus.RUNNING, None),
                            (
                                "authorization_shadow_decision",
                                None,
                                DISPATCH_SCOPE,
                            ),
                            ("execution_accounting", None, None),
                            (
                                "authorization_shadow_decision",
                                None,
                                PUBLICATION_SCOPE,
                            ),
                            (
                                "comparison_review_artifact_intent",
                                None,
                                None,
                            ),
                            (
                                "comparison_review_artifact_action_receipt",
                                None,
                                None,
                            ),
                            ("status", RunStatus.SUCCEEDED, None),
                        ],
                    )
                    binding_payload = events[1].payload
                    binding_digest = binding_payload["binding_digest"]
                    self.assertEqual(binding_payload["schema_version"], 2)
                    self.assertEqual(
                        binding_payload["authorization_shadow_coverage"],
                        COMPARISON_AUTHORIZATION_SHADOW_COVERAGE,
                    )
                    self.assertEqual(
                        binding_payload[
                            "authorization_action_receipt_coverage"
                        ],
                        COMPARISON_ACTION_RECEIPT_COVERAGE,
                    )
                    self.assertRegex(
                        binding_digest,
                        r"^sha256:[0-9a-f]{64}$",
                    )
                    self.assertEqual(
                        binding_payload["binding"]["permission_class"],
                        0,
                    )
                    shadows = (
                        events[2].payload,
                        events[5].payload,
                        events[7].payload,
                    )
                    self.assertEqual(
                        [shadow["schema_version"] for shadow in shadows],
                        [3, 3, 4],
                    )
                    self.assertEqual(
                        [shadow["intent_source"] for shadow in shadows],
                        [
                            "comparison_trial_projection",
                            "comparison_trial_projection",
                            "comparison_review_artifact_projection",
                        ],
                    )
                    self.assertTrue(
                        all(
                            shadow["comparison_binding_digest"]
                            == binding_digest
                            for shadow in shadows
                        )
                    )
                    self.assertEqual(
                        [
                            shadow["task_authorization_intent"]["action"][
                                "verb"
                            ]
                            for shadow in shadows
                        ],
                        ["read", "read", "create"],
                    )
                    self.assertEqual(
                        [shadow["derived_permission_class"] for shadow in shadows],
                        [0, 0, 1],
                    )
                    self.assertEqual(
                        [shadow["requested_permission_class"] for shadow in shadows],
                        [0, 0, 1],
                    )
                    accounting = events[6].payload
                    self.assertEqual(accounting["schema_version"], 2)
                    self.assertEqual(
                        accounting["billing_disposition_digest"],
                        canonical_digest(
                            {
                                "identity_matches": (
                                    accounting["identity_matches"] is True
                                ),
                                "billing_matches": (
                                    accounting["billing_matches"] is True
                                ),
                                "capacity_state": accounting[
                                    "capacity_state"
                                ],
                                "paid_capacity_consumed": accounting[
                                    "paid_capacity_consumed"
                                ],
                                "incremental_ai_charge": accounting[
                                    "incremental_ai_charge"
                                ],
                                "quarantine_required": accounting[
                                    "billing_quarantine_required"
                                ],
                                "circuit_breaker_required": accounting[
                                    "billing_circuit_breaker_required"
                                ],
                                "reason_codes": accounting[
                                    "billing_disposition_reason_codes"
                                ],
                            }
                        ),
                    )
                    pre_effect = events[8].payload
                    action_receipt = events[9].payload
                    self.assertEqual(
                        accounting["billing_disposition_digest"],
                        pre_effect["billing_disposition_digest"],
                    )
                    self.assertEqual(pre_effect["schema_version"], 2)
                    self.assertEqual(pre_effect["receipt_kind"], "pre_effect")
                    self.assertFalse(pre_effect["authorization_enforced"])
                    self.assertTrue(pre_effect["publication_shadow_persisted"])
                    self.assertEqual(
                        pre_effect["publication_request_digest"],
                        shadows[2]["request_digest"],
                    )
                    self.assertEqual(
                        pre_effect["publication_decision_digest"],
                        shadows[2]["decision_digest"],
                    )
                    pre_effect_body = dict(pre_effect)
                    pre_effect_digest = pre_effect_body.pop("receipt_digest")
                    self.assertEqual(
                        pre_effect_digest,
                        canonical_digest(pre_effect_body),
                    )
                    self.assertEqual(action_receipt["schema_version"], 2)
                    self.assertEqual(action_receipt["receipt_kind"], "action")
                    self.assertFalse(action_receipt["authorization_enforced"])
                    self.assertEqual(action_receipt["outcome"], "succeeded")
                    self.assertEqual(
                        action_receipt["pre_effect_receipt_digest"],
                        pre_effect_digest,
                    )
                    self.assertEqual(
                        action_receipt["result_digest"],
                        pre_effect["artifact_digest"],
                    )
                    self.assertEqual(
                        action_receipt["billing_disposition_digest"],
                        accounting["billing_disposition_digest"],
                    )
                    self.assertEqual(
                        action_receipt["observed_artifact_size_bytes"],
                        pre_effect["artifact_size_bytes"],
                    )
                    action_receipt_body = dict(action_receipt)
                    action_receipt_digest = action_receipt_body.pop(
                        "receipt_digest"
                    )
                    self.assertEqual(
                        action_receipt_digest,
                        canonical_digest(action_receipt_body),
                    )
                    persisted_events = "\n".join(
                        event.payload_json for event in events
                    )
                    self.assertNotIn(prepared.prompt, persisted_events)
                    self.assertNotIn("executive_summary", persisted_events)

            inspection = inspect_authorization_shadows(state_path, now=time.time())
            self.assertTrue(inspection.clean)
            self.assertEqual(inspection.inspected_run_count, 6)
            self.assertEqual(inspection.inspected_event_count, 18)
            self.assertEqual(inspection.coverage_gap_count, 0)
            self.assertEqual(inspection.integrity_issue_count, 0)
            self.assertEqual(inspection.parity_mismatch_count, 0)
            for inspected_run in inspection.runs:
                self.assertEqual(
                    inspected_run.run_kind,
                    "controlled_comparison_trial",
                )
                self.assertEqual(
                    inspected_run.authorization_shadow_coverage,
                    COMPARISON_AUTHORIZATION_SHADOW_COVERAGE,
                )
                self.assertEqual(
                    inspected_run.expected_scopes,
                    tuple(
                        sorted(
                            (
                                ADMISSION_SCOPE,
                                DISPATCH_SCOPE,
                                PUBLICATION_SCOPE,
                            )
                        )
                    ),
                )
                self.assertEqual(
                    inspected_run.observed_scopes,
                    tuple(
                        sorted(
                            (ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE)
                        )
                    ),
                )
                self.assertEqual(inspected_run.missing_scopes, ())
                self.assertEqual(inspected_run.integrity_issues, ())
                self.assertTrue(
                    all(not event.integrity_issues for event in inspected_run.events)
                )

    async def test_same_snapshot_different_comparisons_use_distinct_run_ids(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.collision-a",
                "mock.collision-b",
            )
            planned_profiles = tuple(
                ComparisonProfile.from_execution_profile(profile)
                for profile in profiles
            )
            snapshot = comparison_snapshot_from_prepared(prepared)
            output = load_mock_chief_of_staff_output(root, prepared)

            first = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=ControlledComparisonPlan.create(
                    comparison_id="collision-first",
                    snapshot=snapshot,
                    profiles=planned_profiles,
                    repetitions=2,
                    random_seed=17,
                ),
                profiles=profiles,
                runner_factory=lambda _profile: MockRunner(output=output),
            )
            second = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=ControlledComparisonPlan.create(
                    comparison_id="collision-second",
                    snapshot=snapshot,
                    profiles=planned_profiles,
                    repetitions=2,
                    random_seed=17,
                ),
                profiles=profiles,
                runner_factory=lambda _profile: MockRunner(output=output),
            )

            first_run_ids = {row.run_id for row in first.rows}
            second_run_ids = {row.run_id for row in second.rows}
            self.assertEqual(len(first_run_ids), 4)
            self.assertEqual(len(second_run_ids), 4)
            self.assertTrue(first_run_ids.isdisjoint(second_run_ids))
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                persisted_run_ids = {
                    record.run_id for record in state.list_runs()
                }
            self.assertEqual(len(persisted_run_ids), 8)
            self.assertEqual(
                persisted_run_ids,
                first_run_ids | second_run_ids,
            )

    async def test_core_comparison_audit_failure_blocks_before_execute(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.audit-a",
                "mock.audit-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="core-audit-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            requests = []
            original_append_event = SQLiteStateStore.append_event

            def reject_binding(store, run_id, event_type, payload=None, **kwargs):
                if event_type == "comparison_trial_binding":
                    raise RuntimeError("private core audit diagnostic")
                return original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=reject_binding,
                ),
                self.assertRaisesRegex(RuntimeError, "private core audit"),
            ):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=requests,
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(requests, [])
            comparison_directory = (
                root / ".ordomata/comparisons/core-audit-failure"
            )
            self.assertFalse((comparison_directory / "report.json").exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                self.assertIs(
                    state.current_status(runs[0].run_id),
                    RunStatus.BLOCKED,
                )
                events = state.list_events(runs[0].run_id)
                self.assertEqual(
                    [(event.event_type, event.status) for event in events],
                    [
                        ("status", RunStatus.CREATED),
                        ("status", RunStatus.BLOCKED),
                    ],
                )
                self.assertTrue(
                    all(
                        "private core audit diagnostic" not in event.payload_json
                        for event in events
                    )
                )

    async def test_shadow_append_failure_is_non_authoritative_and_redacted(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.shadow-failure-a",
                "mock.shadow-failure-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="shadow-append-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            requests = []
            original_append_event = SQLiteStateStore.append_event

            def reject_shadows(store, run_id, event_type, payload=None, **kwargs):
                if event_type == "authorization_shadow_decision":
                    raise RuntimeError("private shadow diagnostic")
                return original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            with patch.object(
                SQLiteStateStore,
                "append_event",
                new=reject_shadows,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=requests,
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            payload = report.to_mapping()
            self.assertEqual(len(requests), 4)
            self.assertTrue(payload["execution_complete"])
            self.assertTrue(payload["automated_checks_succeeded"])
            self.assertEqual(
                payload["authorization_shadow_coverage"],
                COMPARISON_AUTHORIZATION_SHADOW_COVERAGE,
            )
            state_path = root / ".ordomata/state.sqlite3"
            with SQLiteStateStore(state_path) as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 4)
                persisted_payloads = "\n".join(
                    event.payload_json
                    for run in runs
                    for event in state.list_events(run.run_id)
                )
                self.assertNotIn("private shadow diagnostic", persisted_payloads)
                self.assertTrue(
                    all(
                        not any(
                            event.event_type
                            == "authorization_shadow_decision"
                            for event in state.list_events(run.run_id)
                        )
                        for run in runs
                    )
                )
            inspection = inspect_authorization_shadows(state_path, now=time.time())
            self.assertEqual(inspection.inspected_run_count, 4)
            self.assertEqual(inspection.inspected_event_count, 0)
            self.assertEqual(inspection.coverage_gap_count, 12)
            self.assertTrue(
                all(
                    run.missing_scopes
                    == tuple(
                        sorted(
                            (
                                ADMISSION_SCOPE,
                                DISPATCH_SCOPE,
                                PUBLICATION_SCOPE,
                            )
                        )
                    )
                    for run in inspection.runs
                )
            )
            persisted_report = Path(report.report_path).read_text(
                encoding="utf-8"
            )
            persisted_review = Path(report.review_template_path).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("private shadow diagnostic", persisted_report)
            self.assertNotIn("private shadow diagnostic", persisted_review)

    async def test_artifact_write_failure_records_a_sanitized_failed_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.artifact-write-a",
                "mock.artifact-write-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="artifact-write-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )

            with patch(
                "ordomata.comparison._stage_artifact",
                side_effect=OSError("private artifact write diagnostic"),
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.FAILED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "failed")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_persistence_failed",
            )
            self.assertIsNone(receipt["result_digest"])
            self.assertIsNone(receipt["observed_artifact_size_bytes"])
            persisted = "\n".join(event.payload_json for event in events)
            self.assertNotIn("private artifact write diagnostic", persisted)
            self.assertFalse(
                (
                    root
                    / ".ordomata/comparisons/artifact-write-failure/trials/001/review-output.json"
                ).exists()
            )

    async def test_pre_effect_receipt_failure_prevents_artifact_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.pre-effect-a",
                "mock.pre-effect-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="pre-effect-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            original_append_event = SQLiteStateStore.append_event

            def reject_pre_effect(store, run_id, event_type, payload=None, **kwargs):
                if event_type == "comparison_review_artifact_intent":
                    raise RuntimeError("private pre-effect diagnostic")
                return original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=reject_pre_effect,
                ),
                patch("ordomata.comparison._stage_artifact") as stage_artifact,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            stage_artifact.assert_not_called()
            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.FAILED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            event_types = [event.event_type for event in events]
            self.assertNotIn("comparison_review_artifact_intent", event_types)
            self.assertNotIn(
                "comparison_review_artifact_action_receipt",
                event_types,
            )
            self.assertNotIn(
                "private pre-effect diagnostic",
                "\n".join(event.payload_json for event in events),
            )

    async def test_action_receipt_failure_rolls_back_private_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.receipt-failure-a",
                "mock.receipt-failure-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="action-receipt-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            original_append_event = SQLiteStateStore.append_event

            def reject_action_receipt(
                store, run_id, event_type, payload=None, **kwargs
            ):
                if event_type == "comparison_review_artifact_action_receipt":
                    raise RuntimeError("private action receipt diagnostic")
                return original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            with patch.object(
                SQLiteStateStore,
                "append_event",
                new=reject_action_receipt,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.BLOCKED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            artifact_path = (
                root
                / ".ordomata/comparisons/action-receipt-failure/trials/001/review-output.json"
            )
            self.assertFalse(artifact_path.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            self.assertIn(
                "comparison_review_artifact_intent",
                [event.event_type for event in events],
            )
            self.assertNotIn(
                "comparison_review_artifact_action_receipt",
                [event.event_type for event in events],
            )
            persisted = "\n".join(event.payload_json for event in events)
            self.assertNotIn("private action receipt diagnostic", persisted)

    async def test_action_receipt_builder_failure_rolls_back_private_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "receipt-builder-failure",
            )
            with patch(
                "ordomata.comparison."
                "_comparison_review_artifact_action_receipt",
                side_effect=RuntimeError(
                    "private comparison receipt builder diagnostic"
                ),
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            row = report.rows[0]
            self.assertIs(row.status, RunStatus.FAILED)
            self.assertIsNone(row.review_artifact_path)
            artifact_path = (
                root
                / ".ordomata/comparisons/receipt-builder-failure/trials/001"
                / "review-output.json"
            )
            self.assertFalse(artifact_path.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(row.run_id)
            self.assertFalse(
                any(
                    event.event_type
                    == "comparison_review_artifact_action_receipt"
                    for event in events
                )
            )
            self.assertFalse(events[-1].payload["artifact_observed"])
            self.assertNotIn(
                "private comparison receipt builder diagnostic",
                "\n".join(event.payload_json for event in events),
            )

    async def test_committed_action_receipt_is_reconciled_after_append_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "committed-action-receipt",
            )
            original_append_event = SQLiteStateStore.append_event
            append_failed_after_commit = False

            def commit_action_receipt_then_raise(
                store, run_id, event_type, payload=None, **kwargs
            ):
                nonlocal append_failed_after_commit
                record = original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )
                if (
                    event_type
                    == "comparison_review_artifact_action_receipt"
                    and not append_failed_after_commit
                ):
                    append_failed_after_commit = True
                    raise RuntimeError("private post-commit receipt diagnostic")
                return record

            with patch.object(
                SQLiteStateStore,
                "append_event",
                new=commit_action_receipt_then_raise,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertTrue(append_failed_after_commit)
            first = report.rows[0]
            self.assertIs(first.status, RunStatus.SUCCEEDED)
            self.assertIsNotNone(first.review_artifact_path)
            artifact_path = Path(first.review_artifact_path or "")
            self.assertTrue(artifact_path.is_file())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(first.run_id)
            receipts = [
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            ]
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]["outcome"], "succeeded")
            self.assertEqual(
                receipts[0]["result_digest"],
                receipts[0]["intended_artifact_digest"],
            )
            self.assertNotIn(
                "private post-commit receipt diagnostic",
                "\n".join(event.payload_json for event in events),
            )
            inspection = inspect_authorization_shadows(
                root / ".ordomata/state.sqlite3",
                now=time.time(),
            )
            inspected = next(
                item for item in inspection.runs if item.run_id == first.run_id
            )
            self.assertEqual(inspected.integrity_issues, ())

    async def test_ambiguous_committed_action_receipt_preserves_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "ambiguous-committed-action-receipt",
            )
            original_append_event = SQLiteStateStore.append_event
            append_failed_after_commit = False

            def commit_action_receipt_then_raise(
                store, run_id, event_type, payload=None, **kwargs
            ):
                nonlocal append_failed_after_commit
                record = original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )
                if (
                    event_type
                    == "comparison_review_artifact_action_receipt"
                    and not append_failed_after_commit
                ):
                    append_failed_after_commit = True
                    raise RuntimeError("private ambiguous receipt diagnostic")
                return record

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=commit_action_receipt_then_raise,
                ),
                patch(
                    "ordomata.comparison."
                    "_comparison_review_artifact_action_receipt_persisted",
                    return_value=None,
                ),
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertTrue(append_failed_after_commit)
            self.assertEqual(len(report.rows), 1)
            first = report.rows[0]
            self.assertIs(first.status, RunStatus.QUARANTINED)
            self.assertIsNone(first.review_artifact_path)
            artifact_path = (
                root
                / ".ordomata/comparisons/"
                "ambiguous-committed-action-receipt/trials/001/"
                "review-output.json"
            )
            artifact_bytes = artifact_path.read_bytes()
            self.assertEqual(artifact_path.stat().st_mode & 0o077, 0)
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(first.run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "succeeded")
            self.assertEqual(
                receipt["result_digest"],
                "sha256:" + sha256(artifact_bytes).hexdigest(),
            )
            terminal = [
                event
                for event in events
                if event.status is RunStatus.QUARANTINED
            ][-1]
            self.assertIs(terminal.payload["artifact_observed"], True)
            self.assertNotIn(
                "private ambiguous receipt diagnostic",
                "\n".join(event.payload_json for event in events),
            )
            inspection = inspect_authorization_shadows(
                root / ".ordomata/state.sqlite3",
                now=time.time(),
            )
            inspected = next(
                item for item in inspection.runs if item.run_id == first.run_id
            )
            self.assertEqual(inspected.integrity_issues, ())

    async def test_action_receipt_readback_interruption_quarantines_effect(
        self,
    ) -> None:
        for commit_first in (False, True):
            with (
                self.subTest(commit_first=commit_first),
                tempfile.TemporaryDirectory() as temporary,
            ):
                comparison_id = (
                    "postcommit-readback-interruption"
                    if commit_first
                    else "precommit-readback-interruption"
                )
                root, prepared, profiles, plan = self._artifact_recovery_setup(
                    temporary,
                    comparison_id,
                )
                original_append_event = SQLiteStateStore.append_event
                interruption = asyncio.CancelledError(
                    "private receipt readback interruption diagnostic"
                )

                def append_action_receipt_then_raise(
                    store, run_id, event_type, payload=None, **kwargs
                ):
                    if (
                        event_type
                        != "comparison_review_artifact_action_receipt"
                    ):
                        return original_append_event(
                            store,
                            run_id,
                            event_type,
                            payload,
                            **kwargs,
                        )
                    if commit_first:
                        original_append_event(
                            store,
                            run_id,
                            event_type,
                            payload,
                            **kwargs,
                        )
                    raise RuntimeError(
                        "private receipt append interruption diagnostic"
                    )

                with (
                    patch.object(
                        SQLiteStateStore,
                        "append_event",
                        new=append_action_receipt_then_raise,
                    ),
                    patch(
                        "ordomata.comparison."
                        "_comparison_review_artifact_action_receipt_persisted",
                        side_effect=interruption,
                    ),
                    self.assertRaises(asyncio.CancelledError) as caught,
                ):
                    await run_controlled_comparison(
                        root,
                        prepared=prepared,
                        plan=plan,
                        profiles=profiles,
                        runner_factory=lambda _profile: RecordingMockRunner(
                            requests=[],
                            output=load_mock_chief_of_staff_output(
                                root,
                                prepared,
                            ),
                        ),
                    )

                self.assertIs(caught.exception, interruption)
                cause = caught.exception.__cause__
                self.assertIsInstance(cause, ConfigurationError)
                self.assertEqual(
                    str(cause),
                    "comparison artifact action receipt readback is uncertain",
                )
                artifact_path = (
                    root
                    / ".ordomata/comparisons"
                    / comparison_id
                    / "trials/001/review-output.json"
                )
                self.assertTrue(artifact_path.is_file())
                self.assertEqual(artifact_path.stat().st_mode & 0o077, 0)
                with SQLiteStateStore(
                    root / ".ordomata/state.sqlite3"
                ) as state:
                    runs = state.list_runs()
                    self.assertEqual(len(runs), 1)
                    run = runs[0]
                    self.assertIs(
                        state.current_status(run.run_id),
                        RunStatus.QUARANTINED,
                    )
                    events = state.list_events(run.run_id)
                receipts = [
                    event
                    for event in events
                    if event.event_type
                    == "comparison_review_artifact_action_receipt"
                ]
                self.assertEqual(len(receipts), int(commit_first))
                terminal = [
                    event
                    for event in events
                    if event.status is RunStatus.QUARANTINED
                ][-1]
                self.assertIs(terminal.payload["artifact_observed"], True)
                persisted = "\n".join(event.payload_json for event in events)
                self.assertNotIn(
                    "private receipt readback interruption diagnostic",
                    persisted,
                )
                self.assertNotIn(
                    "private receipt append interruption diagnostic",
                    persisted,
                )
                inspection = inspect_authorization_shadows(
                    root / ".ordomata/state.sqlite3",
                    now=time.time(),
                )
                inspected = next(
                    item
                    for item in inspection.runs
                    if item.run_id == run.run_id
                )
                if commit_first:
                    self.assertEqual(inspected.integrity_issues, ())
                else:
                    self.assertIn(
                        "comparison_publication_action_receipt_missing",
                        inspected.integrity_issues,
                    )

    async def test_internal_staging_cleanup_failure_is_quarantined(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "internal-staging-cleanup",
            )
            original_unlink = os.unlink

            def reject_staging_unlink(path, *args, **kwargs):
                name = Path(os.fspath(path)).name
                if (
                    name.startswith(".review-output.json.")
                    and name.endswith(".tmp")
                ):
                    raise OSError("private staging cleanup diagnostic")
                return original_unlink(path, *args, **kwargs)

            with (
                patch(
                    "ordomata.orchestrator.os.fsync",
                    side_effect=OSError("private staging fsync diagnostic"),
                ),
                patch(
                    "ordomata.artifact_filesystem.os.unlink",
                    new=reject_staging_unlink,
                ),
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            row = report.rows[0]
            self.assertIs(row.status, RunStatus.QUARANTINED)
            self.assertIsNone(row.review_artifact_path)
            self.assertIsNone(row.review_artifact_sha256)
            trial_directory = (
                root
                / ".ordomata/comparisons/internal-staging-cleanup/trials/001"
            )
            self.assertFalse((trial_directory / "review-output.json").exists())
            self.assertEqual(
                len(tuple(trial_directory.glob(".review-output.json.*.tmp"))),
                1,
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(row.run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "unknown")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_publication_outcome_unknown",
            )
            persisted = "\n".join(event.payload_json for event in events)
            self.assertNotIn("private staging cleanup diagnostic", persisted)
            self.assertNotIn("private staging fsync diagnostic", persisted)

    async def test_parent_directory_fsync_failure_is_quarantined(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "directory-fsync-failure",
            )
            original_fsync = os.fsync
            directory_fsync_attempted = False

            def reject_directory_fsync(descriptor):
                nonlocal directory_fsync_attempted
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    directory_fsync_attempted = True
                    raise OSError("private directory fsync diagnostic")
                return original_fsync(descriptor)

            with patch(
                "ordomata.orchestrator.os.fsync",
                new=reject_directory_fsync,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertTrue(directory_fsync_attempted)
            self.assertEqual(len(report.rows), 1)
            row = report.rows[0]
            self.assertIs(row.status, RunStatus.QUARANTINED)
            self.assertIsNone(row.review_artifact_path)
            self.assertIsNone(row.review_artifact_sha256)
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(row.run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "unknown")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_publication_outcome_unknown",
            )
            self.assertNotIn(
                "private directory fsync diagnostic",
                "\n".join(event.payload_json for event in events),
            )

    async def test_promote_then_raise_removes_exact_private_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "promote-then-raise",
            )

            def expose_then_raise(staged_path, artifact_path):
                _promote_staged_artifact(staged_path, artifact_path)
                raise OSError("private post-promotion diagnostic")

            with patch(
                "ordomata.comparison._promote_staged_artifact",
                new=expose_then_raise,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.FAILED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            artifact_path = (
                root
                / ".ordomata/comparisons/promote-then-raise/trials/001/review-output.json"
            )
            self.assertFalse(artifact_path.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "failed")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_persistence_failed",
            )
            self.assertNotIn(
                "private post-promotion diagnostic",
                "\n".join(event.payload_json for event in events),
            )

    async def test_post_promotion_readback_mismatch_is_removed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "readback-mismatch",
            )

            def corrupt_after_promotion(staged_path, artifact_path):
                _promote_staged_artifact(staged_path, artifact_path)
                artifact_path.write_bytes(b"unexpected private bytes")

            with patch(
                "ordomata.comparison._promote_staged_artifact",
                new=corrupt_after_promotion,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.BLOCKED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            artifact_path = (
                root
                / ".ordomata/comparisons/readback-mismatch/trials/001/review-output.json"
            )
            self.assertFalse(artifact_path.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "failed")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_persistence_failed",
            )

    async def test_unremovable_publication_effect_is_quarantined(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "unremovable-publication",
            )
            original_unlink = os.unlink

            def expose_then_raise(staged_path, artifact_path):
                _promote_staged_artifact(staged_path, artifact_path)
                raise OSError("private post-promotion diagnostic")

            def reject_final_unlink(path, *args, **kwargs):
                if Path(os.fspath(path)).name == "review-output.json":
                    raise OSError("private unlink diagnostic")
                return original_unlink(path, *args, **kwargs)

            with (
                patch(
                    "ordomata.comparison._promote_staged_artifact",
                    new=expose_then_raise,
                ),
                patch(
                    "ordomata.artifact_filesystem.os.unlink",
                    new=reject_final_unlink,
                ),
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.QUARANTINED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            artifact_path = (
                root
                / ".ordomata/comparisons/unremovable-publication/trials/001/review-output.json"
            )
            self.assertTrue(artifact_path.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "unknown")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_publication_outcome_unknown",
            )
            persisted = "\n".join(event.payload_json for event in events)
            self.assertNotIn("private post-promotion diagnostic", persisted)
            self.assertNotIn("private unlink diagnostic", persisted)

    async def test_unremovable_staging_effect_is_quarantined(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "unremovable-staging",
            )
            original_unlink = os.unlink

            def retain_staging_name(stage, artifact_path):
                os.link(
                    stage.path,
                    artifact_path,
                    follow_symlinks=False,
                )

            def reject_staging_unlink(path, *args, **kwargs):
                if Path(os.fspath(path)).name.startswith(
                    ".review-output.json."
                ):
                    raise OSError("private staging unlink diagnostic")
                return original_unlink(path, *args, **kwargs)

            with (
                patch(
                    "ordomata.comparison._promote_staged_artifact",
                    new=retain_staging_name,
                ),
                patch(
                    "ordomata.artifact_filesystem.os.unlink",
                    new=reject_staging_unlink,
                ),
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.QUARANTINED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            trial_directory = (
                root
                / ".ordomata/comparisons/unremovable-staging/trials/001"
            )
            self.assertFalse((trial_directory / "review-output.json").exists())
            self.assertEqual(
                len(tuple(trial_directory.glob(".review-output.json.*.tmp"))),
                1,
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "unknown")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_publication_outcome_unknown",
            )
            self.assertNotIn(
                "private staging unlink diagnostic",
                "\n".join(event.payload_json for event in events),
            )

    async def test_cancellation_after_promotion_removes_effect_and_reraises(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "cancel-after-promotion",
            )
            interruption = asyncio.CancelledError(
                "private post-promotion cancellation diagnostic"
            )

            def expose_then_cancel(staged_path, artifact_path):
                _promote_staged_artifact(staged_path, artifact_path)
                raise interruption

            with (
                patch(
                    "ordomata.comparison._promote_staged_artifact",
                    new=expose_then_cancel,
                ),
                self.assertRaises(asyncio.CancelledError) as caught,
            ):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertIs(caught.exception, interruption)
            artifact_path = (
                root
                / ".ordomata/comparisons/cancel-after-promotion/trials/001/review-output.json"
            )
            self.assertFalse(artifact_path.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                self.assertIs(
                    state.current_status(runs[0].run_id),
                    RunStatus.CANCELLED,
                )
                events = state.list_events(runs[0].run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "cancelled")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_persistence_interrupted",
            )
            self.assertNotIn(
                "private post-promotion cancellation diagnostic",
                "\n".join(event.payload_json for event in events),
            )

    async def test_missing_action_receipt_with_unremovable_effect_quarantines(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, prepared, profiles, plan = self._artifact_recovery_setup(
                temporary,
                "unremovable-receipt-gap",
            )
            original_append_event = SQLiteStateStore.append_event
            original_unlink = os.unlink

            def reject_action_receipt(
                store, run_id, event_type, payload=None, **kwargs
            ):
                if event_type == "comparison_review_artifact_action_receipt":
                    raise RuntimeError("private receipt diagnostic")
                return original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            def reject_final_unlink(path, *args, **kwargs):
                if Path(os.fspath(path)).name == "review-output.json":
                    raise OSError("private unlink diagnostic")
                return original_unlink(path, *args, **kwargs)

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=reject_action_receipt,
                ),
                patch(
                    "ordomata.artifact_filesystem.os.unlink",
                    new=reject_final_unlink,
                ),
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(report.rows), 1)
            self.assertIs(report.rows[0].status, RunStatus.QUARANTINED)
            self.assertIsNone(report.rows[0].review_artifact_path)
            artifact_path = (
                root
                / ".ordomata/comparisons/unremovable-receipt-gap/trials/001/review-output.json"
            )
            self.assertTrue(artifact_path.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                events = state.list_events(report.rows[0].run_id)
            self.assertNotIn(
                "comparison_review_artifact_action_receipt",
                [event.event_type for event in events],
            )
            persisted = "\n".join(event.payload_json for event in events)
            self.assertNotIn("private receipt diagnostic", persisted)
            self.assertNotIn("private unlink diagnostic", persisted)

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
                COMPARISON_AUTHORIZATION_SHADOW_COVERAGE,
            )
            self.assertEqual(payload["trials"][0]["status"], "quarantined")

            state_path = root / ".ordomata/state.sqlite3"
            with SQLiteStateStore(state_path) as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                self.assertEqual(
                    runs[0].run_id,
                    payload["trials"][0]["run_id"],
                )
                self.assertIs(
                    runs[0].permission_class,
                    PermissionClass.READ_ONLY,
                )
                self.assertIs(
                    state.current_status(runs[0].run_id),
                    RunStatus.QUARANTINED,
                )
                events = state.list_events(runs[0].run_id)
                self.assertEqual(
                    [event.event_type for event in events],
                    [
                        "status",
                        "comparison_trial_binding",
                        "authorization_shadow_decision",
                        "billing_assessment",
                        "status",
                        "authorization_shadow_decision",
                        "execution_accounting",
                        "authorization_shadow_decision",
                        "comparison_review_artifact_intent",
                        "comparison_review_artifact_action_receipt",
                        "status",
                    ],
                )
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
            inspection = inspect_authorization_shadows(state_path, now=time.time())
            self.assertEqual(inspection.inspected_run_count, 1)
            self.assertEqual(
                inspection.runs[0].observed_scopes,
                tuple(
                    sorted(
                        (ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE)
                    )
                ),
            )
            self.assertEqual(inspection.runs[0].missing_scopes, ())

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
            with SQLiteStateStore(state_path) as state:
                self.assertEqual(len(state.list_runs()), 1)

    async def test_billing_capacity_write_failure_recovers_as_unknown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            fingerprint = "4" * 64
            assessment = self._included_subscription_assessment(fingerprint)
            profiles = self._subscription_profiles(
                "codex.capacity-retry-a",
                "codex.capacity-retry-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="capacity-write-retry",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            executions: list[str] = []
            capacity_writes = 0
            original_capacity_write = (
                SQLiteStateStore.append_billing_capacity_event
            )

            def fail_first_capacity_write(store, **kwargs):
                nonlocal capacity_writes
                capacity_writes += 1
                if capacity_writes == 1:
                    raise RuntimeError("private first capacity write diagnostic")
                return original_capacity_write(store, **kwargs)

            with patch.object(
                SQLiteStateStore,
                "append_billing_capacity_event",
                new=fail_first_capacity_write,
            ):
                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: AdversarialResultRunner(
                        assessment=assessment,
                        postflight_assessment=assessment,
                        output=load_mock_chief_of_staff_output(root, prepared),
                        executions=executions,
                    ),
                )

            payload = report.to_mapping()
            self.assertEqual(capacity_writes, 2)
            self.assertEqual(len(executions), 1)
            self.assertEqual(payload["completed_trial_count"], 1)
            self.assertFalse(payload["execution_complete"])
            self.assertEqual(payload["trials"][0]["status"], "quarantined")
            self.assertIsNone(payload["trials"][0]["review_artifact_path"])
            state_path = root / ".ordomata/state.sqlite3"
            profile_id = payload["trials"][0]["profile_id"]
            with SQLiteStateStore(state_path) as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                run = runs[0]
                self.assertIs(
                    state.current_status(run.run_id),
                    RunStatus.QUARANTINED,
                )
                events = state.list_events(run.run_id)
                self.assertEqual(
                    [event.event_type for event in events],
                    [
                        "status",
                        "comparison_trial_binding",
                        "authorization_shadow_decision",
                        "billing_assessment",
                        "status",
                        "authorization_shadow_decision",
                        "execution_accounting",
                        "status",
                    ],
                )
                accounting = events[-2].payload
                self.assertTrue(accounting["result_observed"])
                self.assertEqual(
                    accounting["paid_capacity_consumed"],
                    "unknown",
                )
                self.assertEqual(
                    accounting["incremental_ai_charge"],
                    "unknown",
                )
                self.assertTrue(accounting["billing_quarantine_required"])
                self.assertTrue(
                    accounting["billing_circuit_breaker_required"]
                )
                capacity = state.latest_billing_capacity_event(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id=profile_id,
                )
                circuits = tuple(
                    state.current_billing_circuit(
                        runner_id="codex",
                        account_identity_fingerprint=account,
                        profile_id=profile,
                    )
                    for account, profile in (
                        (fingerprint, profile_id),
                        (fingerprint, None),
                        (None, profile_id),
                        (None, None),
                    )
                )
            self.assertIsNotNone(capacity)
            assert capacity is not None
            self.assertIs(capacity.capacity_state, CapacityState.UNKNOWN)
            self.assertTrue(
                all(
                    circuit is not None
                    and circuit.state is CircuitBreakerState.OPEN
                    for circuit in circuits
                )
            )
            self.assertNotIn(
                "private first capacity write diagnostic",
                Path(report.report_path).read_text(encoding="utf-8"),
            )

    async def test_billing_capacity_write_and_recovery_failure_raise(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            fingerprint = "5" * 64
            assessment = self._included_subscription_assessment(fingerprint)
            profiles = self._subscription_profiles(
                "codex.capacity-fail-a",
                "codex.capacity-fail-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="capacity-write-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            executions: list[str] = []
            capacity_writes = 0

            def reject_capacity_writes(store, **kwargs):
                nonlocal capacity_writes
                del store, kwargs
                capacity_writes += 1
                raise RuntimeError("private persistent capacity diagnostic")

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_billing_capacity_event",
                    new=reject_capacity_writes,
                ),
                self.assertRaisesRegex(
                    ConfigurationError,
                    "comparison billing recovery could not be persisted",
                ) as caught,
            ):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: AdversarialResultRunner(
                        assessment=assessment,
                        postflight_assessment=assessment,
                        output=load_mock_chief_of_staff_output(root, prepared),
                        executions=executions,
                    ),
                )

            self.assertEqual(capacity_writes, 2)
            self.assertEqual(len(executions), 1)
            self.assertNotIn(
                "private persistent capacity diagnostic",
                str(caught.exception),
            )
            comparison_directory = (
                root / ".ordomata/comparisons/capacity-write-failure"
            )
            self.assertFalse((comparison_directory / "report.json").exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                run = runs[0]
                self.assertIs(
                    state.current_status(run.run_id),
                    RunStatus.QUARANTINED,
                )
                events = state.list_events(run.run_id)
                self.assertNotIn(
                    "comparison_review_artifact_intent",
                    [event.event_type for event in events],
                )
                self.assertNotIn(
                    "comparison_review_artifact_action_receipt",
                    [event.event_type for event in events],
                )
                accounting = next(
                    event.payload
                    for event in events
                    if event.event_type == "execution_accounting"
                )
                self.assertEqual(
                    accounting["paid_capacity_consumed"],
                    "unknown",
                )
                self.assertEqual(
                    accounting["incremental_ai_charge"],
                    "unknown",
                )
                self.assertTrue(accounting["billing_quarantine_required"])
                self.assertTrue(
                    accounting["billing_circuit_breaker_required"]
                )

    async def test_untrusted_subscription_postflight_withholds_usable_output(
        self,
    ) -> None:
        for case in ("missing", "identity_changed"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                prepared = prepare_chief_of_staff(root)
                fingerprint = "7" * 64
                assessment = self._included_subscription_assessment(fingerprint)
                postflight = None
                if case == "identity_changed":
                    changed_fingerprint = "8" * 64
                    self.assertIsNotNone(assessment.attestation)
                    assert assessment.attestation is not None
                    postflight = replace(
                        assessment,
                        account_identity_fingerprint=changed_fingerprint,
                        attestation=replace(
                            assessment.attestation,
                            account_identity_fingerprint=changed_fingerprint,
                        ),
                    )
                profiles = self._subscription_profiles(
                    f"codex.postflight-{case}-a",
                    f"codex.postflight-{case}-b",
                )
                plan = ControlledComparisonPlan.create(
                    comparison_id=f"postflight-{case}",
                    snapshot=comparison_snapshot_from_prepared(prepared),
                    profiles=tuple(
                        ComparisonProfile.from_execution_profile(profile)
                        for profile in profiles
                    ),
                    repetitions=2,
                    random_seed=17,
                )
                executions: list[str] = []

                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: AdversarialResultRunner(
                        assessment=assessment,
                        output=load_mock_chief_of_staff_output(root, prepared),
                        executions=executions,
                        postflight_assessment=postflight,
                    ),
                )
                payload = report.to_mapping()

                self.assertEqual(len(executions), 1)
                self.assertEqual(payload["completed_trial_count"], 1)
                self.assertFalse(payload["execution_complete"])
                self.assertFalse(payload["automated_checks_succeeded"])
                self.assertEqual(payload["trials"][0]["status"], "quarantined")
                artifact_path = Path(
                    payload["trials"][0]["review_artifact_path"]
                )
                artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
                self.assertIsNone(artifact["output"])
                self.assertEqual(
                    artifact["output_withheld_reason"],
                    "billing_or_identity_mismatch",
                )
                self.assertNotIn("executive_summary", json.dumps(artifact))

                with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                    runs = state.list_runs()
                    self.assertEqual(len(runs), 1)
                    self.assertIs(
                        state.current_status(runs[0].run_id),
                        RunStatus.QUARANTINED,
                    )
                    events = state.list_events(runs[0].run_id)
                    event_types = [event.event_type for event in events]
                    self.assertIn(
                        "comparison_review_artifact_intent",
                        event_types,
                    )
                    self.assertIn(
                        "comparison_review_artifact_action_receipt",
                        event_types,
                    )
                    receipt = next(
                        event.payload
                        for event in events
                        if event.event_type
                        == "comparison_review_artifact_action_receipt"
                    )
                    self.assertTrue(receipt["output_withheld"])
                    self.assertEqual(receipt["outcome"], "succeeded")

    async def test_artifact_write_cancellation_records_receipt_and_reraises(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.artifact-cancel-a",
                "mock.artifact-cancel-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="artifact-write-cancelled",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            interruption = asyncio.CancelledError(
                "private artifact cancellation diagnostic"
            )

            with (
                patch(
                    "ordomata.comparison._stage_artifact",
                    side_effect=interruption,
                ),
                self.assertRaises(asyncio.CancelledError) as caught,
            ):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=[],
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertIs(caught.exception, interruption)
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                self.assertIs(
                    state.current_status(runs[0].run_id),
                    RunStatus.CANCELLED,
                )
                events = state.list_events(runs[0].run_id)
            receipt = next(
                event.payload
                for event in events
                if event.event_type
                == "comparison_review_artifact_action_receipt"
            )
            self.assertEqual(receipt["outcome"], "cancelled")
            self.assertEqual(
                receipt["failure_code"],
                "artifact_persistence_interrupted",
            )
            self.assertIsNone(receipt["result_digest"])
            persisted = "\n".join(event.payload_json for event in events)
            self.assertNotIn(
                "private artifact cancellation diagnostic",
                persisted,
            )
            self.assertFalse(
                (
                    root
                    / ".ordomata/comparisons/artifact-write-cancelled/trials/001/review-output.json"
                ).exists()
            )

    async def test_subscription_cancellation_recovers_unknown_billing_and_reraises(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            fingerprint = "9" * 64
            assessment = self._included_subscription_assessment(fingerprint)
            profiles = self._subscription_profiles(
                "codex.cancel-a",
                "codex.cancel-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="subscription-cancelled",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            executions: list[str] = []

            with self.assertRaises(asyncio.CancelledError):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: CancellingSubscriptionRunner(
                        assessment=assessment,
                        output=None,
                        executions=executions,
                    ),
                )

            self.assertEqual(len(executions), 1)
            comparison_directory = (
                root / ".ordomata/comparisons/subscription-cancelled"
            )
            self.assertFalse((comparison_directory / "report.json").exists())
            state_path = root / ".ordomata/state.sqlite3"
            with SQLiteStateStore(state_path) as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                run = runs[0]
                self.assertIs(
                    state.current_status(run.run_id),
                    RunStatus.QUARANTINED,
                )
                events = state.list_events(run.run_id)
                self.assertEqual(
                    [event.event_type for event in events],
                    [
                        "status",
                        "comparison_trial_binding",
                        "authorization_shadow_decision",
                        "billing_assessment",
                        "status",
                        "authorization_shadow_decision",
                        "execution_accounting",
                        "status",
                    ],
                )
                accounting = events[-2].payload
                self.assertFalse(accounting["result_observed"])
                self.assertEqual(
                    accounting["paid_capacity_consumed"],
                    "unknown",
                )
                self.assertEqual(
                    accounting["incremental_ai_charge"],
                    "unknown",
                )
                self.assertTrue(accounting["billing_quarantine_required"])
                self.assertTrue(
                    accounting["billing_circuit_breaker_required"]
                )
                capacity = state.latest_billing_capacity_event(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id=plan.trials[0].profile_id,
                )
                circuits = {
                    (account, profile): state.current_billing_circuit(
                        runner_id="codex",
                        account_identity_fingerprint=account,
                        profile_id=profile,
                    )
                    for account, profile in (
                        (fingerprint, plan.trials[0].profile_id),
                        (fingerprint, None),
                        (None, plan.trials[0].profile_id),
                        (None, None),
                    )
                }
            self.assertIsNotNone(capacity)
            assert capacity is not None
            self.assertIs(capacity.capacity_state, CapacityState.UNKNOWN)
            self.assertTrue(all(value is not None for value in circuits.values()))
            self.assertTrue(
                all(
                    value is not None
                    and value.state is CircuitBreakerState.OPEN
                    for value in circuits.values()
                )
            )

    async def test_subscription_cancellation_recovery_failure_preserves_cancellation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            fingerprint = "6" * 64
            assessment = self._included_subscription_assessment(fingerprint)
            profiles = self._subscription_profiles(
                "codex.cancel-recovery-a",
                "codex.cancel-recovery-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="subscription-cancel-recovery-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            executions: list[str] = []
            capacity_writes = 0

            def reject_capacity_writes(store, **kwargs):
                nonlocal capacity_writes
                del store, kwargs
                capacity_writes += 1
                raise RuntimeError(
                    "private cancellation recovery diagnostic"
                )

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_billing_capacity_event",
                    new=reject_capacity_writes,
                ),
                self.assertRaises(asyncio.CancelledError) as caught,
            ):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: CancellingSubscriptionRunner(
                        assessment=assessment,
                        output=None,
                        executions=executions,
                    ),
                )

            self.assertEqual(capacity_writes, 2)
            self.assertEqual(len(executions), 1)
            cause = caught.exception.__cause__
            self.assertIsInstance(cause, ConfigurationError)
            self.assertEqual(
                str(cause),
                "comparison interruption recovery could not be persisted",
            )
            self.assertEqual(
                caught.exception.__notes__,
                ["Ordomata interruption recovery was not fully persisted."],
            )
            self.assertNotIn(
                "private cancellation recovery diagnostic",
                str(cause),
            )
            self.assertNotIn(
                "private cancellation recovery diagnostic",
                "\n".join(caught.exception.__notes__),
            )
            comparison_directory = (
                root
                / ".ordomata/comparisons/subscription-cancel-recovery-failure"
            )
            self.assertFalse((comparison_directory / "report.json").exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                run = runs[0]
                self.assertIs(
                    state.current_status(run.run_id),
                    RunStatus.QUARANTINED,
                )
                events = state.list_events(run.run_id)
                self.assertEqual(events[-1].status, RunStatus.QUARANTINED)
                self.assertEqual(events[-1].event_type, "status")
                self.assertNotIn(
                    "comparison_review_artifact_intent",
                    [event.event_type for event in events],
                )
                accounting = next(
                    event.payload
                    for event in events
                    if event.event_type == "execution_accounting"
                )
                self.assertEqual(
                    accounting["paid_capacity_consumed"],
                    "unknown",
                )
                self.assertEqual(
                    accounting["incremental_ai_charge"],
                    "unknown",
                )
                self.assertTrue(accounting["billing_quarantine_required"])
                self.assertTrue(
                    accounting["billing_circuit_breaker_required"]
                )

    async def test_terminal_event_failure_cannot_return_running_report(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profiles = self._mock_profiles(
                root,
                "mock.terminal-a",
                "mock.terminal-b",
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="terminal-write-failure",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            requests = []
            original_append_event = SQLiteStateStore.append_event
            terminal_statuses = {
                RunStatus.SUCCEEDED,
                RunStatus.FAILED,
                RunStatus.BLOCKED,
                RunStatus.QUARANTINED,
                RunStatus.CANCELLED,
            }

            def reject_terminal(store, run_id, event_type, payload=None, **kwargs):
                if kwargs.get("status") in terminal_statuses:
                    raise RuntimeError("private terminal audit diagnostic")
                return original_append_event(
                    store,
                    run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=reject_terminal,
                ),
                self.assertRaises(Exception),
            ):
                await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: RecordingMockRunner(
                        requests=requests,
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

            self.assertEqual(len(requests), 1)
            comparison_directory = (
                root / ".ordomata/comparisons/terminal-write-failure"
            )
            self.assertFalse((comparison_directory / "report.json").exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                self.assertIs(
                    state.current_status(runs[0].run_id),
                    RunStatus.RUNNING,
                )

    async def test_mismatched_result_output_is_withheld(
        self,
    ) -> None:
        for mismatch in ("runner", "billing"):
            with (
                self.subTest(mismatch=mismatch),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                prepared = prepare_chief_of_staff(root)
                profiles = self._mock_profiles(
                    root,
                    f"mock.{mismatch}-mismatch-a",
                    f"mock.{mismatch}-mismatch-b",
                )
                plan = ControlledComparisonPlan.create(
                    comparison_id=f"{mismatch}-result-mismatch",
                    snapshot=comparison_snapshot_from_prepared(prepared),
                    profiles=tuple(
                        ComparisonProfile.from_execution_profile(profile)
                        for profile in profiles
                    ),
                    repetitions=2,
                    random_seed=17,
                )
                executions: list[str] = []

                report = await run_controlled_comparison(
                    root,
                    prepared=prepared,
                    plan=plan,
                    profiles=profiles,
                    runner_factory=lambda _profile: MismatchedMockResultRunner(
                        mismatch=mismatch,
                        executions=executions,
                        output=load_mock_chief_of_staff_output(root, prepared),
                    ),
                )

                self.assertEqual(len(executions), 1)
                self.assertEqual(len(report.rows), 1)
                self.assertIs(report.rows[0].status, RunStatus.QUARANTINED)
                artifact = json.loads(
                    Path(report.rows[0].review_artifact_path).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertIsNone(artifact["output"])
                self.assertEqual(
                    artifact["output_withheld_reason"],
                    "billing_or_identity_mismatch",
                )
                self.assertNotIn("executive_summary", json.dumps(artifact))
                with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                    events = state.list_events(report.rows[0].run_id)
                    receipt = next(
                        event.payload
                        for event in events
                        if event.event_type
                        == "comparison_review_artifact_action_receipt"
                    )
                    self.assertTrue(receipt["output_withheld"])
                    self.assertEqual(receipt["outcome"], "succeeded")

    async def test_subscription_exception_quarantines_and_opens_circuits(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            fingerprint = "e" * 64
            assessment = self._included_subscription_assessment(fingerprint)
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
                for profile_id in (
                    "codex.exception-a",
                    "codex.exception-b",
                )
            )
            plan = ControlledComparisonPlan.create(
                comparison_id="subscription-exception",
                snapshot=comparison_snapshot_from_prepared(prepared),
                profiles=tuple(
                    ComparisonProfile.from_execution_profile(profile)
                    for profile in profiles
                ),
                repetitions=2,
                random_seed=17,
            )
            executions = []

            report = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=plan,
                profiles=profiles,
                runner_factory=lambda _profile: ExplodingSubscriptionRunner(
                    assessment=assessment,
                    output=None,
                    executions=executions,
                ),
            )
            payload = report.to_mapping()

            self.assertEqual(len(executions), 1)
            self.assertEqual(payload["completed_trial_count"], 1)
            self.assertFalse(payload["execution_complete"])
            self.assertEqual(payload["trials"][0]["status"], "quarantined")
            self.assertEqual(
                payload["trials"][0]["failure_type"],
                "billing_execution_unknown",
            )
            self.assertEqual(
                payload["trials"][0]["error_codes"],
                ["billing_execution_unknown"],
            )
            self.assertIsNone(payload["trials"][0]["review_artifact_path"])

            profile_id = payload["trials"][0]["profile_id"]
            state_path = root / ".ordomata/state.sqlite3"
            with SQLiteStateStore(state_path) as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                run = runs[0]
                self.assertIs(
                    state.current_status(run.run_id),
                    RunStatus.QUARANTINED,
                )
                events = state.list_events(run.run_id)
                self.assertEqual(
                    [event.event_type for event in events],
                    [
                        "status",
                        "comparison_trial_binding",
                        "authorization_shadow_decision",
                        "billing_assessment",
                        "status",
                        "authorization_shadow_decision",
                        "execution_accounting",
                        "status",
                    ],
                )
                accounting = events[-2].payload
                self.assertEqual(
                    accounting,
                    {
                        "schema_version": 2,
                        "result_observed": False,
                        "identity_matches": None,
                        "billing_matches": None,
                        "runner_event_count": 0,
                        "result_status": "unknown",
                        "harness_process_started": None,
                        "live_model_execution_occurred": None,
                        "subscription_capacity_consumed": None,
                        "paid_capacity_consumed": "unknown",
                        "incremental_ai_charge": "unknown",
                        "capacity_state": "unknown",
                        "billing_disposition_reason_codes": [],
                        "billing_disposition_digest": None,
                        "usage_observation": "unavailable",
                        "billing_quarantine_required": True,
                        "billing_circuit_breaker_required": True,
                        "failure_code": "billing_execution_unknown",
                        "wall_seconds": None,
                    },
                )
                capacity = state.latest_billing_capacity_event(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id=profile_id,
                )
                exact = state.current_billing_circuit(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id=profile_id,
                )
                broad = state.current_billing_circuit(
                    runner_id="codex",
                    account_identity_fingerprint=None,
                    profile_id=profile_id,
                )
                account_wide = state.current_billing_circuit(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id=None,
                )
                global_scope = state.current_billing_circuit(
                    runner_id="codex",
                    account_identity_fingerprint=None,
                    profile_id=None,
                )
                self.assertTrue(
                    all(
                        "private subscription execution diagnostic"
                        not in event.payload_json
                        for event in events
                    )
                )
            self.assertIsNotNone(capacity)
            assert capacity is not None
            self.assertIs(capacity.capacity_state, CapacityState.UNKNOWN)
            self.assertEqual(capacity.reason_code, "post_run_billing_unknown")
            self.assertIsNotNone(exact)
            self.assertIsNotNone(broad)
            self.assertIsNotNone(account_wide)
            self.assertIsNotNone(global_scope)
            assert exact is not None
            assert broad is not None
            assert account_wide is not None
            assert global_scope is not None
            self.assertIs(exact.state, CircuitBreakerState.OPEN)
            self.assertIs(broad.state, CircuitBreakerState.OPEN)
            self.assertIs(account_wide.state, CircuitBreakerState.OPEN)
            self.assertIs(global_scope.state, CircuitBreakerState.OPEN)
            persisted_report = Path(report.report_path).read_text(
                encoding="utf-8"
            )
            persisted_review = Path(report.review_template_path).read_text(
                encoding="utf-8"
            )
            self.assertNotIn(
                "private subscription execution diagnostic",
                persisted_report,
            )
            self.assertNotIn(
                "private subscription execution diagnostic",
                persisted_review,
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

            state_path = root / ".ordomata" / "state.sqlite3"
            with SQLiteStateStore(state_path) as state:
                runs = state.list_runs()
                self.assertEqual(len(runs), 1)
                run = runs[0]
                self.assertEqual(run.run_id, payload["trials"][0]["run_id"])
                self.assertIs(run.permission_class, PermissionClass.READ_ONLY)
                self.assertIs(
                    state.current_status(run.run_id),
                    RunStatus.FAILED,
                )
                events = state.list_events(run.run_id)
                self.assertEqual(
                    [event.event_type for event in events],
                    [
                        "status",
                        "comparison_trial_binding",
                        "authorization_shadow_decision",
                        "billing_assessment",
                        "status",
                        "authorization_shadow_decision",
                        "execution_accounting",
                        "status",
                    ],
                )
                self.assertEqual(
                    events[-2].payload["failure_code"],
                    "runner_execution_error",
                )
                self.assertTrue(
                    all(
                        "secret diagnostic" not in event.payload_json
                        for event in events
                    )
                )
            inspection = inspect_authorization_shadows(state_path, now=time.time())
            self.assertTrue(inspection.clean)
            self.assertEqual(inspection.inspected_run_count, 1)
            self.assertEqual(
                inspection.runs[0].expected_scopes,
                tuple(sorted((ADMISSION_SCOPE, DISPATCH_SCOPE))),
            )
            self.assertEqual(inspection.runs[0].missing_scopes, ())

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
