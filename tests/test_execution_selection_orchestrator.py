import asyncio
from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.billing import LIVE_RUN_EVIDENCE_MARGIN_SECONDS
from ordomata.cli import _run_profile
from ordomata.errors import (
    BillingRouteBlocked,
    ConfigurationError,
    ValidationError,
)
from ordomata.execution_selection import (
    ExecutionSelection,
    build_execution_selection,
)
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PaidContinuationProtection,
    PaidCreditBalance,
    PermissionClass,
    RunnerExecutionResult,
    RunStatus,
    UsageObservation,
)
from ordomata.orchestrator import (
    load_mock_chief_of_staff_output,
    prepare_chief_of_staff,
    run_chief_of_staff,
)
from ordomata.routing import (
    ExecutionProfile,
    RuntimeProfileState,
    TaskRoutingFeatures,
    load_execution_profiles,
    runner_overrides_for_profile,
)
from ordomata.runners.mock import MockRunner
from ordomata.shadow_authorization import task_authorization_intent_digest
from ordomata.state import SQLiteStateStore
from ordomata.task_evidence import TASK_EXECUTION_SELECTION_EVENT_TYPE


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class RecordingMockRunner(MockRunner):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.inspect_count = 0
        self.execute_count = 0
        self.requests = []

    async def inspect_billing_route(self):
        self.inspect_count += 1
        return await super().inspect_billing_route()

    async def execute(self, request, event_sink):
        self.execute_count += 1
        self.requests.append(request)
        return await super().execute(request, event_sink)


class RecordingSubscriptionFixtureRunner:
    runner_id = "codex"

    def __init__(self, assessment, output) -> None:
        self.assessment = assessment
        self.output = output
        self.inspect_count = 0
        self.execute_count = 0

    async def inspect_billing_route(self):
        self.inspect_count += 1
        return self.assessment

    async def execute(self, request, event_sink):
        del event_sink
        self.execute_count += 1
        return RunnerExecutionResult(
            runner_id=self.runner_id,
            run_id=request.run_id,
            status=RunStatus.SUCCEEDED,
            billing_assessment=self.assessment,
            output=self.output,
            usage_observation=UsageObservation.UNAVAILABLE,
            runner_version="deterministic-selection-fixture",
            execution_mode="codex_exec_jsonl_read_only_ephemeral",
            harness_process_started=True,
            live_model_execution_occurred=True,
            subscription_capacity_consumed=True,
            paid_capacity_consumed=PaidCapacityConsumed.NO,
            incremental_ai_charge=IncrementalAICharge.NONE,
            postflight_billing_assessment=self.assessment,
            wall_seconds=0.0,
        )


class NeverExecuteMismatchedRunner:
    runner_id = "codex"

    def __init__(self) -> None:
        self.inspect_count = 0
        self.execute_count = 0

    async def inspect_billing_route(self):
        self.inspect_count += 1
        raise AssertionError("mismatched selection must block before preflight")

    async def execute(self, request, event_sink):
        del request, event_sink
        self.execute_count += 1
        raise AssertionError("mismatched selection must never execute")


class ExecutionSelectionOrchestratorTests(unittest.TestCase):
    def _project(self, temporary: str) -> Path:
        root = Path(temporary)
        for name in ("tasks", "schemas", "fixtures", "profiles"):
            shutil.copytree(REPOSITORY_ROOT / name, root / name)
        return root

    @staticmethod
    def _mock_profile(root: Path) -> ExecutionProfile:
        profiles = load_execution_profiles(root / "profiles" / "default.json")
        return next(profile for profile in profiles if profile.runner_id == "mock")

    @staticmethod
    def _routing_task(
        prepared,
        *,
        lane: str = "mock",
    ) -> TaskRoutingFeatures:
        if lane == "mock":
            allowed_roles = frozenset({"test"})
            allowed_routes = frozenset({BillingRoute.MOCK})
        else:
            allowed_roles = frozenset({"synthesis"})
            allowed_routes = frozenset({BillingRoute.SUBSCRIPTION_INCLUDED})
        return TaskRoutingFeatures(
            task_kind="chief_of_staff",
            permission_class=prepared.contract.permission_class,
            required_capabilities=frozenset(
                {"structured_output", "local_draft", "isolated_workspace"}
            ),
            allowed_roles=allowed_roles,
            allowed_billing_routes=allowed_routes,
            context_bytes=prepared.context_pack.raw_bytes,
            risk=1,
        )

    @classmethod
    def _runtime_state(
        cls,
        root: Path,
        *,
        profile: ExecutionProfile | None = None,
    ) -> RuntimeProfileState:
        selected_profile = profile or cls._mock_profile(root)
        return RuntimeProfileState(
            profile=selected_profile,
            billing_assessment=BillingRouteAssessment(
                runner_id="mock",
                route=BillingRoute.MOCK,
                confidence=AssessmentConfidence.HIGH,
            ),
            available=True,
        )

    @staticmethod
    def _codex_assessment(
        *,
        now: float,
        expires_at: float | None = None,
        fingerprint: str = "c" * 64,
    ) -> BillingRouteAssessment:
        selected_expiry = now + 1_800 if expires_at is None else expires_at
        protection = (
            PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
        )
        attestation = BillingSafetyAttestation(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
            capacity_state=CapacityState.AVAILABLE,
            paid_continuation_protection=protection,
            observed_at=now - 1,
            expires_at=selected_expiry,
            confidence=AssessmentConfidence.HIGH,
            evidence=(
                "operator_attestation:provider_ui_auto_top_up_disabled",
            ),
        )
        return BillingRouteAssessment(
            runner_id="codex",
            route=BillingRoute.SUBSCRIPTION_INCLUDED,
            confidence=AssessmentConfidence.HIGH,
            subscription_name="ChatGPT",
            capacity_state=CapacityState.AVAILABLE,
            paid_continuation_protection=protection,
            paid_credit_balance=PaidCreditBalance.ZERO,
            account_identity_fingerprint=fingerprint,
            capacity_observed_at=now - 1,
            capacity_expires_at=selected_expiry,
            attestation=attestation,
        )

    @staticmethod
    def _install_private_codex_profile(
        root: Path,
        *,
        model_id: str,
    ) -> ExecutionProfile:
        profile_path = root / "profiles" / "default.json"
        document = json.loads(profile_path.read_text(encoding="utf-8"))
        raw_profile = next(
            item
            for item in document["profiles"]
            if item["profile_id"]
            == "codex.subscription.local-draft-synthesis"
        )
        raw_profile["profile_id"] = "codex.private-selection-fixture"
        raw_profile["version"] = "17"
        raw_profile["model_id"] = model_id
        profile_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        profiles = load_execution_profiles(profile_path)
        return next(
            profile
            for profile in profiles
            if profile.profile_id == raw_profile["profile_id"]
        )

    @classmethod
    def _selection(
        cls,
        root: Path,
        prepared,
        *,
        run_id: str,
        selection_mode: str = "operator_explicit",
        profile: ExecutionProfile | None = None,
        context_digest: str | None = None,
        evaluated_at: float | None = None,
        required_valid_until: float | None = None,
    ) -> ExecutionSelection:
        return build_execution_selection(
            run_id=run_id,
            selection_mode=selection_mode,
            task=cls._routing_task(prepared),
            candidates=(cls._runtime_state(root, profile=profile),),
            task_definition_digest=prepared.contract.definition_hash,
            context_digest=(
                prepared.context_pack.snapshot_hash
                if context_digest is None
                else context_digest
            ),
            authorization_intent_digest=task_authorization_intent_digest(
                prepared.contract
            ),
            evaluated_at=time.time() if evaluated_at is None else evaluated_at,
            required_valid_until=required_valid_until,
        )

    @staticmethod
    def _selection_event(root: Path, run_id: str):
        with SQLiteStateStore(root / ".ordomata" / "state.sqlite3") as state:
            events = state.list_events(run_id)
        selections = [
            event
            for event in events
            if event.event_type == TASK_EXECUTION_SELECTION_EVENT_TYPE
        ]
        if len(selections) != 1:
            raise AssertionError(
                f"expected one execution selection event, found {len(selections)}"
            )
        return selections[0], events

    def test_default_mock_persists_named_selection_before_attempt_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            private_instruction = "private-default-selection-instruction-7b2e"

            report = asyncio.run(
                run_chief_of_staff(
                    root,
                    operator_instructions=(private_instruction,),
                    run_id="default-mock-selection",
                )
            )

            selection_event, events = self._selection_event(root, report.run_id)
            payload = selection_event.payload
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(
                payload["selection_digest"],
                canonical_digest(payload["selection"]),
            )
            self.assertEqual(selection_event.event_id, payload["selection_digest"])
            self.assertEqual(
                payload["selection"]["selection_mode"], "controller_default"
            )
            selected = payload["selection"]["selected"]
            self.assertIsNotNone(selected)
            self.assertEqual(
                selected["profile_id"],
                "mock.deterministic.local-draft",
            )
            self.assertEqual(
                selected["profile_ref"],
                canonical_digest(
                    {"profile_id": selected["profile_id"]}
                ),
            )
            for candidate in payload["selection"]["candidates"]:
                self.assertEqual(
                    candidate["profile_ref"],
                    canonical_digest({"profile_id": candidate["profile_id"]}),
                )
            serialized = json.dumps(payload, sort_keys=True)
            for private_value in (
                str(root),
                private_instruction,
                "chief_of_staff.valid",
                "fixture",
            ):
                self.assertNotIn(private_value, serialized)

            binding = next(
                event
                for event in events
                if event.event_type == "task_attempt_authorization_binding"
            )
            billing = next(
                event for event in events if event.event_type == "billing_assessment"
            )
            running = next(
                event
                for event in events
                if event.event_type == "status"
                and event.payload.get("phase") == "runner_execution"
            )
            self.assertLess(selection_event.sequence, binding.sequence)
            self.assertLess(selection_event.sequence, billing.sequence)
            self.assertLess(selection_event.sequence, running.sequence)
            self.assertEqual(binding.payload["schema_version"], 2)
            self.assertEqual(
                binding.payload["binding"]["execution_selection_digest"],
                payload["selection_digest"],
            )

    def test_explicit_mock_selection_preserves_profile_configuration_and_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "explicit-mock-selection"
            prepared = prepare_chief_of_staff(root)
            profile = self._mock_profile(root)
            selection_time = time.time()
            selection = self._selection(
                root,
                prepared,
                run_id=run_id,
                profile=profile,
                evaluated_at=selection_time,
            )
            changed_configuration_selection = self._selection(
                root,
                prepared,
                run_id=run_id,
                profile=replace(profile, settings={}),
                evaluated_at=selection_time,
            )
            self.assertNotEqual(
                selection.selection_digest,
                changed_configuration_selection.selection_digest,
            )
            runner = RecordingMockRunner(
                output=load_mock_chief_of_staff_output(root, prepared)
            )
            overrides = runner_overrides_for_profile(profile)

            with patch(
                "ordomata.orchestrator.prepare_chief_of_staff",
                side_effect=AssertionError(
                    "a supplied prepared snapshot must not be rebuilt"
                ),
            ):
                report = asyncio.run(
                    run_chief_of_staff(
                        root,
                        runner=runner,
                        runner_overrides=overrides,
                        run_id=run_id,
                        profile_id=profile.profile_id,
                        prepared_task=prepared,
                        execution_selection=selection,
                    )
                )

            self.assertEqual(runner.execute_count, 1)
            self.assertEqual(len(runner.requests), 1)
            self.assertEqual(runner.requests[0].prompt, prepared.prompt)
            self.assertEqual(dict(runner.requests[0].runner_overrides), overrides)
            self.assertEqual(
                report.context_snapshot, prepared.context_pack.snapshot_hash
            )
            selection_event, _ = self._selection_event(root, run_id)
            self.assertEqual(selection_event.payload, selection.to_event_payload())
            selection_body = selection_event.payload["selection"]
            self.assertEqual(selection_body["selection_mode"], "operator_explicit")
            selected = selection_body["selected"]
            self.assertEqual(selected["profile_id"], profile.profile_id)
            self.assertEqual(
                selected["profile_ref"],
                canonical_digest({"profile_id": selected["profile_id"]}),
            )
            self.assertEqual(
                selected["profile_version_ref"],
                canonical_digest({"profile_version": profile.version}),
            )
            candidate = selection_body["candidates"][0]
            self.assertEqual(
                selected["profile_configuration_digest"],
                candidate["profile_configuration_digest"],
            )
            self.assertEqual(
                selected["settings_digest"], candidate["settings_digest"]
            )
            self.assertEqual(
                selected["runner_overrides_digest"], canonical_digest(overrides)
            )
            self.assertEqual(selected["runner_id"], "mock")
            self.assertEqual(
                selection_event.payload["selection_digest"],
                selection.selection_digest,
            )

    def test_explicit_mock_cli_path_persists_the_named_profile_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "explicit-mock-cli-selection"
            profile = self._mock_profile(root)

            report = asyncio.run(
                _run_profile(
                    root,
                    profile_id=profile.profile_id,
                    run_id=run_id,
                    operator_instructions=(),
                )
            )

            self.assertEqual(report["status"], RunStatus.SUCCEEDED.value)
            selection_event, events = self._selection_event(root, run_id)
            selection = selection_event.payload["selection"]
            self.assertEqual(selection["selection_mode"], "operator_explicit")
            selected = selection["selected"]
            self.assertEqual(selected["profile_id"], profile.profile_id)
            self.assertEqual(
                selected["profile_ref"],
                canonical_digest({"profile_id": selected["profile_id"]}),
            )
            self.assertEqual(
                selected["profile_version_ref"],
                canonical_digest({"profile_version": profile.version}),
            )
            self.assertEqual(
                selected["profile_configuration_digest"],
                selection["candidates"][0]["profile_configuration_digest"],
            )
            binding = next(
                event
                for event in events
                if event.event_type == "task_attempt_authorization_binding"
            )
            self.assertEqual(binding.payload["schema_version"], 2)
            self.assertEqual(
                binding.payload["binding"]["execution_selection_digest"],
                selection_event.payload["selection_digest"],
            )

    def test_selection_event_digests_model_settings_and_private_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "private-profile-selection"
            prepared = prepare_chief_of_staff(root)
            private_model = "/private/customer/model-private-9af2"
            second_private_model = "/private/customer/model-private-different-4c1e"
            now = time.time()
            assessment = self._codex_assessment(now=now)
            profile = self._install_private_codex_profile(
                root,
                model_id=private_model,
            )
            task = self._routing_task(
                prepared,
                lane="subscription",
            )

            required_valid_until = (
                now
                + prepared.contract.timeout_seconds
                + LIVE_RUN_EVIDENCE_MARGIN_SECONDS
            )

            def build(profile_value: ExecutionProfile) -> ExecutionSelection:
                return build_execution_selection(
                    run_id=run_id,
                    selection_mode="operator_explicit",
                    task=task,
                    candidates=(
                        RuntimeProfileState(
                            profile=profile_value,
                            billing_assessment=assessment,
                            available=True,
                        ),
                    ),
                    task_definition_digest=prepared.contract.definition_hash,
                    context_digest=prepared.context_pack.snapshot_hash,
                    authorization_intent_digest=task_authorization_intent_digest(
                        prepared.contract
                    ),
                    evaluated_at=now,
                    required_valid_until=required_valid_until,
                )

            selection = build(profile)
            changed_selection = build(
                replace(profile, model_id=second_private_model)
            )
            self.assertNotEqual(
                selection.selection_digest,
                changed_selection.selection_digest,
            )
            self.assertEqual(
                selection.required_valid_until,
                required_valid_until,
            )
            self.assertTrue(
                selection.selection["candidates"][0]["billing"][
                    "policy_allowed"
                ]
            )
            runner = RecordingSubscriptionFixtureRunner(
                assessment,
                load_mock_chief_of_staff_output(root, prepared),
            )

            report = asyncio.run(
                run_chief_of_staff(
                    root,
                    runner=runner,
                    runner_overrides=runner_overrides_for_profile(profile),
                    run_id=run_id,
                    profile_id=profile.profile_id,
                    prepared_task=prepared,
                    execution_selection=selection,
                )
            )

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            self.assertEqual(runner.execute_count, 1)
            selection_event, _ = self._selection_event(root, run_id)
            selected = selection_event.payload["selection"]["selected"]
            self.assertEqual(selected["profile_id"], profile.profile_id)
            self.assertEqual(
                selected["profile_ref"],
                canonical_digest({"profile_id": selected["profile_id"]}),
            )
            serialized = selection_event.payload_json
            for private_value in (
                private_model,
                second_private_model,
                str(root),
                "reasoning_effort",
            ):
                self.assertNotIn(private_value, serialized)

    def test_catalog_change_after_selection_blocks_before_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "selection-catalog-drift"
            prepared = prepare_chief_of_staff(root)
            profile = self._mock_profile(root)
            selection = self._selection(root, prepared, run_id=run_id)
            runner = RecordingMockRunner(
                output=load_mock_chief_of_staff_output(root, prepared)
            )
            profile_path = root / "profiles" / "default.json"
            document = json.loads(profile_path.read_text(encoding="utf-8"))
            configured = next(
                item
                for item in document["profiles"]
                if item["profile_id"] == profile.profile_id
            )
            configured["quality_prior"] = 0.75
            profile_path.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValidationError,
                "configured profile",
            ):
                asyncio.run(
                    run_chief_of_staff(
                        root,
                        runner=runner,
                        runner_overrides=runner_overrides_for_profile(profile),
                        run_id=run_id,
                        profile_id=profile.profile_id,
                        prepared_task=prepared,
                        execution_selection=selection,
                    )
                )

            self.assertEqual(runner.inspect_count, 0)
            self.assertEqual(runner.execute_count, 0)
            self.assertFalse((root / ".ordomata").exists())

    def test_catalog_profile_cannot_execute_without_selection_evidence(self) -> None:
        cases = (
            ("named-profile", True),
            ("unnamed-supplied-runner", False),
        )
        for case, supply_profile_id in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"selection-catalog-omitted-{case}"
                prepared = prepare_chief_of_staff(root)
                profile = self._mock_profile(root)
                runner = RecordingMockRunner(
                    output=load_mock_chief_of_staff_output(root, prepared)
                )

                with self.assertRaisesRegex(
                    ValidationError,
                    "requires selection evidence",
                ):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=runner_overrides_for_profile(profile),
                            run_id=run_id,
                            profile_id=(
                                profile.profile_id
                                if supply_profile_id
                                else None
                            ),
                            prepared_task=prepared,
                        )
                    )

                self.assertEqual(runner.inspect_count, 0)
                self.assertEqual(runner.execute_count, 0)
                self.assertFalse((root / ".ordomata").exists())

    def test_subscription_selection_requires_full_timeout_billing_horizon(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "selection-billing-horizon"
            prepared = prepare_chief_of_staff(root)
            profile = next(
                profile
                for profile in load_execution_profiles(
                    root / "profiles" / "default.json"
                )
                if profile.runner_id == "codex"
            )
            now = time.time()
            required_valid_until = (
                now
                + prepared.contract.timeout_seconds
                + LIVE_RUN_EVIDENCE_MARGIN_SECONDS
            )
            assessment = self._codex_assessment(now=now)
            task = self._routing_task(prepared, lane="subscription")
            state = RuntimeProfileState(
                profile=profile,
                billing_assessment=assessment,
                available=True,
            )
            insufficient_selection = build_execution_selection(
                run_id=run_id,
                selection_mode="operator_explicit",
                task=task,
                candidates=(state,),
                task_definition_digest=prepared.contract.definition_hash,
                context_digest=prepared.context_pack.snapshot_hash,
                authorization_intent_digest=task_authorization_intent_digest(
                    prepared.contract
                ),
                evaluated_at=now,
                required_valid_until=required_valid_until - 1,
            )
            runner = RecordingSubscriptionFixtureRunner(
                assessment,
                load_mock_chief_of_staff_output(root, prepared),
            )

            with self.assertRaisesRegex(
                ValidationError,
                "billing evidence horizon",
            ):
                asyncio.run(
                    run_chief_of_staff(
                        root,
                        runner=runner,
                        runner_overrides=runner_overrides_for_profile(profile),
                        run_id=run_id,
                        profile_id=profile.profile_id,
                        prepared_task=prepared,
                        execution_selection=insufficient_selection,
                    )
                )

            self.assertEqual(runner.inspect_count, 0)
            self.assertEqual(runner.execute_count, 0)
            self.assertFalse((root / ".ordomata").exists())

            expiring_assessment = self._codex_assessment(
                now=now,
                expires_at=required_valid_until - 0.5,
            )
            with self.assertRaisesRegex(
                ValidationError,
                "no eligible profile",
            ):
                build_execution_selection(
                    run_id="selection-expiring-billing-evidence",
                    selection_mode="operator_explicit",
                    task=task,
                    candidates=(
                        RuntimeProfileState(
                            profile=profile,
                            billing_assessment=expiring_assessment,
                            available=True,
                        ),
                    ),
                    task_definition_digest=prepared.contract.definition_hash,
                    context_digest=prepared.context_pack.snapshot_hash,
                    authorization_intent_digest=task_authorization_intent_digest(
                        prepared.contract
                    ),
                    evaluated_at=now,
                    required_valid_until=required_valid_until,
                )

    def test_fresh_preflight_account_must_match_selection_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "selection-preflight-account-drift"
            prepared = prepare_chief_of_staff(root)
            profile = next(
                profile
                for profile in load_execution_profiles(
                    root / "profiles" / "default.json"
                )
                if profile.runner_id == "codex"
            )
            now = time.time()
            required_valid_until = (
                now
                + prepared.contract.timeout_seconds
                + LIVE_RUN_EVIDENCE_MARGIN_SECONDS
            )
            selected_assessment = self._codex_assessment(
                now=now,
                fingerprint="c" * 64,
            )
            fresh_preflight = self._codex_assessment(
                now=now,
                fingerprint="d" * 64,
            )
            selection = build_execution_selection(
                run_id=run_id,
                selection_mode="operator_explicit",
                task=self._routing_task(prepared, lane="subscription"),
                candidates=(
                    RuntimeProfileState(
                        profile=profile,
                        billing_assessment=selected_assessment,
                        available=True,
                    ),
                ),
                task_definition_digest=prepared.contract.definition_hash,
                context_digest=prepared.context_pack.snapshot_hash,
                authorization_intent_digest=task_authorization_intent_digest(
                    prepared.contract
                ),
                evaluated_at=now,
                required_valid_until=required_valid_until,
            )
            runner = RecordingSubscriptionFixtureRunner(
                fresh_preflight,
                load_mock_chief_of_staff_output(root, prepared),
            )

            with self.assertRaises((BillingRouteBlocked, ValidationError)):
                asyncio.run(
                    run_chief_of_staff(
                        root,
                        runner=runner,
                        runner_overrides=runner_overrides_for_profile(profile),
                        run_id=run_id,
                        profile_id=profile.profile_id,
                        prepared_task=prepared,
                        execution_selection=selection,
                    )
                )

            self.assertEqual(runner.inspect_count, 1)
            self.assertEqual(runner.execute_count, 0)
            state_path = root / ".ordomata" / "state.sqlite3"
            if state_path.exists():
                with SQLiteStateStore(state_path) as state:
                    self.assertEqual(
                        state.current_status(run_id),
                        RunStatus.BLOCKED,
                    )

    def test_tampered_or_mismatched_selection_blocks_before_execute(self) -> None:
        cases = ("digest", "run", "context", "profile", "overrides")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"selection-mismatch-{case}"
                prepared = prepare_chief_of_staff(root)
                profile = self._mock_profile(root)
                selected_run_id = "different-run" if case == "run" else run_id
                context_digest = (
                    "sha256:" + "0" * 64
                    if case == "context"
                    else prepared.context_pack.snapshot_hash
                )
                selection = self._selection(
                    root,
                    prepared,
                    run_id=selected_run_id,
                    profile=profile,
                    context_digest=context_digest,
                )
                if case == "digest":
                    object.__setattr__(
                        selection,
                        "selection_digest",
                        "sha256:" + "f" * 64,
                    )
                runner = RecordingMockRunner(
                    output=load_mock_chief_of_staff_output(root, prepared)
                )
                overrides = (
                    {"unexpected": "override"}
                    if case == "overrides"
                    else runner_overrides_for_profile(profile)
                )
                selected_profile_id = (
                    "mock.different-profile"
                    if case == "profile"
                    else profile.profile_id
                )

                with self.assertRaises((ConfigurationError, ValidationError)):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=overrides,
                            run_id=run_id,
                            profile_id=selected_profile_id,
                            prepared_task=prepared,
                            execution_selection=selection,
                        )
                    )

                self.assertEqual(runner.execute_count, 0)

    def test_selection_builder_cannot_exceed_profile_class_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profile = replace(
                self._mock_profile(root),
                max_permission_class=PermissionClass.READ_ONLY,
            )

            with self.assertRaises((ConfigurationError, ValidationError)):
                self._selection(
                    root,
                    prepared,
                    run_id="selection-class-ceiling",
                    profile=profile,
                )

            self.assertFalse((root / ".ordomata").exists())

    def test_selected_runner_identity_mismatch_blocks_before_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "selection-runner-mismatch"
            prepared = prepare_chief_of_staff(root)
            profile = self._mock_profile(root)
            selection = self._selection(root, prepared, run_id=run_id)
            runner = NeverExecuteMismatchedRunner()

            with self.assertRaises((ConfigurationError, ValidationError)):
                asyncio.run(
                    run_chief_of_staff(
                        root,
                        runner=runner,
                        runner_overrides=runner_overrides_for_profile(profile),
                        run_id=run_id,
                        profile_id=profile.profile_id,
                        prepared_task=prepared,
                        execution_selection=selection,
                    )
                )

            self.assertEqual(runner.inspect_count, 0)
            self.assertEqual(runner.execute_count, 0)

    def test_selection_persistence_failure_blocks_before_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "selection-precommit-failure"
            prepared = prepare_chief_of_staff(root)
            profile = self._mock_profile(root)
            selection = self._selection(root, prepared, run_id=run_id)
            runner = RecordingMockRunner(
                output=load_mock_chief_of_staff_output(root, prepared)
            )
            original_append_event = SQLiteStateStore.append_event

            def reject_selection(store, observed_run_id, event_type, *args, **kwargs):
                if event_type == TASK_EXECUTION_SELECTION_EVENT_TYPE:
                    raise OSError("private injected selection failure")
                return original_append_event(
                    store, observed_run_id, event_type, *args, **kwargs
                )

            with patch.object(
                SQLiteStateStore,
                "append_event",
                new=reject_selection,
            ):
                with self.assertRaises(OSError):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=runner_overrides_for_profile(profile),
                            run_id=run_id,
                            profile_id=profile.profile_id,
                            prepared_task=prepared,
                            execution_selection=selection,
                        )
                    )

            self.assertEqual(runner.execute_count, 0)
            with SQLiteStateStore(root / ".ordomata" / "state.sqlite3") as state:
                self.assertEqual(state.current_status(run_id), RunStatus.FAILED)
                persisted_json = "\n".join(
                    event.payload_json for event in state.list_events(run_id)
                )
            self.assertNotIn("private injected selection failure", persisted_json)

    def test_selection_commit_then_raise_is_exactly_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "selection-commit-then-raise"
            prepared = prepare_chief_of_staff(root)
            profile = self._mock_profile(root)
            selection = self._selection(root, prepared, run_id=run_id)
            runner = RecordingMockRunner(
                output=load_mock_chief_of_staff_output(root, prepared)
            )
            original_append_event = SQLiteStateStore.append_event
            injected = False

            def commit_then_raise(
                store,
                observed_run_id,
                event_type,
                *args,
                **kwargs,
            ):
                nonlocal injected
                result = original_append_event(
                    store, observed_run_id, event_type, *args, **kwargs
                )
                if (
                    not injected
                    and event_type == TASK_EXECUTION_SELECTION_EVENT_TYPE
                ):
                    injected = True
                    raise OSError("private injected post-commit failure")
                return result

            with patch.object(
                SQLiteStateStore,
                "append_event",
                new=commit_then_raise,
            ):
                report = asyncio.run(
                    run_chief_of_staff(
                        root,
                        runner=runner,
                        runner_overrides=runner_overrides_for_profile(profile),
                        run_id=run_id,
                        profile_id=profile.profile_id,
                        prepared_task=prepared,
                        execution_selection=selection,
                    )
                )

            self.assertTrue(injected)
            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            self.assertEqual(runner.execute_count, 1)
            selection_event, events = self._selection_event(root, run_id)
            self.assertEqual(selection_event.event_id, selection.selection_digest)
            self.assertEqual(
                sum(
                    event.event_type == TASK_EXECUTION_SELECTION_EVENT_TYPE
                    for event in events
                ),
                1,
            )
            self.assertNotIn(
                "private injected post-commit failure",
                "\n".join(event.payload_json for event in events),
            )
