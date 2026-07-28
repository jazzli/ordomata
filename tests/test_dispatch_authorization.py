import asyncio
from contextlib import contextmanager
from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from ordomata.admission_authorization import (
    TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
    TASK_ADMISSION_ACTION_SCOPE,
    TASK_ADMISSION_DECISION_EVENT_TYPE,
    TASK_ADMISSION_ENFORCEMENT_COVERAGE,
)
from ordomata.authorization import (
    AuthorizationEffect,
    DecisionReason,
    ShadowAuthorizationEvaluator,
    canonical_digest,
)
from ordomata.dispatch_authorization import (
    MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
    MOCK_DISPATCH_ACTION_SCOPE,
    MOCK_DISPATCH_DECISION_EVENT_TYPE,
    MOCK_DISPATCH_EXECUTOR_ID,
    MOCK_DISPATCH_OPERATION,
    assert_mock_dispatch_authorized,
    evaluate_mock_dispatch_authorization,
)
from ordomata.errors import AuthorizationBlocked, ValidationError
from ordomata.execution_selection import (
    build_execution_selection,
    execution_profile_configuration_digest,
)
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    RunRequest,
    RunStatus,
)
from ordomata.orchestrator import (
    load_mock_chief_of_staff_output,
    prepare_chief_of_staff,
    run_chief_of_staff,
)
from ordomata.routing import (
    RuntimeProfileState,
    TaskRoutingFeatures,
    load_execution_profiles,
    runner_overrides_for_profile,
)
from ordomata.runners.mock import MockRunner
from ordomata.shadow_authorization import (
    ADMISSION_ACTION_SCOPE,
    DISPATCH_ACTION_SCOPE,
    task_authorization_intent_digest,
)
from ordomata.state import SQLiteStateStore
from ordomata.task_evidence import (
    TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
    build_task_attempt_binding_event,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


@contextmanager
def recording_mock_calls():
    """Instrument the exact MockRunner class without accepting a substitute."""

    calls = {"inspect": 0, "execute": 0, "requests": []}
    original_inspect = MockRunner.inspect_billing_route
    original_execute = MockRunner.execute

    async def recording_inspect(runner):
        calls["inspect"] += 1
        return await original_inspect(runner)

    async def recording_execute(runner, request, event_sink):
        calls["execute"] += 1
        calls["requests"].append(request)
        return await original_execute(runner, request, event_sink)

    with (
        patch.object(
            MockRunner,
            "inspect_billing_route",
            new=recording_inspect,
        ),
        patch.object(MockRunner, "execute", new=recording_execute),
    ):
        yield calls


class OverridingMockRunner(MockRunner):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.inspect_count = 0
        self.execute_count = 0

    async def inspect_billing_route(self):
        self.inspect_count += 1
        raise AssertionError("an overriding mock subclass must not reach preflight")

    async def execute(self, request, event_sink):
        del request, event_sink
        self.execute_count += 1
        raise AssertionError("an overriding mock subclass must never execute")


class DispatchAuthorizationTests(unittest.TestCase):
    def _project(self, temporary: str, *, profiles: bool = True) -> Path:
        root = Path(temporary)
        names = ["tasks", "schemas", "fixtures"]
        if profiles:
            names.append("profiles")
        for name in names:
            shutil.copytree(REPOSITORY_ROOT / name, root / name)
        return root

    @staticmethod
    def _mock_profile(root: Path):
        profiles = load_execution_profiles(root / "profiles" / "default.json")
        return next(profile for profile in profiles if profile.runner_id == "mock")

    @classmethod
    def _explicit_inputs(cls, root: Path, run_id: str):
        prepared = prepare_chief_of_staff(root)
        profile = cls._mock_profile(root)
        task = TaskRoutingFeatures(
            task_kind="chief_of_staff",
            permission_class=prepared.contract.permission_class,
            required_capabilities=frozenset(
                {"structured_output", "local_draft", "isolated_workspace"}
            ),
            allowed_roles=frozenset({"test"}),
            allowed_billing_routes=frozenset({BillingRoute.MOCK}),
            context_bytes=prepared.context_pack.raw_bytes,
            risk=1,
        )
        selection = build_execution_selection(
            run_id=run_id,
            selection_mode="operator_explicit",
            task=task,
            candidates=(
                RuntimeProfileState(
                    profile=profile,
                    billing_assessment=BillingRouteAssessment(
                        runner_id="mock",
                        route=BillingRoute.MOCK,
                        confidence=AssessmentConfidence.HIGH,
                    ),
                    available=True,
                ),
            ),
            task_definition_digest=prepared.contract.definition_hash,
            context_digest=prepared.context_pack.snapshot_hash,
            authorization_intent_digest=task_authorization_intent_digest(
                prepared.contract
            ),
            evaluated_at=time.time(),
        )
        runner = MockRunner(
            output=load_mock_chief_of_staff_output(root, prepared)
        )
        return prepared, profile, selection, runner

    @staticmethod
    def _events(root: Path, run_id: str):
        with SQLiteStateStore(root / ".ordomata" / "state.sqlite3") as state:
            return state.list_events(run_id)

    @staticmethod
    def _only(events, event_type: str):
        matches = [event for event in events if event.event_type == event_type]
        if len(matches) != 1:
            raise AssertionError(
                f"expected one {event_type} event, found {len(matches)}"
            )
        return matches[0]

    def _assert_success_evidence(
        self,
        root: Path,
        run_id: str,
        *,
        private_values: tuple[str, ...] = (),
    ) -> None:
        events = self._events(root, run_id)
        selection = self._only(events, "task_execution_selection")
        binding = self._only(events, "task_attempt_authorization_binding")
        admission_decision = self._only(
            events, TASK_ADMISSION_DECISION_EVENT_TYPE
        )
        admission_receipt = self._only(
            events, TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
        )
        admission_shadow = next(
            event
            for event in events
            if event.event_type == "authorization_shadow_decision"
            and event.payload.get("action_scope") == ADMISSION_ACTION_SCOPE
        )
        billing = self._only(events, "billing_assessment")
        decision = self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
        receipt = self._only(events, MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE)
        accounting = self._only(events, "execution_accounting")
        running = next(
            event
            for event in events
            if event.event_type == "status"
            and event.payload.get("phase") == "runner_execution"
        )
        dispatch_shadow = next(
            event
            for event in events
            if event.event_type == "authorization_shadow_decision"
            and event.payload.get("action_scope") == DISPATCH_ACTION_SCOPE
        )

        self.assertEqual(binding.payload["schema_version"], 5)
        self.assertEqual(
            binding.payload[
                "admission_authorization_enforcement_coverage"
            ],
            TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            binding.payload["authorization_enforcement_coverage"],
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            binding.payload[
                "publication_authorization_enforcement_coverage"
            ],
            TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            admission_decision.payload["enforcement_coverage"],
            TASK_ADMISSION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            admission_decision.payload["action_scope"],
            TASK_ADMISSION_ACTION_SCOPE,
        )
        self.assertTrue(
            admission_decision.payload["authorization_eligible"]
        )
        self.assertEqual(
            admission_decision.payload["task_attempt_binding_digest"],
            binding.payload["binding_digest"],
        )
        self.assertEqual(
            admission_receipt.payload["decision_digest"],
            admission_decision.payload["decision_digest"],
        )
        self.assertEqual(
            admission_receipt.payload["request_digest"],
            admission_decision.payload["request_digest"],
        )
        self.assertEqual(
            admission_receipt.payload["receipt"]["outcome"],
            "succeeded",
        )
        self.assertEqual(
            decision.payload["enforcement_coverage"],
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(decision.payload["mode"], "enforcing")
        self.assertEqual(
            decision.payload["action_scope"], MOCK_DISPATCH_ACTION_SCOPE
        )
        self.assertEqual(decision.payload["effect"], "permit")
        self.assertTrue(decision.payload["authorization_eligible"])
        self.assertTrue(decision.payload["decision_current_at_evaluation"])
        self.assertTrue(decision.payload["authority_ceiling_satisfied"])
        self.assertTrue(decision.payload["obligations_supported"])
        self.assertEqual(
            decision.payload["task_attempt_binding_digest"],
            binding.payload["binding_digest"],
        )
        self.assertEqual(
            decision.payload["execution_selection_digest"],
            selection.payload["selection_digest"],
        )
        self.assertEqual(
            decision.payload["billing_assessment_digest"],
            billing.payload["assessment_digest"],
        )
        self.assertEqual(
            decision.payload["request"]["action"]["operation"],
            MOCK_DISPATCH_OPERATION,
        )
        self.assertEqual(
            decision.event_id,
            canonical_digest(
                {
                    "event_type": MOCK_DISPATCH_DECISION_EVENT_TYPE,
                    "payload": decision.payload,
                    "run_id": run_id,
                }
            ),
        )

        self.assertLess(selection.sequence, binding.sequence)
        self.assertLess(binding.sequence, admission_decision.sequence)
        self.assertLess(admission_decision.sequence, admission_receipt.sequence)
        self.assertLess(admission_receipt.sequence, admission_shadow.sequence)
        self.assertLess(admission_shadow.sequence, billing.sequence)
        self.assertLess(billing.sequence, decision.sequence)
        self.assertLess(decision.sequence, running.sequence)
        self.assertLess(running.sequence, dispatch_shadow.sequence)
        self.assertLess(dispatch_shadow.sequence, receipt.sequence)
        self.assertLess(receipt.sequence, accounting.sequence)
        for runner_event in (
            event for event in events if event.event_type == "runner_event_observed"
        ):
            self.assertLess(decision.sequence, runner_event.sequence)

        receipt_payload = receipt.payload
        receipt_body = receipt_payload["receipt"]
        self.assertEqual(
            receipt_payload["task_attempt_binding_digest"],
            binding.payload["binding_digest"],
        )
        self.assertEqual(
            receipt_payload["execution_selection_digest"],
            selection.payload["selection_digest"],
        )
        self.assertEqual(
            receipt_payload["request_digest"], decision.payload["request_digest"]
        )
        self.assertEqual(
            receipt_payload["decision_digest"],
            decision.payload["decision_digest"],
        )
        self.assertGreaterEqual(
            receipt_body["started_at"], dispatch_shadow.occurred_at
        )
        self.assertEqual(receipt_body["outcome"], "succeeded")
        self.assertEqual(receipt_body["executor_id"], MOCK_DISPATCH_EXECUTOR_ID)
        self.assertEqual(
            receipt_body["request_digest"], decision.payload["request_digest"]
        )
        self.assertEqual(
            receipt_body["decision_digest"], decision.payload["decision_digest"]
        )
        self.assertEqual(receipt.event_id, receipt_body["receipt_id"])
        self.assertEqual(
            receipt_payload["receipt_digest"], canonical_digest(receipt_body)
        )
        self.assertEqual(
            {
                (item["kind"], item["value"])
                for item in receipt_body["obligation_results"]
                if item["satisfied"]
            },
            {
                (item["kind"], item["value"])
                for item in decision.payload["decision"]["obligations"]
            },
        )

        serialized = json.dumps(
            [
                admission_decision.payload,
                admission_receipt.payload,
                decision.payload,
                receipt.payload,
            ],
            sort_keys=True,
        )
        for private_value in private_values:
            self.assertNotIn(private_value, serialized)

    def _run_explicit(self, root: Path, run_id: str):
        prepared, profile, selection, runner = self._explicit_inputs(root, run_id)
        with recording_mock_calls() as calls:
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
        return report, calls

    def test_default_profile_backed_mock_is_authorized_and_executes_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "default-mock-dispatch-permit"
            private_instruction = "private-dispatch-instruction-7f3c"
            counts = {"inspect": 0, "execute": 0}
            original_inspect = MockRunner.inspect_billing_route
            original_execute = MockRunner.execute

            async def recording_inspect(runner):
                counts["inspect"] += 1
                return await original_inspect(runner)

            async def recording_execute(runner, request, event_sink):
                counts["execute"] += 1
                return await original_execute(runner, request, event_sink)

            with (
                patch.object(
                    MockRunner,
                    "inspect_billing_route",
                    new=recording_inspect,
                ),
                patch.object(MockRunner, "execute", new=recording_execute),
            ):
                report = asyncio.run(
                    run_chief_of_staff(
                        root,
                        run_id=run_id,
                        operator_instructions=(private_instruction,),
                    )
                )

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            self.assertEqual(counts, {"inspect": 2, "execute": 1})
            self._assert_success_evidence(
                root,
                run_id,
                private_values=(
                    str(root),
                    private_instruction,
                    "chief_of_staff.valid",
                ),
            )

    def test_explicit_profile_backed_mock_executes_once_with_linked_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "explicit-mock-dispatch-permit"
            report, calls = self._run_explicit(root, run_id)

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            self.assertEqual(calls["inspect"], 2)
            self.assertEqual(calls["execute"], 1)
            self._assert_success_evidence(root, run_id, private_values=(str(root),))

    def test_deny_defer_and_indeterminate_decisions_never_execute(self) -> None:
        original_evaluate = ShadowAuthorizationEvaluator.evaluate

        for case, effect, reason in (
            (
                "deny",
                AuthorizationEffect.DENY,
                DecisionReason.CLASS_DISABLED,
            ),
            (
                "defer",
                AuthorizationEffect.DEFER,
                DecisionReason.APPROVAL_REQUIRED,
            ),
            (
                "indeterminate",
                AuthorizationEffect.INDETERMINATE,
                DecisionReason.EVIDENCE_STALE,
            ),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"mock-dispatch-{case}"
                prepared, profile, selection, runner = self._explicit_inputs(
                    root, run_id
                )

                def force_dispatch_nonpermit(evaluator, request, policy):
                    decision = original_evaluate(evaluator, request, policy)
                    if request.action.operation != MOCK_DISPATCH_OPERATION:
                        return decision
                    return replace(
                        decision,
                        effect=effect,
                        reason_codes=(reason,),
                        reason_details=("fixed dispatch nonpermit",),
                        obligations=(),
                    )

                with (
                    patch.object(
                        ShadowAuthorizationEvaluator,
                        "evaluate",
                        new=force_dispatch_nonpermit,
                    ),
                    recording_mock_calls() as calls,
                    self.assertRaises(AuthorizationBlocked),
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

                self.assertEqual(calls["inspect"], 1)
                self.assertEqual(calls["execute"], 0)
                events = self._events(root, run_id)
                decision = self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
                self.assertEqual(decision.payload["effect"], case)
                self.assertFalse(decision.payload["authorization_eligible"])
                self.assertIn(
                    "authorization_effect_not_permit",
                    decision.payload["block_reason_codes"],
                )
                self.assertFalse(
                    any(
                        event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                        for event in events
                    )
                )
                self.assertFalse(
                    any(
                        event.event_type == "status"
                        and event.payload.get("phase") == "runner_execution"
                        for event in events
                    )
                )
                self.assertFalse(
                    any(event.event_type == "execution_accounting" for event in events)
                )
                with SQLiteStateStore(
                    root / ".ordomata" / "state.sqlite3"
                ) as state:
                    self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)
                    self.assertEqual(state.list_artifacts(run_id), ())

    def test_evaluator_failure_is_redacted_and_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-evaluator-failure"
            prepared, profile, selection, runner = self._explicit_inputs(root, run_id)
            private_error = "private-evaluator-secret-4e9b"

            with (
                patch(
                    "ordomata.orchestrator."
                    "evaluate_mock_dispatch_authorization",
                    side_effect=RuntimeError(private_error),
                ),
                recording_mock_calls() as calls,
                self.assertRaises(AuthorizationBlocked) as caught,
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

            self.assertNotIn(private_error, str(caught.exception))
            self.assertEqual(calls["inspect"], 1)
            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            decision = self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
            self.assertEqual(decision.payload["effect"], "indeterminate")
            self.assertEqual(
                decision.payload["failure_stage"], "request_or_evaluation"
            )
            self.assertIsNone(decision.payload["request"])
            self.assertNotIn(private_error, decision.payload_json)
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )

    def test_decision_serialization_failure_never_reuses_the_permit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-decision-serialization-failure"
            prepared, profile, selection, runner = self._explicit_inputs(
                root, run_id
            )

            with (
                patch(
                    "ordomata.dispatch_authorization."
                    "MockDispatchAuthorization.to_event_payload",
                    side_effect=RuntimeError("private-serialization-failure"),
                ),
                recording_mock_calls() as calls,
                self.assertRaises(AuthorizationBlocked),
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

            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            decision = self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
            self.assertEqual(decision.payload["effect"], "indeterminate")
            self.assertFalse(decision.payload["authorization_eligible"])
            self.assertIsNone(decision.payload["request"])
            self.assertNotIn(
                "private-serialization-failure",
                "\n".join(event.payload_json for event in events),
            )
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)

    def test_expired_decision_after_running_blocks_at_execute_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-expired-at-execute-boundary"
            prepared, profile, selection, runner = self._explicit_inputs(
                root, run_id
            )
            freshness_checks = 0

            def force_expired_action_start(
                authorization,
                *,
                action_started_at,
            ):
                nonlocal freshness_checks
                freshness_checks += 1
                self.assertLess(
                    action_started_at,
                    authorization.decision.expires_at,
                )
                return assert_mock_dispatch_authorized(
                    authorization,
                    action_started_at=authorization.decision.expires_at,
                )

            with (
                patch(
                    "ordomata.orchestrator.assert_mock_dispatch_authorized",
                    new=force_expired_action_start,
                ),
                recording_mock_calls() as calls,
                self.assertRaises(AuthorizationBlocked),
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

            self.assertEqual(freshness_checks, 1)
            self.assertEqual(calls["inspect"], 1)
            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            decision = self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
            running = next(
                event
                for event in events
                if event.status is RunStatus.RUNNING
                and event.payload.get("phase") == "runner_execution"
            )
            dispatch_shadow = next(
                event
                for event in events
                if event.event_type == "authorization_shadow_decision"
                and event.payload.get("action_scope") == DISPATCH_ACTION_SCOPE
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.BLOCKED
                and event.payload.get("phase")
                == "mock_dispatch_authorization_freshness"
            )
            self.assertLess(decision.sequence, running.sequence)
            self.assertLess(running.sequence, dispatch_shadow.sequence)
            self.assertLess(dispatch_shadow.sequence, terminal.sequence)
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_evaluator_base_exception_is_redacted_cancelled_and_reraised(
        self,
    ) -> None:
        class EvaluationCancelled(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-evaluator-cancelled"
            prepared, profile, selection, runner = self._explicit_inputs(
                root, run_id
            )
            private_error = "private-evaluator-cancellation-5da7"

            with (
                patch(
                    "ordomata.orchestrator.evaluate_mock_dispatch_authorization",
                    side_effect=EvaluationCancelled(private_error),
                ),
                recording_mock_calls() as calls,
                self.assertRaises(EvaluationCancelled),
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

            self.assertEqual(calls["inspect"], 1)
            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            decision = self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.CANCELLED
                and event.payload.get("phase")
                == "mock_dispatch_authorization_evaluation"
            )
            self.assertEqual(decision.payload["effect"], "indeterminate")
            self.assertEqual(
                decision.payload["failure_stage"], "request_or_evaluation"
            )
            self.assertIsNone(decision.payload["request"])
            self.assertLess(decision.sequence, terminal.sequence)
            self.assertNotIn(
                private_error,
                "\n".join(event.payload_json for event in events),
            )
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(state.current_status(run_id), RunStatus.CANCELLED)
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_mismatched_mock_result_receipt_is_never_succeeded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-mismatched-result"
            prepared, profile, selection, runner = self._explicit_inputs(
                root, run_id
            )
            original_execute = MockRunner.execute
            execute_count = 0

            async def return_mismatched_result(
                active_runner,
                request,
                event_sink,
            ):
                nonlocal execute_count
                execute_count += 1
                result = await original_execute(
                    active_runner,
                    request,
                    event_sink,
                )
                return replace(result, run_id="different-run")

            with (
                patch.object(
                    MockRunner,
                    "execute",
                    new=return_mismatched_result,
                ),
                self.assertRaises(ValidationError),
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

            self.assertEqual(execute_count, 1)
            events = self._events(root, run_id)
            receipt = self._only(
                events, MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.QUARANTINED
                and event.payload.get("phase") == "runner_result_validation"
            )
            self.assertEqual(receipt.payload["receipt"]["outcome"], "unknown")
            self.assertIsNone(receipt.payload["receipt"]["result_digest"])
            self.assertLess(receipt.sequence, terminal.sequence)
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(
                    state.current_status(run_id), RunStatus.QUARANTINED
                )
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_execute_base_exception_records_cancelled_receipt_and_terminal(
        self,
    ) -> None:
        class ExecutionCancelled(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-execute-cancelled"
            prepared, profile, selection, runner = self._explicit_inputs(
                root, run_id
            )
            execute_count = 0

            async def cancel_execution(active_runner, request, event_sink):
                del active_runner, request, event_sink
                nonlocal execute_count
                execute_count += 1
                raise ExecutionCancelled("operator cancellation")

            with (
                patch.object(
                    MockRunner,
                    "execute",
                    new=cancel_execution,
                ),
                self.assertRaises(ExecutionCancelled),
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

            self.assertEqual(execute_count, 1)
            events = self._events(root, run_id)
            receipt = self._only(
                events, MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.CANCELLED
                and event.payload.get("phase") == "execution"
            )
            self.assertEqual(
                receipt.payload["receipt"]["outcome"], "cancelled"
            )
            self.assertIsNone(receipt.payload["receipt"]["result_digest"])
            self.assertLess(receipt.sequence, terminal.sequence)
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(state.current_status(run_id), RunStatus.CANCELLED)
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_duplicate_permit_obligation_is_rejected_before_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-duplicate-obligation"
            prepared, profile, selection, runner = self._explicit_inputs(
                root, run_id
            )

            def duplicate_obligation(**kwargs):
                authorization = evaluate_mock_dispatch_authorization(**kwargs)
                decision = authorization.decision
                return replace(
                    authorization,
                    decision=replace(
                        decision,
                        obligations=(
                            *decision.obligations,
                            decision.obligations[0],
                        ),
                    ),
                )

            with (
                patch(
                    "ordomata.orchestrator.evaluate_mock_dispatch_authorization",
                    new=duplicate_obligation,
                ),
                recording_mock_calls() as calls,
                self.assertRaises(AuthorizationBlocked),
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

            self.assertEqual(calls["inspect"], 1)
            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            decision = self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
            obligation_pairs = [
                (item["kind"], item["value"])
                for item in decision.payload["decision"]["obligations"]
            ]
            self.assertEqual(len(obligation_pairs), 3)
            self.assertEqual(len(set(obligation_pairs)), 2)
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.BLOCKED
                and event.payload.get("phase")
                == "mock_dispatch_authorization_freshness"
            )
            self.assertGreater(terminal.sequence, decision.sequence)
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_decision_precommit_failure_blocks_before_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-decision-precommit-failure"
            prepared, profile, selection, runner = self._explicit_inputs(root, run_id)
            original_append = SQLiteStateStore.append_event
            private_error = "private-decision-precommit-error-2d1a"

            def reject_decision(store, observed_run_id, event_type, *args, **kwargs):
                if event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE:
                    raise OSError(private_error)
                return original_append(
                    store, observed_run_id, event_type, *args, **kwargs
                )

            with (
                patch.object(SQLiteStateStore, "append_event", new=reject_decision),
                recording_mock_calls() as calls,
                self.assertRaises(OSError),
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

            self.assertEqual(calls["inspect"], 1)
            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE
                    for event in events
                )
            )
            self.assertNotIn(
                private_error,
                "\n".join(event.payload_json for event in events),
            )
            with SQLiteStateStore(root / ".ordomata" / "state.sqlite3") as state:
                self.assertEqual(state.current_status(run_id), RunStatus.FAILED)

    def test_decision_commit_then_raise_reconciles_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-decision-commit-then-raise"
            prepared, profile, selection, runner = self._explicit_inputs(root, run_id)
            original_append = SQLiteStateStore.append_event
            private_error = "private-decision-postcommit-error-6b8f"
            injected = False

            def commit_then_raise(
                store, observed_run_id, event_type, *args, **kwargs
            ):
                nonlocal injected
                result = original_append(
                    store, observed_run_id, event_type, *args, **kwargs
                )
                if not injected and event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE:
                    injected = True
                    raise OSError(private_error)
                return result

            with (
                patch.object(
                    SQLiteStateStore, "append_event", new=commit_then_raise
                ),
                recording_mock_calls() as calls,
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
            self.assertEqual(calls["inspect"], 2)
            self.assertEqual(calls["execute"], 1)
            events = self._events(root, run_id)
            self.assertEqual(
                sum(
                    event.event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE
                    for event in events
                ),
                1,
            )
            self.assertNotIn(
                private_error,
                "\n".join(event.payload_json for event in events),
            )
            self._assert_success_evidence(root, run_id)

    def test_overriding_mock_subclass_is_rejected_before_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-overriding-subclass"
            prepared = prepare_chief_of_staff(root)
            profile = self._mock_profile(root)
            task = TaskRoutingFeatures(
                task_kind="chief_of_staff",
                permission_class=prepared.contract.permission_class,
                required_capabilities=frozenset(
                    {"structured_output", "local_draft", "isolated_workspace"}
                ),
                allowed_roles=frozenset({"test"}),
                allowed_billing_routes=frozenset({BillingRoute.MOCK}),
                context_bytes=prepared.context_pack.raw_bytes,
                risk=1,
            )
            selection = build_execution_selection(
                run_id=run_id,
                selection_mode="operator_explicit",
                task=task,
                candidates=(
                    RuntimeProfileState(
                        profile=profile,
                        billing_assessment=BillingRouteAssessment(
                            runner_id="mock",
                            route=BillingRoute.MOCK,
                            confidence=AssessmentConfidence.HIGH,
                        ),
                        available=True,
                    ),
                ),
                task_definition_digest=prepared.contract.definition_hash,
                context_digest=prepared.context_pack.snapshot_hash,
                authorization_intent_digest=task_authorization_intent_digest(
                    prepared.contract
                ),
                evaluated_at=time.time(),
            )
            runner = OverridingMockRunner(
                output=load_mock_chief_of_staff_output(root, prepared)
            )

            with self.assertRaisesRegex(
                ValidationError,
                "controller-owned mock runner",
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

    def test_non_profile_legacy_mock_remains_compatible_without_enforcement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary, profiles=False)
            run_id = "legacy-non-profile-mock"

            report = asyncio.run(run_chief_of_staff(root, run_id=run_id))

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            events = self._events(root, run_id)
            binding = self._only(events, "task_attempt_authorization_binding")
            self.assertEqual(binding.payload["schema_version"], 1)
            self.assertNotIn(
                "authorization_enforcement_coverage", binding.payload
            )
            self.assertFalse(
                any(
                    event.event_type
                    in {
                        MOCK_DISPATCH_DECISION_EVENT_TYPE,
                        MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
                    }
                    for event in events
                )
            )

    def test_schema_v2_selected_binding_remains_available_for_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profile = self._mock_profile(root)
            request = RunRequest(
                run_id="historical-schema-v2-binding",
                task_id=prepared.contract.task_id,
                task_version=prepared.contract.version,
                prompt=prepared.prompt,
                workspace=root / "historical-workspace",
                run_directory=root / "historical-run",
                output_schema=prepared.contract.output_schema,
                permission_class=prepared.contract.permission_class,
                timeout_seconds=prepared.contract.timeout_seconds,
                attempt=1,
                runner_overrides=runner_overrides_for_profile(profile),
            )

            payload = build_task_attempt_binding_event(
                contract=prepared.contract,
                request=request,
                runner_id="mock",
                context_digest=prepared.context_pack.snapshot_hash,
                prompt_digest=canonical_digest({"prompt": prepared.prompt}),
                project_root=str(root),
                profile_id=profile.profile_id,
                authorization_intent_digest=task_authorization_intent_digest(
                    prepared.contract
                ),
                execution_selection_digest=canonical_digest(
                    {"historical_selection": "v1"}
                ),
                profile_version_ref=canonical_digest(
                    {"profile_version": profile.version}
                ),
                profile_configuration_digest=(
                    execution_profile_configuration_digest(profile)
                ),
                enforce_mock_dispatch=False,
            )

            self.assertEqual(payload["schema_version"], 2)
            self.assertNotIn("authorization_enforcement_coverage", payload)
            self.assertNotIn("workspace_ref", payload["binding"])
            self.assertNotIn(
                "pre_run_approval_requirements_digest", payload["binding"]
            )


if __name__ == "__main__":
    unittest.main()
