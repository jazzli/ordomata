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

import ordomata.dispatch_authorization as dispatch_authorization_module
import ordomata.orchestrator as orchestrator_module
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
from ordomata.errors import (
    AuthorizationBlocked,
    ConfigurationError,
    ValidationError,
)
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
from ordomata.publication_authorization import (
    LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
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
    TASK_ATTEMPT_AUTHORIZATION_BINDING_LINEAGE_SCHEMA_VERSION,
    TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
    TASK_AUTHORIZATION_INTENT_LINEAGE_KIND,
    TASK_AUTHORIZATION_INTENT_LINEAGE_SCHEMA_VERSION,
    TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
    build_task_attempt_binding_event,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


@contextmanager
def recording_mock_calls():
    """Observe controller runner seams without mutating the runner class."""

    calls = {"inspect": 0, "execute": 0, "requests": []}
    original_inspect = orchestrator_module._inspect_runner_billing_route
    original_execute = orchestrator_module._execute_runner

    async def recording_inspect(runner):
        calls["inspect"] += 1
        return await original_inspect(runner)

    async def recording_execute(runner, request, event_sink):
        calls["execute"] += 1
        calls["requests"].append(request)
        return await original_execute(runner, request, event_sink)

    with (
        patch.object(
            orchestrator_module,
            "_inspect_runner_billing_route",
            new=recording_inspect,
        ),
        patch.object(
            orchestrator_module,
            "_execute_runner",
            new=recording_execute,
        ),
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

        self.assertEqual(
            binding.payload["schema_version"],
            TASK_ATTEMPT_AUTHORIZATION_BINDING_LINEAGE_SCHEMA_VERSION,
        )
        intent_lineage = binding.payload["binding"][
            "authorization_intent_lineage"
        ]
        self.assertEqual(
            intent_lineage["schema_version"],
            TASK_AUTHORIZATION_INTENT_LINEAGE_SCHEMA_VERSION,
        )
        self.assertEqual(
            intent_lineage["kind"],
            TASK_AUTHORIZATION_INTENT_LINEAGE_KIND,
        )
        self.assertEqual(
            intent_lineage["authorization_intent_digest"],
            binding.payload["binding"]["authorization_intent_digest"],
        )
        self.assertEqual(
            binding.payload["binding"][
                "authorization_intent_lineage_digest"
            ],
            canonical_digest(intent_lineage),
        )
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
            original_inspect = (
                orchestrator_module._inspect_runner_billing_route
            )
            original_execute = orchestrator_module._execute_runner

            async def recording_inspect(runner):
                counts["inspect"] += 1
                return await original_inspect(runner)

            async def recording_execute(runner, request, event_sink):
                counts["execute"] += 1
                return await original_execute(runner, request, event_sink)

            with (
                patch.object(
                    orchestrator_module,
                    "_inspect_runner_billing_route",
                    new=recording_inspect,
                ),
                patch.object(
                    orchestrator_module,
                    "_execute_runner",
                    new=recording_execute,
                ),
            ):
                report = asyncio.run(
                    run_chief_of_staff(
                        root,
                        run_id=run_id,
                        operator_instructions=(private_instruction,),
                    )
                )

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            self.assertEqual(counts, {"inspect": 1, "execute": 1})
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
            self.assertEqual(calls["inspect"], 1)
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

    def test_expired_decision_blocks_before_running_and_execute(
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
                **current_inputs,
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
                    **current_inputs,
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
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.BLOCKED
                and event.payload.get("phase")
                == "mock_dispatch_authorization_freshness"
            )
            self.assertLess(decision.sequence, terminal.sequence)
            self.assertFalse(
                any(
                    event.status is RunStatus.RUNNING
                    and event.payload.get("phase") == "runner_execution"
                    for event in events
                )
            )
            self.assertFalse(
                any(
                    event.event_type == "authorization_shadow_decision"
                    and event.payload.get("action_scope")
                    == DISPATCH_ACTION_SCOPE
                    for event in events
                )
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
            original_execute = orchestrator_module._execute_runner
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
                    orchestrator_module,
                    "_execute_runner",
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
                    orchestrator_module,
                    "_execute_runner",
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
            self.assertEqual(calls["inspect"], 1)
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

    def test_silent_pre_effect_evidence_drop_never_executes(self) -> None:
        for target in ("billing", "decision", "running"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = f"mock-dispatch-silent-{target}-drop"
                prepared, profile, selection, runner = self._explicit_inputs(
                    root,
                    run_id,
                )
                original_append = SQLiteStateStore.append_event
                dropped = False

                def drop_target(
                    store,
                    observed_run_id,
                    event_type,
                    payload=None,
                    **kwargs,
                ):
                    nonlocal dropped
                    is_target = (
                        target == "billing"
                        and event_type == "billing_assessment"
                    ) or (
                        target == "decision"
                        and event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE
                    ) or (
                        target == "running"
                        and event_type == "status"
                        and payload == {"phase": "runner_execution"}
                        and kwargs.get("status") is RunStatus.RUNNING
                    )
                    if is_target and not dropped:
                        dropped = True
                        return None
                    return original_append(
                        store,
                        observed_run_id,
                        event_type,
                        payload,
                        **kwargs,
                    )

                with (
                    patch.object(
                        SQLiteStateStore,
                        "append_event",
                        new=drop_target,
                    ),
                    recording_mock_calls() as calls,
                    self.assertRaises(ConfigurationError),
                ):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=runner_overrides_for_profile(
                                profile
                            ),
                            run_id=run_id,
                            profile_id=profile.profile_id,
                            prepared_task=prepared,
                            execution_selection=selection,
                        )
                    )

                self.assertTrue(dropped)
                self.assertEqual(calls["inspect"], 1)
                self.assertEqual(calls["execute"], 0)
                events = self._events(root, run_id)
                self.assertFalse(
                    any(event.status is RunStatus.RUNNING for event in events)
                )
                self.assertFalse(
                    any(
                        event.event_type
                        == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                        for event in events
                    )
                )
                self.assertFalse(
                    any(
                        event.event_type == "execution_accounting"
                        for event in events
                    )
                )
                with SQLiteStateStore(
                    root / ".ordomata" / "state.sqlite3"
                ) as state:
                    self.assertEqual(
                        state.current_status(run_id),
                        RunStatus.FAILED,
                    )
                    self.assertEqual(state.list_artifacts(run_id), ())

    def test_final_rebuild_base_exception_cancels_before_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-final-rebuild-cancelled"
            prepared, profile, selection, runner = self._explicit_inputs(
                root,
                run_id,
            )
            original_rebuild = (
                dispatch_authorization_module.
                _evaluate_mock_dispatch_authorization
            )
            rebuild_calls = 0
            private_error = "private-final-rebuild-cancellation-89d2"

            def interrupt_final_rebuild(**kwargs):
                nonlocal rebuild_calls
                rebuild_calls += 1
                if rebuild_calls > 1:
                    raise KeyboardInterrupt(private_error)
                return original_rebuild(**kwargs)

            with (
                patch(
                    "ordomata.dispatch_authorization."
                    "_evaluate_mock_dispatch_authorization",
                    new=interrupt_final_rebuild,
                ),
                recording_mock_calls() as calls,
                self.assertRaises(KeyboardInterrupt),
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

            self.assertEqual(rebuild_calls, 2)
            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
            self.assertFalse(
                any(event.status is RunStatus.RUNNING for event in events)
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.CANCELLED
                and event.payload.get("phase")
                == "mock_dispatch_authorization_freshness"
            )
            self.assertIsNotNone(terminal)
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
                self.assertEqual(
                    state.current_status(run_id),
                    RunStatus.CANCELLED,
                )
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_post_replay_expiry_blocks_and_receipt_uses_boundary_time(
        self,
    ) -> None:
        for expires_before_effect in (True, False):
            with (
                self.subTest(expires_before_effect=expires_before_effect),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = (
                    "mock-dispatch-post-replay-expired"
                    if expires_before_effect
                    else "mock-dispatch-post-replay-current"
                )
                prepared, profile, selection, runner = self._explicit_inputs(
                    root,
                    run_id,
                )
                original_assert = (
                    orchestrator_module.assert_mock_dispatch_authorized
                )
                clock = {"now": 100.0}
                assertion_count = 0
                expected_boundary = 101.0

                def fake_time() -> float:
                    return clock["now"]

                def advance_after_replay(authorization, **kwargs):
                    nonlocal assertion_count
                    original_assert(authorization, **kwargs)
                    assertion_count += 1
                    if assertion_count == 2:
                        clock["now"] = (
                            authorization.decision.expires_at + 1.0
                            if expires_before_effect
                            else expected_boundary
                        )

                with (
                    patch.object(
                        orchestrator_module.time,
                        "time",
                        new=fake_time,
                    ),
                    patch.object(
                        orchestrator_module,
                        "assert_mock_dispatch_authorized",
                        new=advance_after_replay,
                    ),
                    recording_mock_calls() as calls,
                ):
                    if expires_before_effect:
                        with self.assertRaises(AuthorizationBlocked):
                            asyncio.run(
                                run_chief_of_staff(
                                    root,
                                    runner=runner,
                                    runner_overrides=(
                                        runner_overrides_for_profile(profile)
                                    ),
                                    run_id=run_id,
                                    profile_id=profile.profile_id,
                                    prepared_task=prepared,
                                    execution_selection=selection,
                                )
                            )
                    else:
                        report = asyncio.run(
                            run_chief_of_staff(
                                root,
                                runner=runner,
                                runner_overrides=runner_overrides_for_profile(
                                    profile
                                ),
                                run_id=run_id,
                                profile_id=profile.profile_id,
                                prepared_task=prepared,
                                execution_selection=selection,
                            )
                        )
                        self.assertEqual(report.status, RunStatus.SUCCEEDED)

                self.assertEqual(assertion_count, 2)
                events = self._events(root, run_id)
                if expires_before_effect:
                    self.assertEqual(calls["execute"], 0)
                    self.assertFalse(
                        any(
                            event.event_type
                            == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                            for event in events
                        )
                    )
                    with SQLiteStateStore(
                        root / ".ordomata" / "state.sqlite3"
                    ) as state:
                        self.assertEqual(
                            state.current_status(run_id),
                            RunStatus.BLOCKED,
                        )
                else:
                    self.assertEqual(calls["execute"], 1)
                    receipt = self._only(
                        events,
                        MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
                    )
                    self.assertEqual(
                        receipt.payload["receipt"]["started_at"],
                        expected_boundary,
                    )

    def test_silent_selection_or_binding_drop_blocks_before_admission(
        self,
    ) -> None:
        for target_event_type in (
            "task_execution_selection",
            "task_attempt_authorization_binding",
        ):
            with (
                self.subTest(target_event_type=target_event_type),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = f"mock-dispatch-silent-{target_event_type}-drop"
                prepared, profile, selection, runner = self._explicit_inputs(
                    root,
                    run_id,
                )
                original_append = SQLiteStateStore.append_event
                dropped = False

                def drop_required_lineage(
                    store,
                    observed_run_id,
                    event_type,
                    payload=None,
                    **kwargs,
                ):
                    nonlocal dropped
                    if not dropped and event_type == target_event_type:
                        dropped = True
                        return None
                    return original_append(
                        store,
                        observed_run_id,
                        event_type,
                        payload,
                        **kwargs,
                    )

                with (
                    patch.object(
                        SQLiteStateStore,
                        "append_event",
                        new=drop_required_lineage,
                    ),
                    self.assertRaises(ConfigurationError),
                ):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=runner_overrides_for_profile(
                                profile
                            ),
                            run_id=run_id,
                            profile_id=profile.profile_id,
                            prepared_task=prepared,
                            execution_selection=selection,
                        )
                    )

                self.assertTrue(dropped)
                events = self._events(root, run_id)
                self.assertFalse(
                    any(event.status is RunStatus.RUNNING for event in events)
                )
                self.assertFalse(
                    any(
                        event.event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE
                        for event in events
                    )
                )
                with SQLiteStateStore(
                    root / ".ordomata" / "state.sqlite3"
                ) as state:
                    self.assertEqual(
                        state.current_status(run_id),
                        RunStatus.FAILED,
                    )
                    self.assertEqual(state.list_artifacts(run_id), ())

    def test_current_mock_binding_schema_downgrade_never_reaches_admission(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-binding-schema-downgrade"
            prepared, profile, selection, runner = self._explicit_inputs(
                root,
                run_id,
            )
            original_builder = (
                orchestrator_module.build_task_attempt_binding_event
            )

            def build_schema_five_binding(**kwargs):
                return original_builder(
                    **{
                        **kwargs,
                        "bind_dispatch_intent_lineage": False,
                    }
                )

            with (
                patch.object(
                    orchestrator_module,
                    "build_task_attempt_binding_event",
                    new=build_schema_five_binding,
                ),
                recording_mock_calls() as calls,
                self.assertRaisesRegex(
                    ValidationError,
                    "intent lineage binding is unavailable",
                ),
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
            self.assertFalse(
                any(
                    event.event_type == TASK_ADMISSION_DECISION_EVENT_TYPE
                    for event in events
                )
            )
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE
                    for event in events
                )
            )

    def test_silent_execution_accounting_drop_prevents_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-silent-accounting-drop"
            prepared, profile, selection, runner = self._explicit_inputs(
                root,
                run_id,
            )
            original_append = SQLiteStateStore.append_event
            dropped = False

            def drop_accounting(
                store,
                observed_run_id,
                event_type,
                payload=None,
                **kwargs,
            ):
                nonlocal dropped
                if not dropped and event_type == "execution_accounting":
                    dropped = True
                    return None
                return original_append(
                    store,
                    observed_run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=drop_accounting,
                ),
                self.assertRaises(ConfigurationError),
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

            self.assertTrue(dropped)
            events = self._events(root, run_id)
            self._only(events, MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE)
            self.assertFalse(
                any(event.event_type == "execution_accounting" for event in events)
            )
            self.assertFalse(
                any(
                    event.event_type
                    in {
                        LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
                        TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
                        TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                    }
                    for event in events
                )
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertIn(
                    state.current_status(run_id),
                    {RunStatus.FAILED, RunStatus.QUARANTINED},
                )
                self.assertEqual(state.list_artifacts(run_id), ())
            self.assertFalse(
                (root / "artifacts" / "chief-of-staff-lite.json").exists()
            )

    def test_effect_time_authoritative_readback_drop_never_executes(self) -> None:
        for target_event_type in (
            "task_attempt_authorization_binding",
            MOCK_DISPATCH_DECISION_EVENT_TYPE,
        ):
            with (
                self.subTest(target_event_type=target_event_type),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = (
                    "mock-dispatch-effect-time-"
                    f"{target_event_type.replace('_', '-')}-drop"
                )
                prepared, profile, selection, runner = self._explicit_inputs(
                    root,
                    run_id,
                )
                original_list_events = SQLiteStateStore.list_events
                hidden = False

                def hide_authoritative_event_after_running(
                    store,
                    observed_run_id,
                ):
                    nonlocal hidden
                    events = original_list_events(store, observed_run_id)
                    if any(
                        event.status is RunStatus.RUNNING for event in events
                    ):
                        hidden = True
                        return tuple(
                            event
                            for event in events
                            if event.event_type != target_event_type
                        )
                    return events

                with (
                    patch.object(
                        SQLiteStateStore,
                        "list_events",
                        new=hide_authoritative_event_after_running,
                    ),
                    recording_mock_calls() as calls,
                    self.assertRaises(ConfigurationError),
                ):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=runner_overrides_for_profile(
                                profile
                            ),
                            run_id=run_id,
                            profile_id=profile.profile_id,
                            prepared_task=prepared,
                            execution_selection=selection,
                        )
                    )

                self.assertTrue(hidden)
                self.assertEqual(calls["execute"], 0)
                events = self._events(root, run_id)
                self.assertFalse(
                    any(
                        event.event_type
                        == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                        for event in events
                    )
                )
                with SQLiteStateStore(
                    root / ".ordomata" / "state.sqlite3"
                ) as state:
                    self.assertEqual(
                        state.current_status(run_id),
                        RunStatus.FAILED,
                    )
                    self.assertEqual(state.list_artifacts(run_id), ())

    def test_retained_decision_payload_mutation_is_caught_at_final_pep(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-retained-payload-mutation"
            prepared, profile, selection, runner = self._explicit_inputs(
                root,
                run_id,
            )
            original_append = SQLiteStateStore.append_event
            retained_payload = None
            mutated = False

            def mutate_after_precheck(
                store,
                observed_run_id,
                event_type,
                payload=None,
                **kwargs,
            ):
                nonlocal retained_payload, mutated
                result = original_append(
                    store,
                    observed_run_id,
                    event_type,
                    payload,
                    **kwargs,
                )
                if event_type == MOCK_DISPATCH_DECISION_EVENT_TYPE:
                    retained_payload = payload
                elif (
                    not mutated
                    and event_type == "status"
                    and payload == {"phase": "runner_execution"}
                    and kwargs.get("status") is RunStatus.RUNNING
                ):
                    assert retained_payload is not None
                    retained_payload["execution_selection_digest"] = (
                        canonical_digest({"fixture": "late-mutation"})
                    )
                    mutated = True
                return result

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=mutate_after_precheck,
                ),
                recording_mock_calls() as calls,
                self.assertRaises(ConfigurationError),
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

            self.assertTrue(mutated)
            self.assertEqual(calls["execute"], 0)
            events = self._events(root, run_id)
            self._only(events, MOCK_DISPATCH_DECISION_EVENT_TYPE)
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(state.current_status(run_id), RunStatus.FAILED)
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_late_runner_boundary_rebound_never_executes(self) -> None:
        for boundary_name in ("execute", "inspect_billing_route"):
            with (
                self.subTest(boundary_name=boundary_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = f"mock-dispatch-late-rebound-{boundary_name}"
                prepared, profile, selection, runner = self._explicit_inputs(
                    root,
                    run_id,
                )
                original_append = SQLiteStateStore.append_event
                rebound = False

                async def forbidden_boundary(*args, **kwargs):
                    del args, kwargs
                    raise AssertionError("a rebound runner boundary executed")

                def rebound_after_precheck(
                    store,
                    observed_run_id,
                    event_type,
                    payload=None,
                    **kwargs,
                ):
                    nonlocal rebound
                    result = original_append(
                        store,
                        observed_run_id,
                        event_type,
                        payload,
                        **kwargs,
                    )
                    if (
                        not rebound
                        and event_type == "status"
                        and payload == {"phase": "runner_execution"}
                        and kwargs.get("status") is RunStatus.RUNNING
                    ):
                        setattr(runner, boundary_name, forbidden_boundary)
                        rebound = True
                    return result

                with (
                    patch.object(
                        SQLiteStateStore,
                        "append_event",
                        new=rebound_after_precheck,
                    ),
                    recording_mock_calls() as calls,
                    self.assertRaises(AuthorizationBlocked),
                ):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=runner_overrides_for_profile(
                                profile
                            ),
                            run_id=run_id,
                            profile_id=profile.profile_id,
                            prepared_task=prepared,
                            execution_selection=selection,
                        )
                    )

                self.assertTrue(rebound)
                self.assertEqual(calls["execute"], 0)
                events = self._events(root, run_id)
                self.assertFalse(
                    any(
                        event.event_type
                        == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                        for event in events
                    )
                )
                self.assertFalse(
                    any(
                        event.event_type == "execution_accounting"
                        for event in events
                    )
                )
                with SQLiteStateStore(
                    root / ".ordomata" / "state.sqlite3"
                ) as state:
                    self.assertEqual(
                        state.current_status(run_id),
                        RunStatus.BLOCKED,
                    )
                    self.assertEqual(state.list_artifacts(run_id), ())

    def test_late_mock_runner_class_rebound_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-late-class-rebound"
            prepared, profile, selection, runner = self._explicit_inputs(
                root,
                run_id,
            )
            original_append = SQLiteStateStore.append_event
            class_patch = None
            rebound = False
            execute_attempted = False

            async def forbidden_execute(*args, **kwargs):
                nonlocal execute_attempted
                del args, kwargs
                execute_attempted = True
                raise AssertionError("a rebound MockRunner class executed")

            def rebound_class_after_precheck(
                store,
                observed_run_id,
                event_type,
                payload=None,
                **kwargs,
            ):
                nonlocal class_patch, rebound
                result = original_append(
                    store,
                    observed_run_id,
                    event_type,
                    payload,
                    **kwargs,
                )
                if (
                    not rebound
                    and event_type == "status"
                    and payload == {"phase": "runner_execution"}
                    and kwargs.get("status") is RunStatus.RUNNING
                ):
                    class_patch = patch.object(
                        MockRunner,
                        "execute",
                        new=forbidden_execute,
                    )
                    class_patch.start()
                    rebound = True
                return result

            try:
                with (
                    patch.object(
                        SQLiteStateStore,
                        "append_event",
                        new=rebound_class_after_precheck,
                    ),
                    self.assertRaises(AuthorizationBlocked),
                ):
                    asyncio.run(
                        run_chief_of_staff(
                            root,
                            runner=runner,
                            runner_overrides=runner_overrides_for_profile(
                                profile
                            ),
                            run_id=run_id,
                            profile_id=profile.profile_id,
                            prepared_task=prepared,
                            execution_selection=selection,
                        )
                    )
            finally:
                if class_patch is not None:
                    class_patch.stop()

            self.assertTrue(rebound)
            self.assertFalse(execute_attempted)
            events = self._events(root, run_id)
            self.assertFalse(
                any(
                    event.event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            self.assertFalse(
                any(
                    event.event_type == "execution_accounting"
                    for event in events
                )
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(
                    state.current_status(run_id),
                    RunStatus.BLOCKED,
                )
                self.assertEqual(state.list_artifacts(run_id), ())

    def test_silent_dispatch_receipt_drop_quarantines_before_publication(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-silent-receipt-drop"
            prepared, profile, selection, runner = self._explicit_inputs(
                root,
                run_id,
            )
            original_append = SQLiteStateStore.append_event
            dropped = False

            def drop_receipt(
                store,
                observed_run_id,
                event_type,
                payload=None,
                **kwargs,
            ):
                nonlocal dropped
                if (
                    not dropped
                    and event_type == MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE
                ):
                    dropped = True
                    return None
                return original_append(
                    store,
                    observed_run_id,
                    event_type,
                    payload,
                    **kwargs,
                )

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=drop_receipt,
                ),
                recording_mock_calls() as calls,
                self.assertRaises(ConfigurationError),
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

            self.assertTrue(dropped)
            self.assertEqual(calls["execute"], 1)
            events = self._events(root, run_id)
            prohibited_types = {
                MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
                "execution_accounting",
                LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
                TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
                TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            }
            self.assertFalse(
                any(event.event_type in prohibited_types for event in events)
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(
                    state.current_status(run_id),
                    RunStatus.QUARANTINED,
                )
                self.assertEqual(state.list_artifacts(run_id), ())
            self.assertFalse(
                (root / "artifacts" / "chief-of-staff-lite.json").exists()
            )

    def test_malformed_returned_receipt_context_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "mock-dispatch-malformed-returned-receipt"
            prepared, profile, selection, runner = self._explicit_inputs(
                root,
                run_id,
            )
            original_append_receipt = (
                orchestrator_module._append_mock_dispatch_action_receipt
            )

            def return_malformed_context(*args, **kwargs):
                payload = original_append_receipt(*args, **kwargs)
                return {**payload, "receipt": None}

            with (
                patch.object(
                    orchestrator_module,
                    "_append_mock_dispatch_action_receipt",
                    new=return_malformed_context,
                ),
                recording_mock_calls() as calls,
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

            self.assertEqual(calls["execute"], 1)
            events = self._events(root, run_id)
            self._only(events, MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE)
            self.assertFalse(
                any(event.event_type == "execution_accounting" for event in events)
            )
            with SQLiteStateStore(
                root / ".ordomata" / "state.sqlite3"
            ) as state:
                self.assertEqual(
                    state.current_status(run_id),
                    RunStatus.QUARANTINED,
                )
                self.assertEqual(state.list_artifacts(run_id), ())

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
