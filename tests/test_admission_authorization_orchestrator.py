import asyncio
from contextlib import contextmanager
from dataclasses import replace
import itertools
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import ordomata.orchestrator as orchestrator_module
from ordomata.admission_authorization import (
    TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
    TASK_ADMISSION_ACTION_SCOPE,
    TASK_ADMISSION_DECISION_EVENT_TYPE,
    TASK_ADMISSION_ENFORCEMENT_COVERAGE,
    TASK_ADMISSION_EXECUTOR_ID,
    TASK_ADMISSION_OPERATION,
    assert_task_admission_authorized,
)
from ordomata.authorization import (
    AuthorizationEffect,
    AuthorizationEvaluator,
    DecisionReason,
    canonical_digest,
)
from ordomata.dispatch_authorization import (
    MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
    MOCK_DISPATCH_DECISION_EVENT_TYPE,
)
from ordomata.errors import (
    AuthorizationBlocked,
    ConfigurationError,
    ValidationError,
)
from ordomata.execution_selection import build_execution_selection
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
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
    task_authorization_intent_digest,
)
from ordomata.state import SQLiteStateStore
from ordomata.task_evidence import (
    TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_AUTHORIZATION_BINDING_LINEAGE_SCHEMA_VERSION,
    TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


@contextmanager
def recording_mock_calls():
    """Observe controller runner seams without mutating the runner class."""

    calls = {"inspect": 0, "execute": 0}
    original_inspect = orchestrator_module._inspect_runner_billing_route
    original_execute = orchestrator_module._execute_runner

    async def recording_inspect(runner):
        calls["inspect"] += 1
        return await original_inspect(runner)

    async def recording_execute(runner, request, event_sink):
        calls["execute"] += 1
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
        raise AssertionError("an overriding mock must not reach preflight")

    async def execute(self, request, event_sink):
        del request, event_sink
        self.execute_count += 1
        raise AssertionError("an overriding mock must never execute")


class AdmissionAuthorizationOrchestratorTests(unittest.TestCase):
    def _project(self, temporary: str) -> Path:
        root = Path(temporary)
        for name in ("tasks", "schemas", "fixtures", "profiles"):
            shutil.copytree(REPOSITORY_ROOT / name, root / name)
        return root

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

    @staticmethod
    def _admission_shadow(events):
        matches = [
            event
            for event in events
            if event.event_type == "authorization_shadow_decision"
            and event.payload.get("action_scope") == ADMISSION_ACTION_SCOPE
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"expected one admission shadow, found {len(matches)}"
            )
        return matches[0]

    def _assert_no_downstream_work(
        self,
        root: Path,
        run_id: str,
        calls,
    ) -> None:
        self.assertEqual(calls, {"inspect": 0, "execute": 0})
        events = self._events(root, run_id)
        prohibited_types = {
            "billing_assessment",
            "execution_accounting",
            MOCK_DISPATCH_DECISION_EVENT_TYPE,
            MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
            LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
            TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
            TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
        }
        self.assertFalse(
            any(event.event_type in prohibited_types for event in events)
        )
        self.assertFalse(
            any(
                event.event_type == "status"
                and event.payload.get("phase") == "runner_execution"
                for event in events
            )
        )
        self.assertFalse(
            any(
                event.event_type == "authorization_shadow_decision"
                and event.payload.get("action_scope")
                == ADMISSION_ACTION_SCOPE
                for event in events
            )
        )
        with SQLiteStateStore(root / ".ordomata" / "state.sqlite3") as state:
            self.assertEqual(state.list_artifacts(run_id), ())
        self.assertFalse(
            (root / "artifacts" / "chief-of-staff-lite.json").exists()
        )
        workspace = root / ".ordomata" / "runs" / run_id / "workspace"
        self.assertTrue(workspace.is_dir())
        self.assertEqual(tuple(workspace.iterdir()), ())

    def _explicit_mock_inputs(self, root: Path, run_id: str):
        prepared = prepare_chief_of_staff(root)
        profiles = load_execution_profiles(root / "profiles" / "default.json")
        profile = next(item for item in profiles if item.runner_id == "mock")
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
        return prepared, profile, selection

    def test_success_persists_exact_admission_before_any_downstream_work(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "admission-success"
            private_instruction = "private-admission-instruction-91af"

            with recording_mock_calls() as calls:
                report = asyncio.run(
                    run_chief_of_staff(
                        root,
                        run_id=run_id,
                        operator_instructions=(private_instruction,),
                    )
                )

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            self.assertEqual(calls, {"inspect": 1, "execute": 1})
            events = self._events(root, run_id)
            selection = self._only(events, "task_execution_selection")
            binding = self._only(
                events, "task_attempt_authorization_binding"
            )
            decision = self._only(events, TASK_ADMISSION_DECISION_EVENT_TYPE)
            receipt = self._only(
                events, TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
            )
            admission_shadow = self._admission_shadow(events)
            billing = self._only(events, "billing_assessment")
            dispatch_decision = self._only(
                events, MOCK_DISPATCH_DECISION_EVENT_TYPE
            )
            running = next(
                event
                for event in events
                if event.event_type == "status"
                and event.status is RunStatus.RUNNING
                and event.payload.get("phase") == "runner_execution"
            )

            self.assertEqual(
                binding.payload["schema_version"],
                TASK_ATTEMPT_AUTHORIZATION_BINDING_LINEAGE_SCHEMA_VERSION,
            )
            self.assertEqual(
                binding.payload[
                    "admission_authorization_enforcement_coverage"
                ],
                TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE,
            )
            self.assertEqual(
                decision.payload["enforcement_coverage"],
                TASK_ADMISSION_ENFORCEMENT_COVERAGE,
            )
            self.assertEqual(
                decision.payload["action_scope"], TASK_ADMISSION_ACTION_SCOPE
            )
            self.assertEqual(decision.payload["effect"], "permit")
            self.assertTrue(decision.payload["authorization_eligible"])
            self.assertEqual(
                decision.payload["request"]["action"]["operation"],
                TASK_ADMISSION_OPERATION,
            )
            self.assertEqual(
                decision.payload["task_attempt_binding_digest"],
                binding.payload["binding_digest"],
            )
            self.assertEqual(
                decision.payload["execution_selection_digest"],
                selection.payload["selection_digest"],
            )

            body = receipt.payload["receipt"]
            self.assertEqual(body["outcome"], "succeeded")
            self.assertEqual(body["executor_id"], TASK_ADMISSION_EXECUTOR_ID)
            self.assertEqual(receipt.event_id, body["receipt_id"])
            self.assertEqual(
                receipt.payload["receipt_digest"], canonical_digest(body)
            )
            self.assertEqual(
                receipt.payload["admission_result_digest"],
                body["result_digest"],
            )
            self.assertEqual(
                receipt.payload["request_digest"],
                decision.payload["request_digest"],
            )
            self.assertEqual(
                receipt.payload["decision_digest"],
                decision.payload["decision_digest"],
            )

            self.assertLess(selection.sequence, binding.sequence)
            self.assertLess(binding.sequence, decision.sequence)
            self.assertLess(decision.sequence, receipt.sequence)
            self.assertLess(receipt.sequence, admission_shadow.sequence)
            self.assertLess(admission_shadow.sequence, billing.sequence)
            self.assertLess(billing.sequence, dispatch_decision.sequence)
            self.assertLess(dispatch_decision.sequence, running.sequence)

            serialized = json.dumps(
                [decision.payload, receipt.payload], sort_keys=True
            )
            for private_value in (
                str(root),
                private_instruction,
                "chief_of_staff.valid",
            ):
                self.assertNotIn(private_value, serialized)

    def test_evaluator_failure_is_redacted_and_stops_before_preflight(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "admission-evaluator-failure"
            private_error = "private-admission-evaluator-error-4bb2"

            with (
                patch(
                    "ordomata.orchestrator."
                    "evaluate_task_admission_authorization",
                    side_effect=RuntimeError(private_error),
                ),
                recording_mock_calls() as calls,
                self.assertRaises(AuthorizationBlocked) as caught,
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            self.assertNotIn(private_error, str(caught.exception))
            events = self._events(root, run_id)
            decision = self._only(events, TASK_ADMISSION_DECISION_EVENT_TYPE)
            self.assertEqual(decision.payload["effect"], "indeterminate")
            self.assertFalse(decision.payload["authorization_eligible"])
            self.assertEqual(
                decision.payload["failure_stage"], "request_or_evaluation"
            )
            self.assertIsNone(decision.payload["request"])
            self.assertNotIn(private_error, decision.payload_json)
            self.assertFalse(
                any(
                    event.event_type
                    == TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            self._assert_no_downstream_work(root, run_id, calls)

    def test_deny_defer_and_indeterminate_never_cross_admission(self) -> None:
        original_evaluate = AuthorizationEvaluator.evaluate

        for effect, reason in (
            (AuthorizationEffect.DENY, DecisionReason.CLASS_DISABLED),
            (AuthorizationEffect.DEFER, DecisionReason.APPROVAL_REQUIRED),
            (
                AuthorizationEffect.INDETERMINATE,
                DecisionReason.EVIDENCE_STALE,
            ),
        ):
            with self.subTest(effect=effect.value), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"admission-{effect.value}"

                def force_nonpermit(evaluator, request, policy):
                    decision = original_evaluate(evaluator, request, policy)
                    return replace(
                        decision,
                        effect=effect,
                        reason_codes=(reason,),
                        reason_details=("fixed nonpermit fixture",),
                        obligations=(),
                    )

                with (
                    patch.object(
                        AuthorizationEvaluator,
                        "evaluate",
                        new=force_nonpermit,
                    ),
                    recording_mock_calls() as calls,
                    self.assertRaises(AuthorizationBlocked),
                ):
                    asyncio.run(run_chief_of_staff(root, run_id=run_id))

                events = self._events(root, run_id)
                decision = self._only(
                    events, TASK_ADMISSION_DECISION_EVENT_TYPE
                )
                self.assertEqual(decision.payload["effect"], effect.value)
                self.assertFalse(decision.payload["authorization_eligible"])
                self.assertIn(
                    "authorization_effect_not_permit",
                    decision.payload["block_reason_codes"],
                )
                self.assertFalse(
                    any(
                        event.event_type
                        == TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                        for event in events
                    )
                )
                self._assert_no_downstream_work(root, run_id, calls)

    def test_expired_permit_never_crosses_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "admission-expired"
            freshness_checks = 0

            def force_expired(authorization, **kwargs):
                nonlocal freshness_checks
                freshness_checks += 1
                self.assertLess(
                    kwargs["action_started_at"],
                    authorization.decision.expires_at,
                )
                return assert_task_admission_authorized(
                    authorization,
                    **{
                        **kwargs,
                        "action_started_at": (
                            authorization.decision.expires_at
                        ),
                    },
                )

            with (
                patch(
                    "ordomata.orchestrator.assert_task_admission_authorized",
                    new=force_expired,
                ),
                recording_mock_calls() as calls,
                self.assertRaises(AuthorizationBlocked),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            self.assertEqual(freshness_checks, 1)
            events = self._events(root, run_id)
            self._only(events, TASK_ADMISSION_DECISION_EVENT_TYPE)
            self.assertFalse(
                any(
                    event.event_type
                    == TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.BLOCKED
            )
            self.assertEqual(
                terminal.payload,
                {"phase": "task_admission_authorization_freshness"},
            )
            self._assert_no_downstream_work(root, run_id, calls)

    def test_decision_persistence_precommit_fails_and_commit_reconciles(
        self,
    ) -> None:
        original_append = SQLiteStateStore.append_event

        for case in ("precommit", "committed"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"admission-decision-{case}"
                injected = False
                private_error = f"private-decision-{case}-c42a"

                def append_with_failure(
                    store, observed_run_id, event_type, payload=None, **kwargs
                ):
                    nonlocal injected
                    if not injected and event_type == TASK_ADMISSION_DECISION_EVENT_TYPE:
                        injected = True
                        if case == "precommit":
                            raise OSError(private_error)
                        original_append(
                            store,
                            observed_run_id,
                            event_type,
                            payload,
                            **kwargs,
                        )
                        raise OSError(private_error)
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
                        new=append_with_failure,
                    ),
                    recording_mock_calls() as calls,
                ):
                    if case == "precommit":
                        with self.assertRaises(OSError):
                            asyncio.run(
                                run_chief_of_staff(root, run_id=run_id)
                            )
                    else:
                        report = asyncio.run(
                            run_chief_of_staff(root, run_id=run_id)
                        )
                        self.assertEqual(report.status, RunStatus.SUCCEEDED)

                self.assertTrue(injected)
                events = self._events(root, run_id)
                decisions = [
                    event
                    for event in events
                    if event.event_type == TASK_ADMISSION_DECISION_EVENT_TYPE
                ]
                self.assertNotIn(
                    private_error,
                    "\n".join(event.payload_json for event in events),
                )
                if case == "precommit":
                    self.assertEqual(decisions, [])
                    self._assert_no_downstream_work(root, run_id, calls)
                    with SQLiteStateStore(
                        root / ".ordomata" / "state.sqlite3"
                    ) as state:
                        self.assertEqual(
                            state.current_status(run_id), RunStatus.FAILED
                        )
                else:
                    self.assertEqual(len(decisions), 1)
                    self.assertEqual(calls, {"inspect": 1, "execute": 1})

    def test_receipt_persistence_precommit_fails_and_commit_reconciles(
        self,
    ) -> None:
        original_append = SQLiteStateStore.append_event

        for case in ("precommit", "committed"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"admission-receipt-{case}"
                injected = False
                private_error = f"private-receipt-{case}-a293"

                def append_with_failure(
                    store, observed_run_id, event_type, payload=None, **kwargs
                ):
                    nonlocal injected
                    if (
                        not injected
                        and event_type
                        == TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                    ):
                        injected = True
                        if case == "precommit":
                            raise OSError(private_error)
                        original_append(
                            store,
                            observed_run_id,
                            event_type,
                            payload,
                            **kwargs,
                        )
                        raise OSError(private_error)
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
                        new=append_with_failure,
                    ),
                    recording_mock_calls() as calls,
                ):
                    if case == "precommit":
                        with self.assertRaises(OSError):
                            asyncio.run(
                                run_chief_of_staff(root, run_id=run_id)
                            )
                    else:
                        report = asyncio.run(
                            run_chief_of_staff(root, run_id=run_id)
                        )
                        self.assertEqual(report.status, RunStatus.SUCCEEDED)

                self.assertTrue(injected)
                events = self._events(root, run_id)
                receipts = [
                    event
                    for event in events
                    if event.event_type
                    == TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                ]
                self.assertNotIn(
                    private_error,
                    "\n".join(event.payload_json for event in events),
                )
                if case == "precommit":
                    self.assertEqual(receipts, [])
                    self._assert_no_downstream_work(root, run_id, calls)
                    with SQLiteStateStore(
                        root / ".ordomata" / "state.sqlite3"
                    ) as state:
                        self.assertEqual(
                            state.current_status(run_id), RunStatus.FAILED
                        )
                else:
                    self.assertEqual(len(receipts), 1)
                    self.assertEqual(calls, {"inspect": 1, "execute": 1})

    def test_unprovable_admission_readback_never_reaches_billing(self) -> None:
        original_readback = orchestrator_module._event_persistence_state

        for target_event_type, persistence_state in itertools.product(
            (
                TASK_ADMISSION_DECISION_EVENT_TYPE,
                TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
            ),
            (False, None),
        ):
            with (
                self.subTest(
                    event_type=target_event_type,
                    persistence_state=persistence_state,
                ),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = f"admission-readback-{target_event_type}"

                def reject_target_readback(
                    state,
                    observed_run_id,
                    event_type,
                    payload,
                    **kwargs,
                ):
                    if event_type == target_event_type:
                        return persistence_state
                    return original_readback(
                        state,
                        observed_run_id,
                        event_type,
                        payload,
                        **kwargs,
                    )

                with (
                    patch(
                        "ordomata.orchestrator._event_persistence_state",
                        new=reject_target_readback,
                    ),
                    recording_mock_calls() as calls,
                    self.assertRaises(ConfigurationError),
                ):
                    asyncio.run(run_chief_of_staff(root, run_id=run_id))

                events = self._events(root, run_id)
                self._only(events, TASK_ADMISSION_DECISION_EVENT_TYPE)
                receipts = [
                    event
                    for event in events
                    if event.event_type
                    == TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                ]
                self.assertEqual(
                    len(receipts),
                    int(
                        target_event_type
                        == TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE
                    ),
                )
                self._assert_no_downstream_work(root, run_id, calls)
                with SQLiteStateStore(
                    root / ".ordomata" / "state.sqlite3"
                ) as state:
                    self.assertEqual(
                        state.current_status(run_id),
                        RunStatus.FAILED,
                    )

    def test_real_class_consequence_and_approval_stops_precede_billing(
        self,
    ) -> None:
        for case, expected_effect in (
            ("class-zero", AuthorizationEffect.PERMIT),
            ("high-consequence", AuthorizationEffect.DENY),
            ("approval-required", AuthorizationEffect.DEFER),
        ):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                task_path = root / "tasks" / "chief-of-staff-lite.json"
                task = json.loads(task_path.read_text(encoding="utf-8"))
                if case == "class-zero":
                    task["permission_class"] = 0
                elif case == "high-consequence":
                    task["authorization_intent"]["consequences"][
                        "confidentiality"
                    ] = "high"
                else:
                    task["approval_requirements"][
                        "required_before_run"
                    ] = True
                task_path.write_text(
                    json.dumps(task, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                run_id = f"admission-real-{case}"

                with (
                    recording_mock_calls() as calls,
                    self.assertRaises(AuthorizationBlocked),
                ):
                    asyncio.run(run_chief_of_staff(root, run_id=run_id))

                events = self._events(root, run_id)
                decision = self._only(
                    events,
                    TASK_ADMISSION_DECISION_EVENT_TYPE,
                )
                self.assertEqual(
                    decision.payload["effect"],
                    expected_effect.value,
                )
                self.assertFalse(
                    decision.payload["authorization_eligible"]
                )
                self._assert_no_downstream_work(root, run_id, calls)

    def test_overriding_mock_subclass_is_rejected_before_state_creation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "admission-overriding-mock"
            prepared, profile, selection = self._explicit_mock_inputs(
                root, run_id
            )
            runner = OverridingMockRunner(
                output=load_mock_chief_of_staff_output(root, prepared)
            )

            with self.assertRaisesRegex(
                ValidationError, "controller-owned mock runner"
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

    def test_rebound_exact_mock_boundary_is_rejected_before_state_creation(
        self,
    ) -> None:
        for boundary in ("inspect_billing_route", "execute"):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = f"admission-rebound-{boundary}"
                prepared, profile, selection = self._explicit_mock_inputs(
                    root,
                    run_id,
                )
                runner = MockRunner(
                    output=load_mock_chief_of_staff_output(root, prepared)
                )

                async def rebound_boundary(*args, **kwargs):
                    del args, kwargs
                    raise AssertionError("rebound mock boundary was invoked")

                setattr(runner, boundary, rebound_boundary)
                with self.assertRaisesRegex(
                    ValidationError,
                    "controller-owned mock runner",
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

                self.assertFalse((root / ".ordomata").exists())


if __name__ == "__main__":
    unittest.main()
