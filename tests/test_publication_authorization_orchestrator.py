from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from ordomata.admission_authorization import (
    TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
    TASK_ADMISSION_DECISION_EVENT_TYPE,
    TASK_ADMISSION_ENFORCEMENT_COVERAGE,
)
from ordomata.authorization import (
    AuthorizationEffect,
    DecisionReason,
    canonical_digest,
)
from ordomata.artifact_filesystem import remove_owned_published_artifact
from ordomata.errors import (
    AuthorizationBlocked,
    ConfigurationError,
)
from ordomata.models import RunStatus
from ordomata.orchestrator import (
    _promote_staged_artifact,
    run_chief_of_staff,
)
from ordomata.publication_authorization import (
    LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
    LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
    evaluate_local_candidate_publication_authorization,
)
from ordomata.shadow_authorization import (
    ADMISSION_ACTION_SCOPE,
    PUBLICATION_ACTION_SCOPE,
)
from ordomata.state import SQLiteStateStore
from ordomata.task_evidence import (
    TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
    TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class PublicationAuthorizationOrchestratorTests(unittest.TestCase):
    @staticmethod
    def _project(
        temporary: str,
        *,
        profiles: bool = True,
        output_marker: str | None = None,
    ) -> Path:
        root = Path(temporary)
        names = ["tasks", "schemas", "fixtures"]
        if profiles:
            names.append("profiles")
        for name in names:
            shutil.copytree(REPOSITORY_ROOT / name, root / name)
        if output_marker is not None:
            output_path = root / "fixtures/chief_of_staff/valid-output.json"
            output = json.loads(output_path.read_text(encoding="utf-8"))
            output["executive_summary"] += f" {output_marker}"
            output_path.write_text(
                json.dumps(output, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return root

    @staticmethod
    def _events(root: Path, run_id: str):
        with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
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
    def _publication_shadow(events):
        matches = [
            event
            for event in events
            if event.event_type == "authorization_shadow_decision"
            and event.payload.get("action_scope") == PUBLICATION_ACTION_SCOPE
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"expected one publication shadow, found {len(matches)}"
            )
        return matches[0]

    @staticmethod
    def _assert_no_publication_effect(root: Path, run_id: str) -> None:
        with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
            if state.list_artifacts(run_id):
                raise AssertionError("publication metadata was unexpectedly stored")
        artifact = (
            root
            / ".ordomata"
            / "runs"
            / run_id
            / "artifacts"
            / "chief-of-staff-lite.json"
        )
        if artifact.exists():
            raise AssertionError("candidate artifact was unexpectedly published")

    def _assert_enforcing_action_receipt(
        self,
        events,
        *,
        outcome: str,
    ):
        receipt = self._only(
            events,
            TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
        )
        self.assertEqual(receipt.payload["schema_version"], 3)
        self.assertEqual(receipt.payload["mode"], "enforcing")
        self.assertTrue(receipt.payload["authorization_enforced"])
        self.assertEqual(receipt.payload["outcome"], outcome)
        self.assertEqual(
            receipt.payload["enforcement_receipt"]["outcome"],
            outcome,
        )
        self.assertEqual(
            receipt.payload["enforcement_receipt_digest"],
            canonical_digest(receipt.payload["enforcement_receipt"]),
        )
        self.assertEqual(receipt.event_id, receipt.payload["receipt_id"])
        return receipt

    def test_profile_backed_success_orders_enforcing_decision_and_receipts(
        self,
    ) -> None:
        private_instruction = "private-publication-instruction-71fd"
        private_output = "private-publication-output-a28c"
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(
                temporary,
                output_marker=private_output,
            )
            run_id = "publication-enforcement-success"
            report = asyncio.run(
                run_chief_of_staff(
                    root,
                    run_id=run_id,
                    operator_instructions=(private_instruction,),
                )
            )

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            self.assertIsNotNone(report.artifact_path)
            self.assertIn(
                private_output,
                Path(report.artifact_path or "").read_text(encoding="utf-8"),
            )
            events = self._events(root, run_id)
            binding = self._only(
                events,
                "task_attempt_authorization_binding",
            )
            admission_decision = self._only(
                events,
                TASK_ADMISSION_DECISION_EVENT_TYPE,
            )
            admission_receipt = self._only(
                events,
                TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
            )
            admission_shadow = next(
                event
                for event in events
                if event.event_type == "authorization_shadow_decision"
                and event.payload.get("action_scope")
                == ADMISSION_ACTION_SCOPE
            )
            billing = self._only(events, "billing_assessment")
            accounting = self._only(events, "execution_accounting")
            shadow = self._publication_shadow(events)
            decision = self._only(
                events,
                LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
            )
            pre_effect = self._only(
                events,
                TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
            )
            action = self._only(
                events,
                TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.SUCCEEDED
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
            self.assertTrue(
                admission_decision.payload["authorization_eligible"]
            )
            self.assertEqual(
                admission_receipt.payload["decision_digest"],
                admission_decision.payload["decision_digest"],
            )
            self.assertEqual(
                admission_receipt.payload["receipt"]["outcome"],
                "succeeded",
            )
            self.assertEqual(decision.payload["mode"], "enforcing")
            self.assertEqual(decision.payload["effect"], "permit")
            self.assertTrue(decision.payload["authorization_eligible"])
            self.assertEqual(
                decision.payload["enforcement_coverage"],
                LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
            )
            self.assertEqual(
                decision.payload["request"]["action"]["operation"],
                "artifact.publish_local_candidate",
            )
            self.assertEqual(
                decision.event_id,
                canonical_digest(
                    {
                        "event_type": (
                            LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE
                        ),
                        "payload": decision.payload,
                        "run_id": run_id,
                    }
                ),
            )

            self.assertEqual(pre_effect.payload["schema_version"], 3)
            self.assertEqual(pre_effect.payload["mode"], "enforcing")
            self.assertTrue(pre_effect.payload["authorization_enforced"])
            self.assertEqual(
                pre_effect.payload["publication_authorization_event_id"],
                decision.event_id,
            )
            self.assertEqual(
                pre_effect.payload["publication_request_digest"],
                decision.payload["request_digest"],
            )
            self.assertEqual(
                pre_effect.payload["publication_decision_digest"],
                decision.payload["decision_digest"],
            )
            self.assertEqual(
                pre_effect.payload["publication_shadow_request_digest"],
                shadow.payload["request_digest"],
            )
            self.assertEqual(
                pre_effect.payload["publication_shadow_decision_digest"],
                shadow.payload["decision_digest"],
            )

            self.assertEqual(action.payload["schema_version"], 3)
            self.assertEqual(action.payload["mode"], "enforcing")
            self.assertTrue(action.payload["authorization_enforced"])
            self.assertEqual(action.payload["outcome"], "succeeded")
            self.assertEqual(action.event_id, action.payload["receipt_id"])
            self.assertEqual(
                action.payload["publication_authorization_event_id"],
                decision.event_id,
            )
            nested = action.payload["enforcement_receipt"]
            self.assertEqual(nested["outcome"], "succeeded")
            self.assertEqual(
                nested["request_digest"],
                decision.payload["request_digest"],
            )
            self.assertEqual(
                nested["decision_digest"],
                decision.payload["decision_digest"],
            )
            self.assertEqual(
                nested["started_at"],
                action.payload["effect_started_at"],
            )
            self.assertEqual(
                action.payload["enforcement_receipt_digest"],
                canonical_digest(nested),
            )
            action_body = dict(action.payload)
            action_digest = action_body.pop("receipt_digest")
            self.assertEqual(action_digest, canonical_digest(action_body))

            self.assertLess(binding.sequence, admission_decision.sequence)
            self.assertLess(
                admission_decision.sequence,
                admission_receipt.sequence,
            )
            self.assertLess(
                admission_receipt.sequence,
                admission_shadow.sequence,
            )
            self.assertLess(admission_shadow.sequence, billing.sequence)
            self.assertLess(billing.sequence, accounting.sequence)
            self.assertLess(accounting.sequence, shadow.sequence)
            self.assertLess(shadow.sequence, decision.sequence)
            self.assertLess(decision.sequence, pre_effect.sequence)
            self.assertLess(pre_effect.sequence, action.sequence)
            self.assertLess(action.sequence, terminal.sequence)

            serialized = json.dumps(
                [
                    admission_decision.payload,
                    admission_receipt.payload,
                    decision.payload,
                    pre_effect.payload,
                    action.payload,
                ],
                sort_keys=True,
            )
            for private_value in (
                str(root),
                private_instruction,
                private_output,
                "chief_of_staff.valid",
                '"fixture"',
            ):
                self.assertNotIn(private_value, serialized)

    def test_publication_evaluator_failure_is_redacted_and_never_stages(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "publication-evaluator-failure"
            private_error = "private-publication-evaluator-diagnostic-c931"
            with (
                patch(
                    "ordomata.orchestrator."
                    "evaluate_local_candidate_publication_authorization",
                    side_effect=RuntimeError(private_error),
                ),
                patch(
                    "ordomata.orchestrator._stage_artifact",
                    side_effect=AssertionError("publication must not stage"),
                ) as stage,
                self.assertRaises(AuthorizationBlocked),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            stage.assert_not_called()
            events = self._events(root, run_id)
            decision = self._only(
                events,
                LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
            )
            self.assertEqual(decision.payload["effect"], "indeterminate")
            self.assertFalse(decision.payload["authorization_eligible"])
            self.assertEqual(
                decision.payload["failure_stage"],
                "request_or_evaluation",
            )
            self.assertIsNone(decision.payload["request"])
            self.assertFalse(
                any(
                    event.event_type
                    in {
                        TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
                        TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                    }
                    for event in events
                )
            )
            self.assertNotIn(
                private_error,
                "\n".join(event.payload_json for event in events),
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)
            self._assert_no_publication_effect(root, run_id)

    def test_nonpermit_blocks_without_pre_effect_or_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "publication-nonpermit"

            def force_deny(**kwargs):
                authorization = (
                    evaluate_local_candidate_publication_authorization(
                        **kwargs
                    )
                )
                decision = replace(
                    authorization.decision,
                    effect=AuthorizationEffect.DENY,
                    reason_codes=(DecisionReason.CLASS_DISABLED,),
                    reason_details=("fixed publication denial",),
                    obligations=(),
                )
                return replace(
                    authorization,
                    decision=decision,
                    block_reason_codes=("authorization_effect_not_permit",),
                )

            with (
                patch(
                    "ordomata.orchestrator."
                    "evaluate_local_candidate_publication_authorization",
                    new=force_deny,
                ),
                patch(
                    "ordomata.orchestrator._stage_artifact",
                    side_effect=AssertionError("publication must not stage"),
                ) as stage,
                self.assertRaises(AuthorizationBlocked),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            stage.assert_not_called()
            events = self._events(root, run_id)
            decision = self._only(
                events,
                LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
            )
            self.assertEqual(decision.payload["effect"], "deny")
            self.assertFalse(decision.payload["authorization_eligible"])
            self.assertFalse(
                any(
                    event.event_type
                    in {
                        TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
                        TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                    }
                    for event in events
                )
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)
            self._assert_no_publication_effect(root, run_id)

    def test_freshness_failure_after_pre_effect_never_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "publication-freshness-failure"
            with (
                patch(
                    "ordomata.orchestrator."
                    "assert_local_candidate_publication_authorized",
                    side_effect=AuthorizationBlocked(
                        "fixed publication freshness rejection"
                    ),
                ),
                patch(
                    "ordomata.orchestrator._stage_artifact",
                    side_effect=AssertionError("publication must not stage"),
                ) as stage,
                self.assertRaises(AuthorizationBlocked),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            stage.assert_not_called()
            events = self._events(root, run_id)
            self._only(events, LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE)
            self._only(events, TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE)
            self.assertFalse(
                any(
                    event.event_type
                    == TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
                    for event in events
                )
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.BLOCKED
            )
            self.assertEqual(
                terminal.payload,
                {
                    "phase": (
                        "local_candidate_publication_authorization_freshness"
                    )
                },
            )
            self._assert_no_publication_effect(root, run_id)

    def test_cross_candidate_binding_tamper_after_decision_never_stages(
        self,
    ) -> None:
        original_append = SQLiteStateStore.append_event
        for binding_name in ("artifact_digest", "destination_digest"):
            with (
                self.subTest(binding_name=binding_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self._project(temporary)
                run_id = f"publication-cross-candidate-{binding_name}"
                foreign_digest = canonical_digest(
                    {
                        "binding": binding_name,
                        "candidate": "different-local-candidate",
                    }
                )
                captured_authorizations = []
                tampered_after_commit = False

                def capture_authorization(**kwargs):
                    authorization = (
                        evaluate_local_candidate_publication_authorization(
                            **kwargs
                        )
                    )
                    captured_authorizations.append(authorization)
                    return authorization

                def tamper_after_decision_commit(
                    store,
                    observed_run_id,
                    event_type,
                    payload=None,
                    **kwargs,
                ):
                    nonlocal tampered_after_commit
                    result = original_append(
                        store,
                        observed_run_id,
                        event_type,
                        payload,
                        **kwargs,
                    )
                    if (
                        not tampered_after_commit
                        and event_type
                        == LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE
                    ):
                        self.assertEqual(len(captured_authorizations), 1)
                        object.__setattr__(
                            captured_authorizations[0],
                            binding_name,
                            foreign_digest,
                        )
                        tampered_after_commit = True
                    return result

                with (
                    patch(
                        "ordomata.orchestrator."
                        "evaluate_local_candidate_publication_authorization",
                        new=capture_authorization,
                    ),
                    patch.object(
                        SQLiteStateStore,
                        "append_event",
                        new=tamper_after_decision_commit,
                    ),
                    patch(
                        "ordomata.orchestrator._stage_artifact",
                        side_effect=AssertionError("publication must not stage"),
                    ) as stage,
                    self.assertRaises(AuthorizationBlocked),
                ):
                    asyncio.run(run_chief_of_staff(root, run_id=run_id))

                self.assertTrue(tampered_after_commit)
                stage.assert_not_called()
                events = self._events(root, run_id)
                decision = self._only(
                    events,
                    LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
                )
                self.assertNotEqual(
                    decision.payload[binding_name],
                    foreign_digest,
                )
                self.assertEqual(
                    getattr(captured_authorizations[0], binding_name),
                    foreign_digest,
                )
                self._only(
                    events,
                    TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
                )
                self.assertFalse(
                    any(
                        event.event_type
                        == TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
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
                    {
                        "phase": (
                            "local_candidate_publication_authorization_freshness"
                        )
                    },
                )
                with SQLiteStateStore(
                    root / ".ordomata/state.sqlite3"
                ) as state:
                    self.assertEqual(
                        state.current_status(run_id),
                        RunStatus.BLOCKED,
                    )
                self._assert_no_publication_effect(root, run_id)

    def test_forged_decision_wrapper_after_commit_never_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "publication-forged-decision-wrapper"
            original_append = SQLiteStateStore.append_event
            forged_decision_digest = None

            def forge_wrapper_after_decision_commit(
                store,
                observed_run_id,
                event_type,
                payload=None,
                **kwargs,
            ):
                nonlocal forged_decision_digest
                result = original_append(
                    store,
                    observed_run_id,
                    event_type,
                    payload,
                    **kwargs,
                )
                if (
                    forged_decision_digest is None
                    and event_type
                    == LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE
                ):
                    self.assertIsInstance(payload, dict)
                    decision = dict(payload["decision"])
                    decision["reason_details"] = [
                        "forged in-memory publication decision"
                    ]
                    forged_decision_digest = canonical_digest(decision)
                    payload["decision"] = decision
                    payload["decision_digest"] = forged_decision_digest
                return result

            with (
                patch.object(
                    SQLiteStateStore,
                    "append_event",
                    new=forge_wrapper_after_decision_commit,
                ),
                patch(
                    "ordomata.orchestrator._stage_artifact",
                    side_effect=AssertionError("publication must not stage"),
                ) as stage,
                self.assertRaises(AuthorizationBlocked),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            self.assertIsNotNone(forged_decision_digest)
            stage.assert_not_called()
            events = self._events(root, run_id)
            decision = self._only(
                events,
                LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
            )
            self.assertNotEqual(
                decision.payload["decision_digest"],
                forged_decision_digest,
            )
            self.assertNotIn(
                "forged in-memory publication decision",
                decision.payload["decision"]["reason_details"],
            )
            pre_effect = self._only(
                events,
                TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
            )
            self.assertEqual(
                pre_effect.payload["publication_decision_digest"],
                forged_decision_digest,
            )
            self.assertFalse(
                any(
                    event.event_type
                    == TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
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
                {
                    "phase": (
                        "local_candidate_publication_authorization_freshness"
                    )
                },
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(state.current_status(run_id), RunStatus.BLOCKED)
            self._assert_no_publication_effect(root, run_id)

    def test_publication_decision_append_precommit_and_commit_then_raise(
        self,
    ) -> None:
        original_append = SQLiteStateStore.append_event
        for case in ("precommit", "committed"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"publication-decision-{case}"
                injected = False
                stage_calls = 0

                def append_with_failure(
                    store,
                    observed_run_id,
                    event_type,
                    payload=None,
                    **kwargs,
                ):
                    nonlocal injected
                    if (
                        not injected
                        and event_type
                        == LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE
                    ):
                        injected = True
                        if case == "precommit":
                            raise OSError("private decision precommit diagnostic")
                        result = original_append(
                            store,
                            observed_run_id,
                            event_type,
                            payload,
                            **kwargs,
                        )
                        raise OSError("private decision committed diagnostic")
                    return original_append(
                        store,
                        observed_run_id,
                        event_type,
                        payload,
                        **kwargs,
                    )

                from ordomata.orchestrator import _stage_artifact

                def recording_stage(path, content, *, stage):
                    nonlocal stage_calls
                    stage_calls += 1
                    return _stage_artifact(path, content, stage=stage)

                with (
                    patch.object(
                        SQLiteStateStore,
                        "append_event",
                        new=append_with_failure,
                    ),
                    patch(
                        "ordomata.orchestrator._stage_artifact",
                        new=recording_stage,
                    ),
                ):
                    if case == "precommit":
                        with self.assertRaisesRegex(
                            OSError,
                            "precommit",
                        ):
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
                    if event.event_type
                    == LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE
                ]
                if case == "precommit":
                    self.assertEqual(stage_calls, 0)
                    self.assertEqual(decisions, [])
                    with SQLiteStateStore(
                        root / ".ordomata/state.sqlite3"
                    ) as state:
                        self.assertEqual(
                            state.current_status(run_id),
                            RunStatus.FAILED,
                        )
                    self._assert_no_publication_effect(root, run_id)
                else:
                    self.assertEqual(stage_calls, 1)
                    self.assertEqual(len(decisions), 1)
                    self.assertNotIn(
                        "private decision committed diagnostic",
                        "\n".join(event.payload_json for event in events),
                    )

    def test_enforced_staging_failure_records_failed_receipt_without_effect(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "enforced-staging-failure"
            private_error = "private-enforced-staging-diagnostic-3df1"
            with (
                patch(
                    "ordomata.orchestrator._stage_artifact",
                    side_effect=OSError(private_error),
                ),
                self.assertRaisesRegex(OSError, private_error),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            events = self._events(root, run_id)
            decision = self._only(
                events,
                LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
            )
            pre_effect = self._only(
                events,
                TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
            )
            receipt = self._assert_enforcing_action_receipt(
                events,
                outcome="failed",
            )
            terminal = next(
                event
                for event in events
                if event.status is RunStatus.FAILED
            )
            self.assertEqual(
                receipt.payload["failure_code"],
                "artifact_persistence_failed",
            )
            self.assertIsNone(receipt.payload["result_digest"])
            self.assertLess(decision.sequence, pre_effect.sequence)
            self.assertLess(pre_effect.sequence, receipt.sequence)
            self.assertLess(receipt.sequence, terminal.sequence)
            self.assertNotIn(
                private_error,
                "\n".join(event.payload_json for event in events),
            )
            self._assert_no_publication_effect(root, run_id)

    def test_enforced_action_receipt_commit_then_raise_reconciles_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "enforced-action-receipt-committed"
            original_append = SQLiteStateStore.append_event
            injected = False

            def commit_receipt_then_raise(
                store,
                observed_run_id,
                event_type,
                payload=None,
                **kwargs,
            ):
                nonlocal injected
                result = original_append(
                    store,
                    observed_run_id,
                    event_type,
                    payload,
                    **kwargs,
                )
                if (
                    not injected
                    and event_type
                    == TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
                    and isinstance(payload, dict)
                    and payload.get("outcome") == "succeeded"
                ):
                    injected = True
                    raise RuntimeError(
                        "private enforced receipt committed diagnostic"
                    )
                return result

            with patch.object(
                SQLiteStateStore,
                "append_event",
                new=commit_receipt_then_raise,
            ):
                report = asyncio.run(
                    run_chief_of_staff(root, run_id=run_id)
                )

            self.assertTrue(injected)
            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            artifact = Path(report.artifact_path or "")
            self.assertTrue(artifact.is_file())
            events = self._events(root, run_id)
            receipt = self._assert_enforcing_action_receipt(
                events,
                outcome="succeeded",
            )
            self.assertEqual(
                receipt.payload["result_digest"],
                "sha256:" + report.artifact_sha256,
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(len(state.list_artifacts(run_id)), 1)
                self.assertEqual(state.current_status(run_id), RunStatus.SUCCEEDED)
            self.assertNotIn(
                "private enforced receipt committed diagnostic",
                "\n".join(event.payload_json for event in events),
            )

    def test_enforced_action_receipt_precommit_failure_rolls_back_effect(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "enforced-action-receipt-rejected"
            original_append = SQLiteStateStore.append_event
            rejected = False
            private_error = "private enforced receipt precommit diagnostic"

            def reject_success_receipt(
                store,
                observed_run_id,
                event_type,
                payload=None,
                **kwargs,
            ):
                nonlocal rejected
                if (
                    not rejected
                    and event_type
                    == TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
                    and isinstance(payload, dict)
                    and payload.get("outcome") == "succeeded"
                ):
                    rejected = True
                    raise RuntimeError(private_error)
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
                    new=reject_success_receipt,
                ),
                self.assertRaisesRegex(RuntimeError, private_error),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            self.assertTrue(rejected)
            events = self._events(root, run_id)
            receipt = self._assert_enforcing_action_receipt(
                events,
                outcome="failed",
            )
            self.assertEqual(
                receipt.payload["failure_code"],
                "artifact_persistence_failed",
            )
            self.assertIsNone(receipt.payload["result_digest"])
            self.assertNotIn(
                private_error,
                "\n".join(event.payload_json for event in events),
            )
            artifact = (
                root
                / ".ordomata"
                / "runs"
                / run_id
                / "artifacts"
                / "chief-of-staff-lite.json"
            )
            self.assertFalse(artifact.exists())
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(len(state.list_artifacts(run_id)), 1)
                self.assertEqual(state.current_status(run_id), RunStatus.FAILED)

    def test_enforced_post_mutation_cancellation_records_cancelled_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "enforced-post-mutation-cancelled"
            private_error = "private post-mutation cancellation diagnostic"

            def publish_then_cancel(stage, artifact_path):
                _promote_staged_artifact(stage, artifact_path)
                raise asyncio.CancelledError(private_error)

            with (
                patch(
                    "ordomata.orchestrator._promote_staged_artifact",
                    new=publish_then_cancel,
                ),
                self.assertRaisesRegex(asyncio.CancelledError, private_error),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            events = self._events(root, run_id)
            receipt = self._assert_enforcing_action_receipt(
                events,
                outcome="cancelled",
            )
            self.assertEqual(
                receipt.payload["failure_code"],
                "artifact_persistence_interrupted",
            )
            self.assertIsNone(receipt.payload["result_digest"])
            self.assertNotIn(
                private_error,
                "\n".join(event.payload_json for event in events),
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(state.current_status(run_id), RunStatus.CANCELLED)
                self.assertEqual(len(state.list_artifacts(run_id)), 1)
            artifact = (
                root
                / ".ordomata"
                / "runs"
                / run_id
                / "artifacts"
                / "chief-of-staff-lite.json"
            )
            self.assertFalse(artifact.exists())

    def test_enforced_cleanup_uncertainty_records_unknown_and_quarantines(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            run_id = "enforced-cleanup-uncertain"
            cleanup_interrupted = False

            def publish_then_cancel(stage, artifact_path):
                _promote_staged_artifact(stage, artifact_path)
                raise asyncio.CancelledError(
                    "private publication cancellation diagnostic"
                )

            def interrupt_final_cleanup(
                path,
                *,
                staged_identity,
                expected_parent_identity=None,
                stage=None,
            ):
                nonlocal cleanup_interrupted
                if (
                    not cleanup_interrupted
                    and path.name == "chief-of-staff-lite.json"
                ):
                    cleanup_interrupted = True
                    raise asyncio.CancelledError(
                        "private cleanup cancellation diagnostic"
                    )
                return remove_owned_published_artifact(
                    path,
                    staged_identity=staged_identity,
                    expected_parent_identity=expected_parent_identity,
                    stage=stage,
                )

            with (
                patch(
                    "ordomata.orchestrator._promote_staged_artifact",
                    new=publish_then_cancel,
                ),
                patch(
                    "ordomata.orchestrator.remove_owned_published_artifact",
                    new=interrupt_final_cleanup,
                ),
                self.assertRaisesRegex(
                    ConfigurationError,
                    "publication outcome is uncertain",
                ),
            ):
                asyncio.run(run_chief_of_staff(root, run_id=run_id))

            self.assertTrue(cleanup_interrupted)
            events = self._events(root, run_id)
            receipt = self._assert_enforcing_action_receipt(
                events,
                outcome="unknown",
            )
            self.assertEqual(
                receipt.payload["failure_code"],
                "artifact_publication_outcome_unknown",
            )
            self.assertIsNone(receipt.payload["result_digest"])
            self.assertNotIn(
                "private cleanup cancellation diagnostic",
                "\n".join(event.payload_json for event in events),
            )
            with SQLiteStateStore(root / ".ordomata/state.sqlite3") as state:
                self.assertEqual(
                    state.current_status(run_id),
                    RunStatus.QUARANTINED,
                )
                self.assertEqual(len(state.list_artifacts(run_id)), 1)
            artifact = (
                root
                / ".ordomata"
                / "runs"
                / run_id
                / "artifacts"
                / "chief-of-staff-lite.json"
            )
            self.assertTrue(artifact.is_file())

    def test_unprofiled_mock_retains_schema_v1_shadow_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary, profiles=False)
            run_id = "legacy-unprofiled-publication"
            report = asyncio.run(run_chief_of_staff(root, run_id=run_id))

            self.assertEqual(report.status, RunStatus.SUCCEEDED)
            events = self._events(root, run_id)
            binding = self._only(
                events,
                "task_attempt_authorization_binding",
            )
            pre_effect = self._only(
                events,
                TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
            )
            action = self._only(
                events,
                TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            )
            self.assertEqual(binding.payload["schema_version"], 1)
            self.assertNotIn(
                "publication_authorization_enforcement_coverage",
                binding.payload,
            )
            self.assertFalse(
                any(
                    event.event_type
                    == LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE
                    for event in events
                )
            )
            for receipt in (pre_effect.payload, action.payload):
                self.assertEqual(receipt["schema_version"], 2)
                self.assertEqual(receipt["mode"], "shadow")
                self.assertFalse(receipt["authorization_enforced"])


if __name__ == "__main__":
    unittest.main()
