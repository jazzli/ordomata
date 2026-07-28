from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import (
    AuthorizationEffect,
    AuthorizationEvaluator,
    DecisionObligation,
    DecisionReason,
    ImpactLevel,
    ObligationKind,
    ReceiptOutcome,
    canonical_digest,
)
from ordomata.contracts import load_task_contract
from ordomata.dispatch_authorization import (
    MOCK_DISPATCH_ACTION_SCOPE,
    MOCK_DISPATCH_EVENT_SCHEMA_VERSION,
    MOCK_DISPATCH_EXECUTOR_ID,
    MockDispatchAuthorization,
    assert_mock_dispatch_authorized,
    build_mock_dispatch_action_receipt,
    evaluate_mock_dispatch_authorization,
)
from ordomata.errors import AuthorizationBlocked, ValidationError
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    RunRequest,
)
from ordomata.shadow_authorization import resolve_task_authorization_intent


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class MockDispatchPepTests(unittest.TestCase):
    @staticmethod
    def _digest(label: str) -> str:
        return canonical_digest({"fixture": label})

    def setUp(self) -> None:
        self.contract = load_task_contract(
            REPOSITORY_ROOT / "tasks" / "chief-of-staff-lite.json"
        )

    @staticmethod
    def _billing_payload(
        assessment: BillingRouteAssessment,
    ) -> dict[str, object]:
        body: dict[str, object] = {
            "schema_version": 1,
            "runner_id": assessment.runner_id,
            "route": assessment.route.value,
            "confidence": assessment.confidence.value,
            "subscription_name": (
                assessment.subscription_name
                if assessment.subscription_name in {"ChatGPT", "Claude"}
                else None
            ),
            "capacity_state": assessment.capacity_state.value,
            "paid_continuation_protection": (
                assessment.paid_continuation_protection.value
            ),
            "paid_credit_balance": assessment.paid_credit_balance.value,
            "account_identity_verified": bool(
                isinstance(assessment.account_identity_fingerprint, str)
                and len(assessment.account_identity_fingerprint) == 64
                and all(
                    character in "0123456789abcdef"
                    for character in assessment.account_identity_fingerprint
                )
            ),
            "attestation_present": assessment.attestation is not None,
        }
        return {**body, "assessment_digest": canonical_digest(body)}

    def _inputs(self, root: Path, **overrides):
        prompt = "private-dispatch-prompt-marker"
        run_directory = root / ".ordomata" / "runs" / "private-run-marker"
        assessment = BillingRouteAssessment(
            runner_id="mock",
            route=BillingRoute.MOCK,
            confidence=AssessmentConfidence.HIGH,
        )
        billing_payload = self._billing_payload(assessment)
        request = RunRequest(
            run_id="private-dispatch-run-marker",
            task_id=self.contract.task_id,
            task_version=self.contract.version,
            prompt=prompt,
            workspace=run_directory / "workspace",
            run_directory=run_directory,
            output_schema=self.contract.output_schema,
            permission_class=self.contract.permission_class,
            timeout_seconds=self.contract.timeout_seconds,
            runner_overrides={"private_config_marker": "must-not-persist"},
        )
        values = {
            "contract": self.contract,
            "request": request,
            "runner_id": "mock",
            "profile_id": "mock.private-profile-marker",
            "project_root": root,
            "task_attempt_binding_digest": self._digest("binding"),
            "execution_selection_digest": self._digest("selection"),
            "context_digest": self._digest("context"),
            "prompt_digest": (
                "sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            ),
            "billing_assessment": assessment,
            "billing_assessment_payload": billing_payload,
            "billing_assessment_digest": billing_payload["assessment_digest"],
            "evaluated_at": 100.0,
            "legacy_executable": True,
        }
        values.update(overrides)
        if "task_authorization_intent_lineage" not in overrides:
            lineage_contract = values["contract"]
            lineage_request = values["request"]
            intent, intent_source = resolve_task_authorization_intent(
                lineage_contract
            )
            lineage = {
                "schema_version": 1,
                "kind": "task_authorization_intent_lineage",
                "intent_source": intent_source,
                "task_definition_digest": lineage_contract.definition_hash,
                "requested_permission_class": int(
                    lineage_request.permission_class
                ),
                "task_authorization_intent": intent.to_canonical(),
                "authorization_intent_digest": intent.digest,
            }
            values["task_authorization_intent_lineage"] = lineage
            values["task_authorization_intent_lineage_digest"] = (
                canonical_digest(lineage)
            )
        return values

    @staticmethod
    def _persisted_snapshot(authorization) -> dict[str, object]:
        return json.loads(
            json.dumps(authorization.to_event_payload(), sort_keys=True)
        )

    def _assert_at_effect(
        self,
        authorization,
        inputs,
        *,
        action_started_at: float = 101.0,
        persisted_payload=None,
        controller_owned_mock_runner=True,
        **current_overrides,
    ) -> None:
        current_inputs = dict(inputs)
        current_inputs.pop("evaluated_at")
        current_inputs.update(current_overrides)
        assert_mock_dispatch_authorized(
            authorization,
            action_started_at=action_started_at,
            persisted_payload=(
                self._persisted_snapshot(authorization)
                if persisted_payload is None
                else persisted_payload
            ),
            controller_owned_mock_runner=controller_owned_mock_runner,
            **current_inputs,
        )

    def test_exact_permit_and_receipt_preserve_schema_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_mock_dispatch_authorization(**inputs)

            self.assertTrue(authorization.authorized_at_evaluation)
            self.assertEqual(authorization.decision.effect, AuthorizationEffect.PERMIT)
            persisted = self._persisted_snapshot(authorization)
            self._assert_at_effect(
                authorization,
                inputs,
                persisted_payload=persisted,
            )
            receipt = build_mock_dispatch_action_receipt(
                authorization=authorization,
                contract=self.contract,
                action_started_at=101.0,
                completed_at=102.0,
                outcome=ReceiptOutcome.SUCCEEDED,
                result_digest=self._digest("result"),
            )

        self.assertEqual(persisted["schema_version"], 1)
        self.assertEqual(persisted["action_scope"], MOCK_DISPATCH_ACTION_SCOPE)
        self.assertEqual(receipt["schema_version"], MOCK_DISPATCH_EVENT_SCHEMA_VERSION)
        self.assertEqual(
            receipt["receipt"]["executor_id"],
            MOCK_DISPATCH_EXECUTOR_ID,
        )
        self.assertEqual(receipt["receipt"]["outcome"], "succeeded")
        self.assertEqual(
            receipt["receipt_digest"],
            canonical_digest(receipt["receipt"]),
        )

    def test_current_controller_input_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self._inputs(root)
            authorization = evaluate_mock_dispatch_authorization(**inputs)
            persisted = self._persisted_snapshot(authorization)
            other_request = replace(
                inputs["request"],
                run_id="other-private-dispatch-run",
            )
            approval_contract = replace(
                self.contract,
                approval_requirements=replace(
                    self.contract.approval_requirements,
                    required_before_run=True,
                ),
            )
            cases = (
                ("contract", {"contract": approval_contract}),
                ("request", {"request": other_request}),
                ("runner", {"runner_id": "codex"}),
                ("profile", {"profile_id": "mock.other-profile"}),
                ("root", {"project_root": root / "other-root"}),
                (
                    "binding",
                    {"task_attempt_binding_digest": self._digest("other-binding")},
                ),
                (
                    "selection",
                    {"execution_selection_digest": self._digest("other-selection")},
                ),
                (
                    "intent-lineage",
                    {
                        "task_authorization_intent_lineage": {
                            **inputs["task_authorization_intent_lineage"],
                            "intent_source": "legacy_permission_class_fallback",
                        },
                    },
                ),
                (
                    "intent-lineage-digest",
                    {
                        "task_authorization_intent_lineage_digest": self._digest(
                            "other-intent-lineage"
                        ),
                    },
                ),
                ("context", {"context_digest": self._digest("other-context")}),
                ("prompt", {"prompt_digest": self._digest("other-prompt")}),
                ("legacy", {"legacy_executable": False}),
            )
            for case, current_overrides in cases:
                with self.subTest(case=case), self.assertRaises(
                    AuthorizationBlocked
                ):
                    self._assert_at_effect(
                        authorization,
                        inputs,
                        persisted_payload=persisted,
                        **current_overrides,
                    )
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    authorization,
                    inputs,
                    persisted_payload=persisted,
                    controller_owned_mock_runner=False,
                )

    def test_billing_payload_assessment_and_digest_are_one_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            original_payload = dict(inputs["billing_assessment_payload"])

            mismatched_payload = dict(original_payload)
            mismatched_payload["paid_credit_balance"] = "available"
            body = dict(mismatched_payload)
            body.pop("assessment_digest")
            mismatched_payload["assessment_digest"] = canonical_digest(body)
            with self.assertRaisesRegex(
                ValidationError,
                "billing evidence is inconsistent",
            ):
                evaluate_mock_dispatch_authorization(
                    **{
                        **inputs,
                        "billing_assessment_payload": mismatched_payload,
                        "billing_assessment_digest": mismatched_payload[
                            "assessment_digest"
                        ],
                    }
                )

            with self.assertRaisesRegex(
                ValidationError,
                "billing evidence is inconsistent",
            ):
                evaluate_mock_dispatch_authorization(
                    **{
                        **inputs,
                        "billing_assessment_digest": self._digest(
                            "other-billing"
                        ),
                    }
                )

            authorization = evaluate_mock_dispatch_authorization(**inputs)
            changed_assessment = replace(
                inputs["billing_assessment"],
                subscription_name="ChatGPT",
            )
            changed_payload = self._billing_payload(changed_assessment)
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    authorization,
                    inputs,
                    billing_assessment=changed_assessment,
                    billing_assessment_payload=changed_payload,
                    billing_assessment_digest=changed_payload[
                        "assessment_digest"
                    ],
                )

    def test_persisted_wrapper_is_compared_independently_of_method(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_mock_dispatch_authorization(**inputs)
            forged_payload = self._persisted_snapshot(authorization)
            forged_payload["execution_selection_digest"] = self._digest(
                "forged-selection"
            )

            with (
                patch.object(
                    MockDispatchAuthorization,
                    "to_event_payload",
                    return_value=forged_payload,
                ),
                self.assertRaises(AuthorizationBlocked),
            ):
                self._assert_at_effect(
                    authorization,
                    inputs,
                    persisted_payload=forged_payload,
                )

            for case, mutation in (
                (
                    "nested-decision",
                    lambda payload: payload["decision"].update(
                        {"reason_details": ["forged persisted decision"]}
                    ),
                ),
                ("extra-key", lambda payload: payload.update({"extra": True})),
                (
                    "missing-key",
                    lambda payload: payload.pop("billing_assessment_digest"),
                ),
            ):
                mutated = self._persisted_snapshot(authorization)
                mutation(mutated)
                with self.subTest(case=case), self.assertRaises(
                    AuthorizationBlocked
                ):
                    self._assert_at_effect(
                        authorization,
                        inputs,
                        persisted_payload=mutated,
                    )

    def test_independent_policy_replay_rejects_coherent_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_mock_dispatch_authorization(**inputs)
            forged_decision = replace(
                authorization,
                decision=replace(
                    authorization.decision,
                    reason_details=("forged fixed-policy permit",),
                ),
            )
            widened_policy = replace(
                authorization.policy,
                allowed_operations=(
                    *authorization.policy.allowed_operations,
                    "runner.execute_unapproved_attempt",
                ),
            )
            forged_policy = replace(
                authorization,
                policy=widened_policy,
                decision=AuthorizationEvaluator().evaluate(
                    authorization.request,
                    widened_policy,
                ),
            )

            for case, forged in (
                ("decision", forged_decision),
                ("policy", forged_policy),
            ):
                forged_payload = self._persisted_snapshot(forged)
                with (
                    self.subTest(case=case),
                    patch(
                        "ordomata.dispatch_authorization."
                        "evaluate_mock_dispatch_authorization",
                        return_value=forged,
                    ),
                    self.assertRaises(AuthorizationBlocked),
                ):
                    self._assert_at_effect(
                        forged,
                        inputs,
                        persisted_payload=forged_payload,
                    )

    def test_patched_builder_cannot_replay_a_foreign_attempt_permit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            foreign_inputs = self._inputs(root)
            foreign_authorization = evaluate_mock_dispatch_authorization(
                **foreign_inputs
            )
            foreign_payload = self._persisted_snapshot(foreign_authorization)
            current_run_directory = (
                root / ".ordomata" / "runs" / "current-dispatch-run"
            )
            current_inputs = {
                **foreign_inputs,
                "request": replace(
                    foreign_inputs["request"],
                    run_id="current-dispatch-run",
                    run_directory=current_run_directory,
                    workspace=current_run_directory / "workspace",
                ),
                "task_attempt_binding_digest": self._digest(
                    "current-binding"
                ),
                "execution_selection_digest": self._digest(
                    "current-selection"
                ),
                "context_digest": self._digest("current-context"),
            }

            with (
                patch(
                    "ordomata.dispatch_authorization."
                    "evaluate_mock_dispatch_authorization",
                    return_value=foreign_authorization,
                ),
                self.assertRaises(AuthorizationBlocked),
            ):
                self._assert_at_effect(
                    foreign_authorization,
                    current_inputs,
                    persisted_payload=foreign_payload,
                )

    def test_persistent_evaluator_forgery_cannot_bypass_required_approval(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            approval_contract = replace(
                self.contract,
                approval_requirements=replace(
                    self.contract.approval_requirements,
                    required_before_run=True,
                ),
            )
            inputs = self._inputs(
                Path(temporary).resolve(),
                contract=approval_contract,
            )
            original_evaluate = AuthorizationEvaluator.evaluate

            def forge_permit(evaluator, request, policy):
                decision = original_evaluate(evaluator, request, policy)
                return replace(
                    decision,
                    effect=AuthorizationEffect.PERMIT,
                    reason_codes=(DecisionReason.CURRENT_STAGE_PERMIT,),
                    reason_details=("forged approval bypass",),
                    matched_rule_ids=("forged-approval-bypass",),
                    obligations=(
                        DecisionObligation(
                            ObligationKind.AUDIT_RECEIPT,
                            "append_after_action",
                        ),
                        DecisionObligation(
                            ObligationKind.ISOLATED_LOCAL_ONLY,
                            "required",
                        ),
                    ),
                )

            with patch.object(
                AuthorizationEvaluator,
                "evaluate",
                new=forge_permit,
            ):
                authorization = evaluate_mock_dispatch_authorization(**inputs)
                self.assertTrue(authorization.authorized_at_evaluation)
                with self.assertRaises(AuthorizationBlocked):
                    self._assert_at_effect(
                        authorization,
                        inputs,
                        persisted_payload=self._persisted_snapshot(
                            authorization
                        ),
                    )

    def test_receipt_replay_binds_current_contract_consequences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_mock_dispatch_authorization(**inputs)
            assert self.contract.authorization_intent is not None
            high_intent = replace(
                self.contract.authorization_intent,
                consequences=replace(
                    self.contract.authorization_intent.consequences,
                    confidentiality=ImpactLevel.HIGH,
                ),
            )
            high_contract = replace(
                self.contract,
                authorization_intent=high_intent,
            )
            forged = replace(
                authorization,
                task_authorization_intent_digest=high_intent.digest,
            )

            with self.assertRaises(AuthorizationBlocked):
                build_mock_dispatch_action_receipt(
                    authorization=forged,
                    contract=high_contract,
                    action_started_at=101.0,
                    completed_at=102.0,
                    outcome=ReceiptOutcome.SUCCEEDED,
                    result_digest=self._digest("result"),
                )

    def test_lineage_and_patched_lower_risk_resolver_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assert self.contract.authorization_intent is not None
            high_intent = replace(
                self.contract.authorization_intent,
                consequences=replace(
                    self.contract.authorization_intent.consequences,
                    confidentiality=ImpactLevel.HIGH,
                    sensitivity=ImpactLevel.HIGH,
                ),
            )
            high_contract = replace(
                self.contract,
                authorization_intent=high_intent,
            )
            inputs = self._inputs(
                Path(temporary).resolve(),
                contract=high_contract,
            )
            low_intent, low_source = resolve_task_authorization_intent(
                self.contract
            )
            forged_lineage = {
                **inputs["task_authorization_intent_lineage"],
                "intent_source": low_source,
                "task_authorization_intent": low_intent.to_canonical(),
                "authorization_intent_digest": low_intent.digest,
            }

            with (
                patch(
                    "ordomata.dispatch_authorization."
                    "resolve_task_authorization_intent",
                    return_value=(low_intent, low_source),
                ),
                self.assertRaisesRegex(ValidationError, "lineage is inconsistent"),
            ):
                evaluate_mock_dispatch_authorization(
                    **{
                        **inputs,
                        "task_authorization_intent_lineage": forged_lineage,
                        "task_authorization_intent_lineage_digest": (
                            canonical_digest(forged_lineage)
                        ),
                    }
                )

            with self.assertRaisesRegex(
                ValidationError,
                "lineage is inconsistent",
            ):
                evaluate_mock_dispatch_authorization(
                    **{
                        **inputs,
                        "task_authorization_intent_lineage_digest": self._digest(
                            "tampered-lineage"
                        ),
                    }
                )

    def test_nonfinite_or_stale_action_times_and_receipt_times_are_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_mock_dispatch_authorization(**inputs)
            for case, timestamp in (
                ("before-issued", 99.0),
                ("at-expiry", authorization.decision.expires_at),
                ("nan", float("nan")),
                ("positive-infinity", float("inf")),
                ("negative-infinity", float("-inf")),
            ):
                with self.subTest(case=case), self.assertRaises(
                    AuthorizationBlocked
                ):
                    self._assert_at_effect(
                        authorization,
                        inputs,
                        action_started_at=timestamp,
                    )

            for case, completed_at in (
                ("before-start", 100.5),
                ("nan", float("nan")),
                ("infinity", float("inf")),
            ):
                with self.subTest(case=case), self.assertRaises(ValidationError):
                    build_mock_dispatch_action_receipt(
                        authorization=authorization,
                        contract=self.contract,
                        action_started_at=101.0,
                        completed_at=completed_at,
                        outcome=ReceiptOutcome.SUCCEEDED,
                        result_digest=self._digest("result"),
                    )

    def test_invalid_evaluation_time_and_profile_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            for case, overrides in (
                ("nan-time", {"evaluated_at": float("nan")}),
                ("unsafe-profile", {"profile_id": "private/profile"}),
            ):
                with self.subTest(case=case), self.assertRaises(ValidationError):
                    evaluate_mock_dispatch_authorization(
                        **{**inputs, **overrides}
                    )


if __name__ == "__main__":
    unittest.main()
