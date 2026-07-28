from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ordomata.admission_authorization import (
    TASK_ADMISSION_ACTION_SCOPE,
    TASK_ADMISSION_ENFORCEMENT_COVERAGE,
    TASK_ADMISSION_EXECUTOR_ID,
    TASK_ADMISSION_OPERATION,
    TASK_ADMISSION_POLICY_ID,
    TASK_ADMISSION_RESOURCE_TYPE,
    assert_task_admission_authorized,
    build_task_admission_action_receipt,
    build_task_admission_failure_payload,
    evaluate_task_admission_authorization,
    task_admission_authorization_intent_digest,
)
from ordomata.authorization import (
    AuthorizationEffect,
    AuthorizationEvaluator,
    DecisionObligation,
    ImpactLevel,
    ObligationKind,
    Reach,
    canonical_digest,
)
from ordomata.contracts import load_task_contract
from ordomata.errors import AuthorizationBlocked, ValidationError
from ordomata.models import PermissionClass, RunRequest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class TaskAdmissionAuthorizationTests(unittest.TestCase):
    @staticmethod
    def _digest(label: str) -> str:
        return canonical_digest({"fixture": label})

    def setUp(self) -> None:
        self.contract = load_task_contract(
            REPOSITORY_ROOT / "tasks" / "chief-of-staff-lite.json"
        )

    def _inputs(
        self,
        root: Path,
        *,
        contract=None,
        permission_class: PermissionClass | None = None,
        **overrides,
    ):
        selected_contract = self.contract if contract is None else contract
        selected_class = (
            selected_contract.permission_class
            if permission_class is None
            else permission_class
        )
        prompt = "private-admission-prompt-marker"
        run_directory = root / ".ordomata" / "runs" / "private-run-marker"
        request = RunRequest(
            run_id="private-admission-run-marker",
            task_id=selected_contract.task_id,
            task_version=selected_contract.version,
            prompt=prompt,
            workspace=run_directory / "workspace",
            run_directory=run_directory,
            output_schema=selected_contract.output_schema,
            permission_class=selected_class,
            timeout_seconds=selected_contract.timeout_seconds,
            runner_overrides={"private_config_marker": "must-not-persist"},
        )
        values = {
            "contract": selected_contract,
            "request": request,
            "runner_id": "mock",
            "profile_id": "mock.private-profile-marker",
            "project_root": root,
            "controller_owned_mock_runner": True,
            "task_attempt_binding_digest": self._digest("binding"),
            "execution_selection_digest": self._digest("selection"),
            "profile_version_ref": self._digest("profile-version"),
            "profile_configuration_digest": self._digest("profile-config"),
            "context_digest": self._digest("context"),
            "prompt_digest": (
                "sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            ),
            "evaluated_at": 100.0,
            "legacy_executable": True,
        }
        values.update(overrides)
        return values

    @staticmethod
    def _assert_at_effect(
        authorization,
        inputs,
        *,
        action_started_at: float,
        persisted_payload=None,
        **current_overrides,
    ) -> None:
        current_inputs = dict(inputs)
        current_inputs.pop("evaluated_at")
        current_inputs.update(current_overrides)
        assert_task_admission_authorized(
            authorization,
            action_started_at=action_started_at,
            persisted_payload=(
                authorization.to_event_payload()
                if persisted_payload is None
                else persisted_payload
            ),
            **current_inputs,
        )

    def test_exact_class_one_admission_is_permitted_and_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self._inputs(root)
            authorization = evaluate_task_admission_authorization(**inputs)

            self.assertTrue(authorization.authorized_at_evaluation)
            self.assertEqual(authorization.block_reason_codes, ())
            self.assertEqual(
                authorization.decision.effect,
                AuthorizationEffect.PERMIT,
            )
            self.assertEqual(
                authorization.decision.derived_permission_class,
                PermissionClass.LOCAL_DRAFT,
            )
            self.assertEqual(
                authorization.policy.bundle_id,
                TASK_ADMISSION_POLICY_ID,
            )
            self.assertEqual(
                authorization.policy.enabled_classes,
                (PermissionClass.LOCAL_DRAFT,),
            )
            self.assertEqual(
                authorization.request.action.operation,
                TASK_ADMISSION_OPERATION,
            )
            self.assertEqual(
                authorization.request.resource.resource_type,
                TASK_ADMISSION_RESOURCE_TYPE,
            )
            self.assertEqual(
                authorization.request.environment.billing_route.value,
                "mock",
            )
            self.assertEqual(
                authorization.request.environment.network_state.value,
                "disabled",
            )
            self.assertEqual(
                authorization.request.environment.isolation_state.value,
                "verified",
            )
            self._assert_at_effect(
                authorization,
                inputs,
                action_started_at=101.0,
            )

            receipt = build_task_admission_action_receipt(
                authorization=authorization,
                action_started_at=101.0,
                completed_at=102.0,
            )
            repeated = build_task_admission_action_receipt(
                authorization=authorization,
                action_started_at=101.0,
                completed_at=102.0,
            )
            self.assertEqual(receipt, repeated)
            body = receipt["receipt"]
            self.assertEqual(
                receipt["enforcement_coverage"],
                TASK_ADMISSION_ENFORCEMENT_COVERAGE,
            )
            self.assertEqual(
                receipt["action_scope"],
                TASK_ADMISSION_ACTION_SCOPE,
            )
            self.assertEqual(body["executor_id"], TASK_ADMISSION_EXECUTOR_ID)
            self.assertEqual(body["outcome"], "succeeded")
            self.assertEqual(
                body["result_digest"],
                receipt["admission_result_digest"],
            )
            self.assertEqual(
                receipt["receipt_digest"],
                canonical_digest(body),
            )
            self.assertEqual(
                {
                    (item["kind"], item["value"])
                    for item in body["obligation_results"]
                    if item["satisfied"]
                },
                {
                    (ObligationKind.AUDIT_RECEIPT.value, "append_after_action"),
                    (ObligationKind.ISOLATED_LOCAL_ONLY.value, "required"),
                },
            )

            serialized = json.dumps(
                [authorization.to_event_payload(), receipt],
                sort_keys=True,
            )
            for private_value in (
                str(root),
                "private-admission-run-marker",
                "private-admission-prompt-marker",
                "private-run-marker",
                "mock.private-profile-marker",
                "private_config_marker",
                "must-not-persist",
            ):
                self.assertNotIn(private_value, serialized)

    def test_class_zero_and_high_consequence_admission_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            class_zero_contract = replace(
                self.contract,
                permission_class=PermissionClass.READ_ONLY,
            )
            class_zero_inputs = self._inputs(
                root,
                contract=class_zero_contract,
            )
            class_zero = evaluate_task_admission_authorization(
                **class_zero_inputs
            )
            self.assertFalse(class_zero.authorized_at_evaluation)
            self.assertEqual(
                class_zero.decision.derived_permission_class,
                PermissionClass.LOCAL_DRAFT,
            )
            self.assertIn(
                "task_permission_class_not_local_draft",
                class_zero.block_reason_codes,
            )
            self.assertIn(
                "authorization_class_ceiling_exceeded",
                class_zero.block_reason_codes,
            )
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    class_zero,
                    class_zero_inputs,
                    action_started_at=101.0,
                )

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
            high = evaluate_task_admission_authorization(
                **self._inputs(root, contract=high_contract)
            )
            self.assertFalse(high.authorized_at_evaluation)
            self.assertEqual(high.decision.effect, AuthorizationEffect.DENY)
            self.assertEqual(
                high.decision.derived_permission_class,
                PermissionClass.EXTERNAL_CONSEQUENTIAL,
            )
            self.assertIn(
                "authorization_effect_not_permit",
                high.block_reason_codes,
            )

            unsafe_intent = replace(
                self.contract.authorization_intent,
                consequences=replace(
                    self.contract.authorization_intent.consequences,
                    reach=Reach.EXTERNAL,
                    destructive=True,
                    reversible=False,
                ),
            )
            unsafe_contract = replace(
                self.contract,
                authorization_intent=unsafe_intent,
            )
            unsafe = evaluate_task_admission_authorization(
                **self._inputs(root, contract=unsafe_contract)
            )
            self.assertFalse(unsafe.authorized_at_evaluation)
            self.assertEqual(unsafe.decision.effect, AuthorizationEffect.DENY)
            self.assertEqual(
                unsafe.decision.derived_permission_class,
                PermissionClass.EXTERNAL_CONSEQUENTIAL,
            )

    def test_legacy_runner_and_pre_run_approval_gates_are_independent(self) -> None:
        for field, expected in (
            (
                "controller_owned_mock_runner",
                "controller_owned_mock_runner_not_verified",
            ),
            ("legacy_executable", "legacy_gate_not_executable"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                inputs = self._inputs(
                    Path(temporary).resolve(),
                    **{field: False},
                )
                authorization = evaluate_task_admission_authorization(
                    **inputs
                )
                self.assertFalse(authorization.authorized_at_evaluation)
                self.assertIn(expected, authorization.block_reason_codes)
                with self.assertRaises(AuthorizationBlocked):
                    self._assert_at_effect(
                        authorization,
                        inputs,
                        action_started_at=101.0,
                    )

        approval_contract = replace(
            self.contract,
            approval_requirements=replace(
                self.contract.approval_requirements,
                required_before_run=True,
                approver="private-approver-marker",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(
                Path(temporary).resolve(),
                contract=approval_contract,
            )
            authorization = evaluate_task_admission_authorization(**inputs)
        self.assertFalse(authorization.authorized_at_evaluation)
        self.assertEqual(authorization.decision.effect, AuthorizationEffect.DEFER)
        self.assertIn(
            "pre_run_approval_not_supported",
            authorization.block_reason_codes,
        )
        self.assertEqual(len(authorization.policy.approval_requirements), 1)
        self.assertNotIn(
            "private-approver-marker",
            json.dumps(authorization.to_event_payload(), sort_keys=True),
        )

    def test_stale_mutated_or_unpersisted_permit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_task_admission_authorization(**inputs)
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    authorization,
                    inputs,
                    action_started_at=authorization.decision.expires_at,
                )

            mutated = replace(
                authorization,
                decision=replace(
                    authorization.decision,
                    request_digest=self._digest("mutated-request"),
                ),
            )
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    mutated,
                    inputs,
                    action_started_at=101.0,
                    persisted_payload=mutated.to_event_payload(),
                )

            mutated_payload = authorization.to_event_payload()
            mutated_payload["execution_selection_digest"] = self._digest(
                "persisted-other-selection"
            )
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    authorization,
                    inputs,
                    action_started_at=101.0,
                    persisted_payload=mutated_payload,
                )

    def test_cross_attempt_replay_and_current_input_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_task_admission_authorization(**inputs)
            for field, replacement in (
                ("task_attempt_binding_digest", self._digest("other-binding")),
                ("execution_selection_digest", self._digest("other-selection")),
                ("profile_version_ref", self._digest("other-version")),
                (
                    "profile_configuration_digest",
                    self._digest("other-profile-config"),
                ),
                ("context_digest", self._digest("other-context")),
            ):
                with self.subTest(field=field), self.assertRaises(
                    AuthorizationBlocked
                ):
                    self._assert_at_effect(
                        authorization,
                        inputs,
                        action_started_at=101.0,
                        **{field: replacement},
                    )

            other_request = replace(
                inputs["request"],
                run_id="other-private-run-marker",
            )
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    authorization,
                    inputs,
                    action_started_at=101.0,
                    request=other_request,
                )

    def test_final_pep_rejects_a_semantically_forged_permit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            clean_inputs = self._inputs(root)
            clean = evaluate_task_admission_authorization(**clean_inputs)
            assert self.contract.authorization_intent is not None
            high_contract = replace(
                self.contract,
                authorization_intent=replace(
                    self.contract.authorization_intent,
                    consequences=replace(
                        self.contract.authorization_intent.consequences,
                        confidentiality=ImpactLevel.HIGH,
                    ),
                ),
            )
            high_inputs = self._inputs(root, contract=high_contract)
            denied = evaluate_task_admission_authorization(**high_inputs)
            forged = replace(
                denied,
                decision=replace(
                    denied.decision,
                    effect=AuthorizationEffect.PERMIT,
                    derived_permission_class=PermissionClass.LOCAL_DRAFT,
                    obligations=clean.decision.obligations,
                ),
                authority_ceiling_satisfied=True,
                obligations_supported=True,
                block_reason_codes=(),
            )
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    forged,
                    high_inputs,
                    action_started_at=101.0,
                    persisted_payload=forged.to_event_payload(),
                )

    def test_final_pep_requires_independent_fixed_policy_reevaluation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_task_admission_authorization(**inputs)
            forged = replace(
                authorization,
                decision=replace(
                    authorization.decision,
                    reason_details=("forged fixed-policy permit",),
                ),
            )
            with (
                patch(
                    "ordomata.admission_authorization."
                    "evaluate_task_admission_authorization",
                    return_value=forged,
                ),
                self.assertRaises(AuthorizationBlocked),
            ):
                self._assert_at_effect(
                    forged,
                    inputs,
                    action_started_at=101.0,
                    persisted_payload=forged.to_event_payload(),
                )

    def test_duplicate_or_unsupported_obligations_never_authorize(self) -> None:
        original_evaluate = AuthorizationEvaluator.evaluate

        def duplicate_obligation(evaluator, request, policy):
            decision = original_evaluate(evaluator, request, policy)
            return replace(
                decision,
                obligations=decision.obligations + (decision.obligations[0],),
            )

        def unsupported_obligation(evaluator, request, policy):
            decision = original_evaluate(evaluator, request, policy)
            return replace(
                decision,
                obligations=(
                    DecisionObligation(
                        ObligationKind.AUDIT_RECEIPT,
                        "append_after_action",
                    ),
                    DecisionObligation(ObligationKind.READ_ONLY, "required"),
                ),
            )

        for evaluator in (duplicate_obligation, unsupported_obligation):
            with (
                self.subTest(evaluator=evaluator.__name__),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(AuthorizationEvaluator, "evaluate", new=evaluator),
            ):
                inputs = self._inputs(Path(temporary).resolve())
                authorization = evaluate_task_admission_authorization(**inputs)
                self.assertFalse(authorization.authorized_at_evaluation)
                self.assertFalse(authorization.obligations_supported)
                self.assertIn(
                    "authorization_obligation_unsupported",
                    authorization.block_reason_codes,
                )

    def test_failure_payload_and_validation_errors_are_fixed_and_redacted(self) -> None:
        private_marker = "/private/admission/error-marker"
        payload = build_task_admission_failure_payload(
            run_ref=private_marker,
            profile_ref=private_marker,
            task_attempt_binding_digest=private_marker,
            execution_selection_digest=private_marker,
            profile_version_ref=private_marker,
            profile_configuration_digest=private_marker,
            context_digest=private_marker,
            prompt_digest=private_marker,
            task_authorization_intent_digest=private_marker,
            admission_authorization_intent_digest=private_marker,
            requested_permission_class=PermissionClass.LOCAL_DRAFT,
            controller_owned_mock_runner=True,
            legacy_executable=True,
            pre_run_approval_required=False,
            pre_run_approver_ref=private_marker,
            evaluated_at=float("nan"),
        )
        projection = json.dumps(payload, sort_keys=True)
        self.assertNotIn(private_marker, projection)
        self.assertEqual(payload["effect"], "indeterminate")
        self.assertFalse(payload["authorization_eligible"])
        self.assertIsNone(payload["request"])
        self.assertIsNone(payload["evaluated_at"])

        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            inputs["profile_id"] = private_marker
            with self.assertRaises(ValidationError) as caught:
                evaluate_task_admission_authorization(**inputs)
        self.assertNotIn(private_marker, str(caught.exception))

        self.assertEqual(
            task_admission_authorization_intent_digest(self.contract),
            evaluate_task_admission_authorization(
                **self._inputs(REPOSITORY_ROOT.resolve())
            ).admission_authorization_intent_digest,
        )


if __name__ == "__main__":
    unittest.main()
