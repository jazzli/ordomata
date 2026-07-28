from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import (
    AuthorizationEffect,
    AuthorizationEvaluator,
    DecisionObligation,
    ImpactLevel,
    ObligationKind,
    ReceiptOutcome,
    canonical_digest,
)
from ordomata.contracts import load_task_contract
from ordomata.errors import AuthorizationBlocked, ValidationError
from ordomata.models import PermissionClass, RunRequest
from ordomata.publication_authorization import (
    LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE,
    LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
    LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID,
    LOCAL_CANDIDATE_PUBLICATION_OPERATION,
    LOCAL_CANDIDATE_PUBLICATION_POLICY_ID,
    assert_local_candidate_publication_authorized,
    build_local_candidate_publication_enforcement_receipt,
    build_local_candidate_publication_failure_payload,
    evaluate_local_candidate_publication_authorization,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class LocalCandidatePublicationAuthorizationTests(unittest.TestCase):
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
        request = RunRequest(
            run_id="private-publication-run-marker",
            task_id=selected_contract.task_id,
            task_version=selected_contract.version,
            prompt="private-publication-prompt-marker",
            workspace=root / "private-workspace-marker",
            run_directory=root / "private-run-directory-marker",
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
            "dispatch_request_digest": self._digest("dispatch-request"),
            "dispatch_decision_digest": self._digest("dispatch-decision"),
            "dispatch_action_receipt_digest": self._digest(
                "dispatch-action-receipt"
            ),
            "execution_accounting_digest": self._digest("accounting"),
            "billing_disposition_digest": self._digest("billing"),
            "artifact_digest": self._digest("artifact"),
            "destination_digest": self._digest("destination"),
            "artifact_metadata_digest": self._digest("metadata"),
            "artifact_kind": "local_draft",
            "artifact_size_bytes": 128,
            "evaluation_accepted": True,
            "credential_scan_passed": True,
            "safe_publication_prerequisites": True,
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
        assert_local_candidate_publication_authorized(
            authorization,
            action_started_at=action_started_at,
            persisted_payload=(
                authorization.to_event_payload()
                if persisted_payload is None
                else persisted_payload
            ),
            **current_inputs,
        )

    def test_exact_class_one_publication_is_permitted_and_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self._inputs(root)
            authorization = evaluate_local_candidate_publication_authorization(
                **inputs
            )

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
                LOCAL_CANDIDATE_PUBLICATION_POLICY_ID,
            )
            self.assertEqual(
                authorization.policy.enabled_classes,
                (PermissionClass.LOCAL_DRAFT,),
            )
            self.assertEqual(
                authorization.request.action.operation,
                LOCAL_CANDIDATE_PUBLICATION_OPERATION,
            )
            self.assertEqual(
                authorization.request.environment.billing_route.value,
                "local_non_ai",
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

            receipt = build_local_candidate_publication_enforcement_receipt(
                authorization=authorization,
                action_started_at=101.0,
                completed_at=102.0,
                outcome=ReceiptOutcome.SUCCEEDED,
                result_digest=inputs["artifact_digest"],
            )
            body = receipt["receipt"]
            self.assertEqual(
                receipt["enforcement_coverage"],
                LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
            )
            self.assertEqual(
                receipt["action_scope"],
                LOCAL_CANDIDATE_PUBLICATION_ACTION_SCOPE,
            )
            self.assertEqual(
                body["executor_id"],
                LOCAL_CANDIDATE_PUBLICATION_EXECUTOR_ID,
            )
            self.assertEqual(body["outcome"], "succeeded")
            self.assertEqual(body["result_digest"], inputs["artifact_digest"])
            self.assertEqual(
                receipt["receipt_digest"], canonical_digest(body)
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
                "private-publication-run-marker",
                "private-publication-prompt-marker",
                "private-workspace-marker",
                "private-run-directory-marker",
                "mock.private-profile-marker",
                "private_config_marker",
                "must-not-persist",
            ):
                self.assertNotIn(private_value, serialized)

    def test_class_zero_and_high_consequence_publication_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            class_zero_inputs = self._inputs(
                root,
                permission_class=PermissionClass.READ_ONLY,
            )
            class_zero = evaluate_local_candidate_publication_authorization(
                **class_zero_inputs
            )
            self.assertFalse(class_zero.authorized_at_evaluation)
            self.assertEqual(
                class_zero.decision.derived_permission_class,
                PermissionClass.LOCAL_DRAFT,
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
            high = evaluate_local_candidate_publication_authorization(
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
            self.assertIn(
                "authorization_class_ceiling_exceeded",
                high.block_reason_codes,
            )

    def test_legacy_and_safe_publication_prerequisites_are_independent(self) -> None:
        for field, expected in (
            (
                "controller_owned_mock_runner",
                "controller_owned_mock_runner_not_verified",
            ),
            ("legacy_executable", "legacy_gate_not_executable"),
            (
                "safe_publication_prerequisites",
                "safe_publication_prerequisites_not_satisfied",
            ),
            ("evaluation_accepted", "evaluation_not_accepted"),
            ("credential_scan_passed", "credential_scan_not_passed"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                inputs = self._inputs(
                    Path(temporary).resolve(),
                    **{field: False},
                )
                authorization = evaluate_local_candidate_publication_authorization(
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

    def test_stale_or_mutated_permit_is_rejected_at_action_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_local_candidate_publication_authorization(
                **inputs
            )
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
                )

    def test_semantically_forged_high_impact_permit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            clean_inputs = self._inputs(root)
            clean = evaluate_local_candidate_publication_authorization(
                **clean_inputs
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
            high_inputs = self._inputs(root, contract=high_contract)
            denied = evaluate_local_candidate_publication_authorization(
                **high_inputs
            )
            self.assertEqual(denied.decision.effect, AuthorizationEffect.DENY)
            self.assertEqual(
                denied.decision.derived_permission_class,
                PermissionClass.EXTERNAL_CONSEQUENTIAL,
            )

            forged_decision = replace(
                denied.decision,
                effect=AuthorizationEffect.PERMIT,
                derived_permission_class=PermissionClass.LOCAL_DRAFT,
                obligations=clean.decision.obligations,
            )
            forged = replace(
                denied,
                decision=forged_decision,
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

    def test_final_pep_requires_exact_fixed_policy_reevaluation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_local_candidate_publication_authorization(
                **inputs
            )
            forged = replace(
                authorization,
                decision=replace(
                    authorization.decision,
                    reason_details=("forged fixed-policy permit",),
                ),
            )

            with (
                patch(
                    "ordomata.publication_authorization."
                    "evaluate_local_candidate_publication_authorization",
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

    def test_cross_candidate_replay_and_persisted_mutation_are_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary).resolve())
            authorization = evaluate_local_candidate_publication_authorization(
                **inputs
            )
            for field, replacement in (
                ("artifact_digest", self._digest("other-artifact")),
                ("destination_digest", self._digest("other-destination")),
                (
                    "artifact_metadata_digest",
                    self._digest("other-metadata"),
                ),
                ("artifact_kind", "alternate_local_draft"),
                ("artifact_size_bytes", 129),
                (
                    "dispatch_action_receipt_digest",
                    self._digest("other-dispatch-receipt"),
                ),
                (
                    "execution_accounting_digest",
                    self._digest("other-accounting"),
                ),
                (
                    "billing_disposition_digest",
                    self._digest("other-billing"),
                ),
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

            mutated_payload = authorization.to_event_payload()
            mutated_payload["artifact_digest"] = self._digest(
                "persisted-other-artifact"
            )
            with self.assertRaises(AuthorizationBlocked):
                self._assert_at_effect(
                    authorization,
                    inputs,
                    action_started_at=101.0,
                    persisted_payload=mutated_payload,
                )

    def test_duplicate_and_unsupported_obligations_never_authorize(self) -> None:
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
            ):
                with patch.object(
                    AuthorizationEvaluator,
                    "evaluate",
                    new=evaluator,
                ):
                    inputs = self._inputs(Path(temporary).resolve())
                    authorization = (
                        evaluate_local_candidate_publication_authorization(
                            **inputs
                        )
                    )
                self.assertFalse(authorization.authorized_at_evaluation)
                self.assertFalse(authorization.obligations_supported)
                self.assertIn(
                    "authorization_obligation_unsupported",
                    authorization.block_reason_codes,
                )
                with self.assertRaises(AuthorizationBlocked):
                    self._assert_at_effect(
                        authorization,
                        inputs,
                        action_started_at=101.0,
                    )

    def test_failure_payload_and_validation_errors_are_fixed_and_redacted(self) -> None:
        private_marker = "/private/publication/error-marker"
        payload = build_local_candidate_publication_failure_payload(
            task_attempt_binding_digest=private_marker,
            execution_selection_digest=private_marker,
            task_authorization_intent_digest=private_marker,
            publication_authorization_intent_digest=private_marker,
            dispatch_request_digest=private_marker,
            dispatch_decision_digest=private_marker,
            dispatch_action_receipt_digest=private_marker,
            execution_accounting_digest=private_marker,
            billing_disposition_digest=private_marker,
            artifact_digest=private_marker,
            destination_digest=private_marker,
            artifact_metadata_digest=private_marker,
            requested_permission_class=PermissionClass.LOCAL_DRAFT,
            controller_owned_mock_runner=True,
            legacy_executable=True,
            safe_publication_prerequisites=True,
            evaluation_accepted=True,
            credential_scan_passed=True,
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
                evaluate_local_candidate_publication_authorization(**inputs)
        self.assertNotIn(private_marker, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
