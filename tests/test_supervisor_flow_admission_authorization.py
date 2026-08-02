from __future__ import annotations

import json
import unittest

from ordomata.authorization import (
    AuthorizationEffect,
    ObligationKind,
    canonical_digest,
)
from ordomata.errors import AuthorizationBlocked, ValidationError
from ordomata.models import PermissionClass
from ordomata.supervisor_flow_admission_authorization import (
    SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_ACTION_SCOPE,
    SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_ENFORCEMENT_COVERAGE,
    SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_EXECUTOR_ID,
    SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_OPERATION,
    SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_POLICY_ID,
    SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_RESOURCE_TYPE,
    SupervisorFlowAdmission,
    assert_supervisor_flow_admission_authorized,
    build_supervisor_flow_admission_action_receipt,
    evaluate_supervisor_flow_admission_authorization,
)


class SupervisorFlowAdmissionAuthorizationTests(unittest.TestCase):
    @staticmethod
    def _admission(**changes: object) -> SupervisorFlowAdmission:
        values: dict[str, object] = {
            "flow_id": "flow-private-marker",
            "admission_key_ref": canonical_digest(
                {"admission_key": "admit/private-marker"}
            ),
            "flow_request_digest": "a" * 64,
            "initial_flow_event_id": "flow-event-private-marker",
            "occurred_at": 100.0,
        }
        values.update(changes)
        return SupervisorFlowAdmission(**values)

    def test_exact_local_class_one_admission_is_permitted_and_receipted(
        self,
    ) -> None:
        admission = self._admission()
        authorization = evaluate_supervisor_flow_admission_authorization(
            admission=admission,
            legacy_executable=True,
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
            SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_POLICY_ID,
        )
        self.assertEqual(
            authorization.request.action.operation,
            SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_OPERATION,
        )
        self.assertEqual(
            authorization.request.resource.resource_type,
            SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_RESOURCE_TYPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["action_scope"],
            SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_ACTION_SCOPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["enforcement_coverage"],
            SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )

        assert_supervisor_flow_admission_authorized(
            authorization,
            admission=admission,
            action_started_at=101.0,
            persisted_payload=authorization.to_event_payload(),
        )
        receipt = build_supervisor_flow_admission_action_receipt(
            authorization=authorization,
            action_started_at=101.0,
            completed_at=102.0,
        )
        self.assertEqual(
            receipt,
            build_supervisor_flow_admission_action_receipt(
                authorization=authorization,
                action_started_at=101.0,
                completed_at=102.0,
            ),
        )
        self.assertEqual(
            receipt["enforcement_coverage"],
            SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            receipt["receipt"]["executor_id"],
            SUPERVISOR_FLOW_ADMISSION_AUTHORIZATION_EXECUTOR_ID,
        )
        self.assertEqual(receipt["receipt"]["outcome"], "succeeded")
        self.assertEqual(
            receipt["receipt_digest"],
            canonical_digest(receipt["receipt"]),
        )
        self.assertEqual(
            {
                (item["kind"], item["value"])
                for item in receipt["receipt"]["obligation_results"]
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
        self.assertNotIn("flow-private-marker", serialized)
        self.assertNotIn("admit/private-marker", serialized)
        self.assertNotIn("flow-event-private-marker", serialized)

    def test_legacy_gate_payload_and_freshness_fail_closed(self) -> None:
        admission = self._admission()
        authorization = evaluate_supervisor_flow_admission_authorization(
            admission=admission,
            legacy_executable=False,
        )

        self.assertFalse(authorization.authorized_at_evaluation)
        self.assertIn(
            "legacy_admission_not_executable",
            authorization.block_reason_codes,
        )
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_flow_admission_authorized(
                authorization,
                admission=admission,
                action_started_at=101.0,
                persisted_payload=authorization.to_event_payload(),
            )

        permitted = evaluate_supervisor_flow_admission_authorization(
            admission=admission,
            legacy_executable=True,
        )
        tampered = permitted.to_event_payload()
        tampered["effect"] = "deny"
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_flow_admission_authorized(
                permitted,
                admission=admission,
                action_started_at=101.0,
                persisted_payload=tampered,
            )
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_flow_admission_authorized(
                permitted,
                admission=admission,
                action_started_at=221.0,
                persisted_payload=permitted.to_event_payload(),
            )

    def test_invalid_admission_cannot_be_constructed(self) -> None:
        with self.assertRaises(ValidationError):
            self._admission(flow_request_digest="invalid")
        with self.assertRaises(ValidationError):
            self._admission(admission_key_ref="invalid")


if __name__ == "__main__":
    unittest.main()
