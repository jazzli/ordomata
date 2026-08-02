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
from ordomata.supervisor_control_authorization import (
    SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE,
    SUPERVISOR_CONTROL_AUTHORIZATION_ENFORCEMENT_COVERAGE,
    SUPERVISOR_CONTROL_AUTHORIZATION_EXECUTOR_ID,
    SUPERVISOR_CONTROL_AUTHORIZATION_OPERATION,
    SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_ID,
    SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE,
    SupervisorControlTransition,
    assert_supervisor_control_transition_authorized,
    build_supervisor_control_action_receipt,
    evaluate_supervisor_control_authorization,
)


class SupervisorControlAuthorizationTests(unittest.TestCase):
    @staticmethod
    def _transition(**changes: object) -> SupervisorControlTransition:
        values: dict[str, object] = {
            "previous_control_event_id": "synthetic:stopped:0",
            "previous_revision": 0,
            "previous_mode": "stopped",
            "control_event_id": "control-event-private-marker",
            "target_revision": 1,
            "target_mode": "running",
            "actor_ref": canonical_digest(
                {"actor_id": "operator/private-session-marker"}
            ),
            "reason_code": "operator_started",
            "occurred_at": 100.0,
        }
        values.update(changes)
        return SupervisorControlTransition(**values)

    def test_exact_local_class_one_transition_is_permitted_and_receipted(
        self,
    ) -> None:
        transition = self._transition()
        authorization = evaluate_supervisor_control_authorization(
            transition=transition,
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
            SUPERVISOR_CONTROL_AUTHORIZATION_POLICY_ID,
        )
        self.assertEqual(
            authorization.request.action.operation,
            SUPERVISOR_CONTROL_AUTHORIZATION_OPERATION,
        )
        self.assertEqual(
            authorization.request.resource.resource_type,
            SUPERVISOR_CONTROL_AUTHORIZATION_RESOURCE_TYPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["action_scope"],
            SUPERVISOR_CONTROL_AUTHORIZATION_ACTION_SCOPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["enforcement_coverage"],
            SUPERVISOR_CONTROL_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )

        assert_supervisor_control_transition_authorized(
            authorization,
            transition=transition,
            action_started_at=101.0,
            persisted_payload=authorization.to_event_payload(),
        )
        receipt = build_supervisor_control_action_receipt(
            authorization=authorization,
            action_started_at=101.0,
            completed_at=102.0,
        )
        self.assertEqual(
            receipt,
            build_supervisor_control_action_receipt(
                authorization=authorization,
                action_started_at=101.0,
                completed_at=102.0,
            ),
        )
        self.assertEqual(
            receipt["enforcement_coverage"],
            SUPERVISOR_CONTROL_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            receipt["receipt"]["executor_id"],
            SUPERVISOR_CONTROL_AUTHORIZATION_EXECUTOR_ID,
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
        self.assertNotIn("operator/private-session-marker", serialized)

    def test_legacy_gate_payload_and_freshness_fail_closed(self) -> None:
        transition = self._transition()
        authorization = evaluate_supervisor_control_authorization(
            transition=transition,
            legacy_executable=False,
        )

        self.assertFalse(authorization.authorized_at_evaluation)
        self.assertIn(
            "legacy_transition_not_executable",
            authorization.block_reason_codes,
        )
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_control_transition_authorized(
                authorization,
                transition=transition,
                action_started_at=101.0,
                persisted_payload=authorization.to_event_payload(),
            )

        permitted = evaluate_supervisor_control_authorization(
            transition=transition,
            legacy_executable=True,
        )
        tampered = permitted.to_event_payload()
        tampered["effect"] = "deny"
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_control_transition_authorized(
                permitted,
                transition=transition,
                action_started_at=101.0,
                persisted_payload=tampered,
            )
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_control_transition_authorized(
                permitted,
                transition=transition,
                action_started_at=221.0,
                persisted_payload=permitted.to_event_payload(),
            )

    def test_invalid_or_irreversible_transition_cannot_be_constructed(self) -> None:
        with self.assertRaises(ValidationError):
            self._transition(target_mode="paused")
        with self.assertRaises(ValidationError):
            self._transition(target_revision=2)


if __name__ == "__main__":
    unittest.main()
