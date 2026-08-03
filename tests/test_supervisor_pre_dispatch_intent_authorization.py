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
from ordomata.supervisor_pre_dispatch_intent_authorization import (
    SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE,
    SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ENFORCEMENT_COVERAGE,
    SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EXECUTOR_ID,
    SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_OPERATION,
    SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_ID,
    SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_RESOURCE_TYPE,
    SupervisorPreDispatchIntent,
    SupervisorPreDispatchIntentLease,
    assert_supervisor_pre_dispatch_intent_authorized,
    build_supervisor_pre_dispatch_intent_action_receipt,
    evaluate_supervisor_pre_dispatch_intent_authorization,
)


class SupervisorPreDispatchIntentAuthorizationTests(unittest.TestCase):
    @staticmethod
    def _lease(**changes: object) -> SupervisorPreDispatchIntentLease:
        values: dict[str, object] = {
            "lease_key_ref": canonical_digest(
                {"lease_key": "flow:flow-private-marker"}
            ),
            "lease_owner_ref": canonical_digest(
                {"lease_owner": "attempt/private-marker"}
            ),
            "acquired_at": 100.0,
            "renewed_at": 101.0,
            "expires_at": 120.0,
        }
        values.update(changes)
        return SupervisorPreDispatchIntentLease(**values)

    @classmethod
    def _intent(cls, **changes: object) -> SupervisorPreDispatchIntent:
        lease = cls._lease()
        values: dict[str, object] = {
            "flow_id": "flow-private-marker",
            "attempt_id": "attempt-private-marker",
            "run_id": "run-private-marker",
            "source_flow_event_id": "flow-event-private-marker",
            "source_flow_revision": 2,
            "source_flow_occurred_at": 100.0,
            "source_attempt_event_id": "attempt-event-created-private-marker",
            "source_attempt_revision": 1,
            "source_attempt_occurred_at": 100.0,
            "target_attempt_event_id": "attempt-event-dispatch-private-marker",
            "target_attempt_revision": 2,
            "flow_request_digest": "a" * 64,
            "input_digest": "b" * 64,
            "lease_owner_ref": lease.lease_owner_ref,
            "lease_keys_digest": canonical_digest(
                {"lease_keys": ["flow:flow-private-marker", "repo:private"]}
            ),
            "lease_snapshot": (lease,),
            "deadline_at": 160.0,
            "occurred_at": 101.0,
        }
        values.update(changes)
        return SupervisorPreDispatchIntent(**values)

    def test_exact_local_class_one_intent_is_permitted_and_receipted(self) -> None:
        intent = self._intent()
        authorization = evaluate_supervisor_pre_dispatch_intent_authorization(
            intent=intent,
            legacy_executable=True,
        )

        self.assertTrue(authorization.authorized_at_evaluation)
        self.assertEqual(authorization.block_reason_codes, ())
        self.assertEqual(authorization.decision.effect, AuthorizationEffect.PERMIT)
        self.assertEqual(
            authorization.decision.derived_permission_class,
            PermissionClass.LOCAL_DRAFT,
        )
        self.assertEqual(
            authorization.policy.bundle_id,
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_POLICY_ID,
        )
        self.assertEqual(
            authorization.request.action.operation,
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_OPERATION,
        )
        self.assertEqual(
            authorization.request.resource.resource_type,
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_RESOURCE_TYPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["action_scope"],
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ACTION_SCOPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["enforcement_coverage"],
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )

        assert_supervisor_pre_dispatch_intent_authorized(
            authorization,
            intent=intent,
            action_started_at=101.0,
            persisted_payload=authorization.to_event_payload(),
        )
        receipt = build_supervisor_pre_dispatch_intent_action_receipt(
            authorization=authorization,
            action_started_at=101.0,
            completed_at=102.0,
        )
        self.assertEqual(
            receipt,
            build_supervisor_pre_dispatch_intent_action_receipt(
                authorization=authorization,
                action_started_at=101.0,
                completed_at=102.0,
            ),
        )
        self.assertEqual(
            receipt["enforcement_coverage"],
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            receipt["receipt"]["executor_id"],
            SUPERVISOR_PRE_DISPATCH_INTENT_AUTHORIZATION_EXECUTOR_ID,
        )
        self.assertEqual(receipt["receipt"]["outcome"], "succeeded")
        self.assertEqual(receipt["receipt_digest"], canonical_digest(receipt["receipt"]))
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
        for private_value in (
            "flow-private-marker",
            "attempt-private-marker",
            "run-private-marker",
            "flow-event-private-marker",
            "attempt-event-created-private-marker",
            "attempt-event-dispatch-private-marker",
            "attempt/private-marker",
        ):
            self.assertNotIn(private_value, serialized)

    def test_legacy_gate_payload_and_freshness_fail_closed(self) -> None:
        intent = self._intent()
        authorization = evaluate_supervisor_pre_dispatch_intent_authorization(
            intent=intent,
            legacy_executable=False,
        )

        self.assertFalse(authorization.authorized_at_evaluation)
        self.assertIn(
            "legacy_pre_dispatch_intent_not_executable",
            authorization.block_reason_codes,
        )
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_pre_dispatch_intent_authorized(
                authorization,
                intent=intent,
                action_started_at=101.0,
                persisted_payload=authorization.to_event_payload(),
            )

        permitted = evaluate_supervisor_pre_dispatch_intent_authorization(
            intent=intent,
            legacy_executable=True,
        )
        tampered = permitted.to_event_payload()
        tampered["effect"] = "deny"
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_pre_dispatch_intent_authorized(
                permitted,
                intent=intent,
                action_started_at=101.0,
                persisted_payload=tampered,
            )
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_pre_dispatch_intent_authorized(
                permitted,
                intent=intent,
                action_started_at=221.0,
                persisted_payload=permitted.to_event_payload(),
            )

    def test_invalid_intent_or_lease_cannot_be_constructed(self) -> None:
        with self.assertRaises(ValidationError):
            self._intent(target_attempt_revision=3)
        with self.assertRaises(ValidationError):
            self._intent(lease_snapshot=(self._lease(expires_at=101.0),))
        with self.assertRaises(ValidationError):
            self._intent(source_flow_occurred_at=99.0)


if __name__ == "__main__":
    unittest.main()
