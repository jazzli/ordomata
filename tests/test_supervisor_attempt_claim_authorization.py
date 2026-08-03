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
from ordomata.supervisor_attempt_claim_authorization import (
    SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE,
    SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ENFORCEMENT_COVERAGE,
    SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EXECUTOR_ID,
    SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_OPERATION,
    SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_ID,
    SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_RESOURCE_TYPE,
    SupervisorAttemptClaim,
    assert_supervisor_attempt_claim_authorized,
    build_supervisor_attempt_claim_action_receipt,
    evaluate_supervisor_attempt_claim_authorization,
)


class SupervisorAttemptClaimAuthorizationTests(unittest.TestCase):
    @staticmethod
    def _claim(**changes: object) -> SupervisorAttemptClaim:
        values: dict[str, object] = {
            "flow_id": "flow-private-marker",
            "attempt_id": "attempt-private-marker",
            "run_id": "run-private-marker",
            "source_flow_revision": 1,
            "target_flow_revision": 2,
            "control_revision": 1,
            "attempt_number": 1,
            "flow_request_digest": "a" * 64,
            "input_digest": "b" * 64,
            "instance_owner_ref": canonical_digest(
                {"instance_owner": "supervisor/private-marker"}
            ),
            "lease_owner_ref": canonical_digest(
                {"lease_owner": "attempt/private-marker"}
            ),
            "lease_keys_digest": canonical_digest(
                {"lease_keys": ["flow:flow-private-marker", "repo:test"]}
            ),
            "deadline_at": 160.0,
            "lease_expires_at": 120.0,
            "attempt_event_id": "attempt-event-private-marker",
            "flow_event_id": "flow-event-private-marker",
            "occurred_at": 100.0,
        }
        values.update(changes)
        return SupervisorAttemptClaim(**values)

    def test_exact_local_class_one_claim_is_permitted_and_receipted(self) -> None:
        claim = self._claim()
        authorization = evaluate_supervisor_attempt_claim_authorization(
            claim=claim,
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
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_POLICY_ID,
        )
        self.assertEqual(
            authorization.request.action.operation,
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_OPERATION,
        )
        self.assertEqual(
            authorization.request.resource.resource_type,
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_RESOURCE_TYPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["action_scope"],
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ACTION_SCOPE,
        )
        self.assertEqual(
            authorization.to_event_payload()["enforcement_coverage"],
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )

        assert_supervisor_attempt_claim_authorized(
            authorization,
            claim=claim,
            action_started_at=101.0,
            persisted_payload=authorization.to_event_payload(),
        )
        receipt = build_supervisor_attempt_claim_action_receipt(
            authorization=authorization,
            action_started_at=101.0,
            completed_at=102.0,
        )
        self.assertEqual(
            receipt,
            build_supervisor_attempt_claim_action_receipt(
                authorization=authorization,
                action_started_at=101.0,
                completed_at=102.0,
            ),
        )
        self.assertEqual(
            receipt["enforcement_coverage"],
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            receipt["receipt"]["executor_id"],
            SUPERVISOR_ATTEMPT_CLAIM_AUTHORIZATION_EXECUTOR_ID,
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
        for private_value in (
            "flow-private-marker",
            "attempt-private-marker",
            "run-private-marker",
            "supervisor/private-marker",
            "attempt/private-marker",
            "attempt-event-private-marker",
            "flow-event-private-marker",
        ):
            self.assertNotIn(private_value, serialized)

    def test_legacy_gate_payload_and_freshness_fail_closed(self) -> None:
        claim = self._claim()
        authorization = evaluate_supervisor_attempt_claim_authorization(
            claim=claim,
            legacy_executable=False,
        )

        self.assertFalse(authorization.authorized_at_evaluation)
        self.assertIn("legacy_claim_not_executable", authorization.block_reason_codes)
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_attempt_claim_authorized(
                authorization,
                claim=claim,
                action_started_at=101.0,
                persisted_payload=authorization.to_event_payload(),
            )

        permitted = evaluate_supervisor_attempt_claim_authorization(
            claim=claim,
            legacy_executable=True,
        )
        tampered = permitted.to_event_payload()
        tampered["effect"] = "deny"
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_attempt_claim_authorized(
                permitted,
                claim=claim,
                action_started_at=101.0,
                persisted_payload=tampered,
            )
        with self.assertRaises(AuthorizationBlocked):
            assert_supervisor_attempt_claim_authorized(
                permitted,
                claim=claim,
                action_started_at=221.0,
                persisted_payload=permitted.to_event_payload(),
            )

    def test_invalid_claim_cannot_be_constructed(self) -> None:
        with self.assertRaises(ValidationError):
            self._claim(target_flow_revision=3)
        with self.assertRaises(ValidationError):
            self._claim(lease_expires_at=160.1)
        with self.assertRaises(ValidationError):
            self._claim(input_digest="invalid")


if __name__ == "__main__":
    unittest.main()
