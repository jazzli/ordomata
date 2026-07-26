from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from agentops.billing import (
    BillingPolicy,
    FileBillingAttestationLoader,
    LIVE_RUN_ENVIRONMENT_NAME,
    fingerprint_account_identity,
)
from agentops.errors import BillingRouteBlocked, LiveRunDisabled
from agentops.models import (
    AgentEvent,
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PaidContinuationProtection,
    PaidCreditBalance,
)


NOW = 1_000.0
ACCOUNT_FINGERPRINT = "a" * 64


def assessment(
    route: BillingRoute,
    confidence: AssessmentConfidence = AssessmentConfidence.HIGH,
    *,
    safe_subscription: bool = False,
) -> BillingRouteAssessment:
    if safe_subscription:
        attestation = BillingSafetyAttestation(
            runner_id="codex",
            account_identity_fingerprint=ACCOUNT_FINGERPRINT,
            billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
            capacity_state=CapacityState.AVAILABLE,
            paid_continuation_protection=(
                PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
            ),
            observed_at=NOW - 10,
            expires_at=NOW + 10,
            confidence=AssessmentConfidence.HIGH,
            evidence=("operator_attestation:provider_ui_auto_top_up_disabled",),
        )
        return BillingRouteAssessment(
            runner_id="codex",
            route=route,
            confidence=confidence,
            capacity_state=CapacityState.AVAILABLE,
            paid_continuation_protection=(
                PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
            ),
            paid_credit_balance=PaidCreditBalance.ZERO,
            account_identity_fingerprint=ACCOUNT_FINGERPRINT,
            capacity_observed_at=NOW - 1,
            capacity_expires_at=NOW + 1,
            attestation=attestation,
        )
    return BillingRouteAssessment(
        runner_id="test",
        route=route,
        confidence=confidence,
    )


class BillingPolicyTests(unittest.TestCase):
    def test_only_high_confidence_safe_routes_are_allowed(self) -> None:
        subscription = assessment(
            BillingRoute.SUBSCRIPTION_INCLUDED, safe_subscription=True
        )
        self.assertTrue(BillingPolicy.route_is_allowed(subscription, now=NOW))
        BillingPolicy.assert_route_allowed(subscription, now=NOW)
        for route in (BillingRoute.LOCAL_NON_AI, BillingRoute.MOCK):
            with self.subTest(route=route):
                self.assertTrue(BillingPolicy.route_is_allowed(assessment(route)))
                BillingPolicy.assert_route_allowed(assessment(route))

        self.assertFalse(
            BillingPolicy.route_is_allowed(
                assessment(
                    BillingRoute.SUBSCRIPTION_INCLUDED, AssessmentConfidence.MEDIUM
                )
            )
        )

    def test_api_cloud_unknown_and_weak_assessments_fail_closed(self) -> None:
        blocked = (
            assessment(BillingRoute.SEPARATELY_BILLED_API),
            assessment(BillingRoute.CLOUD_PROVIDER_BILLING),
            assessment(BillingRoute.PURCHASED_PRODUCT_CREDIT),
            assessment(BillingRoute.SUBSCRIPTION_OVERAGE),
            assessment(BillingRoute.UNKNOWN),
            assessment(
                BillingRoute.SUBSCRIPTION_INCLUDED, AssessmentConfidence.MEDIUM
            ),
        )
        for item in blocked:
            with self.subTest(item=item):
                with self.assertRaises(BillingRouteBlocked):
                    BillingPolicy.assert_route_allowed(item)

    def test_live_gate_requires_exact_value(self) -> None:
        allowed = assessment(
            BillingRoute.SUBSCRIPTION_INCLUDED, safe_subscription=True
        )
        for value in (None, "", "true", "TRUE", "yes", "0", " 1"):
            environment = {} if value is None else {LIVE_RUN_ENVIRONMENT_NAME: value}
            with self.subTest(value=value):
                with self.assertRaises(LiveRunDisabled):
                    BillingPolicy.assert_live_run_allowed(
                        allowed, environment, now=NOW
                    )

        BillingPolicy.assert_live_run_allowed(
            allowed, {LIVE_RUN_ENVIRONMENT_NAME: "1"}, now=NOW
        )

    def test_live_gate_never_enables_api_route(self) -> None:
        with self.assertRaises(BillingRouteBlocked):
            BillingPolicy.assert_live_run_allowed(
                assessment(BillingRoute.SEPARATELY_BILLED_API),
                {LIVE_RUN_ENVIRONMENT_NAME: "1"},
            )

    def test_local_and_mock_do_not_require_live_gate(self) -> None:
        BillingPolicy.assert_live_run_allowed(
            assessment(BillingRoute.LOCAL_NON_AI), {}
        )
        BillingPolicy.assert_live_run_allowed(assessment(BillingRoute.MOCK), {})

    def test_subscription_login_without_v2_evidence_fails_closed(self) -> None:
        oauth_only = assessment(BillingRoute.SUBSCRIPTION_INCLUDED)
        self.assertFalse(BillingPolicy.route_is_allowed(oauth_only, now=NOW))
        with self.assertRaisesRegex(
            BillingRouteBlocked, "paid_continuation_attestation_missing"
        ):
            BillingPolicy.assert_live_run_allowed(
                oauth_only,
                {LIVE_RUN_ENVIRONMENT_NAME: "1"},
                now=NOW,
            )

    def test_live_evidence_must_outlive_the_requested_run(self) -> None:
        safe = assessment(
            BillingRoute.SUBSCRIPTION_INCLUDED, safe_subscription=True
        )
        self.assertTrue(BillingPolicy.route_is_allowed(safe, now=NOW))
        self.assertFalse(
            BillingPolicy.route_is_allowed(
                safe,
                now=NOW,
                required_valid_until=NOW + 20,
            )
        )

    def test_stale_mismatched_and_positive_credit_evidence_is_blocked(self) -> None:
        safe = assessment(
            BillingRoute.SUBSCRIPTION_INCLUDED, safe_subscription=True
        )
        cases = (
            replace(
                safe,
                attestation=replace(safe.attestation, expires_at=NOW),
            ),
            replace(
                safe,
                attestation=replace(
                    safe.attestation,
                    account_identity_fingerprint="b" * 64,
                ),
            ),
            replace(safe, paid_credit_balance=PaidCreditBalance.POSITIVE),
            replace(
                safe,
                paid_continuation_protection=PaidContinuationProtection.ENABLED,
            ),
            replace(
                safe,
                attestation=replace(
                    safe.attestation,
                    evidence=("arbitrary_direct_claim",),
                ),
            ),
        )
        for item in cases:
            with self.subTest(item=item):
                self.assertFalse(BillingPolicy.route_is_allowed(item, now=NOW))

    def test_post_run_paid_unknown_and_limit_dispositions_are_distinct(self) -> None:
        preflight = assessment(
            BillingRoute.SUBSCRIPTION_INCLUDED, safe_subscription=True
        )
        paid = replace(
            preflight,
            route=BillingRoute.PURCHASED_PRODUCT_CREDIT,
            paid_credit_balance=PaidCreditBalance.POSITIVE,
        )
        paid_result = BillingPolicy.assess_post_run(
            preflight, paid, (), now=NOW
        )
        self.assertTrue(paid_result.quarantine_required)
        self.assertTrue(paid_result.circuit_breaker_required)
        self.assertEqual(paid_result.incremental_ai_charge, IncrementalAICharge.POSSIBLE)

        unknown = BillingPolicy.assess_post_run(preflight, None, (), now=NOW)
        self.assertEqual(unknown.paid_capacity_consumed, PaidCapacityConsumed.UNKNOWN)
        self.assertTrue(unknown.circuit_breaker_required)

        limit = replace(preflight, capacity_state=CapacityState.LIMIT_REACHED)
        limited = BillingPolicy.assess_post_run(preflight, limit, (), now=NOW)
        self.assertEqual(limited.capacity_state, CapacityState.BLOCKED_UNTIL_RESET)
        self.assertEqual(limited.incremental_ai_charge, IncrementalAICharge.NONE)
        self.assertFalse(limited.circuit_breaker_required)

        confirmed = BillingPolicy.assess_post_run(
            preflight,
            preflight,
            (AgentEvent("billing.updated", {"paidCapacityConsumed": True}),),
            now=NOW,
        )
        self.assertEqual(
            confirmed.incremental_ai_charge, IncrementalAICharge.CONFIRMED
        )
        self.assertEqual(confirmed.paid_capacity_consumed, PaidCapacityConsumed.YES)

        for event in (
            AgentEvent("result", {"extraUsageEnabled": True}),
            AgentEvent(
                "turn.completed",
                {"billingRoute": "subscription_overage"},
            ),
            AgentEvent(
                "item.completed",
                {"paidCapacityConsumed": True},
            ),
        ):
            with self.subTest(event_type=event.event_type, payload=event.payload):
                ordinary_event_signal = BillingPolicy.assess_post_run(
                    preflight,
                    preflight,
                    (event,),
                    now=NOW,
                )
                self.assertTrue(ordinary_event_signal.quarantine_required)
                self.assertTrue(ordinary_event_signal.circuit_breaker_required)
                self.assertIn(
                    ordinary_event_signal.incremental_ai_charge,
                    {
                        IncrementalAICharge.POSSIBLE,
                        IncrementalAICharge.CONFIRMED,
                    },
                )

        claude_style_limit = BillingPolicy.assess_post_run(
            preflight,
            preflight,
            (
                AgentEvent(
                    "result",
                    {"is_error": True, "result": "included usage limit reached"},
                ),
            ),
            now=NOW,
        )
        self.assertEqual(
            claude_style_limit.capacity_state,
            CapacityState.BLOCKED_UNTIL_RESET,
        )
        self.assertFalse(claude_style_limit.circuit_breaker_required)


class BillingAttestationLoaderTests(unittest.TestCase):
    def _document(self, *, runner_id: str = "codex", **updates):
        protection = (
            "verified_zero_balance_and_auto_top_up_disabled"
            if runner_id == "codex"
            else "provider_enforced_disabled"
        )
        evidence_codes = (
            ["provider_ui_auto_top_up_disabled"]
            if runner_id == "codex"
            else [
                "provider_ui_extra_usage_disabled",
                "provider_ui_included_capacity_available",
            ]
        )
        record = {
            "runner_id": runner_id,
            "account_identity_fingerprint": ACCOUNT_FINGERPRINT,
            "billing_route": "subscription_included",
            "capacity_state": "available",
            "paid_continuation_protection": protection,
            "observed_at": NOW - 1,
            "expires_at": NOW + 1,
            "confidence": "high",
            "evidence_codes": evidence_codes,
        }
        record.update(updates)
        return {"schema_version": 1, "attestations": [record]}

    def _load(self, document, *, mode: int = 0o600):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "billing-attestations.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            path.chmod(mode)
            return FileBillingAttestationLoader(path).load(
                document["attestations"][0]["runner_id"], ACCOUNT_FINGERPRINT
            )

    def test_loader_accepts_only_semantically_complete_private_evidence(self) -> None:
        loaded = self._load(self._document())
        self.assertIsNotNone(loaded)
        self.assertNotIn(ACCOUNT_FINGERPRINT, repr(loaded))
        self.assertEqual(
            fingerprint_account_identity("codex", "operator@example.invalid"),
            fingerprint_account_identity("codex", "OPERATOR@example.invalid"),
        )

    def test_loader_rejects_permissive_file_and_arbitrary_or_missing_codes(self) -> None:
        self.assertIsNone(self._load(self._document(), mode=0o644))
        self.assertIsNone(
            self._load(self._document(evidence_codes=["arbitrary_claim"]))
        )
        self.assertIsNone(self._load(self._document(evidence_codes=[])))
        self.assertIsNone(
            self._load(
                self._document(
                    paid_continuation_protection="provider_enforced_disabled"
                )
            )
        )

    def test_loader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text(json.dumps(self._document()), encoding="utf-8")
            target.chmod(0o600)
            link = root / "attestation.json"
            link.symlink_to(target)
            self.assertIsNone(
                FileBillingAttestationLoader(link).load(
                    "codex", ACCOUNT_FINGERPRINT
                )
            )


if __name__ == "__main__":
    unittest.main()
