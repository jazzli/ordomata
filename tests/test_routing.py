import unittest
from dataclasses import replace
from pathlib import Path
import tempfile
import time

from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    PaidContinuationProtection,
    PaidCreditBalance,
    PermissionClass,
)
from ordomata.routing import (
    ExecutionProfile,
    ProfileRouter,
    RuntimeProfileState,
    SubscriptionEfficiencyObservation,
    TaskRoutingFeatures,
    load_execution_profiles,
    runner_overrides_for_profile,
)
from ordomata.errors import ConfigurationError, ValidationError


def candidate(
    profile_id: str,
    *,
    route: BillingRoute = BillingRoute.SUBSCRIPTION_INCLUDED,
    success: float = 0.8,
    latency: float = 30.0,
    available: bool = True,
    efficiency_pool: str | None = None,
    efficiency_unit: str | None = None,
    efficiency: float | None = None,
) -> RuntimeProfileState:
    runner_id = profile_id.split("-")[0]
    now = time.time()
    fingerprint = "d" * 64
    protection = (
        PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
        if runner_id == "codex"
        else PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED
    )
    attestation_evidence = (
        ("operator_attestation:provider_ui_auto_top_up_disabled",)
        if runner_id == "codex"
        else (
            (
                "operator_attestation:provider_ui_extra_usage_disabled",
                "operator_attestation:provider_ui_included_capacity_available",
            )
            if runner_id == "claude"
            else (
                "operator_attestation:provider_enforced_paid_continuation_disabled",
            )
        )
    )
    attestation = (
        BillingSafetyAttestation(
            runner_id=runner_id,
            account_identity_fingerprint=fingerprint,
            billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
            capacity_state=CapacityState.AVAILABLE,
            paid_continuation_protection=protection,
            observed_at=now - 1,
            expires_at=now + 60,
            confidence=AssessmentConfidence.HIGH,
            evidence=attestation_evidence,
        )
        if route is BillingRoute.SUBSCRIPTION_INCLUDED
        else None
    )
    return RuntimeProfileState(
        profile=ExecutionProfile(
            profile_id=profile_id,
            version="1",
            runner_id=runner_id,
            model_id=None,
            role="implementer",
            capabilities=frozenset({"structured_output", "read"}),
            task_kinds=frozenset({"chief_of_staff"}),
            allowed_billing_routes=frozenset({BillingRoute.SUBSCRIPTION_INCLUDED}),
            max_permission_class=PermissionClass.LOCAL_DRAFT,
        ),
        billing_assessment=BillingRouteAssessment(
            runner_id=runner_id,
            route=route,
            confidence=AssessmentConfidence.HIGH,
            capacity_state=(
                CapacityState.AVAILABLE
                if route is BillingRoute.SUBSCRIPTION_INCLUDED
                else CapacityState.UNKNOWN
            ),
            paid_continuation_protection=(
                protection
                if route is BillingRoute.SUBSCRIPTION_INCLUDED
                else PaidContinuationProtection.UNKNOWN
            ),
            paid_credit_balance=(
                PaidCreditBalance.ZERO
                if route is BillingRoute.SUBSCRIPTION_INCLUDED
                and runner_id == "codex"
                else PaidCreditBalance.NOT_APPLICABLE
            ),
            account_identity_fingerprint=(
                fingerprint if route is BillingRoute.SUBSCRIPTION_INCLUDED else None
            ),
            capacity_observed_at=(
                now - 1 if route is BillingRoute.SUBSCRIPTION_INCLUDED else None
            ),
            capacity_expires_at=(
                now + 60 if route is BillingRoute.SUBSCRIPTION_INCLUDED else None
            ),
            attestation=attestation,
        ),
        available=available,
        verified_success_rate=success,
        accepted_result_rate=success,
        median_latency_seconds=latency,
        evidence_count=20,
        subscription_efficiency=(
            None
            if efficiency is None
            else SubscriptionEfficiencyObservation(
                included_capacity_pool=efficiency_pool or "",
                included_capacity_unit=efficiency_unit or "",
                accepted_results_per_included_capacity_unit=efficiency,
            )
        ),
    )


class RoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = TaskRoutingFeatures(
            task_kind="chief_of_staff",
            permission_class=PermissionClass.READ_ONLY,
            required_capabilities=frozenset({"structured_output"}),
        )

    def test_prohibited_billing_route_is_hard_rejected(self) -> None:
        decision = ProfileRouter().route(
            self.task,
            [
                candidate("api-fast", route=BillingRoute.SEPARATELY_BILLED_API),
                candidate("codex-safe", success=0.7),
            ],
        )
        self.assertEqual(decision.selected.profile.profile_id, "codex-safe")
        self.assertEqual(decision.rejected[0].profile_id, "api-fast")

    def test_quality_precedes_latency(self) -> None:
        decision = ProfileRouter().route(
            self.task,
            [
                candidate("fast", success=0.7, latency=1.0),
                candidate("careful", success=0.9, latency=120.0),
            ],
        )
        self.assertEqual(decision.selected.profile.profile_id, "careful")
        self.assertEqual(len(ProfileRouter.score_dimensions()), 6)

    def test_correctness_precedes_efficiency_and_latency(self) -> None:
        decision = ProfileRouter().route(
            self.task,
            [
                candidate(
                    "codex-fast",
                    success=0.8,
                    latency=1.0,
                    efficiency_pool="codex-five-hour-window",
                    efficiency_unit="window_percent",
                    efficiency=100.0,
                ),
                candidate(
                    "codex-correct",
                    success=0.9,
                    latency=120.0,
                    efficiency_pool="codex-five-hour-window",
                    efficiency_unit="window_percent",
                    efficiency=0.1,
                ),
            ],
        )
        self.assertEqual(decision.selected.profile.profile_id, "codex-correct")

    def test_risk_fit_precedes_efficiency_and_latency(self) -> None:
        exact_permission = candidate(
            "codex-exact",
            latency=120.0,
            efficiency_pool="codex-five-hour-window",
            efficiency_unit="window_percent",
            efficiency=0.1,
        )
        exact_permission = replace(
            exact_permission,
            profile=replace(
                exact_permission.profile,
                max_permission_class=PermissionClass.READ_ONLY,
            ),
        )
        broad_permission = candidate(
            "codex-broad",
            latency=1.0,
            efficiency_pool="codex-five-hour-window",
            efficiency_unit="window_percent",
            efficiency=100.0,
        )

        decision = ProfileRouter().route(
            self.task, [broad_permission, exact_permission]
        )

        self.assertEqual(decision.selected.profile.profile_id, "codex-exact")

    def test_comparable_subscription_efficiency_precedes_latency(self) -> None:
        decision = ProfileRouter().route(
            self.task,
            [
                candidate(
                    "codex-fast",
                    latency=1.0,
                    efficiency_pool="codex-five-hour-window",
                    efficiency_unit="window_percent",
                    efficiency=0.5,
                ),
                candidate(
                    "codex-efficient",
                    latency=120.0,
                    efficiency_pool="codex-five-hour-window",
                    efficiency_unit="window_percent",
                    efficiency=0.9,
                ),
            ],
        )
        self.assertEqual(decision.selected.profile.profile_id, "codex-efficient")

    def test_incompatible_efficiency_pools_skip_to_latency(self) -> None:
        decision = ProfileRouter().route(
            self.task,
            [
                candidate(
                    "codex-slow",
                    latency=120.0,
                    efficiency_pool="primary-window",
                    efficiency_unit="percent",
                    efficiency=100.0,
                ),
                candidate(
                    "claude-fast",
                    latency=1.0,
                    efficiency_pool="primary-window",
                    efficiency_unit="percent",
                    efficiency=0.01,
                ),
            ],
        )
        self.assertEqual(decision.selected.profile.profile_id, "claude-fast")

    def test_unknown_efficiency_skips_to_latency_without_becoming_zero(self) -> None:
        decision = ProfileRouter().route(
            self.task,
            [
                candidate(
                    "codex-observed",
                    latency=120.0,
                    efficiency_pool="codex-five-hour-window",
                    efficiency_unit="window_percent",
                    efficiency=100.0,
                ),
                candidate("claude-unavailable", latency=1.0),
            ],
        )
        self.assertEqual(
            decision.selected.profile.profile_id, "claude-unavailable"
        )
        unavailable = next(
            item
            for item in decision.ranked
            if item.state.profile.profile_id == "claude-unavailable"
        )
        self.assertIsNone(unavailable.score_vector[-2])

    def test_exact_tie_uses_stable_profile_id_independent_of_input_order(self) -> None:
        first = candidate(
            "codex-a",
            efficiency_pool="codex-five-hour-window",
            efficiency_unit="window_percent",
            efficiency=0.9,
        )
        second = candidate(
            "codex-z",
            efficiency_pool="codex-five-hour-window",
            efficiency_unit="window_percent",
            efficiency=0.9,
        )
        router = ProfileRouter()

        forward = router.route(self.task, [first, second])
        reverse = router.route(self.task, [second, first])

        self.assertEqual(forward.selected.profile.profile_id, "codex-a")
        self.assertEqual(reverse.selected.profile.profile_id, "codex-a")
        self.assertEqual(
            [item.state.profile.profile_id for item in forward.ranked],
            [item.state.profile.profile_id for item in reverse.ranked],
        )

    def test_unknown_routes_fail_closed(self) -> None:
        decision = ProfileRouter().route(
            self.task, [candidate("unknown", route=BillingRoute.UNKNOWN)]
        )
        self.assertTrue(decision.blocked)

    def test_route_provenance_must_match_profile(self) -> None:
        state = candidate("codex-safe")
        spoofed = RuntimeProfileState(
            profile=state.profile,
            billing_assessment=BillingRouteAssessment(
                runner_id="mock",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
            ),
            available=True,
        )
        self.assertTrue(ProfileRouter().route(self.task, [spoofed]).blocked)

    def test_low_confidence_route_fails_closed(self) -> None:
        state = candidate("codex-safe")
        uncertain = RuntimeProfileState(
            profile=state.profile,
            billing_assessment=BillingRouteAssessment(
                runner_id="codex",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.LOW,
            ),
            available=True,
        )
        self.assertTrue(ProfileRouter().route(self.task, [uncertain]).blocked)

    def test_subscription_auth_without_capacity_and_protection_is_ineligible(self) -> None:
        state = candidate("codex-safe")
        auth_only = replace(
            state,
            billing_assessment=BillingRouteAssessment(
                runner_id="codex",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
            ),
        )
        decision = ProfileRouter().route(self.task, [auth_only])
        self.assertTrue(decision.blocked)
        self.assertIn("prohibited", decision.rejected[0].reasons[0])

    def test_default_profiles_are_loadable_and_model_names_are_not_hardcoded(self) -> None:
        profiles = load_execution_profiles(Path("profiles/default.json"))
        self.assertEqual(len(profiles), 3)
        self.assertTrue(all(profile.model_id is None for profile in profiles))
        translated = {
            profile.runner_id: runner_overrides_for_profile(profile)
            for profile in profiles
        }
        self.assertEqual(translated["codex"], {"reasoning_effort": "high"})
        self.assertEqual(
            translated["claude"], {"effort": "high", "max_turns": 3}
        )
        self.assertEqual(translated["mock"], {})

    def test_routing_lane_prevents_mock_subscription_fallback(self) -> None:
        subscription_task = TaskRoutingFeatures(
            task_kind="chief_of_staff",
            permission_class=PermissionClass.READ_ONLY,
            required_capabilities=frozenset({"structured_output"}),
            allowed_roles=frozenset({"synthesis"}),
            allowed_billing_routes=frozenset({BillingRoute.SUBSCRIPTION_INCLUDED}),
        )
        mock = candidate("mock-test", route=BillingRoute.MOCK)
        decision = ProfileRouter().route(subscription_task, [mock])
        self.assertTrue(decision.blocked)

    def test_profile_loader_rejects_embedded_api_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                '{"profiles":[{"profile_id":"bad","version":"1",'
                '"runner_id":"codex","role":"worker",'
                '"allowed_billing_routes":["subscription_included"],'
                '"settings":{"api_key":"value"}}]}',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_execution_profiles(path)

    def test_profile_priors_and_limits_must_be_finite_and_in_range(self) -> None:
        profile = candidate("codex-safe").profile
        for changes in (
            {"quality_prior": float("nan")},
            {"quality_prior": 1.01},
            {"latency_prior_seconds": -1},
            {"max_context_bytes": 0},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValidationError):
                    replace(profile, **changes)

    def test_runtime_observations_must_be_finite_and_in_range(self) -> None:
        state = candidate("codex-safe")
        for changes in (
            {"verified_success_rate": -0.01},
            {"accepted_result_rate": 1.01},
            {"median_latency_seconds": float("inf")},
            {"recent_failure_rate": float("nan")},
            {"evidence_count": -1},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValidationError):
                    replace(state, **changes)

    def test_subscription_efficiency_requires_explicit_compatible_units(self) -> None:
        for changes in (
            {"included_capacity_pool": ""},
            {"included_capacity_unit": ""},
            {"accepted_results_per_included_capacity_unit": float("nan")},
            {"accepted_results_per_included_capacity_unit": -0.01},
        ):
            with self.subTest(changes=changes):
                values = {
                    "included_capacity_pool": "codex-five-hour-window",
                    "included_capacity_unit": "window_percent",
                    "accepted_results_per_included_capacity_unit": 0.9,
                    **changes,
                }
                with self.assertRaises(ValidationError):
                    SubscriptionEfficiencyObservation(**values)

    def test_profile_loader_rejects_non_finite_numeric_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                '{"profiles":[{"profile_id":"bad","version":"1",'
                '"runner_id":"codex","role":"worker",'
                '"allowed_billing_routes":["subscription_included"],'
                '"quality_prior":NaN}]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "quality_prior"):
                load_execution_profiles(path)


if __name__ == "__main__":
    unittest.main()
