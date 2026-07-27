from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import shutil
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from ordomata.authorization import canonical_digest
from ordomata.cli import main
from ordomata.comparison import COMPARISON_AUTHORIZATION_SHADOW_COVERAGE
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingSafetyAttestation,
    CapacityState,
    PaidContinuationProtection,
    PaidCreditBalance,
)
from ordomata.state import SQLiteStateStore


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class CLITests(unittest.TestCase):
    def _project(self, temporary: str) -> Path:
        root = Path(temporary)
        for name in ("tasks", "schemas", "fixtures", "profiles"):
            shutil.copytree(REPOSITORY_ROOT / name, root / name)
        return root

    def _invoke(self, *arguments: str) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_contract_and_profiles_are_exposed_as_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            status, output, errors = self._invoke(
                "--project-root", str(root), "task-validate", "--json"
            )
            self.assertEqual(status, 0, errors)
            task_report = json.loads(output)
            self.assertTrue(task_report["valid"])
            self.assertTrue(task_report["authorization_intent_present"])
            self.assertRegex(
                task_report["authorization_intent_digest"],
                r"^sha256:[0-9a-f]{64}$",
            )

            status, output, errors = self._invoke(
                "--project-root", str(root), "profiles", "--json"
            )
            self.assertEqual(status, 0, errors)
            profiles = json.loads(output)["profiles"]
            self.assertEqual({item["runner_id"] for item in profiles}, {"codex", "claude", "mock"})
            self.assertTrue(all(item["model_id"] is None for item in profiles))

    def test_demo_is_mock_only_and_writes_a_valid_local_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "demo",
                "--run-id",
                "cli-mock-demo",
                "--json",
            )
            self.assertEqual(status, 0, errors)
            report = json.loads(output)
            self.assertEqual(report["runner_id"], "mock")
            self.assertEqual(report["status"], "succeeded")
            self.assertTrue(report["evaluation"]["accepted"])
            self.assertTrue(Path(report["artifact_path"]).is_file())

    def test_auth_inspect_is_read_only_when_state_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)

            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "auth-inspect",
                "--json",
            )

            self.assertEqual(status, 0, errors)
            report = json.loads(output)
            self.assertTrue(report["clean"])
            self.assertFalse(report["database_present"])
            self.assertEqual(report["runs"], [])
            self.assertFalse((root / ".ordomata").exists())

    def test_auth_inspect_reports_all_mock_run_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            demo_status, _, demo_errors = self._invoke(
                "--project-root",
                str(root),
                "demo",
                "--run-id",
                "cli-auth-inspect",
                "--json",
            )
            self.assertEqual(demo_status, 0, demo_errors)

            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "auth-inspect",
                "--run-id",
                "cli-auth-inspect",
                "--json",
            )

            self.assertEqual(status, 0, errors)
            report = json.loads(output)
            self.assertTrue(report["clean"])
            self.assertEqual(report["inspected_event_count"], 3)
            self.assertEqual(report["coverage_gap_count"], 0)
            self.assertEqual(report["parity_mismatch_count"], 0)
            self.assertEqual(report["authority_ceiling_mismatch_count"], 0)
            self.assertEqual(report["runs"][0]["missing_scopes"], [])

    def test_auth_inspect_returns_one_for_recomputed_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            demo_status, _, demo_errors = self._invoke(
                "--project-root",
                str(root),
                "demo",
                "--run-id",
                "cli-auth-mismatch",
                "--json",
            )
            self.assertEqual(demo_status, 0, demo_errors)
            with SQLiteStateStore(root / ".ordomata" / "state.sqlite3") as state:
                original = next(
                    event.payload
                    for event in state.list_events("cli-auth-mismatch")
                    if event.event_type == "authorization_shadow_decision"
                )
                forged = json.loads(json.dumps(original))
                forged["effect"] = "deny"
                forged["decision"]["effect"] = "deny"
                forged["decision_digest"] = canonical_digest(forged["decision"])
                forged["execution_parity"] = True
                state.append_event(
                    "cli-auth-mismatch",
                    "authorization_shadow_decision",
                    forged,
                )

            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "auth-inspect",
                "--mismatches-only",
                "--json",
            )

            self.assertEqual(status, 1, errors)
            report = json.loads(output)
            self.assertFalse(report["clean"])
            self.assertEqual(report["parity_mismatch_count"], 1)
            self.assertEqual(len(report["runs"]), 1)

    def test_auth_inspect_returns_two_for_missing_run_or_malformed_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "auth-inspect",
                "--run-id",
                "missing-inspection-run",
                "--json",
            )
            self.assertEqual(status, 2)
            self.assertEqual(output, "")
            self.assertNotIn("missing-inspection-run", errors)

            state_directory = root / ".ordomata"
            state_directory.mkdir()
            (state_directory / "state.sqlite3").write_text(
                "malformed state marker",
                encoding="utf-8",
            )
            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "auth-inspect",
                "--json",
            )
            self.assertEqual(status, 2)
            self.assertEqual(output, "")
            self.assertIn("unreadable or malformed", errors)
            self.assertNotIn("malformed state marker", errors)

    def test_mock_routing_lane_cannot_select_subscription_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            status, output, errors = self._invoke(
                "--project-root", str(root), "route", "--lane", "mock", "--json"
            )
            self.assertEqual(status, 0, errors)
            report = json.loads(output)
            self.assertEqual(report["selected_profile"], "mock.deterministic.local-draft")
            selected = next(
                item for item in report["profiles"]
                if item["profile_id"] == report["selected_profile"]
            )
            self.assertEqual(selected["disposition"], "eligible")
            self.assertTrue(
                all(
                    item["disposition"] == "rejected"
                    for item in report["profiles"]
                    if item["profile_id"] != report["selected_profile"]
                )
            )

    def test_explicit_mock_profile_runs_without_a_live_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "run",
                "--profile",
                "mock.deterministic.local-draft",
                "--run-id",
                "explicit-mock-profile",
                "--json",
            )
            self.assertEqual(status, 0, errors)
            report = json.loads(output)
            self.assertEqual(report["billing_route"], "mock")
            self.assertEqual(report["status"], "succeeded")

    def test_explicit_incompatible_profile_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            profile_path = root / "profiles" / "default.json"
            document = json.loads(profile_path.read_text(encoding="utf-8"))
            profile = next(
                item
                for item in document["profiles"]
                if item["profile_id"]
                == "codex.subscription.local-draft-synthesis"
            )
            profile["max_permission_class"] = 0
            profile["role"] = "test"
            profile["task_kinds"] = ["repository_audit"]
            profile["capabilities"] = []
            profile["allowed_billing_routes"] = ["mock"]
            profile["max_context_bytes"] = 1
            profile_path.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )

            guarded_execution = AsyncMock(
                side_effect=AssertionError("ineligible profile must not execute")
            )
            diagnostic = SimpleNamespace(
                runner_id="codex",
                billing_route="subscription_included",
                billing_confidence="high",
                subscription_name="ChatGPT",
                billing_evidence=(),
                billing_warnings=(),
                environment=SimpleNamespace(risky_names=()),
                ready_now=True,
                blockers=(),
            )
            fixed_doctor = AsyncMock(
                return_value=SimpleNamespace(runners=(diagnostic,))
            )
            with (
                patch(
                    "ordomata.cli.run_chief_of_staff", new=guarded_execution
                ),
                patch(
                    "ordomata.cli.collect_doctor_report", new=fixed_doctor
                ),
            ):
                status, output, errors = self._invoke(
                    "--project-root",
                    str(root),
                    "run",
                    "--profile",
                    "codex.subscription.local-draft-synthesis",
                    "--run-id",
                    "must-not-run",
                )

            self.assertEqual(status, 2)
            self.assertEqual(output, "")
            self.assertIn("permission class exceeds profile limit", errors)
            self.assertIn("task kind is unsupported", errors)
            self.assertIn("profile role is not enabled", errors)
            self.assertIn("billing route is not allowed by the profile", errors)
            self.assertIn("missing capabilities", errors)
            self.assertIn("context exceeds profile limit", errors)
            fixed_doctor.assert_awaited_once()
            guarded_execution.assert_not_awaited()
            self.assertFalse((root / ".ordomata").exists())

    def test_durable_capacity_block_rejects_route_and_explicit_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            now = time.time()
            fingerprint = "c" * 64
            profile_id = "codex.subscription.local-draft-synthesis"
            state_path = root / ".ordomata" / "state.sqlite3"
            state_path.parent.mkdir(parents=True)
            with SQLiteStateStore(state_path) as state:
                state.append_billing_capacity_event(
                    runner_id="codex",
                    account_identity_fingerprint=fingerprint,
                    profile_id=profile_id,
                    capacity_state=CapacityState.BLOCKED_UNTIL_RESET,
                    reason_code="included_capacity_exhausted",
                    reset_at=now + 600,
                    occurred_at=now - 5,
                )

            attestation = BillingSafetyAttestation(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                ),
                observed_at=now - 10,
                expires_at=now + 600,
                confidence=AssessmentConfidence.HIGH,
                evidence=("provider_ui_auto_top_up_disabled",),
            )
            diagnostic = SimpleNamespace(
                runner_id="codex",
                billing_route="subscription_included",
                billing_confidence="high",
                subscription_name="ChatGPT",
                billing_evidence=(),
                billing_warnings=(),
                environment=SimpleNamespace(risky_names=()),
                ready_now=True,
                blockers=(),
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
                ),
                paid_credit_balance=PaidCreditBalance.ZERO,
                account_identity_fingerprint=fingerprint,
                capacity_observed_at=now - 10,
                capacity_expires_at=now + 600,
                attestation=attestation,
            )
            fixed_doctor = AsyncMock(
                return_value=SimpleNamespace(runners=(diagnostic,))
            )
            guarded_execution = AsyncMock(
                side_effect=AssertionError("durably blocked profile must not execute")
            )
            with (
                patch("ordomata.cli.collect_doctor_report", new=fixed_doctor),
                patch("ordomata.cli.run_chief_of_staff", new=guarded_execution),
            ):
                route_status, route_output, route_errors = self._invoke(
                    "--project-root",
                    str(root),
                    "route",
                    "--lane",
                    "subscription",
                    "--json",
                )
                run_status, run_output, run_errors = self._invoke(
                    "--project-root",
                    str(root),
                    "run",
                    "--profile",
                    profile_id,
                    "--run-id",
                    "durably-blocked-run",
                    "--json",
                )

            self.assertEqual(route_status, 1, route_errors)
            route = json.loads(route_output)
            codex = next(
                item for item in route["profiles"] if item["profile_id"] == profile_id
            )
            self.assertEqual(codex["disposition"], "rejected")
            self.assertIn(
                "durable_billing_state_blocks_dispatch",
                codex["runtime"]["blockers"],
            )
            self.assertEqual(run_status, 2)
            self.assertEqual(run_output, "")
            self.assertIn("durable_billing_state_blocks_dispatch", run_errors)
            guarded_execution.assert_not_awaited()
            self.assertFalse(
                (root / ".ordomata" / "runs" / "durably-blocked-run").exists()
            )

    def test_comparison_plan_is_repeated_randomized_and_no_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "compare-plan",
                "--repetitions",
                "3",
                "--seed",
                "17",
                "--json",
            )
            self.assertEqual(status, 0, errors)
            plan = json.loads(output)
            self.assertTrue(plan["no_execution_performed"])
            self.assertEqual(len(plan["trials"]), 6)
            self.assertEqual(
                {trial["snapshot_digest"] for trial in plan["trials"]},
                {plan["snapshot_digest"]},
            )
            self.assertTrue(plan["fresh_session_per_trial"])

    def test_compare_run_executes_only_named_mock_profiles_under_class_zero(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            profile_path = root / "profiles" / "default.json"
            document = json.loads(profile_path.read_text(encoding="utf-8"))
            source = next(
                profile
                for profile in document["profiles"]
                if profile["profile_id"] == "mock.deterministic.local-draft"
            )
            first = dict(source)
            first["profile_id"] = "mock.compare-a"
            second = dict(source)
            second["profile_id"] = "mock.compare-b"
            document["profiles"].extend((first, second))
            profile_path.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )

            codex_execute = AsyncMock(
                side_effect=AssertionError("mock comparison must not call Codex")
            )
            claude_execute = AsyncMock(
                side_effect=AssertionError("mock comparison must not call Claude")
            )
            with (
                patch("ordomata.runners.CodexRunner.execute", new=codex_execute),
                patch("ordomata.runners.ClaudeRunner.execute", new=claude_execute),
            ):
                status, output, errors = self._invoke(
                    "--project-root",
                    str(root),
                    "compare-run",
                    "--profiles",
                    "mock.compare-a",
                    "mock.compare-b",
                    "--comparison-id",
                    "cli-controlled-mock",
                    "--seed",
                    "17",
                    "--json",
                )

            self.assertEqual(status, 0, errors)
            report = json.loads(output)
            self.assertEqual(len(report["trials"]), 6)
            self.assertEqual(report["controls"]["permission_class"], 0)
            self.assertTrue(report["controls"]["fresh_session_per_trial"])
            self.assertFalse(report["controls"]["outputs_shared_between_trials"])
            self.assertFalse(report["controls"]["external_actions_allowed"])
            self.assertEqual(
                report["authorization_shadow_coverage"],
                COMPARISON_AUTHORIZATION_SHADOW_COVERAGE,
            )
            self.assertEqual(
                {trial["profile_id"] for trial in report["trials"]},
                {"mock.compare-a", "mock.compare-b"},
            )
            self.assertTrue(
                all(trial["status"] == "succeeded" for trial in report["trials"])
            )
            self.assertTrue(Path(report["report_path"]).is_file())
            self.assertTrue(report["automated_checks_succeeded"])
            self.assertEqual(report["human_review_status"], "pending")
            codex_execute.assert_not_awaited()
            claude_execute.assert_not_awaited()

    def test_compare_run_returns_nonzero_for_recorded_verification_failures(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            profile_path = root / "profiles" / "default.json"
            document = json.loads(profile_path.read_text(encoding="utf-8"))
            source = next(
                profile
                for profile in document["profiles"]
                if profile["profile_id"] == "mock.deterministic.local-draft"
            )
            for profile_id in ("mock.failure-a", "mock.failure-b"):
                profile = dict(source)
                profile["profile_id"] = profile_id
                document["profiles"].append(profile)
            profile_path.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )
            with patch(
                "ordomata.cli.load_mock_chief_of_staff_output",
                return_value={},
            ):
                status, output, errors = self._invoke(
                    "--project-root",
                    str(root),
                    "compare-run",
                    "--profiles",
                    "mock.failure-a",
                    "mock.failure-b",
                    "--comparison-id",
                    "cli-recorded-failures",
                    "--json",
                )

            self.assertEqual(status, 1, errors)
            report = json.loads(output)
            self.assertFalse(report["automated_checks_succeeded"])
            self.assertTrue(report["execution_complete"])
            self.assertTrue(
                all(
                    trial["failure_type"] == "verification_failed"
                    for trial in report["trials"]
                )
            )
            self.assertTrue(Path(report["report_path"]).is_file())

    def test_compare_run_stops_before_records_or_execution_when_doctor_blocks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            blocked_doctor = AsyncMock(
                return_value=SimpleNamespace(runners=())
            )
            guarded_comparison = AsyncMock(
                side_effect=AssertionError(
                    "ineligible comparison must not reach execution"
                )
            )
            codex_execute = AsyncMock(
                side_effect=AssertionError("ineligible Codex must not execute")
            )
            claude_execute = AsyncMock(
                side_effect=AssertionError("ineligible Claude must not execute")
            )
            with (
                patch(
                    "ordomata.cli.collect_doctor_report", new=blocked_doctor
                ),
                patch(
                    "ordomata.cli.run_controlled_comparison",
                    new=guarded_comparison,
                ),
                patch("ordomata.runners.CodexRunner.execute", new=codex_execute),
                patch("ordomata.runners.ClaudeRunner.execute", new=claude_execute),
            ):
                status, output, errors = self._invoke(
                    "--project-root",
                    str(root),
                    "compare-run",
                    "--comparison-id",
                    "doctor-blocked",
                    "--json",
                )

            self.assertEqual(status, 2)
            self.assertEqual(output, "")
            self.assertIn("runner was not diagnosed", errors)
            blocked_doctor.assert_awaited_once()
            guarded_comparison.assert_not_awaited()
            codex_execute.assert_not_awaited()
            claude_execute.assert_not_awaited()
            self.assertFalse((root / ".ordomata").exists())

    def test_schedule_inspection_never_claims_or_installs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "schedule-inspect",
                "--interval-seconds",
                "60",
                "--now",
                "100",
                "--json",
            )
            self.assertEqual(status, 0, errors)
            report = json.loads(output)
            self.assertEqual(report["reason"], "due")
            self.assertFalse(report["mutated_state"])
            self.assertFalse(report["installed_os_schedule"])


if __name__ == "__main__":
    unittest.main()
