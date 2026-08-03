from contextlib import closing, redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from ordomata.cli import main
from ordomata.supervisor import SQLiteSupervisorStore


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class SupervisorCLITests(unittest.TestCase):
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

    def _invoke_json(self, root: Path, *arguments: str) -> dict[str, object]:
        status, output, errors = self._invoke(
            "--project-root", str(root), *arguments, "--json"
        )
        self.assertEqual(status, 0, errors)
        self.assertEqual(errors, "")
        return json.loads(output)

    def test_status_and_audit_are_read_only_when_state_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)

            status = self._invoke_json(root, "supervisor", "status")
            audit = self._invoke_json(
                root, "supervisor", "audit", "--now", "1000"
            )

            self.assertEqual(
                status,
                {
                    "control_revision": 0,
                    "database_present": False,
                    "dispatch_blocker": "runtime_abac_enforcement_not_implemented",
                    "dispatch_blockers": [
                        "runtime_abac_enforcement_not_implemented",
                        "repository_worker_containment_not_proven",
                    ],
                    "dispatch_enabled": False,
                    "flow_counts": {},
                    "foreground_lease_active": False,
                    "mode": "stopped",
                    "pending_completion_count": 0,
                    "schema_present": False,
                },
            )
            self.assertFalse(audit["database_present"])
            self.assertEqual(audit["finding_count"], 0)
            self.assertEqual(audit["actionable_count"], 0)
            self.assertEqual(audit["findings"], [])
            self.assertEqual(
                audit["authorization"],
                {
                    "attempt_claim_enforcement_record_count": 0,
                    "clean": True,
                    "control_enforcement_record_count": 0,
                    "database_present": False,
                    "expected_attempt_claim_enforcement_record_count": 0,
                    "expected_control_enforcement_record_count": 0,
                    "expected_flow_admission_enforcement_record_count": 0,
                    "expected_observation_count": 0,
                    "finding_count": 0,
                    "flow_admission_enforcement_record_count": 0,
                    "findings": [],
                    "observation_count": 0,
                    "schema_present": False,
                },
            )
            self.assertFalse((root / ".ordomata").exists())

    def test_status_reads_a_sole_legacy_state_root_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            legacy_state = root / ".agentops" / "state.sqlite3"
            legacy_state.parent.mkdir()
            with SQLiteSupervisorStore(legacy_state):
                pass

            status = self._invoke_json(root, "supervisor", "status")

            self.assertTrue(status["database_present"])
            self.assertTrue(status["schema_present"])
            self.assertFalse((root / ".ordomata").exists())

    def test_dual_state_roots_fail_before_status_can_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            (root / ".ordomata").mkdir()
            (root / ".agentops").mkdir()

            status, output, errors = self._invoke(
                "--project-root", str(root), "supervisor", "status", "--json"
            )

            self.assertEqual(status, 2)
            self.assertEqual(output, "")
            self.assertIn("both .ordomata", errors)
            self.assertFalse((root / ".ordomata" / "state.sqlite3").exists())
            self.assertFalse((root / ".agentops" / "state.sqlite3").exists())

    def test_enqueue_replay_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            arguments = (
                "supervisor",
                "enqueue",
                "--admission-key",
                "cli-idempotency-key",
            )

            first = self._invoke_json(root, *arguments)
            second = self._invoke_json(root, *arguments)

            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertEqual(second["flow_id"], first["flow_id"])
            self.assertEqual(second["request_digest"], first["request_digest"])
            self.assertEqual(second["state"], "queued")
            self.assertEqual(second["revision"], 1)
            self.assertFalse(second["dispatch_enabled"])

            status = self._invoke_json(root, "supervisor", "status")
            self.assertEqual(status["flow_counts"], {"queued": 1})
            audit = self._invoke_json(root, "supervisor", "audit", "--now", "1000")
            self.assertTrue(audit["authorization"]["clean"])
            self.assertEqual(audit["authorization"]["observation_count"], 1)
            self.assertEqual(
                audit["authorization"]["expected_observation_count"], 1
            )

    def test_audit_returns_nonzero_for_authorization_integrity_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            self._invoke_json(
                root,
                "supervisor",
                "enqueue",
                "--admission-key",
                "cli-audit-integrity-key",
            )
            database = root / ".ordomata" / "state.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "DROP TRIGGER supervisor_authorization_observations_no_update"
                )
                connection.execute(
                    """
                    UPDATE supervisor_authorization_observations
                    SET decision_digest = ?
                    """,
                    ("sha256:" + "0" * 64,),
                )
                connection.commit()

            status, output, errors = self._invoke(
                "--project-root",
                str(root),
                "supervisor",
                "audit",
                "--now",
                "1000",
                "--json",
            )
            self.assertEqual(status, 1)
            self.assertEqual(errors, "")
            payload = json.loads(output)
            self.assertEqual(payload["finding_count"], 0)
            self.assertFalse(payload["authorization"]["clean"])
            codes = {
                finding["code"]
                for finding in payload["authorization"]["findings"]
            }
            self.assertIn("authorization_schema_mismatch", codes)
            self.assertIn("decision_digest_mismatch", codes)

    def test_control_commands_persist_optimistic_mode_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)

            expected = (
                ("start", "running", 1),
                ("pause", "paused", 2),
                ("resume", "running", 3),
                ("stop", "stop_requested", 4),
            )
            for command, mode, revision in expected:
                with self.subTest(command=command):
                    result = self._invoke_json(
                        root,
                        "supervisor",
                        command,
                        "--expected-revision",
                        str(revision - 1),
                    )
                    self.assertEqual(result["mode"], mode)
                    self.assertEqual(result["control_revision"], revision)
                    self.assertFalse(result["dispatch_enabled"])
                    self.assertFalse(result["foreground_process_started"])

                    status = self._invoke_json(root, "supervisor", "status")
                    self.assertEqual(status["mode"], mode)
                    self.assertEqual(status["control_revision"], revision)
                    self.assertFalse(status["dispatch_enabled"])

            audit = self._invoke_json(root, "supervisor", "audit", "--now", "1000")
            self.assertTrue(audit["authorization"]["clean"])
            self.assertEqual(audit["authorization"]["observation_count"], 4)
            self.assertEqual(
                audit["authorization"]["expected_observation_count"], 4
            )

    def test_cancellation_is_sticky_across_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            enqueue_arguments = (
                "supervisor",
                "enqueue",
                "--admission-key",
                "cli-cancel-key",
                "--flow-id",
                "cli-cancel-flow",
                "--available-at",
                "1000",
            )
            admitted = self._invoke_json(root, *enqueue_arguments)
            self.assertTrue(admitted["created"])

            cancelled = self._invoke_json(
                root,
                "supervisor",
                "cancel",
                "cli-cancel-flow",
                "--actor",
                "test-operator",
                "--reason",
                "operator_cancelled",
            )
            repeated = self._invoke_json(
                root,
                "supervisor",
                "cancel",
                "cli-cancel-flow",
                "--actor",
                "test-operator",
                "--reason",
                "operator_cancelled",
            )

            self.assertEqual(cancelled["state"], "cancelled")
            self.assertTrue(cancelled["cancellation_requested"])
            self.assertEqual(cancelled["revision"], 2)
            self.assertEqual(repeated, cancelled)

            replay = self._invoke_json(root, *enqueue_arguments)
            self.assertFalse(replay["created"])
            self.assertEqual(replay["state"], "cancelled")
            self.assertEqual(replay["revision"], 2)

            status = self._invoke_json(root, "supervisor", "status")
            self.assertEqual(status["flow_counts"], {"cancelled": 1})
            self.assertEqual(status["pending_completion_count"], 1)
            audit_status, audit_output, audit_errors = self._invoke(
                "--project-root",
                str(root),
                "supervisor",
                "audit",
                "--now",
                "1000",
                "--json",
            )
            self.assertEqual(audit_status, 1)
            self.assertEqual(audit_errors, "")
            audit = json.loads(audit_output)
            self.assertFalse(audit["authorization"]["clean"])
            self.assertEqual(audit["authorization"]["observation_count"], 2)
            self.assertEqual(
                audit["authorization"]["expected_observation_count"], 2
            )
            self.assertIn(
                "legacy_authorization_parity_mismatch",
                {
                    finding["code"]
                    for finding in audit["authorization"]["findings"]
                },
            )

    def test_reconcile_requires_and_applies_exact_preview_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            base_time = time.time() + 100
            self._invoke_json(
                root,
                "supervisor",
                "enqueue",
                "--admission-key",
                "cli-reconcile-key",
                "--flow-id",
                "cli-reconcile-flow",
                "--available-at",
                str(base_time - 1),
            )
            self._invoke_json(root, "supervisor", "start")

            state_path = root / ".ordomata" / "state.sqlite3"
            owner = "test/0000000000000001"
            with SQLiteSupervisorStore(state_path) as store:
                self.assertTrue(
                    store.acquire_foreground(
                        owner, ttl_seconds=20, now=base_time
                    )
                )
                control = store.current_control()
                claim = store.try_claim_next(
                    instance_owner=owner,
                    expected_control_revision=control.revision,
                    ttl_seconds=5,
                    now=base_time,
                )
                self.assertIsNotNone(claim)
                store.release_foreground(owner)

            inspection_time = base_time + 6
            preview = self._invoke_json(
                root,
                "supervisor",
                "reconcile",
                "--now",
                str(inspection_time),
            )
            self.assertFalse(preview["applied"])
            self.assertEqual(preview["finding_count"], 1)
            self.assertEqual(preview["actionable_count"], 1)
            self.assertEqual(
                preview["findings"][0]["action"], "mark_lost_pre_dispatch"
            )

            missing_status, missing_output, missing_errors = self._invoke(
                "--project-root",
                str(root),
                "supervisor",
                "reconcile",
                "--now",
                str(inspection_time),
                "--apply",
                "--json",
            )
            self.assertEqual(missing_status, 2)
            self.assertEqual(missing_output, "")
            self.assertIn("--apply requires the plan digest", missing_errors)

            applied = self._invoke_json(
                root,
                "supervisor",
                "reconcile",
                "--now",
                str(inspection_time),
                "--apply",
                "--plan-digest",
                str(preview["plan_digest"]),
            )
            self.assertTrue(applied["applied"])
            self.assertEqual(applied["applied_count"], 1)
            self.assertEqual(applied["plan_digest"], preview["plan_digest"])
            self.assertEqual(
                applied["actions"][0]["action"], "mark_lost_pre_dispatch"
            )

            after = self._invoke_json(
                root,
                "supervisor",
                "reconcile",
                "--now",
                str(inspection_time),
            )
            self.assertEqual(after["finding_count"], 1)
            self.assertEqual(after["actionable_count"], 0)
            self.assertEqual(
                after["findings"][0]["kind"], "undelivered_completion"
            )
            status = self._invoke_json(root, "supervisor", "status")
            self.assertEqual(status["flow_counts"], {"lost": 1})
            self.assertEqual(status["pending_completion_count"], 1)

    def test_supervise_once_never_dispatches_a_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            self._invoke_json(
                root,
                "supervisor",
                "enqueue",
                "--admission-key",
                "cli-supervise-key",
                "--flow-id",
                "cli-supervise-flow",
                "--available-at",
                "0",
            )
            self._invoke_json(root, "supervisor", "start")

            mock_execute = AsyncMock(
                side_effect=AssertionError("mock runner must not dispatch")
            )
            codex_execute = AsyncMock(
                side_effect=AssertionError("Codex must not dispatch")
            )
            claude_execute = AsyncMock(
                side_effect=AssertionError("Claude must not dispatch")
            )
            with (
                patch("ordomata.runners.MockRunner.execute", new=mock_execute),
                patch("ordomata.runners.CodexRunner.execute", new=codex_execute),
                patch("ordomata.runners.ClaudeRunner.execute", new=claude_execute),
            ):
                report = self._invoke_json(
                    root,
                    "supervise",
                    "--once",
                    "--poll-seconds",
                    "0.01",
                    "--lease-ttl-seconds",
                    "1",
                )

            self.assertEqual(report["ticks"], 1)
            self.assertEqual(report["mode"], "running")
            self.assertFalse(report["dispatch_enabled"])
            self.assertFalse(report["claimed"])
            self.assertEqual(
                report["dispatch_blocker"],
                "runtime_abac_enforcement_not_implemented",
            )
            self.assertEqual(
                report["dispatch_blockers"],
                [
                    "runtime_abac_enforcement_not_implemented",
                    "repository_worker_containment_not_proven",
                ],
            )
            self.assertTrue(report["foreground_only"])
            self.assertFalse(report["installed_os_schedule"])
            self.assertFalse(report["live_model_execution"])
            mock_execute.assert_not_awaited()
            codex_execute.assert_not_awaited()
            claude_execute.assert_not_awaited()

            status = self._invoke_json(root, "supervisor", "status")
            self.assertFalse(status["foreground_lease_active"])
            self.assertEqual(status["flow_counts"], {"queued": 1})


if __name__ == "__main__":
    unittest.main()
