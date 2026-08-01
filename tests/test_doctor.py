from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from ordomata.billing import (
    LEGACY_LIVE_RUN_ENVIRONMENT_NAME,
    LIVE_RUN_ENVIRONMENT_NAME,
)
from ordomata.doctor import collect_doctor_report
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    EnvironmentValidation,
    RunRequest,
    RunnerCapabilities,
)
from ordomata.runners import ClaudeRunner, CodexRunner, MockRunner
from ordomata.runners.base import ProbeResult


class FakeProbe:
    """Fixed local probe; it cannot start a subprocess or contact a service."""

    def __init__(self, responses: Mapping[tuple[str, ...], ProbeResult]) -> None:
        self.responses = dict(responses)
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    async def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path | None = None,
        timeout_seconds: float = 10.0,
    ) -> ProbeResult:
        del cwd, timeout_seconds
        key = tuple(command)
        self.calls.append((key, dict(environment)))
        return self.responses[key]


def result(command: tuple[str, ...], stdout: str) -> ProbeResult:
    return ProbeResult(
        command=command,
        exit_code=0,
        stdout=stdout,
        containment_cleanup_verified=True,
    )


def verified_runners(environment: Mapping[str, str]):
    codex_binary = "/fixtures/codex"
    claude_binary = "/fixtures/claude"
    codex_probe = FakeProbe(
        {
            (codex_binary, "--version"): result(
                (codex_binary, "--version"), "codex 9.1\n"
            ),
            (codex_binary, "exec", "--help"): result(
                (codex_binary, "exec", "--help"),
                "Usage: codex exec --json --output-schema --sandbox "
                "read-only workspace-write --ask-for-approval resume usage "
                "--ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check",
            ),
            (codex_binary, "--help"): result(
                (codex_binary, "--help"),
                "Usage: codex --ask-for-approval --sandbox",
            ),
            (codex_binary, "login", "status"): result(
                (codex_binary, "login", "status"), "Logged in using ChatGPT\n"
            ),
        }
    )
    claude_probe = FakeProbe(
        {
            (claude_binary, "--version"): result(
                (claude_binary, "--version"), "claude 8.2\n"
            ),
            (claude_binary, "--help"): result(
                (claude_binary, "--help"),
                "Usage: claude --print --output-format stream-json "
                "--permission-mode --json-schema plan acceptEdits --resume usage "
                "--safe-mode --no-session-persistence --strict-mcp-config --tools",
            ),
            (claude_binary, "auth", "status", "--json"): result(
                (claude_binary, "auth", "status", "--json"),
                json.dumps(
                    {
                        "loggedIn": True,
                        "authMethod": "claude.ai",
                        "apiProvider": "firstParty",
                    }
                ),
            ),
        }
    )
    return (
        (
            CodexRunner(
                probe=codex_probe,
                executable_resolver=lambda _: codex_binary,
                parent_environment=environment,
            ),
            ClaudeRunner(
                probe=claude_probe,
                executable_resolver=lambda _: claude_binary,
                parent_environment=environment,
            ),
            MockRunner(),
        ),
        (codex_probe, claude_probe),
    )


class DoctorTests(unittest.IsolatedAsyncioTestCase):
    async def test_report_covers_runners_paths_sqlite_and_never_exposes_values(
        self,
    ) -> None:
        environment = {
            "PATH": "/fixtures/safe-path-value",
            "HOME": "/fixtures/safe-home-value",
            "OPENAI_API_KEY": "openai-secret-never-report",
            "ANTHROPIC_API_KEY": "anthropic-secret-never-report",
            "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
            "UNRELATED": "unrelated-value-never-report",
        }
        runners, probes = verified_runners(environment)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run_root = workspace / "not-created-by-doctor" / "runs"
            report = await collect_doctor_report(
                runners,
                environment=environment,
                workspace=workspace,
                run_root=run_root,
            )

            self.assertTrue(report.sqlite.ready)
            self.assertEqual(report.schema_version, 2)
            self.assertTrue(report.sqlite.fts5_available)
            self.assertTrue(report.workspace.ready)
            self.assertTrue(report.run_root.ready)
            self.assertFalse(run_root.exists(), "doctor must not mutate the run root")
            self.assertTrue(report.live_gate.enabled)
            self.assertEqual(report.live_gate.state, "enabled_exactly")
            self.assertEqual(
                [diagnostic.runner_id for diagnostic in report.runners],
                ["codex", "claude", "mock"],
            )
            self.assertFalse(report.runners[0].ready_now)
            self.assertFalse(report.runners[1].ready_now)
            self.assertTrue(report.runners[2].ready_now)
            self.assertFalse(report.subscription_runner_ready_now)

            codex = report.runners[0]
            claude = report.runners[1]
            self.assertEqual(codex.subscription_name, "ChatGPT")
            self.assertEqual(
                codex.billing_route, BillingRoute.SUBSCRIPTION_INCLUDED.value
            )
            self.assertEqual(codex.capacity_evidence_status, "missing")
            self.assertEqual(codex.attestation_status, "missing")
            self.assertIn("billing_route_not_allowed", codex.blockers)
            self.assertTrue(codex.subscription_auth_verified)
            self.assertFalse(codex.subscription_verified)
            self.assertIn("paid_continuation_attestation_missing", codex.blockers)
            self.assertIn("OPENAI_API_KEY", codex.environment.risky_names)
            self.assertIn("ANTHROPIC_API_KEY", claude.environment.risky_names)
            self.assertIn("PATH", codex.environment.sanitized_names)
            self.assertNotIn("OPENAI_API_KEY", codex.environment.sanitized_names)

            serialized = json.dumps(report.to_mapping(), sort_keys=True)
            for value in environment.values():
                if value != "1":
                    self.assertNotIn(value, serialized)
                    self.assertNotIn(value, repr(report))
            for probe in probes:
                for _, child_environment in probe.calls:
                    self.assertNotIn("OPENAI_API_KEY", child_environment)
                    self.assertNotIn("ANTHROPIC_API_KEY", child_environment)

    async def test_live_gate_accepts_only_exact_one_and_blocks_subscription(self) -> None:
        environment = {
            "PATH": "/bin",
            "HOME": "/safe/home",
            "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "true",
        }
        runners, _ = verified_runners(environment)
        with tempfile.TemporaryDirectory() as temporary:
            report = await collect_doctor_report(
                runners[:1],
                environment=environment,
                workspace=temporary,
                run_root=Path(temporary) / "runs",
            )

        self.assertFalse(report.live_gate.enabled)
        self.assertEqual(report.live_gate.state, "set_but_not_exactly_enabled")
        self.assertFalse(report.runners[0].ready_now)
        self.assertIn(
            "live_subscription_gate_disabled", report.runners[0].blockers
        )

    async def test_live_gate_reports_legacy_alias_and_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            legacy = await collect_doctor_report(
                (MockRunner(),),
                environment={LEGACY_LIVE_RUN_ENVIRONMENT_NAME: "1"},
                workspace=temporary,
                run_root=Path(temporary) / "runs",
            )
            conflict = await collect_doctor_report(
                (MockRunner(),),
                environment={
                    LIVE_RUN_ENVIRONMENT_NAME: "0",
                    LEGACY_LIVE_RUN_ENVIRONMENT_NAME: "1",
                },
                workspace=temporary,
                run_root=Path(temporary) / "runs",
            )

        self.assertTrue(legacy.live_gate.enabled)
        self.assertEqual(legacy.live_gate.state, "enabled_via_legacy_alias")
        self.assertFalse(conflict.live_gate.enabled)
        self.assertEqual(conflict.live_gate.state, "conflicting_values")

    async def test_api_route_fails_closed_even_when_live_gate_is_enabled(self) -> None:
        executable = "/fixtures/codex"
        probe = FakeProbe(
            {
                (executable, "--version"): result(
                    (executable, "--version"), "codex 9.1"
                ),
                (executable, "exec", "--help"): result(
                    (executable, "exec", "--help"),
                    "Usage codex exec --json --output-schema --sandbox usage "
                    "--ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check",
                ),
                (executable, "--help"): result(
                    (executable, "--help"),
                    "Usage: codex --ask-for-approval --sandbox",
                ),
                (executable, "login", "status"): result(
                    (executable, "login", "status"), "Logged in with API key"
                ),
            }
        )
        environment = {
            "PATH": "/bin",
            "HOME": "/safe/home",
            "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
        }
        runner = CodexRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment=environment,
        )
        with tempfile.TemporaryDirectory() as temporary:
            report = await collect_doctor_report(
                (runner,),
                environment=environment,
                workspace=temporary,
                run_root=Path(temporary) / "runs",
            )

        diagnostic = report.runners[0]
        self.assertEqual(
            diagnostic.billing_route, BillingRoute.SEPARATELY_BILLED_API.value
        )
        self.assertFalse(diagnostic.billing_route_allowed)
        self.assertFalse(diagnostic.ready_now)
        self.assertIn("billing_route_not_allowed", diagnostic.blockers)

    async def test_faulty_adapter_is_reported_without_echoing_exception_or_env_values(
        self,
    ) -> None:
        leaked_value = "fault-secret-never-report"

        class FaultyRunner:
            @property
            def runner_id(self) -> str:
                return "faulty"

            async def detect_capabilities(self) -> RunnerCapabilities:
                raise RuntimeError(leaked_value)

            async def inspect_billing_route(self) -> BillingRouteAssessment:
                return BillingRouteAssessment(
                    runner_id="faulty",
                    route=BillingRoute.UNKNOWN,
                    confidence=AssessmentConfidence.LOW,
                    evidence=(f"unsafe detail {leaked_value}",),
                )

            async def validate_environment(
                self, request: RunRequest
            ) -> EnvironmentValidation:
                del request
                return EnvironmentValidation(
                    valid=False,
                    sanitized_environment={"PATH": leaked_value},
                    retained_names=("PATH",),
                    errors=(f"bad value {leaked_value}",),
                )

            async def execute(self, request, event_sink):  # pragma: no cover
                raise AssertionError("doctor must never execute a runner")

            async def cancel(self, run_id: str) -> None:  # pragma: no cover
                raise AssertionError("doctor must never cancel a runner")

        environment = {
            "PATH": "/bin",
            "HOME": "/safe/home",
            "OPENAI_API_KEY": leaked_value,
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = await collect_doctor_report(
                (FaultyRunner(),),
                environment=environment,
                workspace=temporary,
                run_root=Path(temporary) / "runs",
            )

        serialized = json.dumps(report.to_mapping(), sort_keys=True)
        self.assertNotIn(leaked_value, serialized)
        diagnostic = report.runners[0]
        self.assertFalse(diagnostic.ready_now)
        self.assertIn("runner_diagnostic_failed", diagnostic.blockers)
        self.assertEqual(
            diagnostic.diagnostic_errors,
            ("capability_probe_failed:RuntimeError",),
        )
        self.assertEqual(diagnostic.environment.sanitized_names, ("PATH",))

    async def test_missing_workspace_blocks_readiness_without_creating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "missing-workspace"
            report = await collect_doctor_report(
                (MockRunner(),),
                environment={},
                workspace=workspace,
                run_root=Path(temporary) / "runs",
            )

            self.assertFalse(workspace.exists())
            self.assertFalse(report.workspace.ready)
            self.assertFalse(report.runners[0].ready_now)
            self.assertIn("workspace_not_ready", report.runners[0].blockers)


if __name__ == "__main__":
    unittest.main()
