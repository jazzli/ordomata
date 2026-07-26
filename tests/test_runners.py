from __future__ import annotations

import json
import asyncio
from dataclasses import replace
import sys
import tempfile
import time
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from ordomata.errors import BillingRouteBlocked, LiveRunDisabled, ValidationError
from ordomata.billing import BillingDispatchReservation
from ordomata.models import (
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
    PermissionClass,
    RunRequest,
    RunStatus,
    UsageObservation,
)
from ordomata.redaction import REDACTED, Redactor
from ordomata.runners import AgentRunner, ClaudeRunner, CodexRunner, MockRunner
from ordomata.runners.base import ProbeResult
from ordomata.runners._harness import FirstPartyHarnessRunner
from ordomata.runners.codex import (
    CodexAppServerBillingProbe,
    CodexBillingEvidence,
    sanitize_codex_billing_snapshot,
)
from ordomata.runners.process import AsyncCommandProbe


class FakeProbe:
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


class StaticCodexBillingProbe:
    def __init__(self, evidence: CodexBillingEvidence | None) -> None:
        self.evidence = evidence
        self.environments: list[dict[str, str]] = []

    async def inspect(self, executable: str, *, environment: Mapping[str, str]):
        del executable
        self.environments.append(dict(environment))
        return self.evidence


class ClosedBillingCircuitGuard:
    def assert_closed(self, assessment: BillingRouteAssessment) -> None:
        del assessment

    def reserve_dispatch(
        self,
        assessment: BillingRouteAssessment,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> BillingDispatchReservation:
        now = time.time()
        return BillingDispatchReservation(
            reservation_id=f"reservation-{owner_id}",
            runner_id=assessment.runner_id,
            account_identity_fingerprint=(
                assessment.account_identity_fingerprint or "0" * 64
            ),
            profile_id=None,
            owner_id=f"owner-{owner_id}",
            lease_keys=("fixture-billing-lease",),
            acquired_at=now,
            expires_at=now + ttl_seconds,
        )

    def complete_dispatch(
        self,
        reservation: BillingDispatchReservation,
        *,
        run_id: str,
        capacity_state: CapacityState,
        capacity_reason_code: str,
        circuit_breaker_required: bool,
        broad_scope_required: bool,
        reason_code: str,
    ) -> None:
        del (
            reservation,
            run_id,
            capacity_state,
            capacity_reason_code,
            circuit_breaker_required,
            broad_scope_required,
            reason_code,
        )


class RecordingBillingCircuitGuard(ClosedBillingCircuitGuard):
    def __init__(self) -> None:
        self.ttls: list[float] = []
        self.completions: list[dict[str, object]] = []

    def reserve_dispatch(
        self,
        assessment: BillingRouteAssessment,
        *,
        owner_id: str,
        ttl_seconds: float,
    ) -> BillingDispatchReservation:
        self.ttls.append(ttl_seconds)
        return super().reserve_dispatch(
            assessment, owner_id=owner_id, ttl_seconds=ttl_seconds
        )

    def complete_dispatch(
        self,
        reservation: BillingDispatchReservation,
        *,
        run_id: str,
        capacity_state: CapacityState,
        capacity_reason_code: str,
        circuit_breaker_required: bool,
        broad_scope_required: bool,
        reason_code: str,
    ) -> None:
        self.completions.append(
            {
                "reservation": reservation,
                "run_id": run_id,
                "capacity_state": capacity_state,
                "capacity_reason_code": capacity_reason_code,
                "circuit_breaker_required": circuit_breaker_required,
                "broad_scope_required": broad_scope_required,
                "reason_code": reason_code,
            }
        )


def probe_result(command: tuple[str, ...], stdout: str) -> ProbeResult:
    return ProbeResult(command=command, exit_code=0, stdout=stdout)


def request(
    workspace: Path,
    *,
    overrides: Mapping[str, object] | None = None,
    permission: PermissionClass = PermissionClass.READ_ONLY,
) -> RunRequest:
    return RunRequest(
        run_id="run-1",
        task_id="task-1",
        task_version="1",
        prompt="private prompt text",
        workspace=workspace,
        run_directory=workspace,
        output_schema={"type": "object"},
        permission_class=permission,
        timeout_seconds=30,
        runner_overrides=overrides or {},
    )


class LocalScriptHarness(FirstPartyHarnessRunner):
    """Local deterministic process used to test live-adapter machinery."""

    def __init__(
        self,
        script: str,
        *,
        script_arguments: tuple[str, ...] = (),
        route: BillingRoute = BillingRoute.SUBSCRIPTION_INCLUDED,
        postflight_route: BillingRoute | None = None,
        parent_environment: Mapping[str, str],
        executable_resolver=None,
        billing_circuit_guard=None,
    ) -> None:
        super().__init__(
            binary=sys.executable,
            executable_resolver=(
                executable_resolver or (lambda _: sys.executable)
            ),
            parent_environment=parent_environment,
            billing_circuit_guard=(
                ClosedBillingCircuitGuard()
                if billing_circuit_guard is None
                else billing_circuit_guard
            ),
        )
        self.script = script
        self.script_arguments = script_arguments
        self.route = route
        self.postflight_route = postflight_route
        self.billing_inspections = 0

    @property
    def runner_id(self) -> str:
        return "local-script"

    async def detect_capabilities(self):
        from ordomata.models import RunnerCapabilities

        installed = self._resolved_binary() is not None
        return RunnerCapabilities(
            runner_id=self.runner_id,
            installed=installed,
            version="deterministic",
            non_interactive=installed,
            structured_output_modes=("jsonl",) if installed else (),
        )

    async def inspect_billing_route(self) -> BillingRouteAssessment:
        if self._resolved_binary() is None:
            return BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.HIGH,
            )
        self.billing_inspections += 1
        selected_route = (
            self.postflight_route
            if self.billing_inspections > 1 and self.postflight_route is not None
            else self.route
        )
        if selected_route is BillingRoute.SUBSCRIPTION_INCLUDED:
            observed_at = time.time()
            fingerprint = "e" * 64
            attestation = BillingSafetyAttestation(
                runner_id=self.runner_id,
                account_identity_fingerprint=fingerprint,
                billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED
                ),
                observed_at=observed_at - 1,
                expires_at=observed_at + 60,
                confidence=AssessmentConfidence.HIGH,
                evidence=(
                    "operator_attestation:provider_enforced_paid_continuation_disabled",
                ),
            )
            return BillingRouteAssessment(
                runner_id=self.runner_id,
                route=selected_route,
                confidence=AssessmentConfidence.HIGH,
                subscription_name="fixture",
                capacity_state=CapacityState.AVAILABLE,
                paid_continuation_protection=(
                    PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED
                ),
                paid_credit_balance=PaidCreditBalance.NOT_APPLICABLE,
                account_identity_fingerprint=fingerprint,
                capacity_observed_at=observed_at - 1,
                capacity_expires_at=observed_at + 60,
                attestation=attestation,
            )
        return BillingRouteAssessment(
            runner_id=self.runner_id,
            route=selected_route,
            confidence=AssessmentConfidence.HIGH,
        )

    def build_command(self, run_request: RunRequest) -> tuple[str, ...]:
        executable = self._resolved_binary() or self._binary
        return (
            executable,
            "-c",
            self.script,
            str(self.output_path(run_request)),
            *self.script_arguments,
        )

    def parse_event_line(self, line: str, redactor: Redactor) -> AgentEvent | None:
        from ordomata.runners.base import parse_jsonl_event

        return parse_jsonl_event(line, redactor=redactor)

    def terminal_success(self, events) -> bool:
        return bool(events) and events[-1].event_type == "turn.completed"


class RunnerDiagnosticTests(unittest.IsolatedAsyncioTestCase):
    async def test_codex_capabilities_and_chatgpt_route(self) -> None:
        executable = "/tools/codex"
        observed_at = time.time()
        billing_probe = StaticCodexBillingProbe(
            CodexBillingEvidence(
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                capacity_state=CapacityState.AVAILABLE,
                paid_credit_balance=PaidCreditBalance.ZERO,
                account_identity_fingerprint="f" * 64,
                observed_at=observed_at,
                expires_at=observed_at + 60,
                evidence=("sanitized fixture",),
            )
        )
        probe = FakeProbe(
            {
                (executable, "--version"): probe_result(
                    (executable, "--version"), "codex-cli 1.2.3\n"
                ),
                (executable, "exec", "--help"): probe_result(
                    (executable, "exec", "--help"),
                    "Usage: codex exec --json --output-schema --sandbox read-only workspace-write "
                    "--ask-for-approval --ephemeral --ignore-user-config "
                    "--ignore-rules --skip-git-repo-check resume usage",
                ),
                (executable, "--help"): probe_result(
                    (executable, "--help"),
                    "Usage: codex --ask-for-approval --sandbox",
                ),
                (executable, "login", "status"): probe_result(
                    (executable, "login", "status"), "Logged in using ChatGPT\n"
                ),
            }
        )
        runner = CodexRunner(
            probe=probe,
            billing_probe=billing_probe,
            executable_resolver=lambda _: executable,
            parent_environment={
                "PATH": "/tools",
                "HOME": "/home/test",
                "OPENAI_API_KEY": "never-forward-this",
            },
        )
        capabilities = await runner.detect_capabilities()
        assessment = await runner.inspect_billing_route()

        self.assertTrue(capabilities.installed)
        self.assertTrue(capabilities.non_interactive)
        self.assertEqual(capabilities.structured_output_modes, ("jsonl",))
        self.assertEqual(assessment.route, BillingRoute.SUBSCRIPTION_INCLUDED)
        self.assertEqual(assessment.confidence, AssessmentConfidence.HIGH)
        self.assertEqual(assessment.capacity_state, CapacityState.AVAILABLE)
        self.assertEqual(assessment.paid_credit_balance, PaidCreditBalance.ZERO)
        self.assertIsNone(assessment.attestation)
        self.assertEqual(assessment.risky_environment_names, ("OPENAI_API_KEY",))
        for _, child_environment in probe.calls:
            self.assertNotIn("OPENAI_API_KEY", child_environment)
            self.assertNotIn("never-forward-this", repr(child_environment))
        self.assertNotIn("OPENAI_API_KEY", billing_probe.environments[0])

    async def test_codex_api_auth_is_classified_as_blocked(self) -> None:
        executable = "/tools/codex"
        probe = FakeProbe(
            {
                (executable, "login", "status"): probe_result(
                    (executable, "login", "status"), "Logged in with API key"
                )
            }
        )
        runner = CodexRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )
        assessment = await runner.inspect_billing_route()
        self.assertEqual(assessment.route, BillingRoute.SEPARATELY_BILLED_API)
        with self.assertRaises(BillingRouteBlocked):
            from ordomata.billing import BillingPolicy

            BillingPolicy.assert_route_allowed(assessment)

    async def test_codex_does_not_accept_negative_chatgpt_json(self) -> None:
        executable = "/tools/codex"
        probe = FakeProbe(
            {
                (executable, "login", "status"): probe_result(
                    (executable, "login", "status"),
                    '{"loggedIn":false,"authMethod":"chatgpt"}',
                )
            }
        )
        runner = CodexRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )
        assessment = await runner.inspect_billing_route()
        self.assertEqual(assessment.route, BillingRoute.UNKNOWN)

    async def test_claude_first_party_oauth_route_and_capabilities(self) -> None:
        executable = "/tools/claude"
        auth = json.dumps(
            {
                "loggedIn": True,
                "authMethod": "claude.ai",
                "apiProvider": "firstParty",
                "subscriptionType": "max",
                "email": "operator@example.invalid",
            }
        )
        probe = FakeProbe(
            {
                (executable, "--version"): probe_result(
                    (executable, "--version"), "2.0.0\n"
                ),
                (executable, "--help"): probe_result(
                    (executable, "--help"),
                    "Usage claude --print --output-format stream-json "
                    "--permission-mode --json-schema --safe-mode "
                    "--no-session-persistence --strict-mcp-config --tools "
                    "plan acceptEdits --resume usage",
                ),
                (executable, "auth", "status", "--json"): probe_result(
                    (executable, "auth", "status", "--json"), auth
                ),
            }
        )
        runner = ClaudeRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={
                "PATH": "/tools",
                "HOME": "/home/test",
                "ANTHROPIC_API_KEY": "excluded-secret",
            },
        )
        capabilities = await runner.detect_capabilities()
        assessment = await runner.inspect_billing_route()

        self.assertTrue(capabilities.non_interactive)
        self.assertEqual(capabilities.structured_output_modes, ("jsonl",))
        self.assertEqual(assessment.route, BillingRoute.SUBSCRIPTION_INCLUDED)
        self.assertIsNotNone(assessment.account_identity_fingerprint)
        self.assertEqual(assessment.capacity_state, CapacityState.UNKNOWN)
        self.assertIn("ANTHROPIC_API_KEY", assessment.risky_environment_names)
        for _, child_environment in probe.calls:
            self.assertNotIn("ANTHROPIC_API_KEY", child_environment)

    async def test_claude_cloud_flag_blocks_without_auth_probe(self) -> None:
        executable = "/tools/claude"
        probe = FakeProbe({})
        runner = ClaudeRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={
                "PATH": "/tools",
                "HOME": "/home/test",
                "CLAUDE_CODE_USE_BEDROCK": "0",
            },
        )
        assessment = await runner.inspect_billing_route()
        self.assertEqual(assessment.route, BillingRoute.CLOUD_PROVIDER_BILLING)
        self.assertEqual(probe.calls, [])

    async def test_claude_structured_api_and_cloud_routes_are_blocked(self) -> None:
        executable = "/tools/claude"
        cases = (
            (
                {"loggedIn": True, "authMethod": "api_key", "apiProvider": "firstParty"},
                BillingRoute.SEPARATELY_BILLED_API,
            ),
            (
                {"loggedIn": True, "authMethod": "oauth", "apiProvider": "bedrock"},
                BillingRoute.CLOUD_PROVIDER_BILLING,
            ),
        )
        for diagnostic, expected_route in cases:
            with self.subTest(diagnostic=diagnostic):
                probe = FakeProbe(
                    {
                        (executable, "auth", "status", "--json"): probe_result(
                            (executable, "auth", "status", "--json"),
                            json.dumps(diagnostic),
                        )
                    }
                )
                runner = ClaudeRunner(
                    probe=probe,
                    executable_resolver=lambda _: executable,
                    parent_environment={"PATH": "/tools", "HOME": "/home/test"},
                )
                assessment = await runner.inspect_billing_route()
                self.assertEqual(assessment.route, expected_route)
                self.assertEqual(assessment.confidence, AssessmentConfidence.HIGH)

    async def test_claude_oauth_requires_logged_in_first_party_provider(self) -> None:
        executable = "/tools/claude"
        for diagnostic in (
            {
                "loggedIn": False,
                "authMethod": "oauth",
                "apiProvider": "firstParty",
                "subscriptionType": "max",
            },
            {
                "loggedIn": True,
                "authMethod": "oauth",
                "apiProvider": "thirdParty",
                "subscriptionType": "max",
            },
        ):
            with self.subTest(diagnostic=diagnostic):
                probe = FakeProbe(
                    {
                        (executable, "auth", "status", "--json"): probe_result(
                            (executable, "auth", "status", "--json"),
                            json.dumps(diagnostic),
                        )
                    }
                )
                runner = ClaudeRunner(
                    probe=probe,
                    executable_resolver=lambda _: executable,
                    parent_environment={"PATH": "/tools", "HOME": "/home/test"},
                )
                assessment = await runner.inspect_billing_route()
                self.assertEqual(assessment.route, BillingRoute.UNKNOWN)

    async def test_claude_oauth_requires_explicit_paid_subscription_type(self) -> None:
        executable = "/tools/claude"
        for subscription_type in (None, "free", "unknown", "unreviewed-plan"):
            diagnostic = {
                "loggedIn": True,
                "authMethod": "oauth",
                "apiProvider": "firstParty",
                "subscriptionType": subscription_type,
                "email": "operator@example.invalid",
            }
            with self.subTest(subscription_type=subscription_type):
                probe = FakeProbe(
                    {
                        (executable, "auth", "status", "--json"): probe_result(
                            (executable, "auth", "status", "--json"),
                            json.dumps(diagnostic),
                        )
                    }
                )
                runner = ClaudeRunner(
                    probe=probe,
                    executable_resolver=lambda _: executable,
                    parent_environment={"PATH": "/tools", "HOME": "/home/test"},
                )
                assessment = await runner.inspect_billing_route()
                self.assertEqual(assessment.route, BillingRoute.UNKNOWN)

    async def test_claude_enabled_extra_usage_is_overage_not_subscription(self) -> None:
        executable = "/tools/claude"
        diagnostic = {
            "loggedIn": True,
            "authMethod": "oauth",
            "apiProvider": "firstParty",
            "subscriptionType": "max",
            "email": "operator@example.invalid",
            "extraUsageEnabled": True,
        }
        probe = FakeProbe(
            {
                (executable, "auth", "status", "--json"): probe_result(
                    (executable, "auth", "status", "--json"),
                    json.dumps(diagnostic),
                )
            }
        )
        runner = ClaudeRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )
        assessment = await runner.inspect_billing_route()
        self.assertEqual(assessment.route, BillingRoute.SUBSCRIPTION_OVERAGE)

    async def test_claude_malformed_or_conflicting_extra_usage_fails_closed(self) -> None:
        executable = "/tools/claude"
        cases = (
            {"extraUsageEnabled": "true"},
            {"extraUsageEnabled": 1},
            {"extraUsageEnabled": False, "overageEnabled": True},
            {"nested": [{"paidUsageEnabled": "false"}]},
        )
        for paid_usage_fields in cases:
            diagnostic = {
                "loggedIn": True,
                "authMethod": "oauth",
                "apiProvider": "firstParty",
                "subscriptionType": "max",
                "email": "operator@example.invalid",
                **paid_usage_fields,
            }
            with self.subTest(paid_usage_fields=paid_usage_fields):
                probe = FakeProbe(
                    {
                        (executable, "auth", "status", "--json"): probe_result(
                            (executable, "auth", "status", "--json"),
                            json.dumps(diagnostic),
                        )
                    }
                )
                runner = ClaudeRunner(
                    probe=probe,
                    executable_resolver=lambda _: executable,
                    parent_environment={"PATH": "/tools", "HOME": "/home/test"},
                )
                assessment = await runner.inspect_billing_route()
                self.assertEqual(assessment.route, BillingRoute.UNKNOWN)

    async def test_claude_rejects_plaintext_login_claim(self) -> None:
        executable = "/tools/claude"
        probe = FakeProbe(
            {
                (executable, "auth", "status", "--json"): probe_result(
                    (executable, "auth", "status", "--json"),
                    "Not currently logged in to claude.ai",
                )
            }
        )
        runner = ClaudeRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )
        assessment = await runner.inspect_billing_route()
        self.assertEqual(assessment.route, BillingRoute.UNKNOWN)


class CommandProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_probe_output_is_bounded(self) -> None:
        probe = AsyncCommandProbe(max_output_bytes=5)
        result = await probe.run(
            (sys.executable, "-c", "print('abcdefgh')"),
            environment={"PATH": "/bin", "HOME": "/tmp"},
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "abcde")

    async def test_probe_timeout_covers_process_lifecycle(self) -> None:
        probe = AsyncCommandProbe()
        started = time.monotonic()
        result = await probe.run(
            (sys.executable, "-c", "import time; time.sleep(10)"),
            environment={"PATH": "/bin", "HOME": "/tmp"},
            timeout_seconds=0.1,
        )
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 2.0)


class CodexBillingProbeTests(unittest.IsolatedAsyncioTestCase):
    def test_snapshot_sanitizer_separates_paid_balance_and_capacity(self) -> None:
        account = {
            "account": {
                "type": "chatgpt",
                "planType": "pro",
                "email": "private-account@example.invalid",
            },
            "requiresOpenaiAuth": True,
        }
        rate_limits = {
            "rateLimits": {
                "credits": {
                    "hasCredits": False,
                    "unlimited": False,
                    "balance": "0",
                },
                "primary": {"usedPercent": 9, "resetsAt": 99_999},
                "rateLimitReachedType": None,
            },
            "rateLimitResetCredits": {
                "availableCount": 2,
                "credits": [{"id": "private-reset-id", "status": "available"}],
            },
        }
        evidence = sanitize_codex_billing_snapshot(
            account, rate_limits, observed_at=100
        )
        self.assertEqual(evidence.route, BillingRoute.SUBSCRIPTION_INCLUDED)
        self.assertEqual(evidence.capacity_state, CapacityState.AVAILABLE)
        self.assertEqual(evidence.paid_credit_balance, PaidCreditBalance.ZERO)
        self.assertNotIn("private-account", repr(evidence))
        self.assertNotIn("private-reset-id", repr(evidence))
        self.assertNotIn("99_999", repr(evidence))

        paid = sanitize_codex_billing_snapshot(
            account,
            {
                "rateLimits": {
                    "credits": {
                        "hasCredits": True,
                        "unlimited": False,
                        "balance": "12.34",
                    },
                    "primary": {"usedPercent": 10},
                }
            },
            observed_at=100,
        )
        self.assertEqual(paid.route, BillingRoute.PURCHASED_PRODUCT_CREDIT)
        self.assertEqual(paid.paid_credit_balance, PaidCreditBalance.POSITIVE)
        self.assertNotIn("12.34", repr(paid))

    async def test_app_server_probe_keeps_stdio_open_and_returns_only_sanitized_data(self) -> None:
        server_source = f"""#!{sys.executable}
import json
import sys
for line in sys.stdin:
    request = json.loads(line)
    request_id = request[\"id\"]
    if request_id == 1:
        result = {{}}
    elif request_id == 2:
        result = {{\"account\": {{\"type\": \"chatgpt\", \"planType\": \"pro\", \"email\": \"private@example.invalid\"}}, \"requiresOpenaiAuth\": True}}
    else:
        result = {{\"rateLimits\": {{\"credits\": {{\"hasCredits\": False, \"unlimited\": False, \"balance\": \"0\"}}, \"primary\": {{\"usedPercent\": 1}}, \"rateLimitReachedType\": None}}, \"rateLimitResetCredits\": {{\"availableCount\": 1, \"credits\": [{{\"id\": \"never-return-this\"}}]}}}}
    print(json.dumps({{\"id\": request_id, \"result\": result}}), flush=True)
"""
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-codex"
            executable.write_text(server_source, encoding="utf-8")
            executable.chmod(0o700)
            probe = CodexAppServerBillingProbe(timeout_seconds=2)
            evidence = await probe.inspect(
                str(executable), environment={"PATH": "/usr/bin:/bin"}
            )
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.paid_credit_balance, PaidCreditBalance.ZERO)
        self.assertNotIn("private@example.invalid", repr(evidence))
        self.assertNotIn("never-return-this", repr(evidence))


class RunnerCommandTests(unittest.TestCase):
    def test_codex_command_uses_stdin_and_bounded_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            runner = CodexRunner(executable_resolver=lambda _: "/tools/codex")
            run_request = request(
                workspace,
                overrides={"model": "gpt-example", "reasoning_effort": "high"},
                permission=PermissionClass.LOCAL_DRAFT,
            )
            command = runner.build_command(run_request)

            self.assertEqual(command[0], "/tools/codex")
            self.assertIn("exec", command)
            self.assertIn("--strict-config", command)
            self.assertIn("--ignore-user-config", command)
            self.assertIn("--ignore-rules", command)
            self.assertIn("--ephemeral", command)
            self.assertIn("--skip-git-repo-check", command)
            self.assertNotIn("--output-last-message", command)
            self.assertIn("never", command)
            self.assertIn("read-only", command)
            self.assertNotIn("workspace-write", command)
            self.assertIn("gpt-example", command)
            self.assertEqual(command[-1], "-")
            self.assertNotIn(run_request.prompt, command)

    def test_codex_reads_structured_output_from_redacted_event_stream(self) -> None:
        runner = CodexRunner(executable_resolver=lambda _: "/tools/codex")
        events = [
            AgentEvent(
                "item.completed",
                {
                    "item": {
                        "type": "agent_message",
                        "text": '{"summary":"local"}',
                    }
                },
            ),
            AgentEvent("turn.completed", {}),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            output = runner._read_output(request(Path(temporary)), events)
        self.assertEqual(output, {"summary": "local"})

    def test_claude_command_uses_stream_json_and_no_prompt_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            runner = ClaudeRunner(executable_resolver=lambda _: "/tools/claude")
            run_request = request(
                workspace,
                overrides={"model": "claude-example", "effort": "medium"},
            )
            command = runner.build_command(run_request)

            self.assertEqual(command[0:2], ("/tools/claude", "--print"))
            self.assertIn("stream-json", command)
            self.assertIn("dontAsk", command)
            self.assertIn("--safe-mode", command)
            settings_index = command.index("--setting-sources")
            self.assertEqual(command[settings_index + 1], "")
            self.assertIn("--no-session-persistence", command)
            tools_index = command.index("--tools")
            self.assertEqual(command[tools_index + 1], "")
            self.assertIn("--strict-mcp-config", command)
            self.assertIn("claude-example", command)
            self.assertNotIn(run_request.prompt, command)

    def test_arbitrary_runner_flags_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            codex = CodexRunner(executable_resolver=lambda _: "/tools/codex")
            claude = ClaudeRunner(executable_resolver=lambda _: "/tools/claude")
            bad_request = request(workspace, overrides={"extra_args": "--danger"})
            with self.assertRaises(ValidationError):
                codex.build_command(bad_request)
            with self.assertRaises(ValidationError):
                claude.build_command(bad_request)

    def test_jsonl_events_are_structured_and_redacted(self) -> None:
        runner = CodexRunner(executable_resolver=lambda _: "/tools/codex")
        event = runner.parse_event_line(
            '{"type":"turn.completed","api_key":"secret",'
            '"usage":{"input_tokens":3}}',
            Redactor(),
        )
        assert event is not None
        self.assertEqual(event.event_type, "turn.completed")
        self.assertEqual(event.payload["api_key"], REDACTED)
        self.assertTrue(event.credential_material_detected)
        with self.assertRaises(ValidationError):
            runner.parse_event_line("not-json", Redactor())


class MockRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_mock_runner_satisfies_protocol_and_is_deterministic(self) -> None:
        events = (
            AgentEvent("analysis", {"step": 1}),
            AgentEvent("result", {"ok": True}),
        )
        output = {"summary": "fixture"}
        runner = MockRunner(events=events, output=output)
        self.assertIsInstance(runner, AgentRunner)

        seen: list[AgentEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            result = await runner.execute(request(Path(temporary)), seen.append)

        self.assertEqual(result.status, RunStatus.SUCCEEDED)
        self.assertEqual(result.output, output)
        self.assertEqual(result.events, events)
        self.assertEqual(seen, list(events))
        self.assertEqual(result.billing_assessment.route, BillingRoute.MOCK)
        self.assertEqual(result.usage_observation, UsageObservation.NOT_APPLICABLE)
        self.assertEqual(result.runner_version, "deterministic")
        self.assertEqual(result.execution_mode, "in_memory_mock")
        self.assertFalse(result.harness_process_started)
        self.assertFalse(result.live_model_execution_occurred)
        self.assertFalse(result.subscription_capacity_consumed)
        self.assertEqual(result.wall_seconds, 0.0)

    async def test_mock_can_simulate_a_blocked_billing_route(self) -> None:
        runner = MockRunner(
            billing_assessment=BillingRouteAssessment(
                runner_id="mock",
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.HIGH,
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(BillingRouteBlocked):
                await runner.execute(request(Path(temporary)), lambda _: None)


class LiveGateTests(unittest.IsolatedAsyncioTestCase):
    async def test_codex_execute_stops_before_model_process_without_gate(self) -> None:
        executable = "/tools/codex"
        now = time.time()
        fingerprint = "1" * 64
        billing_probe = StaticCodexBillingProbe(
            CodexBillingEvidence(
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                capacity_state=CapacityState.AVAILABLE,
                paid_credit_balance=PaidCreditBalance.ZERO,
                account_identity_fingerprint=fingerprint,
                observed_at=now - 1,
                expires_at=now + 60,
            )
        )
        attestation = BillingSafetyAttestation(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
            capacity_state=CapacityState.AVAILABLE,
            paid_continuation_protection=(
                PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
            ),
            observed_at=now - 1,
            expires_at=now + 60,
            confidence=AssessmentConfidence.HIGH,
            evidence=(
                "operator_attestation:provider_ui_auto_top_up_disabled",
            ),
        )
        probe = FakeProbe(
            {
                (executable, "--version"): probe_result(
                    (executable, "--version"), "codex 1"
                ),
                (executable, "exec", "--help"): probe_result(
                    (executable, "exec", "--help"),
                    "Usage: codex exec --json --output-schema --sandbox read-only workspace-write "
                    "--ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check",
                ),
                (executable, "--help"): probe_result(
                    (executable, "--help"),
                    "Usage: codex --ask-for-approval --sandbox",
                ),
                (executable, "login", "status"): probe_result(
                    (executable, "login", "status"), "Logged in using ChatGPT"
                ),
            }
        )
        runner = CodexRunner(
            probe=probe,
            billing_probe=billing_probe,
            billing_attestation=attestation,
            billing_circuit_guard=ClosedBillingCircuitGuard(),
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(LiveRunDisabled):
                await runner.execute(request(Path(temporary)), lambda _: None)

    async def test_codex_chatgpt_auth_and_live_gate_without_attestation_still_blocks(self) -> None:
        executable = "/tools/codex"
        probe = FakeProbe(
            {
                (executable, "--version"): probe_result(
                    (executable, "--version"), "codex 1"
                ),
                (executable, "exec", "--help"): probe_result(
                    (executable, "exec", "--help"),
                    "Usage: codex exec --json --output-schema --sandbox read-only "
                    "--ephemeral --ignore-user-config --ignore-rules "
                    "--skip-git-repo-check usage",
                ),
                (executable, "--help"): probe_result(
                    (executable, "--help"),
                    "Usage: codex --ask-for-approval --sandbox",
                ),
                (executable, "login", "status"): probe_result(
                    (executable, "login", "status"), "Logged in using ChatGPT"
                ),
            }
        )
        runner = CodexRunner(
            probe=probe,
            billing_probe=StaticCodexBillingProbe(None),
            billing_circuit_guard=ClosedBillingCircuitGuard(),
            executable_resolver=lambda _: executable,
            parent_environment={
                "PATH": "/tools",
                "HOME": "/home/test",
                "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(BillingRouteBlocked):
                await runner.execute(request(Path(temporary)), lambda _: None)


class LiveHarnessSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_live_harness_fails_closed_for_legacy_read_only_guard(self) -> None:
        class LegacyGuard:
            def assert_closed(self, assessment: BillingRouteAssessment) -> None:
                del assessment

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            marker = workspace / "must-not-launch"
            runner = LocalScriptHarness(
                f"import pathlib; pathlib.Path({str(marker)!r}).touch()",
                billing_circuit_guard=LegacyGuard(),
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            with self.assertRaisesRegex(
                BillingRouteBlocked, "atomic billing dispatch reservation"
            ):
                await runner.execute(request(workspace), lambda _: None)
            self.assertFalse(marker.exists())

    async def test_reservation_covers_timeout_margin_and_safe_completion(self) -> None:
        guard = RecordingBillingCircuitGuard()
        script = (
            "import json,pathlib,sys; sys.stdin.read(); "
            "pathlib.Path(sys.argv[1]).write_text('{}'); "
            "print(json.dumps({'type':'turn.completed'}))"
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                script,
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            result = await runner.execute(request(Path(temporary)), lambda _: None)
        self.assertEqual(result.status, RunStatus.SUCCEEDED)
        self.assertEqual(guard.ttls, [60.0])
        self.assertEqual(len(guard.completions), 1)
        completion = guard.completions[0]
        self.assertEqual(completion["capacity_state"], CapacityState.AVAILABLE)
        self.assertEqual(
            completion["capacity_reason_code"], "post_run_capacity_available"
        )
        self.assertFalse(completion["circuit_breaker_required"])

    async def test_task_cancellation_opens_broad_breaker_before_release(self) -> None:
        guard = RecordingBillingCircuitGuard()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            runner = LocalScriptHarness(
                "import sys,time; sys.stdin.read(); time.sleep(10)",
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            task = asyncio.create_task(
                runner.execute(request(workspace), lambda _: None)
            )
            for _ in range(100):
                if runner._active_processes:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(runner._active_processes)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertEqual(len(guard.completions), 1)
        completion = guard.completions[0]
        self.assertEqual(completion["capacity_state"], CapacityState.UNKNOWN)
        self.assertEqual(
            completion["capacity_reason_code"], "billing_dispatch_interrupted"
        )
        self.assertTrue(completion["circuit_breaker_required"])
        self.assertTrue(completion["broad_scope_required"])
        self.assertEqual(completion["reason_code"], "billing_dispatch_interrupted")
        self.assertFalse(runner._active_processes)

    async def test_dispatch_pins_one_verified_executable(self) -> None:
        resolutions: list[str] = []

        def changing_resolver(_: str) -> str:
            resolutions.append("resolved")
            return sys.executable if len(resolutions) == 1 else "/unverified/harness"

        script = (
            "import json,pathlib,sys; sys.stdin.read(); "
            "pathlib.Path(sys.argv[1]).write_text('{}'); "
            "print(json.dumps({'type':'turn.completed'}))"
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                script,
                executable_resolver=changing_resolver,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            result = await runner.execute(request(Path(temporary)), lambda _: None)
        self.assertEqual(result.status, RunStatus.SUCCEEDED)
        self.assertEqual(resolutions, ["resolved"])

    async def test_post_launch_event_sink_failure_runs_billing_postflight(self) -> None:
        script = (
            "import json,sys; sys.stdin.read(); "
            "print(json.dumps({'type':'turn.completed'}))"
        )

        def failing_sink(_: AgentEvent) -> None:
            raise RuntimeError("sensitive event sink detail")

        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                script,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            result = await runner.execute(request(Path(temporary)), failing_sink)
        self.assertEqual(result.status, RunStatus.QUARANTINED)
        self.assertEqual(runner.billing_inspections, 2)
        self.assertEqual(result.incremental_ai_charge, IncrementalAICharge.UNKNOWN)
        self.assertTrue(result.billing_circuit_breaker_required)
        self.assertEqual(
            result.billing_disposition_reasons,
            ("harness_execution_outcome_unknown",),
        )
        self.assertNotIn("sensitive event sink detail", repr(result))

    async def test_post_launch_output_failure_runs_billing_postflight(self) -> None:
        script = (
            "import json,sys; sys.stdin.read(); "
            "print(json.dumps({'type':'turn.completed'}))"
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                script,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )

            def failing_output(*_):
                raise RuntimeError("sensitive output detail")

            runner._read_output = failing_output
            result = await runner.execute(request(Path(temporary)), lambda _: None)
        self.assertEqual(result.status, RunStatus.QUARANTINED)
        self.assertEqual(runner.billing_inspections, 2)
        self.assertEqual(result.incremental_ai_charge, IncrementalAICharge.UNKNOWN)
        self.assertEqual(
            result.billing_disposition_reasons,
            ("harness_execution_outcome_unknown",),
        )
        self.assertNotIn("sensitive output detail", repr(result))

    async def test_raw_output_is_redacted_in_memory_and_removed_from_disk(self) -> None:
        script = (
            "import json,pathlib,sys; "
            "sys.stdin.read(); "
            "value=pathlib.Path(sys.argv[2]).read_text(); "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps({'summary':value})); "
            "print(json.dumps({'type':'turn.completed'}))"
        )
        secret = "sk-fixturecredential123456789"
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            secret_path = workspace / "fixture-input.txt"
            secret_path.write_text(secret, encoding="utf-8")
            runner = LocalScriptHarness(
                script,
                script_arguments=(str(secret_path),),
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "OPENAI_API_KEY": secret,
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            run_request = request(workspace)
            run_request = replace(
                run_request,
                output_schema={
                    "type": "object",
                    "properties": {"summary": {"type": "string"}},
                    "required": ["summary"],
                    "additionalProperties": False,
                },
            )
            result = await runner.execute(run_request, lambda _: None)
            self.assertEqual(result.status, RunStatus.SUCCEEDED)
            self.assertEqual(result.output, {"summary": REDACTED})
            self.assertTrue(result.credential_material_detected)
            self.assertTrue(result.harness_process_started)
            self.assertTrue(result.live_model_execution_occurred)
            self.assertTrue(result.subscription_capacity_consumed)
            self.assertEqual(result.execution_mode, "non_interactive_jsonl")
            self.assertIsNotNone(result.wall_seconds)
            self.assertFalse(runner.output_path(run_request).exists())

    async def test_live_adapter_rejects_mock_route_before_process_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            runner = LocalScriptHarness(
                "raise AssertionError('must not start')",
                route=BillingRoute.MOCK,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            with self.assertRaises(BillingRouteBlocked):
                await runner.execute(request(workspace), lambda _: None)
            self.assertFalse(runner.schema_path(request(workspace)).exists())

    async def test_paid_postflight_quarantines_and_requests_circuit_breaker(self) -> None:
        script = (
            "import json,pathlib,sys; sys.stdin.read(); "
            "pathlib.Path(sys.argv[1]).write_text('{}'); "
            "print(json.dumps({'type':'turn.completed'}))"
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            runner = LocalScriptHarness(
                script,
                postflight_route=BillingRoute.PURCHASED_PRODUCT_CREDIT,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            result = await runner.execute(request(workspace), lambda _: None)
        self.assertEqual(result.status, RunStatus.QUARANTINED)
        self.assertTrue(result.billing_quarantine_required)
        self.assertTrue(result.billing_circuit_breaker_required)
        self.assertEqual(result.paid_capacity_consumed, PaidCapacityConsumed.UNKNOWN)
        self.assertEqual(result.incremental_ai_charge, IncrementalAICharge.POSSIBLE)
        self.assertEqual(
            result.billing_disposition_reasons,
            ("post_run_paid_route_possible",),
        )

    async def test_wall_timeout_covers_blocked_stdin_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            runner = LocalScriptHarness(
                "import time; time.sleep(10)",
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            base = request(workspace)
            run_request = RunRequest(
                run_id=base.run_id,
                task_id=base.task_id,
                task_version=base.task_version,
                prompt="x" * 2_000_000,
                workspace=base.workspace,
                run_directory=base.run_directory,
                output_schema=base.output_schema,
                permission_class=base.permission_class,
                timeout_seconds=1,
            )
            started = time.monotonic()
            result = await runner.execute(run_request, lambda _: None)
            elapsed = time.monotonic() - started
            self.assertEqual(result.status, RunStatus.FAILED)
            self.assertLess(elapsed, 3.0)
            self.assertIn("Harness execution timed out.", result.errors)


class TerminalEventTests(unittest.TestCase):
    def test_codex_requires_last_terminal_event_to_be_completed(self) -> None:
        runner = CodexRunner(executable_resolver=lambda _: "/tools/codex")
        self.assertTrue(
            runner.terminal_success([AgentEvent("turn.completed", {"usage": {}})])
        )
        self.assertFalse(
            runner.terminal_success(
                [AgentEvent("turn.completed", {}), AgentEvent("error", {})]
            )
        )
        self.assertFalse(
            runner.terminal_success(
                [AgentEvent("turn.completed", {}), AgentEvent("fatal", {})]
            )
        )

    def test_claude_rejects_error_result_even_with_success_subtype(self) -> None:
        runner = ClaudeRunner(executable_resolver=lambda _: "/tools/claude")
        self.assertTrue(
            runner.terminal_success(
                [AgentEvent("result", {"subtype": "success", "is_error": False})]
            )
        )
        self.assertFalse(
            runner.terminal_success(
                [AgentEvent("result", {"subtype": "success", "is_error": True})]
            )
        )
        self.assertFalse(
            runner.terminal_success(
                [AgentEvent("result", {"subtype": "success"})]
            )
        )
        self.assertFalse(
            runner.terminal_success(
                [
                    AgentEvent("result", {"subtype": "success", "is_error": False}),
                    AgentEvent("error", {}),
                ]
            )
        )


if __name__ == "__main__":
    unittest.main()
