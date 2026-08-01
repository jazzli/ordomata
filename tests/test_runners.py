from __future__ import annotations

import json
import asyncio
from dataclasses import replace
import os
import signal
import sys
import tempfile
import time
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

from ordomata.errors import (
    BillingRouteBlocked,
    LiveRunDisabled,
    RunnerUnavailable,
    ValidationError,
)
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
from ordomata.runners import (
    AgentRunner,
    ClaudeRunner,
    CodexRunner,
    CONTROLLER_EVENT_SINK_LIMIT,
    ControllerEventSink,
    MockRunner,
)
from ordomata.runners.base import ProbeResult
from ordomata.runners._harness import (
    FirstPartyHarnessRunner,
    HarnessCancellationError,
    HarnessProcessLimits,
)
from ordomata.runners.codex import (
    CodexAppServerBillingProbe,
    CodexBillingEvidence,
    sanitize_codex_billing_snapshot,
)
from ordomata.runners.containment import (
    CleanupDisposition,
    CleanupResult,
    posix_containment_available,
)
from ordomata.runners import _harness as harness_module
from ordomata.runners import codex as codex_module
from ordomata.runners import containment as containment_module
from ordomata.runners.process import AsyncCommandProbe, ProbeContainmentError


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
    return ProbeResult(
        command=command,
        exit_code=0,
        stdout=stdout,
        containment_cleanup_verified=True,
    )


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
        process_limits: HarnessProcessLimits | None = None,
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
            process_limits=process_limits,
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
    async def test_optional_probe_containment_failure_is_fatal(self) -> None:
        executable = "/tools/codex"
        responses = {
            (executable, "--version"): probe_result(
                (executable, "--version"), "codex-cli 1.2.3\n"
            ),
            (executable, "exec", "--help"): probe_result(
                (executable, "exec", "--help"),
                "Usage: codex exec --json --output-schema",
            ),
        }

        async def run_probe(command, **_kwargs):
            normalized = tuple(command)
            if normalized == (executable, "--help"):
                raise ProbeContainmentError
            return responses[normalized]

        probe = mock.Mock()
        probe.run = mock.AsyncMock(side_effect=run_probe)
        runner = CodexRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )

        with self.assertRaises(RunnerUnavailable) as raised:
            await runner.detect_capabilities()

        self.assertEqual(
            str(raised.exception),
            "Runner diagnostic process containment could not be verified.",
        )

    async def test_timed_out_probe_result_is_rejected_even_after_clean_exit(
        self,
    ) -> None:
        executable = "/tools/codex"
        command = (executable, "--version")
        probe = FakeProbe(
            {
                command: ProbeResult(
                    command,
                    0,
                    stdout="codex 1",
                    timed_out=True,
                    containment_cleanup_verified=True,
                )
            }
        )
        runner = CodexRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )

        self.assertIsNone(await runner._run_probe(command))

    async def test_custom_probe_without_cleanup_evidence_is_fatal(self) -> None:
        executable = "/tools/codex"
        probe = FakeProbe(
            {
                (executable, "--version"): ProbeResult(
                    (executable, "--version"), 0, stdout="codex 1"
                ),
                (executable, "exec", "--help"): ProbeResult(
                    (executable, "exec", "--help"),
                    0,
                    stdout="Usage: codex exec --json --output-schema",
                ),
                (executable, "--help"): ProbeResult(
                    (executable, "--help"),
                    0,
                    stdout="Usage: codex --ask-for-approval --sandbox",
                ),
            }
        )
        runner = CodexRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )

        with self.assertRaises(RunnerUnavailable) as raised:
            await runner.detect_capabilities()

        self.assertEqual(
            str(raised.exception),
            "Runner diagnostic process containment could not be verified.",
        )

    async def test_optional_unverified_probe_receipt_is_fatal(self) -> None:
        executable = "/tools/codex"
        probe = FakeProbe(
            {
                (executable, "--version"): probe_result(
                    (executable, "--version"), "codex-cli 1.2.3\n"
                ),
                (executable, "exec", "--help"): probe_result(
                    (executable, "exec", "--help"),
                    "Usage: codex exec --json --output-schema",
                ),
                (executable, "--help"): ProbeResult(
                    (executable, "--help"),
                    0,
                    stdout="Usage: codex --ask-for-approval --sandbox",
                    containment_cleanup_verified=False,
                ),
            }
        )
        runner = CodexRunner(
            probe=probe,
            executable_resolver=lambda _: executable,
            parent_environment={"PATH": "/tools", "HOME": "/home/test"},
        )

        with self.assertRaises(RunnerUnavailable) as raised:
            await runner.detect_capabilities()

        self.assertEqual(
            str(raised.exception),
            "Runner diagnostic process containment could not be verified.",
        )

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
        self.assertTrue(result.output_limit_exceeded)
        self.assertTrue(result.containment_cleanup_verified)

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
    def test_app_server_probe_rejects_invalid_resource_limits(self) -> None:
        for timeout in (True, 0, -1, float("inf"), 61):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                CodexAppServerBillingProbe(timeout_seconds=timeout)
        for maximum in (True, 0, -1, 1024 * 1024 + 1):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                CodexAppServerBillingProbe(max_output_bytes=maximum)

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

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_app_server_probe_stderr_overflow_fails_promptly(self) -> None:
        server_source = f"""#!{sys.executable}
import os
import time
os.write(2, b'x' * 200000)
time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-codex"
            executable.write_text(server_source, encoding="utf-8")
            executable.chmod(0o700)
            probe = CodexAppServerBillingProbe(
                timeout_seconds=5,
                max_output_bytes=1024,
            )
            started = time.monotonic()
            evidence = await probe.inspect(
                str(executable), environment={"PATH": "/usr/bin:/bin"}
            )
        self.assertIsNone(evidence)
        self.assertLess(time.monotonic() - started, 2.0)

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_app_server_probe_rejects_stderr_overflow_after_valid_reply(
        self,
    ) -> None:
        server_source = f"""#!{sys.executable}
import json
import os
import sys
import time
for line in sys.stdin:
    request = json.loads(line)
    request_id = request["id"]
    if request_id == 1:
        result = {{}}
    elif request_id == 2:
        result = {{"account": {{"type": "chatgpt", "planType": "pro"}}}}
    else:
        result = {{"rateLimits": {{"credits": {{"hasCredits": False, "unlimited": False, "balance": "0"}}, "primary": {{"usedPercent": 1}}, "rateLimitReachedType": None}}}}
    print(json.dumps({{"id": request_id, "result": result}}), flush=True)
    if request_id == 3:
        os.write(2, b'x' * 200000)
        time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-codex"
            executable.write_text(server_source, encoding="utf-8")
            executable.chmod(0o700)
            probe = CodexAppServerBillingProbe(
                timeout_seconds=5,
                max_output_bytes=1024,
            )
            evidence = await probe.inspect(
                str(executable), environment={"PATH": "/usr/bin:/bin"}
            )

        self.assertIsNone(evidence)

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_app_server_probe_rejects_stdout_overflow_after_valid_reply(
        self,
    ) -> None:
        server_source = f"""#!{sys.executable}
import json
import os
import sys
import time
for line in sys.stdin:
    request = json.loads(line)
    request_id = request["id"]
    if request_id == 1:
        result = {{}}
    elif request_id == 2:
        result = {{"account": {{"type": "chatgpt", "planType": "pro"}}}}
    else:
        result = {{"rateLimits": {{"credits": {{"hasCredits": False, "unlimited": False, "balance": "0"}}, "primary": {{"usedPercent": 1}}, "rateLimitReachedType": None}}}}
    print(json.dumps({{"id": request_id, "result": result}}), flush=True)
    if request_id == 3:
        os.write(1, b'x' * 200000)
        time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-codex"
            executable.write_text(server_source, encoding="utf-8")
            executable.chmod(0o700)
            probe = CodexAppServerBillingProbe(
                timeout_seconds=5,
                max_output_bytes=1024,
            )
            evidence = await probe.inspect(
                str(executable), environment={"PATH": "/usr/bin:/bin"}
            )

        self.assertIsNone(evidence)

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_app_server_probe_counts_messages_after_valid_reply(
        self,
    ) -> None:
        server_source = f"""#!{sys.executable}
import json
import sys
import time
for line in sys.stdin:
    request = json.loads(line)
    request_id = request["id"]
    if request_id == 1:
        result = {{}}
    elif request_id == 2:
        result = {{"account": {{"type": "chatgpt", "planType": "pro"}}}}
    else:
        result = {{"rateLimits": {{"credits": {{"hasCredits": False, "unlimited": False, "balance": "0"}}, "primary": {{"usedPercent": 1}}, "rateLimitReachedType": None}}}}
    print(json.dumps({{"id": request_id, "result": result}}), flush=True)
    if request_id == 3:
        for sequence in range(300):
            print(json.dumps({{"method": "notice", "params": sequence}}))
        sys.stdout.flush()
        time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "fake-codex"
            executable.write_text(server_source, encoding="utf-8")
            executable.chmod(0o700)
            probe = CodexAppServerBillingProbe(timeout_seconds=5)
            evidence = await probe.inspect(
                str(executable), environment={"PATH": "/usr/bin:/bin"}
            )

        self.assertIsNone(evidence)

    async def test_app_server_task_settling_defers_fresh_cancellation(
        self,
    ) -> None:
        protocol_task = asyncio.create_task(asyncio.sleep(60))
        stderr_task = asyncio.create_task(asyncio.sleep(60))
        wait_task = asyncio.create_task(asyncio.sleep(60))
        overflow_task = asyncio.create_task(asyncio.sleep(60))
        settle_task = asyncio.create_task(
            codex_module._settle_codex_billing_tasks(
                protocol_task,
                stderr_task,
                wait_task,
                overflow_task,
            )
        )
        await asyncio.sleep(0.01)

        settle_task.cancel()
        settle_task.cancel()
        cancellation_deferred, tasks_settled = await asyncio.wait_for(
            settle_task, timeout=2.0
        )

        self.assertTrue(cancellation_deferred)
        self.assertTrue(tasks_settled)
        self.assertEqual(settle_task.cancelling(), 2)
        self.assertTrue(protocol_task.done())
        self.assertTrue(stderr_task.done())
        self.assertTrue(wait_task.done())
        self.assertTrue(overflow_task.done())

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_app_server_cancellation_requires_verified_cleanup(self) -> None:
        real_terminate = codex_module.terminate_contained_process

        async def uncertain_after_cleanup(*args, **kwargs) -> CleanupResult:
            cleanup = await real_terminate(*args, **kwargs)
            return replace(
                cleanup,
                disposition=CleanupDisposition.UNCERTAIN,
                reason_code="fixture_cleanup_unknown",
                process_group_absent=False,
            )

        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            active_path = temporary_path / "active.txt"
            server_source = f"""#!{sys.executable}
import pathlib
import time
pathlib.Path({str(active_path)!r}).write_text('active')
time.sleep(60)
"""
            executable = temporary_path / "fake-codex"
            executable.write_text(server_source, encoding="utf-8")
            executable.chmod(0o700)
            probe = CodexAppServerBillingProbe(timeout_seconds=10)
            task = asyncio.create_task(
                probe.inspect(
                    str(executable), environment={"PATH": "/usr/bin:/bin"}
                )
            )
            for _ in range(200):
                if active_path.exists():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(active_path.exists())

            with mock.patch.object(
                codex_module,
                "terminate_contained_process",
                new=uncertain_after_cleanup,
            ):
                task.cancel()
                with self.assertRaises(ProbeContainmentError) as raised:
                    await asyncio.wait_for(task, timeout=3.0)

        self.assertEqual(
            str(raised.exception),
            "diagnostic process-group cleanup could not be verified",
        )

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_app_server_probe_cancellation_removes_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            identity_path = temporary_path / "process-group.txt"
            child_source = "import time; time.sleep(60)"
            server_source = f"""#!{sys.executable}
import os
import pathlib
import subprocess
import sys
import time
subprocess.Popen([sys.executable, "-c", {child_source!r}])
pathlib.Path({str(identity_path)!r}).write_text(str(os.getpgrp()))
time.sleep(60)
"""
            executable = temporary_path / "fake-codex"
            executable.write_text(server_source, encoding="utf-8")
            executable.chmod(0o700)
            probe = CodexAppServerBillingProbe(timeout_seconds=10)
            task = asyncio.create_task(
                probe.inspect(
                    str(executable), environment={"PATH": "/usr/bin:/bin"}
                )
            )
            process_group_id: int | None = None
            try:
                for _ in range(200):
                    if identity_path.exists():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(identity_path.exists())
                process_group_id = int(identity_path.read_text())
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=3.0)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process_group_id, 0)
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                if process_group_id is not None:
                    try:
                        os.killpg(process_group_id, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


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
    def test_controller_event_sink_is_sealed_and_bounded(self) -> None:
        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):

            class InvalidSink(ControllerEventSink):
                pass

        sink = ControllerEventSink()
        event = AgentEvent("result", {})
        for _ in range(CONTROLLER_EVENT_SINK_LIMIT):
            sink(event)
        self.assertEqual(sink.count, CONTROLLER_EVENT_SINK_LIMIT)
        with self.assertRaisesRegex(ValidationError, "controller limit"):
            sink(event)

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
                await runner.execute(request(Path(temporary)), ControllerEventSink())


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
                await runner.execute(request(Path(temporary)), ControllerEventSink())

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
                await runner.execute(request(Path(temporary)), ControllerEventSink())


class LiveHarnessSafetyTests(unittest.IsolatedAsyncioTestCase):
    def test_cleanup_limits_must_fit_the_billing_reservation_budget(self) -> None:
        with self.assertRaisesRegex(ValueError, "billing-safe cleanup budget"):
            HarnessProcessLimits(
                term_grace_seconds=2.0,
                kill_grace_seconds=2.0,
                stream_settle_seconds=1.1,
            )

    async def test_native_async_sink_is_rejected_before_reservation_or_launch(
        self,
    ) -> None:
        guard = RecordingBillingCircuitGuard()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            marker = workspace / "must-not-launch"
            runner = LocalScriptHarness(
                f"import pathlib; pathlib.Path({str(marker)!r}).touch()",
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )

            async def cancellation_resistant_sink(_: AgentEvent) -> None:
                while True:
                    try:
                        await asyncio.sleep(60)
                    except asyncio.CancelledError:
                        continue

            with self.assertRaisesRegex(
                ValidationError, "event sink must be controller-owned"
            ):
                await runner.execute(request(workspace), cancellation_resistant_sink)

            self.assertFalse(marker.exists())
            self.assertFalse(runner.schema_path(request(workspace)).exists())
            self.assertFalse(runner._active_processes)
            self.assertFalse(runner._executing_runs)
            self.assertFalse(runner._run_directory_descriptors)
            self.assertEqual(guard.ttls, [])

    async def test_run_directory_must_be_owner_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            workspace.chmod(0o755)
            runner = LocalScriptHarness(
                "raise AssertionError('must not start')",
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            try:
                with self.assertRaisesRegex(
                    ValidationError, "Run directory lease could not be verified"
                ):
                    await runner.execute(request(workspace), ControllerEventSink())
            finally:
                workspace.chmod(0o700)

        self.assertFalse(runner._active_processes)
        self.assertFalse(runner._run_directory_descriptors)

    async def test_controller_task_settlement_is_bounded_and_reports_unsettled(
        self,
    ) -> None:
        cancellation_seen = asyncio.Event()
        release_cancellation = asyncio.Event()

        async def delayed_cancellation() -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await release_cancellation.wait()

        task = asyncio.create_task(delayed_cancellation())
        await asyncio.sleep(0)
        started = time.monotonic()
        cancellation_deferred, tasks_settled = (
            await harness_module._settle_harness_tasks(
                task,
                timeout_seconds=0.01,
            )
        )
        elapsed = time.monotonic() - started

        self.assertTrue(cancellation_seen.is_set())
        self.assertFalse(task.done())
        self.assertFalse(cancellation_deferred)
        self.assertFalse(tasks_settled)
        self.assertLess(elapsed, 0.2)

        release_cancellation.set()
        await asyncio.wait_for(task, timeout=0.5)
        self.assertTrue(task.done())

    async def test_controller_task_settlement_proof_failure_quarantines(
        self,
    ) -> None:
        guard = RecordingBillingCircuitGuard()
        real_settle = harness_module._settle_harness_tasks

        async def report_unsettled(*tasks, timeout_seconds: float):
            cancellation_deferred, tasks_settled = await real_settle(
                *tasks,
                timeout_seconds=timeout_seconds,
            )
            self.assertTrue(tasks_settled)
            return cancellation_deferred, False

        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                "import sys,time; sys.stdin.read(); time.sleep(30)",
                billing_circuit_guard=guard,
                process_limits=HarnessProcessLimits(
                    term_grace_seconds=0.05,
                    kill_grace_seconds=0.5,
                    stream_settle_seconds=0.2,
                ),
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            run_request = replace(
                request(Path(temporary)),
                timeout_seconds=1,
            )
            with mock.patch.object(
                harness_module,
                "_settle_harness_tasks",
                new=report_unsettled,
            ):
                result = await runner.execute(run_request, ControllerEventSink())

        self.assertEqual(result.status, RunStatus.QUARANTINED)
        self.assertIsNone(result.output)
        self.assertEqual(
            result.paid_capacity_consumed,
            PaidCapacityConsumed.UNKNOWN,
        )
        self.assertEqual(
            result.incremental_ai_charge,
            IncrementalAICharge.UNKNOWN,
        )
        self.assertIn(
            "Harness controller task settlement could not be verified.",
            result.errors,
        )
        self.assertIn(
            "Harness execution outcome could not be verified.",
            result.errors,
        )
        self.assertEqual(
            result.billing_disposition_reasons,
            ("harness_execution_outcome_unknown",),
        )
        self.assertTrue(result.billing_quarantine_required)
        self.assertTrue(result.billing_circuit_breaker_required)
        self.assertEqual(len(guard.completions), 1)
        self.assertEqual(
            guard.completions[0]["capacity_state"],
            CapacityState.UNKNOWN,
        )
        self.assertEqual(
            guard.completions[0]["capacity_reason_code"],
            "post_run_billing_unknown",
        )
        self.assertTrue(guard.completions[0]["broad_scope_required"])
        self.assertFalse(runner._active_processes)
        self.assertFalse(runner._run_directory_descriptors)

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
                await runner.execute(request(workspace), ControllerEventSink())
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
            result = await runner.execute(request(Path(temporary)), ControllerEventSink())
        self.assertEqual(result.status, RunStatus.SUCCEEDED)
        self.assertEqual(guard.ttls, [95.0])
        self.assertEqual(len(guard.completions), 1)
        completion = guard.completions[0]
        self.assertEqual(completion["capacity_state"], CapacityState.AVAILABLE)
        self.assertEqual(
            completion["capacity_reason_code"], "post_run_capacity_available"
        )
        self.assertFalse(completion["circuit_breaker_required"])

    async def test_postflight_timeout_quarantines_inside_reservation_budget(
        self,
    ) -> None:
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
            inspect_billing_route = runner.inspect_billing_route

            async def delayed_postflight() -> BillingRouteAssessment:
                assessment = await inspect_billing_route()
                if runner.billing_inspections > 1:
                    await asyncio.sleep(1)
                return assessment

            runner.inspect_billing_route = delayed_postflight  # type: ignore[method-assign]
            started = time.monotonic()
            with mock.patch(
                "ordomata.runners._harness._BILLING_POSTFLIGHT_BUDGET_SECONDS",
                0.05,
            ):
                result = await runner.execute(
                    request(Path(temporary)), ControllerEventSink()
                )

        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(guard.ttls, [95.0])
        self.assertEqual(result.status, RunStatus.QUARANTINED)
        self.assertIsNone(result.postflight_billing_assessment)
        self.assertTrue(result.billing_quarantine_required)
        self.assertTrue(result.billing_circuit_breaker_required)
        self.assertTrue(guard.completions[0]["broad_scope_required"])

    async def test_short_reservation_is_rejected_and_directory_fd_is_closed(
        self,
    ) -> None:
        class ShortReservationGuard(RecordingBillingCircuitGuard):
            def reserve_dispatch(self, *args, **kwargs):
                reservation = super().reserve_dispatch(*args, **kwargs)
                return replace(
                    reservation,
                    expires_at=reservation.acquired_at + 1.0,
                )

        guard = ShortReservationGuard()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            marker = workspace / "must-not-launch"
            runner = LocalScriptHarness(
                f"import pathlib; pathlib.Path({str(marker)!r}).touch()",
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            captured_descriptors: list[int] = []
            prepare_run_files = runner._prepare_run_files

            def capturing_prepare(run_request: RunRequest) -> None:
                prepare_run_files(run_request)
                captured_descriptors.append(
                    runner._run_directory_descriptors[run_request.run_id]
                )

            runner._prepare_run_files = capturing_prepare  # type: ignore[method-assign]
            with self.assertRaisesRegex(
                BillingRouteBlocked, "does not cover the governed run"
            ):
                await runner.execute(request(workspace), ControllerEventSink())

            self.assertEqual(guard.ttls, [95.0])
            self.assertEqual(len(captured_descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(captured_descriptors[0])
            self.assertFalse(marker.exists())
            self.assertFalse(runner._run_directory_descriptors)
            self.assertEqual(len(guard.completions), 1)
            self.assertTrue(guard.completions[0]["broad_scope_required"])

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
                runner.execute(request(workspace), ControllerEventSink())
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

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_cancel_during_launch_collects_cleanup_before_returning(self) -> None:
        guard = RecordingBillingCircuitGuard()
        real_create_subprocess_exec = asyncio.create_subprocess_exec
        process_created = asyncio.Event()
        release_creation = asyncio.Event()
        created_process_group: list[int] = []

        async def delayed_creation(*args, **kwargs):
            process = await real_create_subprocess_exec(*args, **kwargs)
            created_process_group.append(process.pid)
            process_created.set()
            await release_creation.wait()
            return process

        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                "import time; time.sleep(30)",
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            with mock.patch.object(
                containment_module.asyncio,
                "create_subprocess_exec",
                new=delayed_creation,
            ):
                execute_task = asyncio.create_task(
                    runner.execute(request(Path(temporary)), ControllerEventSink())
                )
                await asyncio.wait_for(process_created.wait(), timeout=2.0)
                cancel_task = asyncio.create_task(runner.cancel("run-1"))
                await asyncio.sleep(0)
                self.assertFalse(cancel_task.done())
                release_creation.set()
                await asyncio.wait_for(cancel_task, timeout=3.0)
                with self.assertRaises(asyncio.CancelledError):
                    await execute_task

        self.assertEqual(len(created_process_group), 1)
        with self.assertRaises(ProcessLookupError):
            os.killpg(created_process_group[0], 0)
        self.assertFalse(runner._active_processes)
        self.assertFalse(runner._executing_runs)
        self.assertEqual(len(guard.completions), 1)
        self.assertTrue(guard.completions[0]["broad_scope_required"])
        self.assertEqual(
            guard.completions[0]["reason_code"],
            "billing_dispatch_interrupted",
        )

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_cancelling_cancel_waits_for_launch_cleanup(self) -> None:
        guard = RecordingBillingCircuitGuard()
        real_create_subprocess_exec = asyncio.create_subprocess_exec
        process_created = asyncio.Event()
        release_creation = asyncio.Event()
        created_process_group: list[int] = []

        async def delayed_creation(*args, **kwargs):
            process = await real_create_subprocess_exec(*args, **kwargs)
            created_process_group.append(process.pid)
            process_created.set()
            await release_creation.wait()
            return process

        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                "import time; time.sleep(30)",
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            with mock.patch.object(
                containment_module.asyncio,
                "create_subprocess_exec",
                new=delayed_creation,
            ):
                execute_task = asyncio.create_task(
                    runner.execute(request(Path(temporary)), ControllerEventSink())
                )
                await asyncio.wait_for(process_created.wait(), timeout=2.0)
                cancel_task = asyncio.create_task(runner.cancel("run-1"))
                await asyncio.sleep(0)
                cancel_task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(cancel_task.done())
                release_creation.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(cancel_task, timeout=3.0)
                with self.assertRaises(asyncio.CancelledError):
                    await execute_task

        self.assertEqual(len(created_process_group), 1)
        with self.assertRaises(ProcessLookupError):
            os.killpg(created_process_group[0], 0)
        self.assertFalse(runner._active_processes)
        self.assertFalse(runner._executing_runs)
        self.assertFalse(runner._run_directory_descriptors)
        self.assertEqual(len(guard.completions), 1)
        self.assertTrue(guard.completions[0]["broad_scope_required"])

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_cancel_reports_unverified_cleanup(self) -> None:
        guard = RecordingBillingCircuitGuard()

        async def uncertain_cleanup(*_args, **_kwargs) -> CleanupResult:
            return CleanupResult(
                disposition=CleanupDisposition.UNCERTAIN,
                reason_code="fixture_cleanup_unknown",
                term_sent=False,
                kill_sent=False,
                direct_child_reaped=False,
                process_group_absent=False,
                returncode=None,
            )

        script = (
            "import json,sys,time; sys.stdin.read(); time.sleep(0.2); "
            "print(json.dumps({'type':'turn.completed'}), flush=True)"
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
            execute_task = asyncio.create_task(
                runner.execute(request(Path(temporary)), ControllerEventSink())
            )
            for _ in range(100):
                if runner._active_processes:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(runner._active_processes)
            with mock.patch(
                "ordomata.runners._harness.terminate_contained_process",
                new=uncertain_cleanup,
            ):
                with self.assertRaises(HarnessCancellationError) as raised:
                    await runner.cancel("run-1")
                result = await asyncio.wait_for(execute_task, timeout=2.0)

        self.assertEqual(
            str(raised.exception),
            "Harness process-group cancellation could not be verified.",
        )
        self.assertEqual(result.status, RunStatus.QUARANTINED)
        self.assertTrue(result.billing_circuit_breaker_required)
        self.assertTrue(guard.completions[0]["broad_scope_required"])
        self.assertFalse(runner._active_processes)
        self.assertFalse(runner._run_directory_descriptors)

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_direct_exit_with_pipe_holding_descendant_is_quarantined(
        self,
    ) -> None:
        guard = RecordingBillingCircuitGuard()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            identity_path = workspace / "process-group.txt"
            child_source = "import time; time.sleep(30)"
            script = (
                "import json,os,pathlib,subprocess,sys; "
                "sys.stdin.read(); "
                f"subprocess.Popen([sys.executable, '-c', {child_source!r}]); "
                f"pathlib.Path({str(identity_path)!r}).write_text(str(os.getpgrp())); "
                "print(json.dumps({'type':'turn.completed'}), flush=True)"
            )
            runner = LocalScriptHarness(
                script,
                billing_circuit_guard=guard,
                process_limits=HarnessProcessLimits(
                    term_grace_seconds=0.1,
                    kill_grace_seconds=0.5,
                    stream_settle_seconds=0.2,
                ),
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            process_group_id: int | None = None
            started = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    runner.execute(request(workspace), ControllerEventSink()),
                    timeout=4.0,
                )
                elapsed = time.monotonic() - started
                process_group_id = int(identity_path.read_text())
                self.assertLess(elapsed, 2.0)
                self.assertEqual(result.status, RunStatus.QUARANTINED)
                self.assertIsNone(result.output)
                self.assertEqual(
                    result.billing_disposition_reasons,
                    ("harness_execution_outcome_unknown",),
                )
                self.assertTrue(result.billing_circuit_breaker_required)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process_group_id, 0)
            finally:
                if process_group_id is not None:
                    try:
                        os.killpg(process_group_id, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        self.assertTrue(guard.completions[0]["broad_scope_required"])

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_harness_stream_limit_is_bounded_and_opens_broad_circuit(
        self,
    ) -> None:
        guard = RecordingBillingCircuitGuard()
        script = (
            "import json,sys,time; sys.stdin.read(); "
            "line=json.dumps({'type':'progress','payload':'x'*80}); "
            "[(print(line, flush=True)) for _ in range(100)]; time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = LocalScriptHarness(
                script,
                billing_circuit_guard=guard,
                process_limits=HarnessProcessLimits(
                    stdout_bytes=2048,
                    stderr_bytes=256,
                    event_line_bytes=256,
                    physical_line_count=16,
                    event_count=3,
                    parse_error_count=2,
                    output_file_bytes=256,
                    term_grace_seconds=0.1,
                    kill_grace_seconds=0.5,
                    stream_settle_seconds=0.2,
                ),
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            started = time.monotonic()
            result = await runner.execute(request(Path(temporary)), ControllerEventSink())
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(result.status, RunStatus.QUARANTINED)
        self.assertLessEqual(len(result.events), 3)
        self.assertIsNone(result.output)
        self.assertIn("Harness output exceeded a controller limit.", result.errors)
        self.assertNotIn("x" * 40, repr(result.errors))
        self.assertEqual(
            result.billing_disposition_reasons,
            ("harness_execution_outcome_unknown",),
        )
        self.assertTrue(guard.completions[0]["broad_scope_required"])

    @unittest.skipUnless(
        hasattr(os, "O_NOFOLLOW") and posix_containment_available(),
        "safe no-follow output inspection is unavailable",
    )
    async def test_harness_output_symlink_is_not_followed(self) -> None:
        guard = RecordingBillingCircuitGuard()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "private-target.json"
            target.write_text('{"private":"must-not-return"}', encoding="utf-8")
            script = (
                "import json,os,pathlib,sys; sys.stdin.read(); "
                f"os.symlink({str(target)!r}, sys.argv[1]); "
                "print(json.dumps({'type':'turn.completed'}), flush=True)"
            )
            runner = LocalScriptHarness(
                script,
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            run_request = request(workspace)
            result = await runner.execute(run_request, ControllerEventSink())

            self.assertEqual(result.status, RunStatus.QUARANTINED)
            self.assertIsNone(result.output)
            self.assertNotIn("must-not-return", repr(result))
            self.assertTrue(target.is_file())
            self.assertFalse(runner.output_path(run_request).exists())
        self.assertEqual(
            result.billing_disposition_reasons,
            ("harness_execution_outcome_unknown",),
        )
        self.assertTrue(guard.completions[0]["broad_scope_required"])

    @unittest.skipUnless(
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and posix_containment_available(),
        "safe descriptor-relative output inspection is unavailable",
    )
    async def test_harness_output_ancestor_swap_is_not_followed_or_unlinked(
        self,
    ) -> None:
        guard = RecordingBillingCircuitGuard()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            workspace = parent / "run"
            renamed = parent / "renamed-run"
            external = parent / "external"
            workspace.mkdir(mode=0o700)
            external.mkdir()
            script = (
                "import json,os,pathlib,sys; sys.stdin.read(); "
                "run=pathlib.Path(sys.argv[2]); "
                "renamed=pathlib.Path(sys.argv[3]); "
                "external=pathlib.Path(sys.argv[4]); "
                "os.rename(run, renamed); os.symlink(external, run); "
                "(run / pathlib.Path(sys.argv[1]).name).write_text("
                "json.dumps({'private':'must-not-return'})); "
                "print(json.dumps({'type':'turn.completed'}), flush=True)"
            )
            runner = LocalScriptHarness(
                script,
                script_arguments=(str(workspace), str(renamed), str(external)),
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            run_request = request(workspace)
            try:
                result = await runner.execute(run_request, ControllerEventSink())
                external_output = external / "local-script-output.json"
                self.assertEqual(result.status, RunStatus.QUARANTINED)
                self.assertIsNone(result.output)
                self.assertNotIn("must-not-return", repr(result))
                self.assertTrue(external_output.is_file())
                self.assertEqual(
                    external_output.read_text(encoding="utf-8"),
                    '{"private": "must-not-return"}',
                )
                self.assertFalse(runner._run_directory_descriptors)
            finally:
                if workspace.is_symlink():
                    workspace.unlink()
                if renamed.exists() and not workspace.exists():
                    renamed.rename(workspace)
        self.assertEqual(
            result.billing_disposition_reasons,
            ("harness_execution_outcome_unknown",),
        )
        self.assertTrue(guard.completions[0]["broad_scope_required"])

    @unittest.skipUnless(
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and posix_containment_available(),
        "safe descriptor-relative output inspection is unavailable",
    )
    async def test_harness_output_name_swap_after_open_fails_closed(self) -> None:
        guard = RecordingBillingCircuitGuard()
        script = (
            "import json,pathlib,sys; sys.stdin.read(); "
            "pathlib.Path(sys.argv[1]).write_text("
            "json.dumps({'private':'must-not-return'})); "
            "print(json.dumps({'type':'turn.completed'}), flush=True)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            output_path = workspace / "local-script-output.json"
            moved_output = workspace / "moved-output.json"
            external_target = workspace / "external-target.json"
            external_target.write_text('{"safe":true}', encoding="utf-8")
            runner = LocalScriptHarness(
                script,
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            real_unlink = os.unlink
            swapped = False

            def swapping_unlink(path, *args, **kwargs):
                nonlocal swapped
                if (
                    not swapped
                    and path == "local-script-output.json"
                    and kwargs.get("dir_fd") is not None
                ):
                    swapped = True
                    output_path.rename(moved_output)
                    output_path.symlink_to(external_target)
                return real_unlink(path, *args, **kwargs)

            with mock.patch(
                "ordomata.runners._harness.os.unlink",
                new=swapping_unlink,
            ):
                result = await runner.execute(request(workspace), ControllerEventSink())

            self.assertTrue(swapped)
            self.assertEqual(result.status, RunStatus.QUARANTINED)
            self.assertIsNone(result.output)
            self.assertNotIn("must-not-return", repr(result))
            self.assertTrue(external_target.is_file())
            self.assertTrue(moved_output.is_file())
            self.assertTrue(result.billing_circuit_breaker_required)
            self.assertFalse(runner._run_directory_descriptors)
        self.assertTrue(guard.completions[0]["broad_scope_required"])

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_blocking_sink_is_rejected_without_invocation_before_launch(
        self,
    ) -> None:
        sink_called = False
        guard = RecordingBillingCircuitGuard()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            marker = workspace / "must-not-launch"
            runner = LocalScriptHarness(
                f"import pathlib; pathlib.Path({str(marker)!r}).touch()",
                billing_circuit_guard=guard,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )

            def blocking_sink(_: AgentEvent) -> None:
                nonlocal sink_called
                sink_called = True
                time.sleep(30)

            started = time.monotonic()
            with self.assertRaisesRegex(
                ValidationError, "event sink must be controller-owned"
            ):
                await runner.execute(request(workspace), blocking_sink)

            self.assertLess(time.monotonic() - started, 1.0)
            self.assertFalse(sink_called)
            self.assertFalse(marker.exists())
            self.assertEqual(guard.ttls, [])
        self.assertFalse(runner._active_processes)
        self.assertFalse(runner._run_directory_descriptors)

    @unittest.skipUnless(
        posix_containment_available(),
        "POSIX process-group containment is unavailable",
    )
    async def test_verified_timeout_kills_term_ignoring_process_group(self) -> None:
        guard = RecordingBillingCircuitGuard()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            identity_path = workspace / "process-group.txt"
            child_source = (
                "import signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
            )
            script = (
                "import os,pathlib,signal,subprocess,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"subprocess.Popen([sys.executable, '-c', {child_source!r}]); "
                f"pathlib.Path({str(identity_path)!r}).write_text(str(os.getpgrp())); "
                "sys.stdin.read(); time.sleep(30)"
            )
            runner = LocalScriptHarness(
                script,
                billing_circuit_guard=guard,
                process_limits=HarnessProcessLimits(
                    term_grace_seconds=0.05,
                    kill_grace_seconds=0.5,
                    stream_settle_seconds=0.2,
                ),
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            run_request = replace(request(workspace), timeout_seconds=1)
            process_group_id: int | None = None
            started = time.monotonic()
            try:
                result = await runner.execute(run_request, ControllerEventSink())
                process_group_id = int(identity_path.read_text())
                self.assertLess(time.monotonic() - started, 3.0)
                self.assertEqual(result.status, RunStatus.FAILED)
                self.assertIn("Harness execution timed out.", result.errors)
                self.assertFalse(result.billing_circuit_breaker_required)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process_group_id, 0)
            finally:
                if process_group_id is not None:
                    try:
                        os.killpg(process_group_id, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        self.assertFalse(guard.completions[0]["broad_scope_required"])

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
            result = await runner.execute(request(Path(temporary)), ControllerEventSink())
        self.assertEqual(result.status, RunStatus.SUCCEEDED)
        self.assertEqual(resolutions, ["resolved"])

    async def test_controller_event_sink_count_matches_returned_events(self) -> None:
        script = (
            "import json,pathlib,sys; sys.stdin.read(); "
            "pathlib.Path(sys.argv[1]).write_text('{}'); "
            "print(json.dumps({'type':'turn.completed'}))"
        )
        with tempfile.TemporaryDirectory() as temporary:
            sink = ControllerEventSink()
            runner = LocalScriptHarness(
                script,
                parent_environment={
                    "PATH": "/bin",
                    "HOME": "/safe/home",
                    "ORDOMATA_ALLOW_SUBSCRIPTION_RUNS": "1",
                },
            )
            result = await runner.execute(request(Path(temporary)), sink)
        self.assertEqual(result.status, RunStatus.SUCCEEDED)
        self.assertEqual(runner.billing_inspections, 2)
        self.assertEqual(sink.count, 1)
        self.assertEqual(sink.count, len(result.events))

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
            result = await runner.execute(request(Path(temporary)), ControllerEventSink())
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
            result = await runner.execute(run_request, ControllerEventSink())
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
                await runner.execute(request(workspace), ControllerEventSink())
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
            result = await runner.execute(request(workspace), ControllerEventSink())
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
            result = await runner.execute(run_request, ControllerEventSink())
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
