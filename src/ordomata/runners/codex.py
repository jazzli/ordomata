"""Subscription-only adapter for the first-party Codex CLI."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import math
import time
from typing import Any, Protocol

from ..billing import fingerprint_account_identity
from ..environment import inspect_risky_environment
from ..errors import ValidationError
from ..models import (
    AgentEvent,
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    CapacityState,
    EnvironmentValidation,
    PaidContinuationProtection,
    PaidCreditBalance,
    RunRequest,
    RunnerCapabilities,
)
from ..redaction import Redactor
from ._harness import (
    FirstPartyHarnessRunner,
    add_environment_findings,
    clean_version,
    validate_override_text,
)
from .base import parse_jsonl_event
from .containment import (
    CleanupResult,
    ContainedProcess,
    drain_bounded_stream,
    iter_bounded_lines,
    launch_contained_process,
    terminate_contained_process,
)
from .process import ProbeContainmentError


_ALLOWED_OVERRIDES = frozenset({"model", "reasoning_effort"})
_REASONING_EFFORTS = frozenset({"minimal", "low", "medium", "high", "xhigh"})
_CAPACITY_EVIDENCE_TTL_SECONDS = 5 * 60
_SUBSCRIPTION_PLAN_TYPES = frozenset(
    {"go", "plus", "pro", "prolite", "team", "business", "enterprise", "edu"}
)
_USAGE_BASED_PLAN_TYPES = frozenset(
    {"self_serve_business_usage_based", "enterprise_cbp_usage_based"}
)
_MAX_BILLING_PROBE_TIMEOUT_SECONDS = 60.0
_MAX_BILLING_PROBE_OUTPUT_BYTES = 1024 * 1024
_MAX_BILLING_PROBE_LINE_BYTES = 64 * 1024
_MAX_BILLING_PROBE_MESSAGE_COUNT = 256
_BILLING_PROBE_TERM_GRACE_SECONDS = 0.5
_BILLING_PROBE_KILL_GRACE_SECONDS = 0.5
_BILLING_PROBE_STREAM_SETTLE_SECONDS = 0.5


class _CodexBillingProbeLimitExceeded(RuntimeError):
    """A diagnostic-free internal signal for controller limit breaches."""


@dataclass(frozen=True, slots=True)
class CodexBillingEvidence:
    """Sanitized output of read-only Codex app-server account diagnostics."""

    route: BillingRoute
    capacity_state: CapacityState
    paid_credit_balance: PaidCreditBalance
    account_identity_fingerprint: str | None
    observed_at: float
    expires_at: float
    evidence: tuple[str, ...] = ()


class CodexBillingProbe(Protocol):
    async def inspect(
        self,
        executable: str,
        *,
        environment: Mapping[str, str],
    ) -> CodexBillingEvidence | None: ...


class CodexAppServerBillingProbe:
    """Read account and rate limits without starting a model turn.

    Raw account identities, numeric balances, and reset-credit identifiers are
    consumed only in memory and never returned, logged, or placed in errors.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 128 * 1024,
        clock=time.time,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > _MAX_BILLING_PROBE_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "timeout_seconds must be finite, positive, and no greater than "
                f"{_MAX_BILLING_PROBE_TIMEOUT_SECONDS}"
            )
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or max_output_bytes < 1
            or max_output_bytes > _MAX_BILLING_PROBE_OUTPUT_BYTES
        ):
            raise ValueError(
                "max_output_bytes must be a positive integer no greater than "
                f"{_MAX_BILLING_PROBE_OUTPUT_BYTES}"
            )
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes
        self._clock = clock

    async def inspect(
        self,
        executable: str,
        *,
        environment: Mapping[str, str],
    ) -> CodexBillingEvidence | None:
        contained: ContainedProcess | None = None
        protocol_task: asyncio.Task[CodexBillingEvidence] | None = None
        candidate_future: asyncio.Future[CodexBillingEvidence | None] | None = None
        stderr_task: asyncio.Task[Any] | None = None
        wait_task: asyncio.Task[int] | None = None
        overflow_task: asyncio.Task[bool] | None = None
        candidate: CodexBillingEvidence | None = None
        failed = False
        pending_interruption: BaseException | None = None
        cleanup: CleanupResult | None = None
        cleanup_cancellation_deferred = False
        overflow_event = asyncio.Event()
        try:
            async with asyncio.timeout(self._timeout_seconds):
                contained = await launch_contained_process(
                    (executable, "app-server", "--stdio"),
                    environment=environment,
                    stdin=asyncio.subprocess.PIPE,
                )
                process = contained.process
                assert process.stdin is not None
                assert process.stdout is not None
                assert process.stderr is not None
                stderr_task = asyncio.create_task(
                    drain_bounded_stream(
                        process.stderr,
                        max_bytes=self._max_output_bytes,
                        overflow_event=overflow_event,
                    )
                )
                candidate_future = asyncio.get_running_loop().create_future()
                protocol_task = asyncio.create_task(
                    _run_codex_billing_protocol(
                        process.stdin,
                        process.stdout,
                        maximum_bytes=self._max_output_bytes,
                        overflow_event=overflow_event,
                        candidate_future=candidate_future,
                        clock=self._clock,
                    )
                )
                wait_task = asyncio.create_task(process.wait())
                overflow_task = asyncio.create_task(overflow_event.wait())
                watched: set[asyncio.Future[Any]] = {
                    candidate_future,
                    protocol_task,
                    stderr_task,
                    wait_task,
                    overflow_task,
                }
                while candidate is None:
                    done, _ = await asyncio.wait(
                        watched,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if overflow_event.is_set():
                        raise _CodexBillingProbeLimitExceeded
                    if stderr_task in done:
                        stderr_result = stderr_task.result()
                        if stderr_result.truncated:
                            raise _CodexBillingProbeLimitExceeded
                        watched.remove(stderr_task)
                    if candidate_future in done:
                        candidate = candidate_future.result()
                        if candidate is None:
                            raise ValueError(
                                "Codex app-server billing protocol failed"
                            )
                        break
                    if protocol_task in done:
                        # Protocol completion before the candidate future is a
                        # failure; a raised task result stays sanitized here.
                        protocol_task.result()
                        raise ValueError(
                            "Codex app-server closed before billing evidence was ready"
                        )
                    if wait_task in done:
                        # A clean response can already be buffered when the
                        # direct process exits.  Keep consuming the bounded
                        # protocol stream; EOF will otherwise fail it closed.
                        wait_task.result()
                        watched.remove(wait_task)
        except asyncio.CancelledError as exc:
            pending_interruption = exc
        except Exception:
            failed = True
        except BaseException as exc:
            pending_interruption = exc

        if contained is not None:
            cleanup, cleanup_cancellation_deferred = (
                await _cleanup_codex_billing_process(contained)
            )
        if candidate_future is not None and not candidate_future.done():
            candidate_future.cancel()
        settle_cancellation_deferred, tasks_settled = (
            await _settle_codex_billing_tasks(
                protocol_task,
                stderr_task,
                wait_task,
                overflow_task,
            )
        )

        if contained is not None and (
            cleanup is None or not cleanup.verified or not tasks_settled
        ):
            raise ProbeContainmentError from None
        if pending_interruption is not None:
            raise pending_interruption
        if cleanup_cancellation_deferred or settle_cancellation_deferred:
            raise asyncio.CancelledError
        stderr_verified = False
        if (
            stderr_task is not None
            and stderr_task.done()
            and not stderr_task.cancelled()
        ):
            try:
                stderr_verified = not stderr_task.result().truncated
            except BaseException:
                stderr_verified = False
        protocol_verified = False
        if (
            protocol_task is not None
            and protocol_task.done()
            and not protocol_task.cancelled()
        ):
            try:
                protocol_verified = protocol_task.result() == candidate
            except BaseException:
                protocol_verified = False
        if (
            failed
            or candidate is None
            or cleanup is None
            or not protocol_verified
            or not stderr_verified
            or overflow_event.is_set()
        ):
            return None
        return candidate


class CodexRunner(FirstPartyHarnessRunner):
    """Run Codex only when ``codex login status`` proves ChatGPT auth."""

    def __init__(
        self,
        *,
        billing_probe: CodexBillingProbe | None = None,
        **kwargs,
    ) -> None:
        self._billing_probe = billing_probe or CodexAppServerBillingProbe()
        super().__init__(binary=kwargs.pop("binary", "codex"), **kwargs)

    @property
    def runner_id(self) -> str:
        return "codex"

    async def detect_capabilities(self) -> RunnerCapabilities:
        executable = self._resolved_binary()
        if executable is None:
            return RunnerCapabilities(runner_id=self.runner_id, installed=False)

        version_result = await self._run_probe((executable, "--version"))
        help_result = await self._run_probe((executable, "exec", "--help"))
        root_help_result = await self._run_probe((executable, "--help"))
        help_text = ""
        if help_result is not None and help_result.exit_code == 0:
            help_text = f"{help_result.stdout}\n{help_result.stderr}".lower()
        root_help_text = ""
        if root_help_result is not None and root_help_result.exit_code == 0:
            root_help_text = (
                f"{root_help_result.stdout}\n{root_help_result.stderr}".lower()
            )

        required_flags = (
            "--json",
            "--output-schema",
            "--sandbox",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
        )
        structured = ("jsonl",) if "--json" in help_text else ()
        sandbox_modes: list[str] = []
        if "--sandbox" in help_text:
            for mode in ("read-only", "workspace-write"):
                if mode in help_text:
                    sandbox_modes.append(mode)
        permissions: list[str] = []
        if "--ask-for-approval" in root_help_text:
            permissions.append("ask-for-approval")

        notes: list[str] = []
        if help_result is None or help_result.exit_code != 0:
            notes.append("Codex exec help could not be inspected.")
        if root_help_result is None or root_help_result.exit_code != 0:
            notes.append("Codex global help could not be inspected.")
        return RunnerCapabilities(
            runner_id=self.runner_id,
            installed=True,
            version=(
                clean_version(version_result.stdout or version_result.stderr)
                if version_result is not None and version_result.exit_code == 0
                else None
            ),
            non_interactive=(
                "usage" in help_text
                and "exec" in help_text
                and all(flag in help_text for flag in required_flags)
            ),
            structured_output_modes=structured,
            session_resume="resume" in help_text,
            sandbox_modes=tuple(sandbox_modes),
            permission_modes=tuple(permissions),
            usage_telemetry="usage" in help_text or bool(structured),
            scheduler_support=False,
            notes=tuple(notes),
        )

    async def inspect_billing_route(self) -> BillingRouteAssessment:
        risky = inspect_risky_environment(self._parent_environment())
        warnings = _risk_warnings(risky)
        executable = self._resolved_binary()
        if executable is None:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.HIGH,
                evidence=("Codex executable was not found.",),
                warnings=warnings,
                risky_environment_names=risky,
            ))

        result = await self._run_probe((executable, "login", "status"))
        if result is None or result.timed_out or result.exit_code != 0:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.LOW,
                evidence=("Codex authentication route could not be verified.",),
                warnings=warnings,
                risky_environment_names=risky,
            ))

        normalized = f"{result.stdout}\n{result.stderr}".casefold()
        compact = "".join(normalized.split())
        if _reports_api_auth(normalized, compact):
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.SEPARATELY_BILLED_API,
                confidence=AssessmentConfidence.HIGH,
                evidence=("Codex authentication diagnostic reports API authentication.",),
                warnings=warnings,
                risky_environment_names=risky,
            ))
        if _reports_chatgpt_auth(result.stdout, result.stderr):
            billing_evidence = await self._inspect_app_server_billing(executable)
            route = BillingRoute.SUBSCRIPTION_INCLUDED
            capacity_state = CapacityState.UNKNOWN
            paid_credit_balance = PaidCreditBalance.UNKNOWN
            account_fingerprint = None
            capacity_observed_at = None
            capacity_expires_at = None
            evidence = [
                "Codex authentication diagnostic reports ChatGPT authentication.",
                "Model API credentials are excluded from the child environment.",
            ]
            if billing_evidence is not None:
                if billing_evidence.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
                    route = billing_evidence.route
                capacity_state = billing_evidence.capacity_state
                paid_credit_balance = billing_evidence.paid_credit_balance
                account_fingerprint = billing_evidence.account_identity_fingerprint
                capacity_observed_at = billing_evidence.observed_at
                capacity_expires_at = billing_evidence.expires_at
                evidence.extend(billing_evidence.evidence)
            else:
                evidence.append(
                    "Codex app-server billing and capacity evidence was unavailable."
                )
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=route,
                confidence=AssessmentConfidence.HIGH,
                subscription_name="ChatGPT",
                evidence=tuple(evidence),
                warnings=warnings,
                risky_environment_names=risky,
                capacity_state=capacity_state,
                paid_continuation_protection=PaidContinuationProtection.UNKNOWN,
                paid_credit_balance=paid_credit_balance,
                account_identity_fingerprint=account_fingerprint,
                capacity_observed_at=capacity_observed_at,
                capacity_expires_at=capacity_expires_at,
            ))
        return self._apply_billing_attestation(BillingRouteAssessment(
            runner_id=self.runner_id,
            route=BillingRoute.UNKNOWN,
            confidence=AssessmentConfidence.LOW,
            evidence=("Codex authentication diagnostic was ambiguous.",),
            warnings=warnings,
            risky_environment_names=risky,
        ))

    async def _inspect_app_server_billing(
        self, executable: str
    ) -> CodexBillingEvidence | None:
        validation = self._environment_validation()
        if not validation.valid:
            return None
        try:
            return await self._billing_probe.inspect(
                executable,
                environment=validation.sanitized_environment,
            )
        except Exception:
            # Probe implementations are not allowed to surface raw account or
            # balance diagnostics through exception text.
            return None

    async def validate_environment(
        self, request: RunRequest
    ) -> EnvironmentValidation:
        validation = await super().validate_environment(request)
        missing = [
            name
            for name in ("HOME", "PATH")
            if name not in validation.sanitized_environment
        ]
        errors = (
            ("Codex child environment requires " + ", ".join(missing) + ".",)
            if missing
            else ()
        )
        return add_environment_findings(validation, errors=errors)

    def build_command(self, request: RunRequest) -> tuple[str, ...]:
        _reject_unknown_overrides(request.runner_overrides)
        executable = self._resolved_binary() or self._binary
        # The current workflow is prompt-in / structured-output-out and the
        # deterministic controller owns the only artifact write.  A Class 1
        # result therefore does not imply harness filesystem authority.  A
        # future repository-patch workflow must introduce and validate an
        # explicit write capability before this adapter may widen the sandbox.
        sandbox = "read-only"
        command = [
            executable,
            "--ask-for-approval",
            "never",
            "--sandbox",
            sandbox,
            "--cd",
            str(request.workspace),
            "exec",
            "--json",
            "--strict-config",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--output-schema",
            str(self.schema_path(request)),
        ]
        model = request.runner_overrides.get("model")
        if model is not None:
            command.extend(("--model", validate_override_text("model", model)))
        effort = request.runner_overrides.get("reasoning_effort")
        if effort is not None:
            effort = validate_override_text("reasoning_effort", effort)
            if effort not in _REASONING_EFFORTS:
                raise ValidationError("Unsupported Codex reasoning effort.")
            command.extend(("--config", f'model_reasoning_effort="{effort}"'))
        # The prompt is delivered over stdin and therefore never appears in the
        # process list, command audit, or shell history.
        command.append("-")
        return tuple(command)

    def parse_event_line(self, line: str, redactor: Redactor) -> AgentEvent | None:
        return parse_jsonl_event(line, redactor=redactor)

    def execution_mode(self, request: RunRequest) -> str:
        del request
        return "codex_exec_jsonl_read_only_ephemeral"

    def _read_output(self, request: RunRequest, events: list[AgentEvent]) -> Any:
        del request
        for event in reversed(events):
            if event.event_type != "item.completed":
                continue
            item = event.payload.get("item")
            if not isinstance(item, Mapping) or item.get("type") != "agent_message":
                continue
            text = item.get("text")
            if not isinstance(text, str):
                return None
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return None

    def terminal_success(self, events: tuple[AgentEvent, ...] | list[AgentEvent]) -> bool:
        return bool(events) and events[-1].event_type == "turn.completed"


async def _write_rpc_request(
    stdin: asyncio.StreamWriter,
    request: Mapping[str, Any],
) -> None:
    payload = json.dumps(request, separators=(",", ":"), sort_keys=True).encode("utf-8")
    stdin.write(payload + b"\n")
    await stdin.drain()


async def _run_codex_billing_protocol(
    stdin: asyncio.StreamWriter,
    stdout: asyncio.StreamReader,
    *,
    maximum_bytes: int,
    overflow_event: asyncio.Event,
    candidate_future: asyncio.Future[CodexBillingEvidence | None],
    clock: Callable[[], float],
) -> CodexBillingEvidence:
    lines = iter_bounded_lines(
        stdout,
        max_total_bytes=maximum_bytes,
        max_line_bytes=min(maximum_bytes, _MAX_BILLING_PROBE_LINE_BYTES),
        overflow_event=overflow_event,
    )
    observed_messages = [0]
    try:
        await _write_rpc_request(
            stdin,
            {
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "agentops-billing-probe",
                        "version": "0",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            },
        )
        await _read_rpc_result(
            lines,
            request_id=1,
            observed_messages=observed_messages,
        )
        await _write_rpc_request(
            stdin,
            {
                "id": 2,
                "method": "account/read",
                "params": {"refreshToken": False},
            },
        )
        account = await _read_rpc_result(
            lines,
            request_id=2,
            observed_messages=observed_messages,
        )
        await _write_rpc_request(
            stdin,
            {"id": 3, "method": "account/rateLimits/read", "params": None},
        )
        rate_limits = await _read_rpc_result(
            lines,
            request_id=3,
            observed_messages=observed_messages,
        )
        candidate = sanitize_codex_billing_snapshot(
            account,
            rate_limits,
            observed_at=clock(),
        )
        if not candidate_future.done():
            candidate_future.set_result(candidate)

        # Keep the one stdout consumer alive until cleanup closes the pipe.
        # This preserves aggregate-byte, per-line, and message-count
        # enforcement for output buffered or emitted after the final reply.
        async for line in lines:
            _decode_rpc_message(line, observed_messages=observed_messages)
        return candidate
    except BaseException:
        if not candidate_future.done():
            candidate_future.set_result(None)
        await _drain_failed_codex_protocol(lines, stdout)
        raise


async def _drain_failed_codex_protocol(
    lines: AsyncIterator[bytes],
    stdout: asyncio.StreamReader,
) -> None:
    """Release parser buffers and drain stdout without retaining diagnostics."""

    close_lines = getattr(lines, "aclose", None)
    if callable(close_lines):
        try:
            await close_lines()
        except BaseException:
            pass
    try:
        await drain_bounded_stream(stdout, max_bytes=0)
    except BaseException:
        pass


async def _read_rpc_result(
    lines: AsyncIterator[bytes],
    *,
    request_id: int,
    observed_messages: list[int],
) -> Mapping[str, Any]:
    async for line in lines:
        message = _decode_rpc_message(
            line,
            observed_messages=observed_messages,
        )
        if not isinstance(message, Mapping):
            continue
        response_id = message.get("id")
        if (
            isinstance(response_id, bool)
            or not isinstance(response_id, int)
            or response_id != request_id
        ):
            continue
        result = message.get("result")
        if not isinstance(result, Mapping) or "error" in message:
            raise ValueError("Codex app-server diagnostic request failed")
        return result
    raise ValueError("Codex app-server closed before a diagnostic response")


def _decode_rpc_message(
    line: bytes,
    *,
    observed_messages: list[int],
) -> Any:
    observed_messages[0] += 1
    if observed_messages[0] > _MAX_BILLING_PROBE_MESSAGE_COUNT:
        raise _CodexBillingProbeLimitExceeded
    try:
        return json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError(
            "Codex app-server returned an invalid diagnostic response"
        ) from None


async def _cleanup_codex_billing_process(
    contained: ContainedProcess,
) -> tuple[CleanupResult | None, bool]:
    async def cleanup() -> CleanupResult:
        stdin = contained.process.stdin
        if stdin is not None:
            try:
                stdin.close()
            except (OSError, RuntimeError):
                pass
        return await terminate_contained_process(
            contained,
            term_grace_seconds=_BILLING_PROBE_TERM_GRACE_SECONDS,
            kill_grace_seconds=_BILLING_PROBE_KILL_GRACE_SECONDS,
        )

    cleanup_task = asyncio.create_task(cleanup())
    cancellation_deferred = False
    while True:
        try:
            return await asyncio.shield(cleanup_task), cancellation_deferred
        except asyncio.CancelledError:
            if cleanup_task.cancelled():
                return None, True
            cancellation_deferred = True
        except BaseException:
            return None, cancellation_deferred


async def _settle_codex_billing_tasks(
    protocol_task: asyncio.Task[Any] | None,
    stderr_task: asyncio.Task[Any] | None,
    wait_task: asyncio.Task[Any] | None,
    overflow_task: asyncio.Task[Any] | None,
) -> tuple[bool, bool]:
    """Drain post-cleanup tasks, then cancel them within a fixed budget."""

    drained = tuple(
        task
        for task in (protocol_task, stderr_task, wait_task)
        if task is not None
    )
    present = drained + (() if overflow_task is None else (overflow_task,))
    if not present:
        return False, True

    # The overflow watcher has no EOF condition.  The remaining tasks must be
    # allowed to observe the pipe closures caused by verified process cleanup;
    # otherwise a limit crossed just after the final RPC response could be
    # hidden by eagerly cancelling the stderr drainer.
    if overflow_task is not None and not overflow_task.done():
        overflow_task.cancel()
    graceful = tuple(task for task in drained if not task.done())
    cancellation_deferred = False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _BILLING_PROBE_STREAM_SETTLE_SECONDS
    while graceful and not all(task.done() for task in graceful):
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            await asyncio.wait(
                graceful,
                timeout=remaining,
                return_when=asyncio.ALL_COMPLETED,
            )
        except asyncio.CancelledError:
            cancellation_deferred = True

    for task in present:
        if not task.done():
            task.cancel()
    settlement = asyncio.gather(*present, return_exceptions=True)
    deadline = loop.time() + _BILLING_PROBE_STREAM_SETTLE_SECONDS
    while not settlement.done():
        remaining = deadline - loop.time()
        if remaining <= 0:
            for task in present:
                if not task.done():
                    task.cancel()
            return cancellation_deferred, False
        try:
            await asyncio.wait(
                (settlement,),
                timeout=remaining,
                return_when=asyncio.ALL_COMPLETED,
            )
        except asyncio.CancelledError:
            cancellation_deferred = True
    return cancellation_deferred, True


def sanitize_codex_billing_snapshot(
    account_response: Mapping[str, Any],
    rate_limit_response: Mapping[str, Any],
    *,
    observed_at: float,
) -> CodexBillingEvidence:
    """Reduce app-server data to non-sensitive billing eligibility evidence."""

    route = BillingRoute.UNKNOWN
    fingerprint: str | None = None
    evidence: list[str] = []
    account = account_response.get("account")
    if isinstance(account, Mapping):
        account_type = account.get("type")
        if account_type == "apiKey":
            route = BillingRoute.SEPARATELY_BILLED_API
            evidence.append("Codex app-server reports API-key authentication.")
        elif account_type == "amazonBedrock":
            route = BillingRoute.CLOUD_PROVIDER_BILLING
            evidence.append("Codex app-server reports a cloud-provider account.")
        elif account_type == "chatgpt":
            plan_type = account.get("planType")
            if plan_type in _SUBSCRIPTION_PLAN_TYPES:
                route = BillingRoute.SUBSCRIPTION_INCLUDED
                evidence.append("Codex app-server reports a subscription plan.")
            elif plan_type in _USAGE_BASED_PLAN_TYPES:
                route = BillingRoute.SUBSCRIPTION_OVERAGE
                evidence.append("Codex app-server reports a usage-based plan.")
            else:
                evidence.append("Codex app-server plan type is not subscription-safe.")
            raw_identity = account.get("email")
            if isinstance(raw_identity, str) and raw_identity.strip():
                fingerprint = fingerprint_account_identity("codex", raw_identity)
                evidence.append("Codex account identity was fingerprinted in memory.")

    snapshot = rate_limit_response.get("rateLimits")
    capacity_state = CapacityState.UNKNOWN
    paid_balance = PaidCreditBalance.UNKNOWN
    if isinstance(snapshot, Mapping):
        paid_balance = _classify_credit_balance(snapshot.get("credits"))
        if paid_balance in {PaidCreditBalance.POSITIVE, PaidCreditBalance.UNLIMITED}:
            route = BillingRoute.PURCHASED_PRODUCT_CREDIT
            evidence.append("Codex app-server reports usable paid product credits.")
        elif paid_balance is PaidCreditBalance.ZERO:
            evidence.append("Codex app-server reports a zero paid-credit balance.")
        reached_type = snapshot.get("rateLimitReachedType")
        if reached_type in {
            "workspace_owner_credits_depleted",
            "workspace_member_credits_depleted",
        } and route is not BillingRoute.PURCHASED_PRODUCT_CREDIT:
            route = BillingRoute.UNKNOWN
            evidence.append(
                "Codex app-server reports an ambiguous workspace-credit depletion."
            )
        capacity_state = _classify_capacity(snapshot)
        if capacity_state is CapacityState.AVAILABLE:
            evidence.append("Codex app-server reports included capacity available.")
        elif capacity_state is CapacityState.LIMIT_REACHED:
            evidence.append("Codex app-server reports an included-capacity limit.")

    # rateLimitResetCredits is intentionally ignored. Those are free explicit
    # reset grants with a separate mutating consume RPC, which Ordomata never
    # invokes automatically and must not confuse with paid product credits.
    return CodexBillingEvidence(
        route=route,
        capacity_state=capacity_state,
        paid_credit_balance=paid_balance,
        account_identity_fingerprint=fingerprint,
        observed_at=float(observed_at),
        expires_at=float(observed_at) + _CAPACITY_EVIDENCE_TTL_SECONDS,
        evidence=tuple(evidence),
    )


def _classify_credit_balance(value: Any) -> PaidCreditBalance:
    if not isinstance(value, Mapping):
        return PaidCreditBalance.UNKNOWN
    has_credits = value.get("hasCredits")
    unlimited = value.get("unlimited")
    raw_balance = value.get("balance")
    if not isinstance(has_credits, bool) or not isinstance(unlimited, bool):
        return PaidCreditBalance.UNKNOWN
    if unlimited:
        return PaidCreditBalance.UNLIMITED
    if has_credits:
        return PaidCreditBalance.POSITIVE
    if not isinstance(raw_balance, str) or len(raw_balance) > 64:
        return PaidCreditBalance.UNKNOWN
    try:
        balance = Decimal(raw_balance.strip())
    except (InvalidOperation, ValueError):
        return PaidCreditBalance.UNKNOWN
    if not balance.is_finite() or balance < 0:
        return PaidCreditBalance.UNKNOWN
    if balance > 0:
        # A contradictory positive numeric balance still fails closed.
        return PaidCreditBalance.POSITIVE
    return PaidCreditBalance.ZERO


def _classify_capacity(snapshot: Mapping[str, Any]) -> CapacityState:
    reached_type = snapshot.get("rateLimitReachedType")
    if isinstance(reached_type, str) and reached_type in {
        "rate_limit_reached",
        "workspace_owner_usage_limit_reached",
        "workspace_member_usage_limit_reached",
    }:
        return CapacityState.LIMIT_REACHED
    primary = snapshot.get("primary")
    if not isinstance(primary, Mapping):
        return CapacityState.UNKNOWN
    used_percent = primary.get("usedPercent")
    if isinstance(used_percent, bool) or not isinstance(used_percent, int):
        return CapacityState.UNKNOWN
    if not 0 <= used_percent <= 100:
        return CapacityState.UNKNOWN
    return (
        CapacityState.LIMIT_REACHED
        if used_percent >= 100
        else CapacityState.AVAILABLE
    )


def _reports_chatgpt_auth(stdout: str, stderr: str) -> bool:
    """Recognize only the documented positive Codex status line."""

    lines = [
        line.strip().casefold().rstrip(".!")
        for line in f"{stdout}\n{stderr}".splitlines()
        if line.strip()
    ]
    return "logged in using chatgpt" in lines


def _reports_api_auth(normalized: str, compact: str) -> bool:
    phrases = (
        "api key",
        "api-key",
        "openai api",
        '"authmethod":"apikey"',
        '"auth_mode":"api_key"',
        '"authtype":"api_key"',
    )
    return any(phrase in normalized or phrase in compact for phrase in phrases)


def _risk_warnings(risky: tuple[str, ...]) -> tuple[str, ...]:
    relevant = tuple(
        name
        for name in risky
        if name.upper() in {"OPENAI_API_KEY", "CODEX_API_KEY"}
    )
    if not relevant:
        return ()
    return (
        "Risky Codex environment names were present in the parent and excluded: "
        + ", ".join(relevant),
    )


def _reject_unknown_overrides(overrides: Mapping[str, object]) -> None:
    unknown = sorted(set(overrides) - _ALLOWED_OVERRIDES)
    if unknown:
        raise ValidationError("Unsupported Codex runner overrides: " + ", ".join(unknown))


__all__ = [
    "CodexAppServerBillingProbe",
    "CodexBillingEvidence",
    "CodexBillingProbe",
    "CodexRunner",
    "sanitize_codex_billing_snapshot",
]
