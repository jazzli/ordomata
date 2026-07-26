"""Shared execution machinery for first-party subscription harnesses."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..billing import (
    BILLING_DISPATCH_COMPLETION_MARGIN_SECONDS,
    BillingAttestationLoader,
    BillingCircuitGuard,
    BillingDispatchReservation,
    BillingPolicy,
    BillingPostRunDisposition,
    LIVE_RUN_EVIDENCE_MARGIN_SECONDS,
)
from ..environment import build_child_environment, inspect_risky_environment
from ..errors import BillingRouteBlocked, RunnerUnavailable, ValidationError
from ..models import (
    AgentEvent,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    EnvironmentValidation,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PaidContinuationProtection,
    PermissionClass,
    RunRequest,
    RunnerCapabilities,
    RunnerExecutionResult,
    RunStatus,
    UsageObservation,
)
from ..redaction import Redactor
from ..schema import validate_instance
from .base import CommandProbe, EventSink, emit_event
from .process import AsyncCommandProbe


ExecutableResolver = Callable[[str], str | None]
_UNBOUND_EXECUTABLE = object()


class FirstPartyHarnessRunner(ABC):
    """Safe common implementation for live first-party CLI adapters."""

    def __init__(
        self,
        *,
        binary: str,
        probe: CommandProbe | None = None,
        parent_environment: Mapping[str, str] | None = None,
        approved_environment: Mapping[str, str] | None = None,
        executable_resolver: ExecutableResolver = shutil.which,
        billing_attestation: BillingSafetyAttestation | None = None,
        billing_attestation_loader: BillingAttestationLoader | None = None,
        billing_circuit_guard: BillingCircuitGuard | None = None,
        billing_clock: Callable[[], float] = time.time,
    ) -> None:
        self._binary = binary
        self._probe = probe or AsyncCommandProbe()
        self._fixed_parent_environment = (
            dict(parent_environment) if parent_environment is not None else None
        )
        self._approved_environment = dict(approved_environment or {})
        self._executable_resolver = executable_resolver
        self._billing_attestation = billing_attestation
        self._billing_attestation_loader = billing_attestation_loader
        self._billing_circuit_guard = billing_circuit_guard
        self._billing_clock = billing_clock
        self._bound_parent_environment: ContextVar[dict[str, str] | None] = ContextVar(
            f"agentops_parent_environment_{id(self)}", default=None
        )
        self._bound_executable: ContextVar[object | str | None] = ContextVar(
            f"agentops_executable_{id(self)}", default=_UNBOUND_EXECUTABLE
        )
        self._active_processes: dict[str, asyncio.subprocess.Process] = {}
        self._cancelled_runs: set[str] = set()

    @property
    @abstractmethod
    def runner_id(self) -> str: ...

    def _parent_environment(self) -> dict[str, str]:
        bound = self._bound_parent_environment.get()
        if bound is not None:
            return dict(bound)
        if self._fixed_parent_environment is not None:
            return dict(self._fixed_parent_environment)
        return dict(os.environ)

    def _environment_validation(self) -> EnvironmentValidation:
        return build_child_environment(
            self._parent_environment(), approved=self._approved_environment
        )

    def _resolved_binary(self) -> str | None:
        bound = self._bound_executable.get()
        if bound is not _UNBOUND_EXECUTABLE:
            return bound if isinstance(bound, str) else None
        resolved = self._executable_resolver(self._binary)
        return resolved if isinstance(resolved, str) and resolved else None

    async def _run_probe(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float = 10.0,
    ):
        validation = self._environment_validation()
        if not validation.valid:
            return None
        try:
            return await self._probe.run(
                command,
                environment=validation.sanitized_environment,
                timeout_seconds=timeout_seconds,
            )
        except (OSError, TimeoutError):
            return None

    @abstractmethod
    async def detect_capabilities(self) -> RunnerCapabilities: ...

    @abstractmethod
    async def inspect_billing_route(self) -> BillingRouteAssessment: ...

    def _apply_billing_attestation(
        self, assessment: BillingRouteAssessment
    ) -> BillingRouteAssessment:
        """Attach evidence without allowing it to override contradictory probes."""

        attestation = self._billing_attestation
        if attestation is None and self._billing_attestation_loader is not None:
            try:
                attestation = self._billing_attestation_loader.load(
                    assessment.runner_id,
                    assessment.account_identity_fingerprint,
                )
            except Exception:
                # A malformed or unavailable local attestation always means
                # no evidence; loader exception text is not retained.
                attestation = None
        if attestation is None:
            return assessment
        capacity_state = assessment.capacity_state
        capacity_observed_at = assessment.capacity_observed_at
        capacity_expires_at = assessment.capacity_expires_at
        if capacity_state is CapacityState.UNKNOWN:
            capacity_state = attestation.capacity_state
            capacity_observed_at = attestation.observed_at
            capacity_expires_at = attestation.expires_at
        protection = assessment.paid_continuation_protection
        if protection is PaidContinuationProtection.UNKNOWN:
            protection = attestation.paid_continuation_protection
        return replace(
            assessment,
            capacity_state=capacity_state,
            capacity_observed_at=capacity_observed_at,
            capacity_expires_at=capacity_expires_at,
            paid_continuation_protection=protection,
            attestation=attestation,
        )

    async def validate_environment(
        self, request: RunRequest
    ) -> EnvironmentValidation:
        del request
        return self._environment_validation()

    @abstractmethod
    def build_command(self, request: RunRequest) -> tuple[str, ...]: ...

    @abstractmethod
    def parse_event_line(self, line: str, redactor: Redactor) -> AgentEvent | None: ...

    def terminal_success(self, events: Sequence[AgentEvent]) -> bool:
        """Confirm a documented terminal-success event, not merely exit code zero."""

        del events
        return False

    def execution_mode(self, request: RunRequest) -> str:
        """Return a bounded adapter-authored label for audit accounting."""

        del request
        return "non_interactive_jsonl"

    def _read_output(self, request: RunRequest, events: list[AgentEvent]) -> Any:
        del events
        output_path = self.output_path(request)
        if not output_path.exists():
            return None
        raw = output_path.read_text(encoding="utf-8")
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def output_path(self, request: RunRequest) -> Path:
        return request.run_directory / f"{self.runner_id}-output.json"

    def schema_path(self, request: RunRequest) -> Path:
        return request.run_directory / "output-schema.json"

    def _prepare_run_files(self, request: RunRequest) -> None:
        if request.run_directory.is_symlink() or not request.run_directory.is_dir():
            raise ValidationError(
                "Run directory must be an existing, non-symlinked directory."
            )
        schema_path = self.schema_path(request)
        output_path = self.output_path(request)
        if schema_path.exists() or schema_path.is_symlink():
            raise ValidationError("Run schema path already exists.")
        if output_path.exists() or output_path.is_symlink():
            raise ValidationError("Run output path already exists.")
        schema = json.dumps(
            request.output_schema,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(schema_path, flags, 0o600)
        except OSError as exc:
            raise ValidationError("Run schema path could not be created safely.") from exc
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(schema + "\n")

    @staticmethod
    def _validate_request(request: RunRequest) -> None:
        if request.permission_class not in {
            PermissionClass.READ_ONLY,
            PermissionClass.LOCAL_DRAFT,
        }:
            raise ValidationError(
                "Only permission classes 0 (read-only) and 1 (local draft) are enabled."
            )
        if request.timeout_seconds < 1:
            raise ValidationError("Run timeout must be positive.")
        if not request.workspace.is_dir():
            raise ValidationError("Run workspace must be an existing directory.")
        if request.workspace.is_symlink() or request.run_directory.is_symlink():
            raise ValidationError("Run workspace and directory must not be symlinks.")
        if not request.run_directory.is_dir():
            raise ValidationError("Run directory must be an existing directory.")
        try:
            request.workspace.resolve().relative_to(request.run_directory.resolve())
        except ValueError as exc:
            raise ValidationError(
                "Live runner workspaces must be isolated inside the run directory."
            ) from exc
        if request.run_id == "" or request.task_id == "":
            raise ValidationError("Run and task identifiers must be non-empty.")

    async def execute(
        self, request: RunRequest, event_sink: EventSink
    ) -> RunnerExecutionResult:
        snapshot = (
            dict(self._fixed_parent_environment)
            if self._fixed_parent_environment is not None
            else dict(os.environ)
        )
        resolved = self._executable_resolver(self._binary)
        if not isinstance(resolved, str) or not resolved:
            resolved = None
        environment_token = self._bound_parent_environment.set(snapshot)
        executable_token = self._bound_executable.set(resolved)
        try:
            return await self._execute_with_bound_environment(request, event_sink)
        finally:
            self._bound_executable.reset(executable_token)
            self._bound_parent_environment.reset(environment_token)

    async def _execute_with_bound_environment(
        self, request: RunRequest, event_sink: EventSink
    ) -> RunnerExecutionResult:
        self._validate_request(request)
        if request.run_id in self._active_processes:
            raise ValidationError(f"Run {request.run_id!r} is already active.")

        capabilities = await self.detect_capabilities()
        if not capabilities.installed:
            raise RunnerUnavailable(f"Runner {self.runner_id!r} is not installed.")
        if not capabilities.non_interactive:
            raise RunnerUnavailable(
                f"Runner {self.runner_id!r} lacks non-interactive execution support."
            )
        if "jsonl" not in capabilities.structured_output_modes:
            raise RunnerUnavailable(
                f"Runner {self.runner_id!r} lacks required JSONL output support."
            )

        assessment = await self.inspect_billing_route()
        if assessment.runner_id != self.runner_id:
            raise BillingRouteBlocked(
                "Runner billing assessment identity does not match the selected adapter."
            )
        if assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
            raise BillingRouteBlocked(
                "First-party live harness adapters require a verified subscription route."
            )
        if self._billing_circuit_guard is None:
            raise BillingRouteBlocked(
                "Live subscription execution requires a durable billing circuit guard."
            )
        preflight_now = self._billing_clock()
        BillingPolicy.assert_live_run_allowed(
            assessment,
            environment=self._parent_environment(),
            now=preflight_now,
            required_valid_until=(
                preflight_now
                + request.timeout_seconds
                + LIVE_RUN_EVIDENCE_MARGIN_SECONDS
            ),
        )
        validation = await self.validate_environment(request)
        if not validation.valid:
            raise ValidationError("; ".join(validation.errors))

        parent = self._parent_environment()
        risky_values = [parent[name] for name in inspect_risky_environment(parent)]
        redactor = Redactor(risky_values)
        self._prepare_run_files(request)
        command = self.build_command(request)
        verified_executable = self._resolved_binary()
        if (
            verified_executable is None
            or not command
            or command[0] != verified_executable
        ):
            raise RunnerUnavailable(
                "Harness command does not use the executable verified in this dispatch."
            )
        reserve_dispatch = getattr(
            self._billing_circuit_guard, "reserve_dispatch", None
        )
        complete_dispatch = getattr(
            self._billing_circuit_guard, "complete_dispatch", None
        )
        if not callable(reserve_dispatch) or not callable(complete_dispatch):
            raise BillingRouteBlocked(
                "Live subscription execution requires an atomic billing dispatch reservation."
            )
        try:
            reservation = reserve_dispatch(
                assessment,
                owner_id=request.run_id,
                ttl_seconds=(
                    request.timeout_seconds
                    + BILLING_DISPATCH_COMPLETION_MARGIN_SECONDS
                ),
            )
        except BillingRouteBlocked:
            raise
        except Exception as exc:
            raise BillingRouteBlocked(
                "Billing dispatch reservation could not be verified."
            ) from exc
        if not isinstance(reservation, BillingDispatchReservation):
            raise BillingRouteBlocked(
                "Billing dispatch reservation is unavailable or invalid."
            )

        try:
            result = await self._execute_reserved(
                request=request,
                event_sink=event_sink,
                capabilities=capabilities,
                assessment=assessment,
                validation=validation,
                redactor=redactor,
                command=command,
            )
        except BaseException:
            await self._abort_active_process(request)
            self._finish_reservation_after_interruption(
                reservation,
                run_id=request.run_id,
            )
            raise

        try:
            capacity_state = _effective_billing_capacity(result)
            complete_dispatch(
                reservation,
                run_id=request.run_id,
                capacity_state=capacity_state,
                capacity_reason_code=_billing_capacity_reason(capacity_state),
                circuit_breaker_required=(
                    result.billing_circuit_breaker_required
                ),
                broad_scope_required=_broad_billing_scope_required(result),
                reason_code=_billing_circuit_reason(result),
            )
        except Exception:
            # A missing/lost reservation or failed durable finalization makes
            # the entire billing outcome unknown.  Retry once with the broadest
            # safe breaker request; the SQLite guard keeps the operation
            # idempotently fail-closed with respect to lease ownership.
            try:
                complete_dispatch(
                    reservation,
                    run_id=request.run_id,
                    capacity_state=CapacityState.UNKNOWN,
                    capacity_reason_code="billing_dispatch_finalization_failed",
                    circuit_breaker_required=True,
                    broad_scope_required=True,
                    reason_code="billing_dispatch_finalization_failed",
                )
            except Exception:
                pass
            result = replace(
                result,
                status=RunStatus.QUARANTINED,
                paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
                incremental_ai_charge=IncrementalAICharge.UNKNOWN,
                billing_quarantine_required=True,
                billing_circuit_breaker_required=True,
                billing_disposition_reasons=tuple(
                    dict.fromkeys(
                        (
                            *result.billing_disposition_reasons,
                            "billing_dispatch_finalization_failed",
                        )
                    )
                ),
                errors=tuple(
                    dict.fromkeys(
                        (
                            *result.errors,
                            "Billing dispatch finalization could not be verified.",
                        )
                    )
                ),
            )
        return result

    async def _execute_reserved(
        self,
        *,
        request: RunRequest,
        event_sink: EventSink,
        capabilities: RunnerCapabilities,
        assessment: BillingRouteAssessment,
        validation: EnvironmentValidation,
        redactor: Redactor,
        command: Sequence[str],
    ) -> RunnerExecutionResult:
        events: list[AgentEvent] = []
        parse_errors: list[str] = []
        stderr_text = ""
        timed_out = False
        launch_attempted = False
        execution_outcome_unknown = False

        process: asyncio.subprocess.Process | None = None
        stdout_task: asyncio.Task[None] | None = None
        stderr_task: asyncio.Task[str] | None = None
        execution_started_at = time.monotonic()
        try:
            async with asyncio.timeout(request.timeout_seconds):
                launch_attempted = True
                process = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=request.workspace,
                    env=dict(validation.sanitized_environment),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                self._active_processes[request.run_id] = process

                async def consume_stdout() -> None:
                    assert process is not None and process.stdout is not None
                    while line_bytes := await process.stdout.readline():
                        line = line_bytes.decode("utf-8", errors="replace")
                        try:
                            event = self.parse_event_line(line, redactor)
                        except ValidationError as exc:
                            parse_errors.append(str(exc))
                            continue
                        if event is not None:
                            events.append(event)
                            await emit_event(event_sink, event)

                async def consume_stderr() -> str:
                    assert process is not None and process.stderr is not None
                    raw = await process.stderr.read()
                    return redactor.redact_text(
                        raw.decode("utf-8", errors="replace")
                    )

                stdout_task = asyncio.create_task(consume_stdout())
                stderr_task = asyncio.create_task(consume_stderr())
                assert process.stdin is not None
                process.stdin.write(request.prompt.encode("utf-8"))
                await process.stdin.drain()
                process.stdin.close()
                await process.wait()
                await stdout_task
                stderr_text = await stderr_task
        except TimeoutError:
            timed_out = True
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            for task in (stdout_task, stderr_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (stdout_task, stderr_task) if task is not None),
                return_exceptions=True,
            )
        except Exception:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            for task in (stdout_task, stderr_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (stdout_task, stderr_task) if task is not None),
                return_exceptions=True,
            )
            self.output_path(request).unlink(missing_ok=True)
            # Once process creation has been attempted, an adapter, event-sink,
            # or stream-processing failure cannot prove whether provider-side
            # capacity was consumed. Preserve a sanitized result so the caller
            # can durably open the billing circuit instead of losing postflight
            # accounting to an exception path.
            execution_outcome_unknown = launch_attempted
        except BaseException:
            # Task cancellation and other BaseException paths must not orphan
            # a harness process or let the durable dispatch lease go before an
            # UNKNOWN billing breaker is recorded by the outer reservation
            # handler.
            if process is not None and process.returncode is None:
                process.kill()
            for task in (stdout_task, stderr_task):
                if task is not None and not task.done():
                    task.cancel()
            cleanup_tasks: list[asyncio.Future[Any] | asyncio.Task[Any]] = [
                task
                for task in (stdout_task, stderr_task)
                if task is not None
            ]
            if process is not None:
                cleanup_tasks.append(asyncio.ensure_future(process.wait()))
            if cleanup_tasks:
                cleanup = asyncio.gather(*cleanup_tasks, return_exceptions=True)
                try:
                    await asyncio.shield(cleanup)
                except BaseException:
                    # The cleanup future remains scheduled even if a second
                    # cancellation request interrupts this task.
                    pass
            try:
                self.output_path(request).unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            self._active_processes.pop(request.run_id, None)

        errors = list(parse_errors)
        if timed_out:
            errors.append("Harness execution timed out.")
        if execution_outcome_unknown:
            errors.append("Harness execution outcome could not be verified.")
        return_code = None if process is None else process.returncode
        if stderr_text.strip() and (return_code or 0) != 0:
            errors.append(stderr_text.strip()[:4_000])

        try:
            terminal_succeeded = self.terminal_success(events)
        except Exception:
            terminal_succeeded = False
            execution_outcome_unknown = True
            errors.append("Harness terminal state could not be verified.")
        cancelled = request.run_id in self._cancelled_runs
        self._cancelled_runs.discard(request.run_id)
        if cancelled:
            status = RunStatus.CANCELLED
        elif (
            timed_out
            or execution_outcome_unknown
            or process is None
            or (return_code or 0) != 0
            or parse_errors
        ):
            status = RunStatus.FAILED
        elif not terminal_succeeded:
            status = RunStatus.FAILED
            errors.append("Harness stream ended without a valid terminal-success event.")
        else:
            status = RunStatus.SUCCEEDED

        output: Any = None
        credential_material_detected = any(
            event.credential_material_detected for event in events
        )
        try:
            raw_output = self._read_output(request, events)
            output = redactor.redact(raw_output)
            credential_material_detected = (
                output != raw_output or credential_material_detected
            )
        except Exception:
            execution_outcome_unknown = True
            status = RunStatus.FAILED
            errors.append("Harness output could not be read safely.")
        finally:
            # Adapters that use a transient output path must never leave it
            # behind; Codex and Claude currently extract from in-memory events.
            try:
                self.output_path(request).unlink(missing_ok=True)
            except OSError:
                execution_outcome_unknown = True
                status = RunStatus.FAILED
                errors.append("Harness output could not be removed safely.")
        if status is RunStatus.SUCCEEDED:
            try:
                schema_result = validate_instance(output, request.output_schema)
            except Exception:
                execution_outcome_unknown = True
                status = RunStatus.FAILED
                errors.append(
                    "Harness output validation could not be completed safely."
                )
            else:
                if not schema_result.valid:
                    status = RunStatus.FAILED
                    errors.append(
                        "Harness output failed deterministic structured-output validation."
                    )
        usage = _collect_usage(events)
        if process is None:
            model_execution_observed: bool | None = False
        elif terminal_succeeded or usage:
            model_execution_observed = True
        else:
            # A spawned CLI alone does not prove that a model turn reached the
            # provider or consumed subscription capacity.
            model_execution_observed = None
        postflight_assessment: BillingRouteAssessment | None = None
        disposition = None
        if launch_attempted:
            try:
                postflight_assessment = await self.inspect_billing_route()
            except Exception:
                # Adapter exception text may contain provider diagnostics and
                # therefore must never be copied into the run result.
                postflight_assessment = None
            if execution_outcome_unknown:
                disposition = BillingPostRunDisposition(
                    capacity_state=CapacityState.UNKNOWN,
                    paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
                    incremental_ai_charge=IncrementalAICharge.UNKNOWN,
                    quarantine_required=True,
                    circuit_breaker_required=True,
                    reasons=(
                        "harness_launch_outcome_unknown"
                        if process is None
                        else "harness_execution_outcome_unknown",
                    ),
                )
            else:
                disposition = BillingPolicy.assess_post_run(
                    assessment,
                    postflight_assessment,
                    events,
                    now=self._billing_clock(),
                )
            if (
                postflight_assessment is not None
                and disposition.capacity_state is CapacityState.BLOCKED_UNTIL_RESET
            ):
                postflight_assessment = replace(
                    postflight_assessment,
                    capacity_state=CapacityState.BLOCKED_UNTIL_RESET,
                )
            if disposition.quarantine_required:
                status = RunStatus.QUARANTINED
                errors.append("Post-run billing evidence required quarantine.")
        return RunnerExecutionResult(
            runner_id=self.runner_id,
            run_id=request.run_id,
            status=status,
            billing_assessment=assessment,
            exit_code=return_code,
            session_id=_collect_session_id(events),
            output=output,
            usage=usage,
            usage_observation=(
                UsageObservation.OBSERVED if usage else UsageObservation.UNAVAILABLE
            ),
            events=tuple(events),
            errors=tuple(errors),
            credential_material_detected=credential_material_detected,
            runner_version=capabilities.version,
            execution_mode=self.execution_mode(request),
            harness_process_started=process is not None,
            live_model_execution_occurred=model_execution_observed,
            subscription_capacity_consumed=model_execution_observed,
            paid_capacity_consumed=(
                disposition.paid_capacity_consumed
                if disposition is not None
                else PaidCapacityConsumed.NO
            ),
            incremental_ai_charge=(
                disposition.incremental_ai_charge
                if disposition is not None
                else IncrementalAICharge.NONE
            ),
            postflight_billing_assessment=postflight_assessment,
            billing_quarantine_required=(
                disposition.quarantine_required if disposition is not None else False
            ),
            billing_circuit_breaker_required=(
                disposition.circuit_breaker_required
                if disposition is not None
                else False
            ),
            billing_disposition_reasons=(
                disposition.reasons if disposition is not None else ()
            ),
            wall_seconds=max(0.0, time.monotonic() - execution_started_at),
        )

    async def _abort_active_process(self, request: RunRequest) -> None:
        """Best-effort local cleanup before an interrupted reservation closes."""

        process = self._active_processes.pop(request.run_id, None)
        if process is not None and process.returncode is None:
            process.kill()
            try:
                await asyncio.shield(process.wait())
            except BaseException:
                pass
        try:
            self.output_path(request).unlink(missing_ok=True)
        except OSError:
            pass

    def _finish_reservation_after_interruption(
        self,
        reservation: BillingDispatchReservation,
        *,
        run_id: str,
    ) -> None:
        """Record UNKNOWN billing state before releasing an interrupted lease."""

        guard = self._billing_circuit_guard
        complete_dispatch = (
            None if guard is None else getattr(guard, "complete_dispatch", None)
        )
        if not callable(complete_dispatch):
            return
        try:
            complete_dispatch(
                reservation,
                run_id=run_id,
                capacity_state=CapacityState.UNKNOWN,
                capacity_reason_code="billing_dispatch_interrupted",
                circuit_breaker_required=True,
                broad_scope_required=True,
                reason_code="billing_dispatch_interrupted",
            )
        except Exception:
            # Do not release independently: retaining the lease until its TTL
            # is the only safe fallback when durable breaker recording fails.
            return

    async def cancel(self, run_id: str) -> None:
        process = self._active_processes.get(run_id)
        if process is None:
            return
        self._cancelled_runs.add(run_id)
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:
            process.kill()
            await process.wait()


def _broad_billing_scope_required(result: RunnerExecutionResult) -> bool:
    """Return whether identity uncertainty requires provider-wide blocking."""

    preflight_fingerprint = result.billing_assessment.account_identity_fingerprint
    postflight = result.postflight_billing_assessment
    postflight_fingerprint = (
        None if postflight is None else postflight.account_identity_fingerprint
    )
    return (
        not isinstance(preflight_fingerprint, str)
        or not isinstance(postflight_fingerprint, str)
        or postflight_fingerprint != preflight_fingerprint
    )


def _billing_circuit_reason(result: RunnerExecutionResult) -> str:
    """Map a runner disposition to one bounded, non-diagnostic reason code."""

    if result.paid_capacity_consumed is PaidCapacityConsumed.YES:
        return "post_run_paid_capacity_consumed"
    if result.incremental_ai_charge in {
        IncrementalAICharge.POSSIBLE,
        IncrementalAICharge.CONFIRMED,
    }:
        return "post_run_paid_route_possible"
    return "post_run_billing_evidence_unknown"


def _effective_billing_capacity(result: RunnerExecutionResult) -> CapacityState:
    """Return the sanitized capacity state that must be durable before unlock."""

    postflight = result.postflight_billing_assessment
    if not isinstance(postflight, BillingRouteAssessment):
        return CapacityState.UNKNOWN
    state = postflight.capacity_state
    return state if isinstance(state, CapacityState) else CapacityState.UNKNOWN


def _billing_capacity_reason(state: CapacityState) -> str:
    """Map capacity evidence to one bounded append-only ledger reason."""

    if state is CapacityState.AVAILABLE:
        return "post_run_capacity_available"
    if state in {CapacityState.LIMIT_REACHED, CapacityState.BLOCKED_UNTIL_RESET}:
        return "included_capacity_exhausted"
    if state is CapacityState.COOLDOWN:
        return "post_run_capacity_cooldown"
    return "post_run_billing_unknown"


def _collect_session_id(events: Sequence[AgentEvent]) -> str | None:
    for event in events:
        for name in ("thread_id", "session_id"):
            value = event.payload.get(name)
            if isinstance(value, str) and value:
                return value
    return None


def _collect_usage(events: Sequence[AgentEvent]) -> dict[str, Any]:
    for event in reversed(events):
        value = event.payload.get("usage")
        if isinstance(value, Mapping):
            return {str(key): item for key, item in value.items()}
        result = event.payload.get("result")
        if isinstance(result, Mapping) and isinstance(result.get("usage"), Mapping):
            return {str(key): item for key, item in result["usage"].items()}
    return {}


def clean_version(output: str) -> str | None:
    """Return a bounded, single-line version without carrying diagnostics."""

    for line in output.splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return None


def validate_override_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValidationError(f"Runner override {name!r} must be a short string.")
    if value.startswith("-") or "\x00" in value or "\n" in value or "\r" in value:
        raise ValidationError(f"Runner override {name!r} contains unsafe characters.")
    return value


def add_environment_findings(
    validation: EnvironmentValidation,
    *,
    errors: Sequence[str] = (),
    warnings: Sequence[str] = (),
) -> EnvironmentValidation:
    """Return a copy of a frozen validation with runner-specific findings."""

    combined_errors = (*validation.errors, *errors)
    return EnvironmentValidation(
        valid=validation.valid and not errors,
        sanitized_environment=dict(validation.sanitized_environment),
        retained_names=validation.retained_names,
        excluded_names=validation.excluded_names,
        errors=combined_errors,
        warnings=(*validation.warnings, *warnings),
    )


__all__ = [
    "FirstPartyHarnessRunner",
    "add_environment_findings",
    "clean_version",
    "validate_override_text",
]
