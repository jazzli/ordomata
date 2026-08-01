"""Shared execution machinery for first-party subscription harnesses."""

from __future__ import annotations

import asyncio
import json
import math
import os
import shutil
import stat
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
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
from .base import CommandProbe, ControllerEventSink, EventSink, emit_event
from .containment import (
    CleanupResult,
    ContainedProcess,
    ContainmentUnavailableError,
    ContainmentVerificationError,
    StreamLimitExceeded,
    iter_bounded_lines,
    launch_contained_process,
    require_containment_support,
    terminate_contained_process,
)
from .process import AsyncCommandProbe, ProbeContainmentError


ExecutableResolver = Callable[[str], str | None]
_UNBOUND_EXECUTABLE = object()
_MAX_HARNESS_CLEANUP_BUDGET_SECONDS = 5.0
_BILLING_POSTFLIGHT_BUDGET_SECONDS = 25.0
_BILLING_POSTFLIGHT_RECOVERY_BUDGET_SECONDS = 5.0
_BILLING_FINALIZATION_BUDGET_SECONDS = 10.0
_BILLING_COMPLETION_SLACK_SECONDS = 15.0
_BILLING_PRELAUNCH_SLACK_SECONDS = 5.0
_BILLING_RESERVATION_ACQUISITION_ALLOWANCE_SECONDS = 5.0

if (
    _MAX_HARNESS_CLEANUP_BUDGET_SECONDS
    + _BILLING_POSTFLIGHT_BUDGET_SECONDS
    + _BILLING_POSTFLIGHT_RECOVERY_BUDGET_SECONDS
    + _BILLING_FINALIZATION_BUDGET_SECONDS
    + _BILLING_COMPLETION_SLACK_SECONDS
    != BILLING_DISPATCH_COMPLETION_MARGIN_SECONDS
):  # pragma: no cover - import-time controller invariant
    raise RuntimeError("Live billing reservation budgets are inconsistent.")


@dataclass(frozen=True, slots=True)
class HarnessProcessLimits:
    """Controller-owned live-process resource ceilings."""

    stdout_bytes: int = 8 * 1024 * 1024
    stderr_bytes: int = 256 * 1024
    event_line_bytes: int = 1024 * 1024
    physical_line_count: int = 8192
    event_count: int = 4096
    parse_error_count: int = 64
    output_file_bytes: int = 1024 * 1024
    term_grace_seconds: float = 0.5
    kill_grace_seconds: float = 0.5
    stream_settle_seconds: float = 0.5

    def __post_init__(self) -> None:
        for name in (
            "stdout_bytes",
            "stderr_bytes",
            "event_line_bytes",
            "physical_line_count",
            "event_count",
            "parse_error_count",
            "output_file_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.event_line_bytes > self.stdout_bytes:
            raise ValueError("event_line_bytes must not exceed stdout_bytes")
        for name in (
            "term_grace_seconds",
            "kill_grace_seconds",
            "stream_settle_seconds",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
                or value > 10
            ):
                raise ValueError(f"{name} must be finite and between 0 and 10")
        if (
            self.term_grace_seconds
            + self.kill_grace_seconds
            + self.stream_settle_seconds
            > _MAX_HARNESS_CLEANUP_BUDGET_SECONDS
        ):
            raise ValueError(
                "process cleanup limits exceed the billing-safe cleanup budget"
            )


class _HarnessOutputLimitExceeded(RuntimeError):
    pass


class HarnessCancellationError(OSError):
    """A fixed failure to prove that an active harness was cancelled."""

    def __init__(self) -> None:
        super().__init__("Harness process-group cancellation could not be verified.")


@dataclass(slots=True)
class _ActiveHarnessProcess:
    contained: ContainedProcess
    limits: HarnessProcessLimits
    cancel_requested: bool = False
    cleanup_task: asyncio.Task[CleanupResult] | None = None
    cleanup_result: CleanupResult | None = None
    cleanup_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def collect_cleanup(self) -> tuple[CleanupResult | None, bool]:
        async with self.cleanup_lock:
            if self.cleanup_result is not None:
                return self.cleanup_result, False
            if self.cleanup_task is None:
                self.cleanup_task = asyncio.create_task(
                    terminate_contained_process(
                        self.contained,
                        term_grace_seconds=self.limits.term_grace_seconds,
                        kill_grace_seconds=self.limits.kill_grace_seconds,
                    )
                )
            cleanup_task = self.cleanup_task
        cancellation_deferred = False
        while True:
            try:
                cleanup = await asyncio.shield(cleanup_task)
                break
            except asyncio.CancelledError:
                if cleanup_task.cancelled():
                    return None, cancellation_deferred
                cancellation_deferred = True
            except BaseException:
                return None, cancellation_deferred
        async with self.cleanup_lock:
            self.cleanup_result = cleanup
        return cleanup, cancellation_deferred


class FirstPartyHarnessRunner(ABC):
    """Common governed execution for current first-party CLI adapters.

    The shared subprocess primitive controls only the original POSIX process
    group.  Runner isolation remains a separate eligibility requirement; this
    class is not the future adversarial repository-worker boundary.
    """

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
        process_limits: HarnessProcessLimits | None = None,
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
        self._process_limits = process_limits or HarnessProcessLimits()
        self._bound_parent_environment: ContextVar[dict[str, str] | None] = ContextVar(
            f"ordomata_parent_environment_{id(self)}", default=None
        )
        self._bound_executable: ContextVar[object | str | None] = ContextVar(
            f"ordomata_executable_{id(self)}", default=_UNBOUND_EXECUTABLE
        )
        self._active_processes: dict[str, _ActiveHarnessProcess] = {}
        self._executing_runs: dict[str, asyncio.Task[Any]] = {}
        self._run_directory_descriptors: dict[str, int] = {}

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
            result = await self._probe.run(
                command,
                environment=validation.sanitized_environment,
                timeout_seconds=timeout_seconds,
            )
        except (
            ContainmentUnavailableError,
            ContainmentVerificationError,
            ProbeContainmentError,
        ):
            raise RunnerUnavailable(
                "Runner diagnostic process containment could not be verified."
            ) from None
        except (OSError, TimeoutError):
            return None
        if not result.containment_cleanup_verified:
            raise RunnerUnavailable(
                "Runner diagnostic process containment could not be verified."
            )
        if result.timed_out or result.output_limit_exceeded:
            return None
        return result

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

    def _schema_name(self) -> str:
        return "output-schema.json"

    def _output_name(self) -> str:
        name = f"{self.runner_id}-output.json"
        if (
            not self.runner_id
            or "\x00" in name
            or os.sep in name
            or (os.altsep is not None and os.altsep in name)
        ):
            raise ValidationError("Harness output name is invalid.")
        return name

    def _run_directory_descriptor(self, request: RunRequest) -> int:
        descriptor = self._run_directory_descriptors.get(request.run_id)
        if descriptor is None:
            raise ValidationError("Run directory lease is unavailable.")
        return descriptor

    @staticmethod
    def _verify_run_directory_lease(
        request: RunRequest,
        directory_descriptor: int,
    ) -> None:
        try:
            pinned = os.fstat(directory_descriptor)
            current = os.stat(request.run_directory, follow_symlinks=False)
        except OSError as exc:
            raise ValidationError("Run directory lease could not be verified.") from exc
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or pinned.st_uid != os.geteuid()
            or stat.S_IMODE(pinned.st_mode) != 0o700
            or not stat.S_ISDIR(current.st_mode)
            or current.st_uid != pinned.st_uid
            or current.st_dev != pinned.st_dev
            or current.st_ino != pinned.st_ino
            or current.st_mode != pinned.st_mode
        ):
            raise ValidationError("Run directory lease could not be verified.")

    def _release_run_directory_lease(self, request: RunRequest) -> bool:
        """Remove transient output and close one pinned directory descriptor."""

        directory_descriptor = self._run_directory_descriptors.get(request.run_id)
        if directory_descriptor is None:
            return True
        output_removed = False
        close_verified = True
        try:
            output_removed = self._unlink_output_for_request(request)
        finally:
            self._run_directory_descriptors.pop(request.run_id, None)
            try:
                os.close(directory_descriptor)
            except OSError:
                close_verified = False
        return output_removed and close_verified

    def _unlink_output_for_request(self, request: RunRequest) -> bool:
        """Unlink only the output name in the controller-pinned directory."""

        try:
            directory_descriptor = self._run_directory_descriptor(request)
            os.unlink(self._output_name(), dir_fd=directory_descriptor)
        except FileNotFoundError:
            return True
        except (OSError, ValidationError):
            return False
        return True

    @staticmethod
    def _validate_live_event_sink(event_sink: EventSink) -> None:
        if type(event_sink) is not ControllerEventSink:
            raise ValidationError(
                "Live harness event sink must be controller-owned."
            )
        if event_sink.count != 0:
            raise ValidationError("Live harness event sink must be fresh.")

    def _read_output(self, request: RunRequest, events: list[AgentEvent]) -> Any:
        del events
        directory_descriptor = self._run_directory_descriptor(request)
        self._verify_run_directory_lease(request, directory_descriptor)
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValidationError("Harness output cannot be opened safely.")
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(
                self._output_name(),
                flags,
                dir_fd=directory_descriptor,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValidationError("Harness output could not be opened safely.") from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.geteuid()
            ):
                raise ValidationError("Harness output must be one regular file.")
            if before.st_size > self._process_limits.output_file_bytes:
                raise ValidationError("Harness output exceeded its byte limit.")
            try:
                os.unlink(
                    self._output_name(),
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise ValidationError(
                    "Harness output could not be removed safely."
                ) from exc
            baseline = os.fstat(descriptor)
            if (
                baseline.st_dev != before.st_dev
                or baseline.st_ino != before.st_ino
                or baseline.st_nlink != 0
            ):
                raise ValidationError("Harness output could not be isolated safely.")
            chunks: list[bytes] = []
            observed = 0
            while True:
                maximum_read = min(
                    64 * 1024,
                    self._process_limits.output_file_bytes + 1 - observed,
                )
                chunk = os.read(descriptor, maximum_read)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > self._process_limits.output_file_bytes:
                    raise ValidationError("Harness output exceeded its byte limit.")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if _file_signature(baseline) != _file_signature(after):
                raise ValidationError("Harness output changed while it was read.")
            raw = b"".join(chunks).decode("utf-8")
        finally:
            os.close(descriptor)
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def output_path(self, request: RunRequest) -> Path:
        return request.run_directory / self._output_name()

    def schema_path(self, request: RunRequest) -> Path:
        return request.run_directory / self._schema_name()

    def _prepare_run_files(self, request: RunRequest) -> None:
        schema = json.dumps(
            request.output_schema,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        if request.run_directory.is_symlink() or not request.run_directory.is_dir():
            raise ValidationError(
                "Run directory must be an existing, non-symlinked directory."
            )
        if request.run_id in self._run_directory_descriptors:
            raise ValidationError("Run directory is already leased.")
        required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
        if any(not hasattr(os, name) for name in required_flags):
            raise ValidationError("Run directory cannot be opened safely.")
        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            directory_descriptor = os.open(request.run_directory, directory_flags)
        except OSError as exc:
            raise ValidationError("Run directory could not be opened safely.") from exc
        schema_created = False
        try:
            self._verify_run_directory_lease(request, directory_descriptor)
            for name, message in (
                (self._schema_name(), "Run schema path already exists."),
                (self._output_name(), "Run output path already exists."),
            ):
                try:
                    os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise ValidationError(
                        "Run file namespace could not be inspected safely."
                    ) from exc
                raise ValidationError(message)
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
            )
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(
                    self._schema_name(),
                    flags,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise ValidationError(
                    "Run schema path could not be created safely."
                ) from exc
            schema_created = True
            try:
                handle = os.fdopen(descriptor, "w", encoding="utf-8")
            except BaseException:
                os.close(descriptor)
                raise
            try:
                with handle:
                    handle.write(schema + "\n")
            except OSError as exc:
                raise ValidationError(
                    "Run schema could not be written safely."
                ) from exc
            self._verify_run_directory_lease(request, directory_descriptor)
        except BaseException:
            try:
                if schema_created:
                    try:
                        os.unlink(self._schema_name(), dir_fd=directory_descriptor)
                    except OSError:
                        pass
            finally:
                try:
                    os.close(directory_descriptor)
                except OSError:
                    pass
            raise
        self._run_directory_descriptors[request.run_id] = directory_descriptor

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
        owner = asyncio.current_task()
        if owner is None:
            raise RuntimeError("Live harness execution requires an asyncio task.")
        if request.run_id in self._executing_runs:
            raise ValidationError(f"Run {request.run_id!r} is already active.")
        self._executing_runs[request.run_id] = owner
        try:
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
                result = await self._execute_with_bound_environment(
                    request, event_sink
                )
            finally:
                self._bound_executable.reset(executable_token)
                self._bound_parent_environment.reset(environment_token)
            if not self._release_run_directory_lease(request):
                raise ValidationError("Run directory cleanup could not be verified.")
            return result
        except BaseException:
            self._release_run_directory_lease(request)
            raise
        finally:
            if self._executing_runs.get(request.run_id) is owner:
                self._executing_runs.pop(request.run_id, None)

    async def _execute_with_bound_environment(
        self, request: RunRequest, event_sink: EventSink
    ) -> RunnerExecutionResult:
        self._validate_request(request)
        self._validate_live_event_sink(event_sink)
        if request.run_id in self._active_processes:
            raise ValidationError(f"Run {request.run_id!r} is already active.")
        try:
            require_containment_support()
        except ContainmentUnavailableError as exc:
            raise RunnerUnavailable(
                "Live harness process-group lifecycle control is unavailable."
            ) from exc

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
        self._verify_run_directory_lease(
            request,
            self._run_directory_descriptor(request),
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
                    + _BILLING_RESERVATION_ACQUISITION_ALLOWANCE_SECONDS
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
            reservation_now = self._billing_clock()
            _assert_billing_reservation_covers_dispatch(
                reservation,
                assessment=assessment,
                request=request,
                now=reservation_now,
            )
            self._verify_run_directory_lease(
                request,
                self._run_directory_descriptor(request),
            )
            BillingPolicy.assert_live_run_allowed(
                assessment,
                environment=self._parent_environment(),
                now=reservation_now,
                required_valid_until=(
                    reservation_now
                    + request.timeout_seconds
                    + _MAX_HARNESS_CLEANUP_BUDGET_SECONDS
                    + _BILLING_PRELAUNCH_SLACK_SECONDS
                ),
            )
            result = await self._execute_reserved(
                request=request,
                event_sink=event_sink,
                capabilities=capabilities,
                assessment=assessment,
                validation=validation,
                redactor=redactor,
                command=command,
            )
            if event_sink.count != len(result.events):
                raise ValidationError(
                    "Live harness event observations do not match its result."
                )
            if not self._release_run_directory_lease(request):
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
                                "harness_artifact_cleanup_unknown",
                            )
                        )
                    ),
                    errors=tuple(
                        dict.fromkeys(
                            (
                                *result.errors,
                                "Harness artifact cleanup could not be verified.",
                            )
                        )
                    ),
                )
        except BaseException:
            try:
                await self._abort_active_process(request)
            finally:
                try:
                    self._release_run_directory_lease(request)
                finally:
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
        stream_limit_exceeded = False
        launch_attempted = False
        execution_outcome_unknown = False
        tasks_settled = True

        active: _ActiveHarnessProcess | None = None
        process: asyncio.subprocess.Process | None = None
        stdin_task: asyncio.Task[None] | None = None
        stdout_task: asyncio.Task[None] | None = None
        stderr_task: asyncio.Task[str] | None = None
        wait_task: asyncio.Task[int] | None = None
        execution_started_at = time.monotonic()
        try:
            async with asyncio.timeout(request.timeout_seconds):
                self._verify_run_directory_lease(
                    request,
                    self._run_directory_descriptor(request),
                )
                launch_attempted = True
                contained = await launch_contained_process(
                    command,
                    cwd=request.workspace,
                    environment=validation.sanitized_environment,
                    stdin=asyncio.subprocess.PIPE,
                )
                active = _ActiveHarnessProcess(contained, self._process_limits)
                self._active_processes[request.run_id] = active
                process = contained.process

                async def consume_stdout() -> None:
                    assert process is not None and process.stdout is not None
                    physical_lines = 0
                    async for line_bytes in iter_bounded_lines(
                        process.stdout,
                        max_total_bytes=self._process_limits.stdout_bytes,
                        max_line_bytes=self._process_limits.event_line_bytes,
                    ):
                        physical_lines += 1
                        if physical_lines > self._process_limits.physical_line_count:
                            raise _HarnessOutputLimitExceeded
                        line = line_bytes.decode("utf-8", errors="replace")
                        try:
                            event = self.parse_event_line(line, redactor)
                        except ValidationError:
                            if (
                                len(parse_errors)
                                >= self._process_limits.parse_error_count
                            ):
                                raise _HarnessOutputLimitExceeded from None
                            parse_errors.append("Harness emitted an invalid event.")
                            continue
                        if event is not None:
                            if len(events) >= self._process_limits.event_count:
                                raise _HarnessOutputLimitExceeded
                            events.append(event)
                            emit_event(event_sink, event)

                async def consume_stderr() -> str:
                    assert process is not None and process.stderr is not None
                    raw = bytearray()
                    async for chunk in iter_bounded_lines(
                        process.stderr,
                        max_total_bytes=self._process_limits.stderr_bytes,
                        max_line_bytes=self._process_limits.stderr_bytes,
                    ):
                        raw.extend(chunk)
                    return redactor.redact_text(
                        bytes(raw).decode("utf-8", errors="replace")
                    )

                async def deliver_stdin() -> None:
                    assert process is not None and process.stdin is not None
                    try:
                        process.stdin.write(request.prompt.encode("utf-8"))
                        await process.stdin.drain()
                    finally:
                        _close_process_stdin(process)

                stdin_task = asyncio.create_task(deliver_stdin())
                stdout_task = asyncio.create_task(consume_stdout())
                stderr_task = asyncio.create_task(consume_stderr())
                wait_task = asyncio.create_task(_wait_for_direct_process_exit(process))
                pending: set[asyncio.Task[Any]] = {
                    stdin_task,
                    wait_task,
                    stdout_task,
                    stderr_task,
                }
                while wait_task in pending:
                    completed, pending = await asyncio.wait(
                        pending,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    # Reader and event-sink failures must preempt the child
                    # immediately instead of waiting for its direct exit.
                    for io_task in (stdin_task, stdout_task, stderr_task):
                        if io_task in completed:
                            await io_task
                    if wait_task not in completed:
                        continue
                    await wait_task
                    cleanup, cancellation_deferred = await active.collect_cleanup()
                    if cancellation_deferred:
                        raise asyncio.CancelledError
                    if (
                        cleanup is None
                        or not cleanup.verified
                        or (
                            cleanup.reason_code != "already_exited"
                            and not active.cancel_requested
                        )
                    ):
                        execution_outcome_unknown = True
                    try:
                        async with asyncio.timeout(
                            self._process_limits.stream_settle_seconds
                        ):
                            await asyncio.gather(
                                stdin_task,
                                stdout_task,
                                stderr_task,
                            )
                    except TimeoutError:
                        raise _HarnessOutputLimitExceeded from None
                    stderr_text = stderr_task.result()
        except TimeoutError:
            timed_out = True
            _close_process_stdin(process)
            if active is not None:
                cleanup, cancellation_deferred = await active.collect_cleanup()
                if cleanup is None or not cleanup.verified:
                    execution_outcome_unknown = True
                if cancellation_deferred:
                    raise asyncio.CancelledError
            elif launch_attempted:
                execution_outcome_unknown = True
            settling_cancelled, tasks_settled = await _settle_harness_tasks(
                stdin_task,
                stdout_task,
                stderr_task,
                wait_task,
                timeout_seconds=self._process_limits.stream_settle_seconds,
            )
            if not tasks_settled:
                execution_outcome_unknown = True
            if settling_cancelled:
                raise asyncio.CancelledError
        except (StreamLimitExceeded, _HarnessOutputLimitExceeded):
            stream_limit_exceeded = True
            execution_outcome_unknown = launch_attempted
            _close_process_stdin(process)
            if active is not None:
                cleanup, cancellation_deferred = await active.collect_cleanup()
                if cleanup is None or not cleanup.verified:
                    execution_outcome_unknown = True
                if cancellation_deferred:
                    raise asyncio.CancelledError
            settling_cancelled, tasks_settled = await _settle_harness_tasks(
                stdin_task,
                stdout_task,
                stderr_task,
                wait_task,
                timeout_seconds=self._process_limits.stream_settle_seconds,
            )
            if not tasks_settled:
                execution_outcome_unknown = True
            if settling_cancelled:
                raise asyncio.CancelledError
        except Exception:
            _close_process_stdin(process)
            if active is not None:
                cleanup, cancellation_deferred = await active.collect_cleanup()
                if cleanup is None or not cleanup.verified:
                    execution_outcome_unknown = True
                if cancellation_deferred:
                    raise asyncio.CancelledError
            settling_cancelled, tasks_settled = await _settle_harness_tasks(
                stdin_task,
                stdout_task,
                stderr_task,
                wait_task,
                timeout_seconds=self._process_limits.stream_settle_seconds,
            )
            if not tasks_settled:
                execution_outcome_unknown = True
            if settling_cancelled:
                raise asyncio.CancelledError
            self._unlink_output_for_request(request)
            # Once process creation has been attempted, an adapter, event-sink,
            # or stream-processing failure cannot prove whether provider-side
            # capacity was consumed. Preserve a sanitized result so the caller
            # can durably open the billing circuit instead of losing postflight
            # accounting to an exception path.
            execution_outcome_unknown = (
                execution_outcome_unknown or launch_attempted
            )
        except BaseException:
            _close_process_stdin(process)
            if active is not None:
                await active.collect_cleanup()
            _, tasks_settled = await _settle_harness_tasks(
                stdin_task,
                stdout_task,
                stderr_task,
                wait_task,
                timeout_seconds=self._process_limits.stream_settle_seconds,
            )
            if not tasks_settled:
                execution_outcome_unknown = True
            self._unlink_output_for_request(request)
            raise
        finally:
            _close_process_stdin(process)
            if self._active_processes.get(request.run_id) is active:
                self._active_processes.pop(request.run_id, None)

        errors = list(parse_errors)
        if timed_out:
            errors.append("Harness execution timed out.")
        if stream_limit_exceeded:
            errors.append("Harness output exceeded a controller limit.")
        if launch_attempted and not tasks_settled:
            errors.append("Harness controller task settlement could not be verified.")
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
        cancelled = active.cancel_requested if active is not None else False
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
            if not execution_outcome_unknown and not cancelled:
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
            if not self._unlink_output_for_request(request):
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
        if (
            execution_outcome_unknown
            and "Harness execution outcome could not be verified." not in errors
        ):
            errors.append("Harness execution outcome could not be verified.")
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
                async with asyncio.timeout(_BILLING_POSTFLIGHT_BUDGET_SECONDS):
                    postflight_assessment = await self.inspect_billing_route()
            except (Exception, TimeoutError):
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

        active = self._active_processes.get(request.run_id)
        if active is not None:
            try:
                await active.collect_cleanup()
            except BaseException:
                # Reservation finalization below must still record broad UNKNOWN
                # even if a second interruption reaches this best-effort guard.
                pass
            finally:
                if self._active_processes.get(request.run_id) is active:
                    self._active_processes.pop(request.run_id, None)
        self._unlink_output_for_request(request)

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
        active = self._active_processes.get(run_id)
        if active is not None:
            active.cancel_requested = True
            cleanup, cancellation_deferred = await active.collect_cleanup()
            if cleanup is None or not cleanup.verified:
                raise HarnessCancellationError
            if cancellation_deferred:
                raise asyncio.CancelledError
            return
        owner = self._executing_runs.get(run_id)
        if owner is None or owner is asyncio.current_task():
            return
        owner.cancel()
        collection = asyncio.gather(owner, return_exceptions=True)
        cancellation_deferred = False
        while True:
            try:
                outcomes = await asyncio.shield(collection)
                break
            except asyncio.CancelledError:
                if collection.cancelled():
                    raise
                cancellation_deferred = True
        if outcomes and isinstance(outcomes[0], RunnerExecutionResult):
            result = outcomes[0]
            if result.billing_quarantine_required:
                raise HarnessCancellationError
        if cancellation_deferred:
            raise asyncio.CancelledError


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
    """Return metadata that must remain stable across one bounded output read."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _assert_billing_reservation_covers_dispatch(
    reservation: BillingDispatchReservation,
    *,
    assessment: BillingRouteAssessment,
    request: RunRequest,
    now: float,
) -> None:
    """Reject a malformed, mismatched, stale, or prematurely expiring lease."""

    required_until = (
        now
        + request.timeout_seconds
        + BILLING_DISPATCH_COMPLETION_MARGIN_SECONDS
    )
    if (
        not math.isfinite(now)
        or reservation.runner_id != assessment.runner_id
        or reservation.account_identity_fingerprint
        != assessment.account_identity_fingerprint
        or not reservation.reservation_id
        or not reservation.owner_id
        or not reservation.lease_keys
        or any(not isinstance(key, str) or not key for key in reservation.lease_keys)
        or not math.isfinite(reservation.acquired_at)
        or not math.isfinite(reservation.expires_at)
        or reservation.acquired_at > now
        or reservation.expires_at <= reservation.acquired_at
        or reservation.expires_at < required_until
    ):
        raise BillingRouteBlocked(
            "Billing dispatch reservation does not cover the governed run."
        )


def _close_process_stdin(process: asyncio.subprocess.Process | None) -> None:
    """Close a child input pipe without retaining transport diagnostics."""

    if process is None or process.stdin is None:
        return
    try:
        process.stdin.close()
    except (AttributeError, OSError, RuntimeError):
        pass


async def _wait_for_direct_process_exit(
    process: asyncio.subprocess.Process,
) -> int:
    """Observe the reaped direct child without waiting on inherited pipes."""

    while process.returncode is None:
        await asyncio.sleep(0.01)
    return process.returncode


async def _settle_harness_tasks(
    *tasks: asyncio.Task[Any] | None,
    timeout_seconds: float,
) -> tuple[bool, bool]:
    """Cancel tasks and report cancellation deferral plus bounded settlement."""

    selected = tuple(task for task in tasks if task is not None)
    if not selected:
        return False, True
    for task in selected:
        if not task.done():
            task.cancel()
    settling = asyncio.gather(*selected, return_exceptions=True)
    cancellation_deferred = False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while not settling.done():
        remaining = deadline - loop.time()
        if remaining <= 0:
            return cancellation_deferred, False
        try:
            await asyncio.wait(
                (settling,),
                timeout=remaining,
                return_when=asyncio.ALL_COMPLETED,
            )
        except asyncio.CancelledError:
            cancellation_deferred = True
    return cancellation_deferred, True


def _broad_billing_scope_required(result: RunnerExecutionResult) -> bool:
    """Return whether identity uncertainty requires provider-wide blocking."""

    if {
        "harness_artifact_cleanup_unknown",
        "harness_execution_outcome_unknown",
        "harness_launch_outcome_unknown",
    }.intersection(result.billing_disposition_reasons):
        return True
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
    if not isinstance(state, CapacityState):
        return CapacityState.UNKNOWN
    if state is CapacityState.AVAILABLE and (
        result.status is RunStatus.QUARANTINED
        or result.billing_quarantine_required
        or result.billing_circuit_breaker_required
        or {
            "harness_artifact_cleanup_unknown",
            "harness_execution_outcome_unknown",
            "harness_launch_outcome_unknown",
        }.intersection(result.billing_disposition_reasons)
    ):
        # A safety-failed dispatch cannot publish positive capacity evidence.
        # Preserve restrictive postflight states, but demote AVAILABLE until a
        # fresh independently governed observation re-establishes it.
        return CapacityState.UNKNOWN
    return state


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
    "HarnessCancellationError",
    "HarnessProcessLimits",
    "add_environment_findings",
    "clean_version",
    "validate_override_text",
]
