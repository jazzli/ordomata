"""Controller-owned POSIX process-group lifecycle and bounded stream draining.

This module intentionally provides mechanics, not authorization.  Callers remain
responsible for route, billing, workspace, and command authorization before
launching a process.  No function in this module invokes a shell.

The boundary is deliberately narrow: ``VERIFIED`` proves only that the original
POSIX process group is absent and its direct child was reaped.  A descendant can
escape with ``setsid()`` or ``setpgid()``.  This module is therefore not a
process-tree, sandbox, container, or adversarial repository-worker boundary.
"""

from __future__ import annotations

import asyncio
import math
import os
import signal
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TypeVar


DEFAULT_PIPE_BUFFER_LIMIT = 64 * 1024
DEFAULT_STREAM_CHUNK_BYTES = 64 * 1024
MAX_PIPE_BUFFER_LIMIT = 1024 * 1024
MAX_STREAM_CHUNK_BYTES = 1024 * 1024
MAX_CLEANUP_GRACE_SECONDS = 30.0

_POSIX_PROCESS_GROUPS_AVAILABLE = (
    os.name == "posix"
    and hasattr(os, "killpg")
    and hasattr(os, "getpgid")
    and hasattr(os, "getsid")
    and hasattr(signal, "SIGTERM")
    and hasattr(signal, "SIGKILL")
)
_TaskResult = TypeVar("_TaskResult")


class ContainmentUnavailableError(OSError):
    """Raised when the host cannot provide POSIX process-group lifecycle control."""

    def __init__(self) -> None:
        super().__init__("POSIX process-group lifecycle control is unavailable")


class StreamLimitExceeded(RuntimeError):
    """A sanitized signal that a bounded stream crossed a controller limit."""

    def __init__(self, *, reason_code: str, limit: int, observed: int) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.limit = limit
        self.observed = observed


class CleanupDisposition(StrEnum):
    """Whether controller-owned process cleanup was positively verified."""

    VERIFIED = "verified"
    UNCERTAIN = "uncertain"


class _ProcessGroupPresence(StrEnum):
    ABSENT = "absent"
    PRESENT = "present"
    UNKNOWN = "unknown"


class _ContainedIdentityStatus(StrEnum):
    VERIFIED = "verified"
    VANISHED = "vanished"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ContainedProcess:
    """A direct child launched as leader of a controller-owned POSIX session."""

    process: asyncio.subprocess.Process
    process_group_id: int
    controller_pid: int

    @property
    def session_id(self) -> int:
        """The new session ID, which is identical to its leader's process ID."""

        return self.process_group_id


@dataclass(frozen=True, slots=True)
class CleanupResult:
    """Bounded evidence about only the originally verified process group."""

    disposition: CleanupDisposition
    reason_code: str
    term_sent: bool
    kill_sent: bool
    direct_child_reaped: bool
    process_group_absent: bool
    returncode: int | None

    @property
    def verified(self) -> bool:
        """Return whether direct-child reap and original-group absence are proven."""

        return self.disposition is CleanupDisposition.VERIFIED


class ContainedProcessLaunchCancelled(asyncio.CancelledError):
    """Launch cancellation after any returned child received bounded cleanup."""

    def __init__(self, cleanup_result: CleanupResult) -> None:
        super().__init__("contained process launch cancelled")
        self.cleanup_result = cleanup_result


class ContainmentVerificationError(OSError):
    """Raised after a new session identity could not be positively verified."""

    def __init__(self, cleanup_result: CleanupResult | None) -> None:
        super().__init__("contained process identity verification failed")
        self.cleanup_result = cleanup_result


@dataclass(frozen=True, slots=True)
class BoundedStreamResult:
    """A bounded prefix plus accounting for all bytes drained from one stream."""

    data: bytes
    observed_bytes: int
    truncated: bool

    def decode(self, encoding: str = "utf-8", *, errors: str = "replace") -> str:
        return self.data.decode(encoding, errors=errors)


@dataclass(frozen=True, slots=True)
class ProcessStreamResult:
    """Bounded, independently accounted stdout and stderr results."""

    stdout: BoundedStreamResult
    stderr: BoundedStreamResult

    @property
    def limit_exceeded(self) -> bool:
        return self.stdout.truncated or self.stderr.truncated


def posix_containment_available() -> bool:
    """Return whether this host exposes the required POSIX primitives."""

    return _POSIX_PROCESS_GROUPS_AVAILABLE


def require_containment_support() -> None:
    """Fail before launch when POSIX process-group lifecycle control is absent."""

    if not posix_containment_available():
        raise ContainmentUnavailableError()


async def launch_contained_process(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path | None = None,
    stdin: int = asyncio.subprocess.DEVNULL,
    pipe_buffer_limit: int = DEFAULT_PIPE_BUFFER_LIMIT,
) -> ContainedProcess:
    """Launch an executable in a new POSIX session with piped output.

    ``stdin`` is deliberately restricted to ``DEVNULL`` or ``PIPE`` so this
    primitive cannot inherit an ambient descriptor.  Stdout and stderr are
    always pipes so callers can apply bounded draining.
    """

    require_containment_support()
    normalized_command = _validate_command(command)
    normalized_environment = _validate_environment(environment)
    if stdin not in (asyncio.subprocess.DEVNULL, asyncio.subprocess.PIPE):
        raise ValueError("stdin must be asyncio.subprocess.DEVNULL or PIPE")
    _validate_size(
        pipe_buffer_limit,
        name="pipe_buffer_limit",
        maximum=MAX_PIPE_BUFFER_LIMIT,
        allow_zero=False,
    )

    creation_task = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *normalized_command,
            cwd=cwd,
            env=normalized_environment,
            stdin=stdin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            limit=pipe_buffer_limit,
        )
    )
    try:
        process = await asyncio.shield(creation_task)
    except asyncio.CancelledError:
        # create_subprocess_exec has no controller-visible child handle until it
        # returns.  Finish the shielded creation, then contain any returned
        # process before cancellation can escape and orphan an untracked group.
        try:
            process, _ = await _await_task_deferring_cancellation(creation_task)
        except BaseException:
            raise ContainmentVerificationError(None) from None
        contained = _contained_process(process)
        cleanup_task = asyncio.create_task(terminate_contained_process(contained))
        try:
            cleanup, _ = await _await_task_deferring_cancellation(cleanup_task)
        except BaseException:
            cleanup = None
        if cleanup is not None and cleanup.verified:
            raise ContainedProcessLaunchCancelled(cleanup) from None
        raise ContainmentVerificationError(cleanup) from None
    contained = _contained_process(process)
    identity_status = _contained_identity_status(contained)
    if identity_status is _ContainedIdentityStatus.VERIFIED:
        return contained
    cleanup_task = asyncio.create_task(terminate_contained_process(contained))
    try:
        cleanup, cancellation_deferred = await _await_task_deferring_cancellation(
            cleanup_task
        )
    except BaseException:
        cleanup = None
        cancellation_deferred = False
    if cancellation_deferred:
        if cleanup is not None and cleanup.verified:
            raise ContainedProcessLaunchCancelled(cleanup) from None
        raise ContainmentVerificationError(cleanup) from None
    if (
        identity_status is _ContainedIdentityStatus.VANISHED
        and cleanup is not None
        and cleanup.verified
        and cleanup.reason_code == "already_exited"
        and not cleanup.term_sent
        and not cleanup.kill_sent
    ):
        # A legitimate short-lived child can exit between spawn return and the
        # controller's identity queries.  Accept only positive proof that both
        # the expected group and the already-reaped direct child are gone.
        return contained
    raise ContainmentVerificationError(cleanup) from None


async def terminate_contained_process(
    contained: ContainedProcess,
    *,
    term_grace_seconds: float = 0.5,
    kill_grace_seconds: float = 0.5,
) -> CleanupResult:
    """Terminate and verify an owned process group within bounded grace periods.

    A verified result requires both positive original-group absence and reaping
    of the direct child.  It makes no claim about descendants that changed
    session or process group.  Unsupported hosts, ownership mismatches, signal
    failures, lingering group members, and unreaped children are all reported
    as uncertain.  Callers running in a cancellable task should shield this
    coroutine and keep its task alive until it returns.
    """

    _validate_grace(term_grace_seconds, name="term_grace_seconds")
    _validate_grace(kill_grace_seconds, name="kill_grace_seconds")
    if not posix_containment_available():
        return _cleanup_result(
            contained,
            reason_code="containment_unavailable",
        )
    if contained.controller_pid != os.getpid():
        return _cleanup_result(
            contained,
            reason_code="controller_ownership_mismatch",
        )
    if (
        contained.process_group_id <= 1
        or contained.process_group_id != contained.process.pid
    ):
        return _cleanup_result(
            contained,
            reason_code="invalid_process_group_identity",
        )

    initial_presence = _process_group_presence(contained.process_group_id)
    if initial_presence is _ProcessGroupPresence.ABSENT:
        presence, direct_reaped = await _wait_for_absence_and_reap(
            contained,
            timeout_seconds=term_grace_seconds,
        )
        return _final_cleanup_result(
            contained,
            presence=presence,
            direct_reaped=direct_reaped,
            verified_reason="already_exited",
            term_sent=False,
            kill_sent=False,
        )
    if initial_presence is _ProcessGroupPresence.UNKNOWN:
        return _cleanup_result(
            contained,
            reason_code="process_group_status_unknown",
        )

    # When the direct leader is still alive, revalidate the session identity
    # immediately before signaling.  A vanished leader can legitimately leave
    # descendants in the already-verified group; a live mismatch or an
    # unreadable identity is never safe to signal.
    if contained.process.returncode is None:
        identity_status = _contained_identity_status(contained)
        if identity_status is not _ContainedIdentityStatus.VERIFIED:
            return _cleanup_result(
                contained,
                reason_code="process_group_identity_unknown",
            )

    term_sent, term_presence = _signal_process_group(
        contained.process_group_id, signal.SIGTERM
    )
    if term_presence is _ProcessGroupPresence.UNKNOWN:
        return _cleanup_result(
            contained,
            reason_code="process_group_signal_status_unknown",
        )
    presence, direct_reaped = await _wait_for_absence_and_reap(
        contained,
        timeout_seconds=term_grace_seconds,
    )
    if presence is _ProcessGroupPresence.ABSENT and direct_reaped:
        return _final_cleanup_result(
            contained,
            presence=presence,
            direct_reaped=direct_reaped,
            verified_reason="terminated" if term_sent else "already_exited",
            term_sent=term_sent,
            kill_sent=False,
        )

    # A ProcessLookupError from TERM is evidence that the group disappeared at
    # that instant.  If it reappears here, never signal the potentially reused
    # process-group ID.
    if term_presence is _ProcessGroupPresence.ABSENT:
        return _final_cleanup_result(
            contained,
            presence=presence,
            direct_reaped=direct_reaped,
            verified_reason="already_exited",
            term_sent=term_sent,
            kill_sent=False,
        )

    if presence is _ProcessGroupPresence.UNKNOWN:
        return _final_cleanup_result(
            contained,
            presence=presence,
            direct_reaped=direct_reaped,
            verified_reason="terminated",
            term_sent=term_sent,
            kill_sent=False,
        )
    if (
        contained.process.returncode is None
        and _contained_identity_status(contained)
        is not _ContainedIdentityStatus.VERIFIED
    ):
        return _cleanup_result(
            contained,
            reason_code="process_group_identity_unknown",
            term_sent=term_sent,
        )

    kill_sent, _kill_presence = _signal_process_group(
        contained.process_group_id, signal.SIGKILL
    )
    presence, direct_reaped = await _wait_for_absence_and_reap(
        contained,
        timeout_seconds=kill_grace_seconds,
    )
    return _final_cleanup_result(
        contained,
        presence=presence,
        direct_reaped=direct_reaped,
        verified_reason="killed" if kill_sent else "already_exited",
        term_sent=term_sent,
        kill_sent=kill_sent,
    )


async def drain_bounded_stream(
    reader: asyncio.StreamReader,
    *,
    max_bytes: int,
    chunk_bytes: int = DEFAULT_STREAM_CHUNK_BYTES,
    overflow_event: asyncio.Event | None = None,
) -> BoundedStreamResult:
    """Drain a stream to EOF while retaining no more than ``max_bytes``.

    The optional event is set on the first byte beyond the retention limit.  It
    lets a concurrent controller initiate process-group cleanup while this
    coroutine keeps draining until the resulting pipe closure.
    """

    _validate_size(max_bytes, name="max_bytes", maximum=None, allow_zero=True)
    _validate_size(
        chunk_bytes,
        name="chunk_bytes",
        maximum=MAX_STREAM_CHUNK_BYTES,
        allow_zero=False,
    )
    retained = bytearray()
    observed_bytes = 0
    while chunk := await reader.read(chunk_bytes):
        observed_bytes += len(chunk)
        remaining = max_bytes - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
        if observed_bytes > max_bytes and overflow_event is not None:
            overflow_event.set()
    return BoundedStreamResult(
        data=bytes(retained),
        observed_bytes=observed_bytes,
        truncated=observed_bytes > max_bytes,
    )


async def iter_bounded_lines(
    reader: asyncio.StreamReader,
    *,
    max_total_bytes: int,
    max_line_bytes: int,
    chunk_bytes: int = DEFAULT_STREAM_CHUNK_BYTES,
    overflow_event: asyncio.Event | None = None,
) -> AsyncIterator[bytes]:
    """Yield physical lines while enforcing total and per-line byte limits.

    Unlike ``StreamReader.readline()``, this iterator never delegates line-size
    policy to asyncio's transport buffer.  Newline bytes count toward both
    limits.  A limit breach raises ``StreamLimitExceeded`` without retaining
    the offending byte or any private stream content in the exception.

    A caller that catches a breach must terminate the contained process and
    drain or close the remaining pipe before awaiting process completion.
    """

    _validate_size(
        max_total_bytes,
        name="max_total_bytes",
        maximum=None,
        allow_zero=True,
    )
    _validate_size(
        max_line_bytes,
        name="max_line_bytes",
        maximum=None,
        allow_zero=True,
    )
    _validate_size(
        chunk_bytes,
        name="chunk_bytes",
        maximum=MAX_STREAM_CHUNK_BYTES,
        allow_zero=False,
    )

    line = bytearray()
    observed_total = 0
    while chunk := await reader.read(chunk_bytes):
        offset = 0
        while offset < len(chunk):
            newline_index = chunk.find(b"\n", offset)
            segment_end = (
                len(chunk) if newline_index < 0 else newline_index + 1
            )
            segment_length = segment_end - offset
            total_remaining = max_total_bytes - observed_total
            line_remaining = max_line_bytes - len(line)
            accepted = min(segment_length, total_remaining, line_remaining)
            if accepted > 0:
                line.extend(chunk[offset : offset + accepted])
                observed_total += accepted
                offset += accepted
            if accepted < segment_length:
                if overflow_event is not None:
                    overflow_event.set()
                if total_remaining <= line_remaining:
                    raise StreamLimitExceeded(
                        reason_code="stream_total_bytes_limit_exceeded",
                        limit=max_total_bytes,
                        observed=observed_total + 1,
                    )
                raise StreamLimitExceeded(
                    reason_code="stream_line_bytes_limit_exceeded",
                    limit=max_line_bytes,
                    observed=len(line) + 1,
                )
            if newline_index >= 0:
                yield bytes(line)
                line.clear()
    if line:
        yield bytes(line)


async def drain_process_streams(
    contained: ContainedProcess,
    *,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    chunk_bytes: int = DEFAULT_STREAM_CHUNK_BYTES,
    overflow_event: asyncio.Event | None = None,
) -> ProcessStreamResult:
    """Drain both child pipes concurrently with independent retention limits."""

    _validate_size(
        max_stdout_bytes,
        name="max_stdout_bytes",
        maximum=None,
        allow_zero=True,
    )
    _validate_size(
        max_stderr_bytes,
        name="max_stderr_bytes",
        maximum=None,
        allow_zero=True,
    )
    _validate_size(
        chunk_bytes,
        name="chunk_bytes",
        maximum=MAX_STREAM_CHUNK_BYTES,
        allow_zero=False,
    )
    stdout = contained.process.stdout
    stderr = contained.process.stderr
    if stdout is None or stderr is None:
        raise ValueError("contained process stdout and stderr must be pipes")
    stdout_result, stderr_result = await asyncio.gather(
        drain_bounded_stream(
            stdout,
            max_bytes=max_stdout_bytes,
            chunk_bytes=chunk_bytes,
            overflow_event=overflow_event,
        ),
        drain_bounded_stream(
            stderr,
            max_bytes=max_stderr_bytes,
            chunk_bytes=chunk_bytes,
            overflow_event=overflow_event,
        ),
    )
    return ProcessStreamResult(stdout=stdout_result, stderr=stderr_result)


def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)) or not command:
        raise ValueError("command must be a non-empty sequence of strings")
    normalized = tuple(command)
    if any(not isinstance(argument, str) for argument in normalized):
        raise TypeError("command arguments must be strings")
    if not normalized[0]:
        raise ValueError("command executable must not be empty")
    if any("\x00" in argument for argument in normalized):
        raise ValueError("command arguments must not contain NUL bytes")
    return normalized


def _validate_environment(environment: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in environment.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("environment keys and values must be strings")
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            raise ValueError("environment contains an invalid key or value")
        normalized[key] = value
    return normalized


def _validate_size(
    value: int,
    *,
    name: str,
    maximum: int | None,
    allow_zero: bool,
) -> None:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{name} must be a {qualifier} integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must not exceed {maximum}")


def _validate_grace(value: float, *, name: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or value > MAX_CLEANUP_GRACE_SECONDS
    ):
        raise ValueError(
            f"{name} must be finite and between 0 and "
            f"{MAX_CLEANUP_GRACE_SECONDS} seconds"
        )


def _process_group_presence(process_group_id: int) -> _ProcessGroupPresence:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return _ProcessGroupPresence.ABSENT
    except (PermissionError, OSError):
        return _ProcessGroupPresence.UNKNOWN
    return _ProcessGroupPresence.PRESENT


def _signal_process_group(
    process_group_id: int, signal_number: int
) -> tuple[bool, _ProcessGroupPresence]:
    try:
        os.killpg(process_group_id, signal_number)
    except ProcessLookupError:
        return False, _ProcessGroupPresence.ABSENT
    except (PermissionError, OSError):
        return False, _ProcessGroupPresence.UNKNOWN
    return True, _ProcessGroupPresence.PRESENT


async def _wait_for_absence_and_reap(
    contained: ContainedProcess,
    *,
    timeout_seconds: float,
) -> tuple[_ProcessGroupPresence, bool]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while True:
        presence = _process_group_presence(contained.process_group_id)
        direct_reaped = contained.process.returncode is not None
        if presence is _ProcessGroupPresence.ABSENT and direct_reaped:
            return presence, True
        remaining = deadline - loop.time()
        if remaining <= 0:
            return presence, direct_reaped
        await asyncio.sleep(min(0.01, remaining))


def _contained_process(process: asyncio.subprocess.Process) -> ContainedProcess:
    return ContainedProcess(
        process=process,
        process_group_id=process.pid,
        controller_pid=os.getpid(),
    )


def _contained_identity_status(
    contained: ContainedProcess,
) -> _ContainedIdentityStatus:
    try:
        process_group_id = os.getpgid(contained.process.pid)
    except ProcessLookupError:
        return _ContainedIdentityStatus.VANISHED
    except OSError:
        return _ContainedIdentityStatus.UNKNOWN
    if process_group_id != contained.process_group_id:
        return _ContainedIdentityStatus.MISMATCH
    try:
        session_id = os.getsid(contained.process.pid)
    except ProcessLookupError:
        return _ContainedIdentityStatus.VANISHED
    except OSError:
        return _ContainedIdentityStatus.UNKNOWN
    if session_id != contained.session_id:
        return _ContainedIdentityStatus.MISMATCH
    return _ContainedIdentityStatus.VERIFIED


async def _await_task_deferring_cancellation(
    task: asyncio.Task[_TaskResult],
) -> tuple[_TaskResult, bool]:
    cancellation_deferred = False
    while True:
        try:
            return await asyncio.shield(task), cancellation_deferred
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancellation_deferred = True


def _final_cleanup_result(
    contained: ContainedProcess,
    *,
    presence: _ProcessGroupPresence,
    direct_reaped: bool,
    verified_reason: str,
    term_sent: bool,
    kill_sent: bool,
) -> CleanupResult:
    group_absent = presence is _ProcessGroupPresence.ABSENT
    if group_absent and direct_reaped:
        disposition = CleanupDisposition.VERIFIED
        reason_code = verified_reason
    elif presence is _ProcessGroupPresence.UNKNOWN:
        disposition = CleanupDisposition.UNCERTAIN
        reason_code = "process_group_status_unknown"
    elif not group_absent:
        disposition = CleanupDisposition.UNCERTAIN
        reason_code = "process_group_still_present"
    else:
        disposition = CleanupDisposition.UNCERTAIN
        reason_code = "direct_child_not_reaped"
    return CleanupResult(
        disposition=disposition,
        reason_code=reason_code,
        term_sent=term_sent,
        kill_sent=kill_sent,
        direct_child_reaped=direct_reaped,
        process_group_absent=group_absent,
        returncode=contained.process.returncode,
    )


def _cleanup_result(
    contained: ContainedProcess,
    *,
    reason_code: str,
    term_sent: bool = False,
    kill_sent: bool = False,
) -> CleanupResult:
    return CleanupResult(
        disposition=CleanupDisposition.UNCERTAIN,
        reason_code=reason_code,
        term_sent=term_sent,
        kill_sent=kill_sent,
        direct_child_reaped=contained.process.returncode is not None,
        process_group_absent=False,
        returncode=contained.process.returncode,
    )


__all__ = [
    "BoundedStreamResult",
    "CleanupDisposition",
    "CleanupResult",
    "ContainedProcess",
    "ContainedProcessLaunchCancelled",
    "ContainmentUnavailableError",
    "ContainmentVerificationError",
    "ProcessStreamResult",
    "StreamLimitExceeded",
    "drain_bounded_stream",
    "drain_process_streams",
    "iter_bounded_lines",
    "launch_contained_process",
    "posix_containment_available",
    "require_containment_support",
    "terminate_contained_process",
]
