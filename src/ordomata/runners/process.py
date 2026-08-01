"""Subprocess utilities used by first-party coding-harness adapters."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Mapping, Sequence
from pathlib import Path

from .base import ProbeResult
from .containment import (
    CleanupResult,
    ContainedProcess,
    ProcessStreamResult,
    drain_process_streams,
    launch_contained_process,
    require_containment_support,
    terminate_contained_process,
)


_STREAM_SETTLE_SECONDS = 0.5
_OUTPUT_LIMIT_EXIT_GRACE_SECONDS = 0.05


class ProbeContainmentError(OSError):
    """A fixed failure to prove diagnostic process-group cleanup."""

    def __init__(self) -> None:
        super().__init__("diagnostic process-group cleanup could not be verified")


class _ProbeOutputLimitExceeded(RuntimeError):
    pass


class AsyncCommandProbe:
    """Run bounded diagnostic commands without invoking a shell."""

    def __init__(self, *, max_output_bytes: int = 256_000) -> None:
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or max_output_bytes < 1
        ):
            raise ValueError("max_output_bytes must be a positive integer")
        self._max_output_bytes = max_output_bytes

    async def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path | None = None,
        timeout_seconds: float = 10.0,
    ) -> ProbeResult:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        require_containment_support()

        contained: ContainedProcess | None = None
        streams_task: asyncio.Task[ProcessStreamResult] | None = None
        wait_task: asyncio.Task[int] | None = None
        overflow_task: asyncio.Task[bool] | None = None
        streams: ProcessStreamResult | None = None
        overflow_event = asyncio.Event()
        try:
            async with asyncio.timeout(timeout_seconds):
                contained = await launch_contained_process(
                    command,
                    environment=environment,
                    cwd=cwd,
                )
                streams_task = asyncio.create_task(
                    drain_process_streams(
                        contained,
                        max_stdout_bytes=self._max_output_bytes,
                        max_stderr_bytes=self._max_output_bytes,
                        overflow_event=overflow_event,
                    )
                )
                wait_task = asyncio.create_task(
                    _wait_for_direct_child_exit(contained)
                )
                overflow_task = asyncio.create_task(overflow_event.wait())
                pending = {
                    streams_task,
                    wait_task,
                    overflow_task,
                }
                while pending:
                    done, pending = await asyncio.wait(
                        pending,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if overflow_event.is_set():
                        await _allow_finished_command_to_settle(
                            streams_task, wait_task
                        )
                        raise _ProbeOutputLimitExceeded
                    if streams_task in done:
                        streams = streams_task.result()
                        if streams.limit_exceeded:
                            await _allow_finished_command_to_settle(
                                streams_task, wait_task
                            )
                            raise _ProbeOutputLimitExceeded
                    if wait_task in done:
                        break

            assert contained is not None
            cleanup, cancellation_deferred = await _verified_cleanup(contained)
            (
                settled_streams,
                settle_cancellation_deferred,
                tasks_settled,
            ) = await _settle_tasks(
                streams_task, wait_task=wait_task, overflow_task=overflow_task
            )
            if settled_streams is not None:
                streams = settled_streams
            if not cleanup.verified or not tasks_settled:
                raise ProbeContainmentError from None
            if cancellation_deferred or settle_cancellation_deferred:
                raise asyncio.CancelledError
            if streams is None:
                raise ProbeContainmentError from None
            residual_group = cleanup.reason_code != "already_exited"
            return ProbeResult(
                tuple(command),
                -1 if residual_group else (contained.process.returncode or 0),
                streams.stdout.decode(),
                streams.stderr.decode(),
                containment_cleanup_verified=cleanup.verified and not residual_group,
            )
        except TimeoutError:
            cleanup_verified = True
            cancellation_deferred = False
            if contained is not None:
                cleanup, cancellation_deferred = await _verified_cleanup(contained)
                cleanup_verified = cleanup.verified
            streams, settle_cancellation_deferred, tasks_settled = await _settle_tasks(
                streams_task, wait_task=wait_task, overflow_task=overflow_task
            )
            if not cleanup_verified or not tasks_settled:
                raise ProbeContainmentError from None
            if cancellation_deferred or settle_cancellation_deferred:
                raise asyncio.CancelledError
            return ProbeResult(
                tuple(command),
                _returncode(contained),
                _stdout_text(streams),
                _stderr_text(streams),
                timed_out=True,
                containment_cleanup_verified=True,
            )
        except _ProbeOutputLimitExceeded:
            if contained is None:
                raise ProbeContainmentError from None
            cleanup, cancellation_deferred = await _verified_cleanup(contained)
            streams, settle_cancellation_deferred, tasks_settled = await _settle_tasks(
                streams_task, wait_task=wait_task, overflow_task=overflow_task
            )
            if not cleanup.verified or not tasks_settled:
                raise ProbeContainmentError from None
            if cancellation_deferred or settle_cancellation_deferred:
                raise asyncio.CancelledError
            return ProbeResult(
                tuple(command),
                _returncode(contained),
                _stdout_text(streams),
                _stderr_text(streams),
                output_limit_exceeded=True,
                containment_cleanup_verified=True,
            )
        except asyncio.CancelledError:
            cleanup_verified = True
            if contained is not None:
                cleanup, _ = await _verified_cleanup(contained)
                cleanup_verified = cleanup.verified
            _, _, tasks_settled = await _settle_tasks(
                streams_task, wait_task=wait_task, overflow_task=overflow_task
            )
            if not cleanup_verified or not tasks_settled:
                raise ProbeContainmentError from None
            raise
        except OSError:
            if contained is not None:
                cleanup, cleanup_cancellation_deferred = await _verified_cleanup(
                    contained
                )
                _, settle_cancellation_deferred, tasks_settled = await _settle_tasks(
                    streams_task, wait_task=wait_task, overflow_task=overflow_task
                )
                if not cleanup.verified or not tasks_settled:
                    raise ProbeContainmentError from None
                if (
                    cleanup_cancellation_deferred
                    or settle_cancellation_deferred
                ):
                    raise asyncio.CancelledError
            raise
        except Exception:
            if contained is not None:
                cleanup, cleanup_cancellation_deferred = await _verified_cleanup(
                    contained
                )
                _, settle_cancellation_deferred, tasks_settled = await _settle_tasks(
                    streams_task, wait_task=wait_task, overflow_task=overflow_task
                )
                if not cleanup.verified or not tasks_settled:
                    raise ProbeContainmentError from None
                if (
                    cleanup_cancellation_deferred
                    or settle_cancellation_deferred
                ):
                    raise asyncio.CancelledError
            raise ProbeContainmentError from None
        except BaseException:
            cleanup_verified = True
            cleanup_cancellation_deferred = False
            if contained is not None:
                cleanup, cleanup_cancellation_deferred = await _verified_cleanup(
                    contained
                )
                cleanup_verified = cleanup.verified
            _, settle_cancellation_deferred, tasks_settled = await _settle_tasks(
                streams_task, wait_task=wait_task, overflow_task=overflow_task
            )
            if not cleanup_verified or not tasks_settled:
                raise ProbeContainmentError from None
            if cleanup_cancellation_deferred or settle_cancellation_deferred:
                raise asyncio.CancelledError
            raise


async def _verified_cleanup(
    contained: ContainedProcess,
) -> tuple[CleanupResult, bool]:
    cleanup_task = asyncio.create_task(terminate_contained_process(contained))
    cancellation_deferred = False
    while True:
        try:
            return await asyncio.shield(cleanup_task), cancellation_deferred
        except asyncio.CancelledError:
            if cleanup_task.cancelled():
                raise
            cancellation_deferred = True


async def _allow_finished_command_to_settle(
    streams_task: asyncio.Task[ProcessStreamResult],
    wait_task: asyncio.Task[int],
) -> None:
    pending = {
        task for task in (streams_task, wait_task) if not task.done()
    }
    if pending:
        await asyncio.wait(
            pending,
            timeout=_OUTPUT_LIMIT_EXIT_GRACE_SECONDS,
            return_when=asyncio.ALL_COMPLETED,
        )


async def _wait_for_direct_child_exit(contained: ContainedProcess) -> int:
    while contained.process.returncode is None:
        await asyncio.sleep(0.01)
    return contained.process.returncode


async def _settle_tasks(
    streams_task: asyncio.Task[ProcessStreamResult] | None,
    *,
    wait_task: asyncio.Task[int] | None,
    overflow_task: asyncio.Task[bool] | None,
) -> tuple[ProcessStreamResult | None, bool, bool]:
    cancellation_deferred = False
    if overflow_task is not None and not overflow_task.done():
        overflow_task.cancel()
    if streams_task is not None and not streams_task.done():
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _STREAM_SETTLE_SECONDS
        while not streams_task.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                await asyncio.wait((streams_task,), timeout=remaining)
            except asyncio.CancelledError:
                cancellation_deferred = True
        if not streams_task.done():
            streams_task.cancel()
    if wait_task is not None and not wait_task.done():
        wait_task.cancel()
    pending = tuple(
        task
        for task in (streams_task, wait_task, overflow_task)
        if task is not None
    )
    tasks_settled = True
    if pending:
        gathering = asyncio.gather(*pending, return_exceptions=True)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _STREAM_SETTLE_SECONDS
        while not gathering.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                tasks_settled = False
                break
            try:
                await asyncio.wait((gathering,), timeout=remaining)
            except asyncio.CancelledError:
                cancellation_deferred = True
    if (
        streams_task is not None
        and streams_task.done()
        and not streams_task.cancelled()
    ):
        try:
            return streams_task.result(), cancellation_deferred, tasks_settled
        except BaseException:
            return None, cancellation_deferred, tasks_settled
    return None, cancellation_deferred, tasks_settled


def _returncode(contained: ContainedProcess | None) -> int:
    if contained is None or contained.process.returncode is None:
        return -1
    return contained.process.returncode


def _stdout_text(streams: ProcessStreamResult | None) -> str:
    return "" if streams is None else streams.stdout.decode()


def _stderr_text(streams: ProcessStreamResult | None) -> str:
    return "" if streams is None else streams.stderr.decode()


__all__ = ["AsyncCommandProbe", "ProbeContainmentError"]
