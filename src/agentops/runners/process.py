"""Subprocess utilities used by first-party coding-harness adapters."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from pathlib import Path

from .base import ProbeResult


class AsyncCommandProbe:
    """Run bounded diagnostic commands without invoking a shell."""

    def __init__(self, *, max_output_bytes: int = 256_000) -> None:
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        self._max_output_bytes = max_output_bytes

    async def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path | None = None,
        timeout_seconds: float = 10.0,
    ) -> ProbeResult:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        process: asyncio.subprocess.Process | None = None
        try:
            async with asyncio.timeout(timeout_seconds):
                process = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=cwd,
                    env=dict(environment),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()
        except TimeoutError:
            if process is not None and process.returncode is None:
                process.kill()
                stdout, stderr = await process.communicate()
            else:
                stdout, stderr = b"", b""
            return ProbeResult(
                tuple(command),
                (
                    process.returncode
                    if process is not None and process.returncode is not None
                    else -1
                ),
                _decode_bounded(stdout, self._max_output_bytes),
                _decode_bounded(stderr, self._max_output_bytes),
                timed_out=True,
            )
        except BaseException:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            raise
        assert process is not None
        return ProbeResult(
            tuple(command),
            process.returncode or 0,
            _decode_bounded(stdout, self._max_output_bytes),
            _decode_bounded(stderr, self._max_output_bytes),
        )


def _decode_bounded(value: bytes, limit: int) -> str:
    return value[:limit].decode("utf-8", errors="replace")


__all__ = ["AsyncCommandProbe"]
