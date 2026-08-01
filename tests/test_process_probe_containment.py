from __future__ import annotations

import asyncio
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ordomata.runners import process as process_module
from ordomata.runners.base import ProbeResult
from ordomata.runners.containment import (
    CleanupDisposition,
    CleanupResult,
    posix_containment_available,
)
from ordomata.runners.process import AsyncCommandProbe, ProbeContainmentError


@unittest.skipUnless(
    posix_containment_available(),
    "POSIX process-group containment is unavailable",
)
class AsyncCommandProbeContainmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_output_limit_succeeds(self) -> None:
        probe = AsyncCommandProbe(max_output_bytes=5)

        result = await probe.run(
            (
                sys.executable,
                "-c",
                "import os; os.write(1, b'abcde'); os.write(2, b'vwxyz')",
            ),
            environment={},
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "abcde")
        self.assertEqual(result.stderr, "vwxyz")
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limit_exceeded)
        self.assertTrue(result.containment_cleanup_verified)

    async def test_one_byte_over_limit_sets_failure_flag(self) -> None:
        probe = AsyncCommandProbe(max_output_bytes=5)
        started = time.monotonic()

        result = await probe.run(
            (
                sys.executable,
                "-c",
                "import os,time; os.write(1, b'abcdef'); time.sleep(60)",
            ),
            environment={},
            timeout_seconds=5.0,
        )

        self.assertEqual(result.stdout, "abcde")
        self.assertFalse(result.timed_out)
        self.assertTrue(result.output_limit_exceeded)
        self.assertTrue(result.containment_cleanup_verified)
        self.assertLess(time.monotonic() - started, 2.0)

    async def test_timeout_removes_descendant_process_group(self) -> None:
        probe = AsyncCommandProbe()
        with tempfile.TemporaryDirectory() as temporary_directory:
            identity_path = Path(temporary_directory) / "process-group.txt"
            program = self._descendant_program(identity_path)
            process_group_id: int | None = None
            try:
                result = await probe.run(
                    (sys.executable, "-c", program),
                    environment={},
                    timeout_seconds=0.5,
                )
                process_group_id = int(identity_path.read_text().split()[0])

                self.assertTrue(result.timed_out)
                self.assertFalse(result.output_limit_exceeded)
                self.assertTrue(result.containment_cleanup_verified)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process_group_id, 0)
            finally:
                self._kill_test_group_if_present(process_group_id)

    async def test_direct_exit_cleans_pipe_holding_descendant_promptly(self) -> None:
        probe = AsyncCommandProbe()
        with tempfile.TemporaryDirectory() as temporary_directory:
            identity_path = Path(temporary_directory) / "process-group.txt"
            process_group_id: int | None = None
            started = time.monotonic()
            try:
                result = await probe.run(
                    (
                        sys.executable,
                        "-c",
                        self._descendant_program(identity_path, parent_sleeps=False),
                    ),
                    environment={},
                    timeout_seconds=5.0,
                )
                process_group_id = int(identity_path.read_text().split()[0])

                self.assertEqual(result.exit_code, -1)
                self.assertFalse(result.timed_out)
                self.assertFalse(result.output_limit_exceeded)
                self.assertFalse(result.containment_cleanup_verified)
                self.assertLess(time.monotonic() - started, 2.0)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process_group_id, 0)
            finally:
                self._kill_test_group_if_present(process_group_id)

    async def test_cancellation_removes_descendant_process_group(self) -> None:
        probe = AsyncCommandProbe()
        with tempfile.TemporaryDirectory() as temporary_directory:
            identity_path = Path(temporary_directory) / "process-group.txt"
            probe_task = asyncio.create_task(
                probe.run(
                    (
                        sys.executable,
                        "-c",
                        self._descendant_program(identity_path),
                    ),
                    environment={},
                    timeout_seconds=10.0,
                )
            )
            process_group_id: int | None = None
            try:
                await self._wait_for_path(identity_path)
                process_group_id = int(identity_path.read_text().split()[0])
                probe_task.cancel()

                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(probe_task, timeout=3.0)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process_group_id, 0)
            finally:
                if not probe_task.done():
                    probe_task.cancel()
                    await asyncio.gather(probe_task, return_exceptions=True)
                self._kill_test_group_if_present(process_group_id)

    async def test_uncertain_cleanup_raises_fixed_sanitized_error(self) -> None:
        uncertain = CleanupResult(
            disposition=CleanupDisposition.UNCERTAIN,
            reason_code="process_group_status_unknown",
            term_sent=False,
            kill_sent=False,
            direct_child_reaped=True,
            process_group_absent=False,
            returncode=0,
        )
        probe = AsyncCommandProbe()
        with mock.patch.object(
            process_module,
            "terminate_contained_process",
            new=mock.AsyncMock(return_value=uncertain),
        ):
            with self.assertRaises(ProbeContainmentError) as raised:
                await probe.run(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import time; "
                            "print('PRIVATE-DIAGNOSTIC', flush=True); "
                            "time.sleep(0.05)"
                        ),
                    ),
                    environment={},
                )

        self.assertEqual(
            str(raised.exception),
            "diagnostic process-group cleanup could not be verified",
        )
        self.assertNotIn("PRIVATE-DIAGNOSTIC", str(raised.exception))

    async def test_stream_settling_defers_and_reports_fresh_cancellation(
        self,
    ) -> None:
        streams_task = asyncio.create_task(asyncio.sleep(60))
        wait_task = asyncio.create_task(asyncio.sleep(60))
        overflow_task = asyncio.create_task(asyncio.sleep(60))
        settle_task = asyncio.create_task(
            process_module._settle_tasks(
                streams_task,
                wait_task=wait_task,
                overflow_task=overflow_task,
            )
        )
        await asyncio.sleep(0.01)

        settle_task.cancel()
        settle_task.cancel()
        streams, cancellation_deferred, tasks_settled = await asyncio.wait_for(
            settle_task, timeout=2.0
        )

        self.assertIsNone(streams)
        self.assertTrue(cancellation_deferred)
        self.assertTrue(tasks_settled)
        self.assertEqual(settle_task.cancelling(), 2)
        self.assertTrue(streams_task.done())
        self.assertTrue(wait_task.done())
        self.assertTrue(overflow_task.done())

    @staticmethod
    def _descendant_program(
        identity_path: Path,
        *,
        parent_sleeps: bool = True,
    ) -> str:
        child_program = "import time; time.sleep(60)"
        return (
            "import os,pathlib,subprocess,sys,time; "
            f"child=subprocess.Popen([sys.executable, '-c', {child_program!r}]); "
            f"pathlib.Path({str(identity_path)!r}).write_text("
            "f'{os.getpgrp()} {child.pid}'); "
            + ("time.sleep(60)" if parent_sleeps else "")
        )

    async def _wait_for_path(self, path: Path) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 2.0
        while not path.exists():
            if loop.time() >= deadline:
                self.fail("diagnostic subprocess did not publish its process group")
            await asyncio.sleep(0.01)

    @staticmethod
    def _kill_test_group_if_present(process_group_id: int | None) -> None:
        if process_group_id is None:
            return
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass


class ProbeResultDefaultsTests(unittest.TestCase):
    def test_containment_evidence_defaults_fail_closed(self) -> None:
        result = ProbeResult(("fake",), 0)

        self.assertFalse(result.output_limit_exceeded)
        self.assertFalse(result.containment_cleanup_verified)


if __name__ == "__main__":
    unittest.main()
