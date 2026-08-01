from __future__ import annotations

import asyncio
import os
import signal
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ordomata.runners import containment
from ordomata.runners.containment import (
    CleanupDisposition,
    ContainedProcessLaunchCancelled,
    ContainmentUnavailableError,
    StreamLimitExceeded,
    drain_process_streams,
    iter_bounded_lines,
    launch_contained_process,
    terminate_contained_process,
)


class BoundedStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_drain_process_streams_retains_only_bounded_prefixes(self) -> None:
        contained = await launch_contained_process(
            (
                sys.executable,
                "-c",
                (
                    "import os; "
                    "os.write(1, b'a' * 200000); "
                    "os.write(2, b'b' * 120000)"
                ),
            ),
            environment={},
        )
        overflow_event = asyncio.Event()

        streams = await asyncio.wait_for(
            drain_process_streams(
                contained,
                max_stdout_bytes=31,
                max_stderr_bytes=47,
                chunk_bytes=4096,
                overflow_event=overflow_event,
            ),
            timeout=5.0,
        )
        await asyncio.wait_for(contained.process.wait(), timeout=1.0)

        self.assertEqual(streams.stdout.data, b"a" * 31)
        self.assertEqual(streams.stdout.observed_bytes, 200000)
        self.assertTrue(streams.stdout.truncated)
        self.assertEqual(streams.stderr.data, b"b" * 47)
        self.assertEqual(streams.stderr.observed_bytes, 120000)
        self.assertTrue(streams.stderr.truncated)
        self.assertTrue(streams.limit_exceeded)
        self.assertTrue(overflow_event.is_set())

    async def test_bounded_line_iterator_yields_newline_and_final_tail(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"one\ntwo\ntail")
        reader.feed_eof()

        lines = [
            line
            async for line in iter_bounded_lines(
                reader,
                max_total_bytes=12,
                max_line_bytes=5,
                chunk_bytes=3,
            )
        ]

        self.assertEqual(lines, [b"one\n", b"two\n", b"tail"])

    async def test_bounded_line_iterator_fails_at_total_byte_limit(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"ok\nnext")
        reader.feed_eof()
        overflow_event = asyncio.Event()
        lines = iter_bounded_lines(
            reader,
            max_total_bytes=5,
            max_line_bytes=20,
            overflow_event=overflow_event,
        )

        self.assertEqual(await anext(lines), b"ok\n")
        with self.assertRaises(StreamLimitExceeded) as raised:
            await anext(lines)

        self.assertEqual(
            raised.exception.reason_code,
            "stream_total_bytes_limit_exceeded",
        )
        self.assertEqual(raised.exception.limit, 5)
        self.assertEqual(raised.exception.observed, 6)
        self.assertEqual(str(raised.exception), raised.exception.reason_code)
        self.assertTrue(overflow_event.is_set())

    async def test_bounded_line_iterator_fails_at_line_byte_limit(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"ok\n12345\n")
        reader.feed_eof()
        lines = iter_bounded_lines(
            reader,
            max_total_bytes=100,
            max_line_bytes=4,
            chunk_bytes=2,
        )

        self.assertEqual(await anext(lines), b"ok\n")
        with self.assertRaises(StreamLimitExceeded) as raised:
            await anext(lines)

        self.assertEqual(
            raised.exception.reason_code,
            "stream_line_bytes_limit_exceeded",
        )
        self.assertEqual(raised.exception.limit, 4)
        self.assertEqual(raised.exception.observed, 5)


@unittest.skipUnless(
    containment.posix_containment_available(),
    "POSIX process-group containment is unavailable",
)
class PosixContainmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_fast_exit_launches_do_not_fail_identity_race(self) -> None:
        for _ in range(50):
            contained = await launch_contained_process(
                (sys.executable, "-c", "pass"),
                environment={},
            )
            streams = await drain_process_streams(
                contained,
                max_stdout_bytes=0,
                max_stderr_bytes=0,
            )
            await contained.process.wait()
            cleanup = await terminate_contained_process(contained)

            self.assertFalse(streams.limit_exceeded)
            self.assertEqual(cleanup.disposition, CleanupDisposition.VERIFIED)
            self.assertTrue(cleanup.process_group_absent)
            self.assertTrue(cleanup.direct_child_reaped)

    async def test_launch_creates_new_session_and_cleanup_verifies_exit(self) -> None:
        contained = await launch_contained_process(
            (
                sys.executable,
                "-c",
                "import time; print('done', flush=True); time.sleep(0.05)",
            ),
            environment={},
        )
        streams = await drain_process_streams(
            contained,
            max_stdout_bytes=100,
            max_stderr_bytes=100,
        )
        await contained.process.wait()

        cleanup = await terminate_contained_process(contained)

        self.assertEqual(streams.stdout.data, b"done\n")
        self.assertEqual(cleanup.disposition, CleanupDisposition.VERIFIED)
        self.assertEqual(cleanup.reason_code, "already_exited")
        self.assertFalse(cleanup.term_sent)
        self.assertFalse(cleanup.kill_sent)
        self.assertTrue(cleanup.direct_child_reaped)
        self.assertTrue(cleanup.process_group_absent)

    async def test_launch_cancellation_cleans_process_created_during_race(
        self,
    ) -> None:
        real_create_subprocess_exec = asyncio.create_subprocess_exec
        process_created = asyncio.Event()
        release_creation = asyncio.Event()
        created_pid: list[int] = []

        async def delayed_creation(*args: object, **kwargs: object):
            process = await real_create_subprocess_exec(*args, **kwargs)
            created_pid.append(process.pid)
            process_created.set()
            await release_creation.wait()
            return process

        with mock.patch.object(
            containment.asyncio,
            "create_subprocess_exec",
            new=delayed_creation,
        ):
            launch_task = asyncio.create_task(
                launch_contained_process(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import signal,time; "
                            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                            "time.sleep(60)"
                        ),
                    ),
                    environment={},
                )
            )
            await asyncio.wait_for(process_created.wait(), timeout=2.0)
            launch_task.cancel()
            await asyncio.sleep(0)
            release_creation.set()
            with self.assertRaises(ContainedProcessLaunchCancelled) as raised:
                await asyncio.wait_for(launch_task, timeout=3.0)

        cleanup = raised.exception.cleanup_result
        self.assertIsNotNone(cleanup)
        assert cleanup is not None
        self.assertEqual(cleanup.disposition, CleanupDisposition.VERIFIED)
        self.assertTrue(cleanup.process_group_absent)
        self.assertEqual(len(created_pid), 1)
        with self.assertRaises(ProcessLookupError):
            os.killpg(created_pid[0], 0)

    async def test_cleanup_escalates_and_removes_descendant_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            pid_path = Path(temporary_directory) / "descendant.pid"
            child_program = (
                "import signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(60)"
            )
            parent_program = (
                "import pathlib,signal,subprocess,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"child=subprocess.Popen([sys.executable, '-c', {child_program!r}]); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                "time.sleep(60)"
            )
            contained = await launch_contained_process(
                (sys.executable, "-c", parent_program),
                environment={},
            )
            streams_task = asyncio.create_task(
                drain_process_streams(
                    contained,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                )
            )
            self.addAsyncCleanup(self._ensure_cleanup, contained, streams_task)
            await self._wait_for_path(pid_path)

            self.assertEqual(
                os.getpgid(contained.process.pid), contained.process_group_id
            )
            self.assertEqual(
                os.getsid(contained.process.pid), contained.session_id
            )
            cleanup = await terminate_contained_process(
                contained,
                term_grace_seconds=0.05,
                kill_grace_seconds=2.0,
            )
            await asyncio.wait_for(streams_task, timeout=2.0)

            self.assertEqual(cleanup.disposition, CleanupDisposition.VERIFIED)
            self.assertEqual(cleanup.reason_code, "killed")
            self.assertTrue(cleanup.term_sent)
            self.assertTrue(cleanup.kill_sent)
            self.assertTrue(cleanup.direct_child_reaped)
            self.assertTrue(cleanup.process_group_absent)
            with self.assertRaises(ProcessLookupError):
                os.killpg(contained.process_group_id, 0)

    async def test_verified_scope_excludes_descendants_that_create_a_session(
        self,
    ) -> None:
        """VERIFIED is intentionally original-group evidence, not tree evidence."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            pid_path = Path(temporary_directory) / "escaped.pid"
            escaped_program = "import time; time.sleep(60)"
            parent_program = (
                "import pathlib,subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable, '-c', {escaped_program!r}], "
                "start_new_session=True); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                "time.sleep(60)"
            )
            contained = await launch_contained_process(
                (sys.executable, "-c", parent_program),
                environment={},
            )
            escaped_pid: int | None = None
            try:
                await self._wait_for_path(pid_path)
                escaped_pid = int(pid_path.read_text())
                cleanup = await terminate_contained_process(
                    contained,
                    term_grace_seconds=0.1,
                    kill_grace_seconds=1.0,
                )

                self.assertTrue(cleanup.verified)
                self.assertTrue(cleanup.process_group_absent)
                self.assertNotEqual(os.getpgid(escaped_pid), contained.process_group_id)
                os.kill(escaped_pid, 0)
            finally:
                if contained.process.returncode is None:
                    await terminate_contained_process(contained)
                if escaped_pid is not None:
                    try:
                        os.kill(escaped_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    async def test_cleanup_rejects_controller_ownership_mismatch(self) -> None:
        contained = await launch_contained_process(
            (sys.executable, "-c", "import time; time.sleep(60)"),
            environment={},
        )
        forged = replace(contained, controller_pid=os.getpid() + 1)

        uncertain = await terminate_contained_process(forged)
        cleanup = await terminate_contained_process(
            contained,
            term_grace_seconds=0.1,
            kill_grace_seconds=1.0,
        )

        self.assertEqual(uncertain.disposition, CleanupDisposition.UNCERTAIN)
        self.assertEqual(
            uncertain.reason_code, "controller_ownership_mismatch"
        )
        self.assertFalse(uncertain.term_sent)
        self.assertFalse(uncertain.kill_sent)
        self.assertEqual(cleanup.disposition, CleanupDisposition.VERIFIED)

    async def test_cleanup_never_signals_when_group_presence_is_unknown(self) -> None:
        contained = await launch_contained_process(
            (sys.executable, "-c", "import time; time.sleep(60)"),
            environment={},
        )
        try:
            with mock.patch.object(
                containment,
                "_process_group_presence",
                return_value=containment._ProcessGroupPresence.UNKNOWN,
            ), mock.patch.object(
                containment, "_signal_process_group"
            ) as signal_group:
                uncertain = await terminate_contained_process(contained)

            self.assertEqual(
                uncertain.disposition,
                CleanupDisposition.UNCERTAIN,
            )
            self.assertEqual(
                uncertain.reason_code,
                "process_group_status_unknown",
            )
            signal_group.assert_not_called()
        finally:
            await terminate_contained_process(
                contained,
                term_grace_seconds=0.1,
                kill_grace_seconds=1.0,
            )

    async def test_cleanup_revalidates_live_group_identity_before_signal(self) -> None:
        contained = await launch_contained_process(
            (sys.executable, "-c", "import time; time.sleep(60)"),
            environment={},
        )
        try:
            with mock.patch.object(
                containment,
                "_contained_identity_status",
                return_value=containment._ContainedIdentityStatus.MISMATCH,
            ), mock.patch.object(
                containment, "_signal_process_group"
            ) as signal_group:
                uncertain = await terminate_contained_process(contained)

            self.assertEqual(
                uncertain.disposition,
                CleanupDisposition.UNCERTAIN,
            )
            self.assertEqual(
                uncertain.reason_code,
                "process_group_identity_unknown",
            )
            signal_group.assert_not_called()
        finally:
            await terminate_contained_process(
                contained,
                term_grace_seconds=0.1,
                kill_grace_seconds=1.0,
            )

    async def test_unknown_term_result_never_escalates_to_kill(self) -> None:
        contained = await launch_contained_process(
            (sys.executable, "-c", "import time; time.sleep(60)"),
            environment={},
        )
        try:
            with mock.patch.object(
                containment,
                "_signal_process_group",
                return_value=(False, containment._ProcessGroupPresence.UNKNOWN),
            ) as signal_group:
                uncertain = await terminate_contained_process(contained)

            self.assertEqual(
                uncertain.disposition,
                CleanupDisposition.UNCERTAIN,
            )
            self.assertEqual(
                uncertain.reason_code,
                "process_group_signal_status_unknown",
            )
            signal_group.assert_called_once_with(
                contained.process_group_id,
                signal.SIGTERM,
            )
        finally:
            await terminate_contained_process(
                contained,
                term_grace_seconds=0.1,
                kill_grace_seconds=1.0,
            )

    async def _wait_for_path(self, path: Path) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 2.0
        while not path.exists():
            if loop.time() >= deadline:
                self.fail("test subprocess did not publish descendant PID")
            await asyncio.sleep(0.01)

    async def _ensure_cleanup(
        self,
        contained: containment.ContainedProcess,
        streams_task: asyncio.Task[containment.ProcessStreamResult],
    ) -> None:
        if contained.process.returncode is None:
            await terminate_contained_process(
                contained,
                term_grace_seconds=0.05,
                kill_grace_seconds=1.0,
            )
        if not streams_task.done():
            streams_task.cancel()
        await asyncio.gather(streams_task, return_exceptions=True)


class UnsupportedContainmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_host_fails_before_process_creation(self) -> None:
        with mock.patch.object(
            containment, "_POSIX_PROCESS_GROUPS_AVAILABLE", False
        ), mock.patch.object(
            asyncio, "create_subprocess_exec", new=mock.AsyncMock()
        ) as create_process:
            with self.assertRaises(ContainmentUnavailableError):
                await launch_contained_process(
                    (sys.executable, "-c", "pass"),
                    environment={},
                )

        create_process.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
