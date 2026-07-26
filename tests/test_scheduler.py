from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from agentops.scheduler import (
    ClaimReason,
    ExecutionTimedOut,
    IntervalSchedule,
    RunOnceScheduler,
    current_slot,
)
from agentops.state import SQLiteStateStore


class RunOnceSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = SQLiteStateStore(Path(self.temporary.name) / "state.sqlite3")
        ids = iter(("claim-a", "claim-b", "claim-c", "claim-d"))
        self.scheduler = RunOnceScheduler(self.store, id_factory=lambda: next(ids))

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    @staticmethod
    def _schedule(schedule_id: str = "lint", **changes: object) -> IntervalSchedule:
        values = {
            "schedule_id": schedule_id,
            "task_id": schedule_id,
            "interval_seconds": 60,
            "timeout_seconds": 30,
            "anchor_at": 100.0,
            "resource_keys": ("repo:one", "runner:codex"),
        }
        values.update(changes)
        return IntervalSchedule(**values)

    def test_slot_calculation_and_misfire_are_deterministic(self) -> None:
        schedule = self._schedule(misfire_grace_seconds=5)
        self.assertIsNone(current_slot(schedule, 99))
        self.assertEqual(current_slot(schedule, 160).slot_id, "1")
        self.assertEqual(self.scheduler.inspect(schedule, now=99).reason, ClaimReason.NOT_DUE)
        self.assertEqual(self.scheduler.inspect(schedule, now=107).reason, ClaimReason.MISFIRED)

    def test_inspection_reports_due_without_claiming(self) -> None:
        schedule = self._schedule()
        decision = self.scheduler.inspect(schedule, now=100)
        self.assertEqual(decision.reason, ClaimReason.DUE)
        self.assertIsNone(decision.claim)
        self.assertEqual(self.store.list_schedule_claims(), ())

    def test_claim_prevents_duplicate_dispatch_but_release_frees_resources(self) -> None:
        schedule = self._schedule()
        decision = self.scheduler.claim_due(schedule, owner_id="daemon", now=100)
        self.assertEqual(decision.reason, ClaimReason.CLAIMED)
        self.assertIsNotNone(decision.claim)
        duplicate = self.scheduler.claim_due(schedule, owner_id="daemon", now=101)
        self.assertEqual(duplicate.reason, ClaimReason.DUPLICATE)
        self.assertEqual(self.scheduler.release(decision.claim), 3)
        still_duplicate = self.scheduler.claim_due(schedule, owner_id="daemon", now=102)
        self.assertEqual(still_duplicate.reason, ClaimReason.DUPLICATE)

    def test_shared_resource_blocks_other_schedule_until_release_or_timeout(self) -> None:
        first = self.scheduler.claim_due(self._schedule("lint"), owner_id="daemon", now=100)
        second = self.scheduler.claim_due(self._schedule("types"), owner_id="daemon", now=100)
        self.assertEqual(second.reason, ClaimReason.RESOURCE_BUSY)
        self.scheduler.release(first.claim)
        retried = self.scheduler.claim_due(self._schedule("types"), owner_id="daemon", now=101)
        self.assertEqual(retried.reason, ClaimReason.CLAIMED)

    def test_claim_has_fixed_timeout(self) -> None:
        claim = self.scheduler.claim_due(
            self._schedule(timeout_seconds=10), owner_id="daemon", now=100
        ).claim
        self.assertEqual(claim.remaining_seconds(104), 6)
        self.assertFalse(claim.timed_out(109.99))
        self.assertTrue(claim.timed_out(110))
        with self.assertRaises(ExecutionTimedOut):
            claim.require_active(110)


if __name__ == "__main__":
    unittest.main()
