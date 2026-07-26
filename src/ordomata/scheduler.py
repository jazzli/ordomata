"""Deterministic local scheduling primitives.

This module intentionally contains no daemon, sleeping loop, cron installer, or
``launchd`` integration.  A caller invokes :meth:`RunOnceScheduler.claim_due`
when it chooses to perform one scheduling pass.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
import math
import time
from uuid import uuid4

from .errors import OrdomataError, ValidationError
from .state import SQLiteStateStore, ScheduleClaimRecord


class ExecutionTimedOut(OrdomataError):
    """A claimed execution exhausted its fixed wall-clock deadline."""


class ClaimReason(StrEnum):
    DUE = "due"
    CLAIMED = "claimed"
    NOT_DUE = "not_due"
    MISFIRED = "misfired"
    DUPLICATE = "duplicate"
    RESOURCE_BUSY = "resource_busy"


@dataclass(frozen=True, slots=True)
class IntervalSchedule:
    """A fixed-interval schedule evaluated against explicit wall-clock time."""

    schedule_id: str
    task_id: str
    interval_seconds: int
    timeout_seconds: int
    anchor_at: float = 0.0
    misfire_grace_seconds: int | None = None
    resource_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("schedule_id", "task_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{field_name} must be a non-empty string")
        for field_name in ("interval_seconds", "timeout_seconds"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValidationError(f"{field_name} must be a positive integer")
        if (
            isinstance(self.anchor_at, bool)
            or not isinstance(self.anchor_at, (int, float))
            or not math.isfinite(float(self.anchor_at))
            or self.anchor_at < 0
        ):
            raise ValidationError("anchor_at must be a non-negative finite number")
        if self.misfire_grace_seconds is not None and (
            isinstance(self.misfire_grace_seconds, bool)
            or not isinstance(self.misfire_grace_seconds, int)
            or self.misfire_grace_seconds < 0
        ):
            raise ValidationError("misfire_grace_seconds must be a non-negative integer")
        if not isinstance(self.resource_keys, tuple):
            raise ValidationError("resource_keys must be an immutable tuple")
        if len(set(self.resource_keys)) != len(self.resource_keys):
            raise ValidationError("resource_keys must be unique")
        for key in self.resource_keys:
            if not isinstance(key, str) or not key.strip():
                raise ValidationError("resource keys must be non-empty strings")

    @property
    def effective_misfire_grace_seconds(self) -> int:
        if self.misfire_grace_seconds is None:
            return self.interval_seconds
        return self.misfire_grace_seconds


@dataclass(frozen=True, slots=True)
class ScheduleSlot:
    schedule_id: str
    slot_index: int
    slot_id: str
    scheduled_for: float


@dataclass(frozen=True, slots=True)
class ScheduledClaim:
    claim_id: str
    schedule_id: str
    task_id: str
    slot_id: str
    scheduled_for: float
    claimed_at: float
    deadline_at: float
    owner_id: str
    lease_keys: tuple[str, ...]

    def remaining_seconds(self, now: float) -> float:
        _validate_now(now)
        return max(0.0, self.deadline_at - float(now))

    def timed_out(self, now: float) -> bool:
        _validate_now(now)
        return float(now) >= self.deadline_at

    def require_active(self, now: float) -> None:
        if self.timed_out(now):
            raise ExecutionTimedOut(
                f"schedule claim {self.claim_id} reached its execution deadline"
            )


@dataclass(frozen=True, slots=True)
class ClaimDecision:
    reason: ClaimReason
    slot: ScheduleSlot | None = None
    claim: ScheduledClaim | None = None

    @property
    def claimed(self) -> bool:
        return self.claim is not None


def _validate_now(now: float) -> float:
    if (
        isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not math.isfinite(float(now))
        or now < 0
    ):
        raise ValidationError("now must be a non-negative finite number")
    return float(now)


def current_slot(schedule: IntervalSchedule, now: float) -> ScheduleSlot | None:
    """Return the interval containing ``now``, or ``None`` before the anchor."""

    timestamp = _validate_now(now)
    if timestamp < schedule.anchor_at:
        return None
    slot_index = math.floor((timestamp - schedule.anchor_at) / schedule.interval_seconds)
    scheduled_for = float(schedule.anchor_at + slot_index * schedule.interval_seconds)
    return ScheduleSlot(
        schedule_id=schedule.schedule_id,
        slot_index=slot_index,
        slot_id=str(slot_index),
        scheduled_for=scheduled_for,
    )


class RunOnceScheduler:
    """Atomically claim due work during one caller-driven scheduling pass."""

    def __init__(
        self,
        state: SQLiteStateStore,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] = lambda: uuid4().hex,
    ) -> None:
        self._state = state
        self._clock = clock
        self._id_factory = id_factory

    def inspect(self, schedule: IntervalSchedule, *, now: float | None = None) -> ClaimDecision:
        """Evaluate due/misfire state without mutating SQLite."""

        timestamp = _validate_now(self._clock() if now is None else now)
        slot = current_slot(schedule, timestamp)
        if slot is None:
            return ClaimDecision(ClaimReason.NOT_DUE)
        if timestamp - slot.scheduled_for > schedule.effective_misfire_grace_seconds:
            return ClaimDecision(ClaimReason.MISFIRED, slot=slot)
        existing = self._state.get_schedule_claim(schedule.schedule_id, slot.slot_id)
        if existing is not None:
            return ClaimDecision(ClaimReason.DUPLICATE, slot=slot)
        return ClaimDecision(ClaimReason.DUE, slot=slot)

    def claim_due(
        self,
        schedule: IntervalSchedule,
        *,
        owner_id: str,
        now: float | None = None,
    ) -> ClaimDecision:
        """Claim the current slot and its concurrency resources atomically."""

        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValidationError("owner_id must be a non-empty string")
        timestamp = _validate_now(self._clock() if now is None else now)
        inspection = self.inspect(schedule, now=timestamp)
        if inspection.reason is not ClaimReason.DUE:
            return inspection
        slot = inspection.slot
        assert slot is not None

        claim_id = self._id_factory()
        if not isinstance(claim_id, str) or not claim_id.strip():
            raise ValidationError("id_factory must return a non-empty string")
        lease_owner = f"{owner_id}/{claim_id}"
        lease_keys = tuple(
            sorted({f"schedule:{schedule.schedule_id}", *schedule.resource_keys})
        )
        deadline_at = timestamp + schedule.timeout_seconds
        record = self._state.try_claim_schedule_slot(
            claim_id=claim_id,
            schedule_id=schedule.schedule_id,
            slot_id=slot.slot_id,
            scheduled_for=slot.scheduled_for,
            claimed_at=timestamp,
            deadline_at=deadline_at,
            owner_id=lease_owner,
            lease_keys=lease_keys,
        )
        if record is None:
            if self._state.get_schedule_claim(schedule.schedule_id, slot.slot_id) is not None:
                return ClaimDecision(ClaimReason.DUPLICATE, slot=slot)
            return ClaimDecision(ClaimReason.RESOURCE_BUSY, slot=slot)
        return ClaimDecision(
            ClaimReason.CLAIMED,
            slot=slot,
            claim=self._claim_from_record(schedule, record),
        )

    def release(self, claim: ScheduledClaim) -> int:
        """Release only mutable resource leases; the slot claim remains."""

        return self._state.release_leases(claim.lease_keys, claim.owner_id)

    @staticmethod
    def _claim_from_record(
        schedule: IntervalSchedule, record: ScheduleClaimRecord
    ) -> ScheduledClaim:
        return ScheduledClaim(
            claim_id=record.claim_id,
            schedule_id=record.schedule_id,
            task_id=schedule.task_id,
            slot_id=record.slot_id,
            scheduled_for=record.scheduled_for,
            claimed_at=record.claimed_at,
            deadline_at=record.deadline_at,
            owner_id=record.owner_id,
            lease_keys=record.lease_keys,
        )


__all__ = [
    "ClaimDecision",
    "ClaimReason",
    "ExecutionTimedOut",
    "IntervalSchedule",
    "RunOnceScheduler",
    "ScheduleSlot",
    "ScheduledClaim",
    "current_slot",
]
