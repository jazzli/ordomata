"""Deterministic runner for tests, benchmarks, and offline development."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from ..billing import BillingPolicy
from ..errors import BillingRouteBlocked, ValidationError
from ..models import (
    AgentEvent,
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    EnvironmentValidation,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PermissionClass,
    RunRequest,
    RunnerCapabilities,
    RunnerExecutionResult,
    RunStatus,
    UsageObservation,
)
from .base import EventSink, emit_event


class MockRunner:
    """Emit a fixed event script without starting a subprocess or model."""

    def __init__(
        self,
        *,
        events: Sequence[AgentEvent] = (),
        output: Any = None,
        status: RunStatus = RunStatus.SUCCEEDED,
        errors: Sequence[str] = (),
        billing_assessment: BillingRouteAssessment | None = None,
    ) -> None:
        self._events = tuple(events)
        self._output = output
        self._status = status
        self._errors = tuple(errors)
        self._billing_assessment = billing_assessment or BillingRouteAssessment(
            runner_id="mock",
            route=BillingRoute.MOCK,
            confidence=AssessmentConfidence.HIGH,
            evidence=("Deterministic mock runner; no model execution.",),
        )
        self._active: set[str] = set()
        self._cancelled: set[str] = set()

    @property
    def runner_id(self) -> str:
        return "mock"

    async def detect_capabilities(self) -> RunnerCapabilities:
        return RunnerCapabilities(
            runner_id=self.runner_id,
            installed=True,
            version="deterministic",
            non_interactive=True,
            structured_output_modes=("memory",),
            session_resume=False,
            usage_telemetry=False,
            scheduler_support=True,
            notes=("No subprocess or AI model is used.",),
        )

    async def inspect_billing_route(self) -> BillingRouteAssessment:
        return self._billing_assessment

    async def validate_environment(
        self, request: RunRequest
    ) -> EnvironmentValidation:
        errors: tuple[str, ...] = ()
        if request.permission_class not in {
            PermissionClass.READ_ONLY,
            PermissionClass.LOCAL_DRAFT,
        }:
            errors = ("Mock runner supports only permission classes 0 and 1.",)
        return EnvironmentValidation(
            valid=not errors,
            sanitized_environment={},
            errors=errors,
        )

    async def execute(
        self, request: RunRequest, event_sink: EventSink
    ) -> RunnerExecutionResult:
        if request.run_id in self._active:
            raise ValidationError(f"Run {request.run_id!r} is already active.")
        validation = await self.validate_environment(request)
        if not validation.valid:
            raise ValidationError("; ".join(validation.errors))
        assessment = await self.inspect_billing_route()
        if (
            assessment.runner_id != self.runner_id
            or assessment.route is not BillingRoute.MOCK
        ):
            raise BillingRouteBlocked(
                "Mock runner requires an identity-matched mock billing route."
            )
        BillingPolicy.assert_route_allowed(assessment)

        self._active.add(request.run_id)
        emitted: list[AgentEvent] = []
        try:
            for event in self._events:
                await asyncio.sleep(0)
                if request.run_id in self._cancelled:
                    break
                emitted.append(event)
                emit_event(event_sink, event)
        finally:
            self._active.discard(request.run_id)

        cancelled = request.run_id in self._cancelled
        self._cancelled.discard(request.run_id)
        status = RunStatus.CANCELLED if cancelled else self._status
        output = (
            {"run_id": request.run_id, "task_id": request.task_id}
            if self._output is None
            else self._output
        )
        return RunnerExecutionResult(
            runner_id=self.runner_id,
            run_id=request.run_id,
            status=status,
            billing_assessment=assessment,
            exit_code=None,
            session_id=None,
            output=output,
            usage={},
            usage_observation=UsageObservation.NOT_APPLICABLE,
            events=tuple(emitted),
            errors=self._errors,
            runner_version="deterministic",
            execution_mode="in_memory_mock",
            harness_process_started=False,
            live_model_execution_occurred=False,
            subscription_capacity_consumed=False,
            paid_capacity_consumed=PaidCapacityConsumed.NOT_APPLICABLE,
            incremental_ai_charge=IncrementalAICharge.NONE,
            wall_seconds=0.0,
        )

    async def cancel(self, run_id: str) -> None:
        if run_id in self._active:
            self._cancelled.add(run_id)


DeterministicMockRunner = MockRunner


__all__ = ["DeterministicMockRunner", "MockRunner"]
