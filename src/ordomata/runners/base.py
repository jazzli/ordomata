"""Provider-neutral runner contracts and shared parsing helpers."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..errors import ValidationError
from ..models import (
    AgentEvent,
    BillingRouteAssessment,
    EnvironmentValidation,
    RunRequest,
    RunnerCapabilities,
    RunnerExecutionResult,
)
from ..redaction import DEFAULT_REDACTOR, Redactor


EventSink = Callable[[AgentEvent], None]
CONTROLLER_EVENT_SINK_LIMIT = 4096


class ControllerEventSink:
    """Sealed, count-only sink safe for timeout-critical live runners."""

    __slots__ = ("_count",)

    def __init__(self) -> None:
        self._count = 0

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ControllerEventSink cannot be subclassed")

    @property
    def count(self) -> int:
        return self._count

    def __call__(self, event: AgentEvent) -> None:
        if not isinstance(event, AgentEvent):
            raise ValidationError("Runner emitted an invalid event type.")
        if self._count >= CONTROLLER_EVENT_SINK_LIMIT:
            raise ValidationError(
                "Runner event count exceeded the controller limit."
            )
        self._count += 1


@runtime_checkable
class AgentRunner(Protocol):
    """The orchestration core's asynchronous, provider-neutral boundary."""

    @property
    def runner_id(self) -> str: ...

    async def detect_capabilities(self) -> RunnerCapabilities: ...

    async def inspect_billing_route(self) -> BillingRouteAssessment: ...

    async def validate_environment(
        self, request: RunRequest
    ) -> EnvironmentValidation: ...

    async def execute(
        self, request: RunRequest, event_sink: EventSink
    ) -> RunnerExecutionResult: ...

    async def cancel(self, run_id: str) -> None: ...


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Bounded output and explicit original-group cleanup evidence."""

    command: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    output_limit_exceeded: bool = False
    containment_cleanup_verified: bool = False


@runtime_checkable
class CommandProbe(Protocol):
    async def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path | None = None,
        timeout_seconds: float = 10.0,
    ) -> ProbeResult: ...


def emit_event(event_sink: EventSink, event: AgentEvent) -> None:
    """Deliver one event through a synchronous runner callback."""

    result = event_sink(event)
    if result is None:
        return
    if inspect.iscoroutine(result):
        result.close()
    raise ValidationError("Runner event sinks must be synchronous and return None.")


def parse_jsonl_event(
    line: str,
    *,
    redactor: Redactor = DEFAULT_REDACTOR,
) -> AgentEvent | None:
    """Parse one JSON object event, rejecting malformed structured output."""

    if not line.strip():
        return None
    try:
        decoded = json.loads(line)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValidationError("Harness emitted malformed JSONL output.") from exc
    if not isinstance(decoded, dict):
        raise ValidationError("Harness JSONL event must be an object.")
    event_type = decoded.get("type") or decoded.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        raise ValidationError("Harness JSONL event is missing a string event type.")
    event_type = redactor.redact_text(event_type)
    redacted = redactor.redact(decoded)
    assert isinstance(redacted, dict)
    return AgentEvent(
        event_type=event_type,
        payload=redacted,
        credential_material_detected=redacted != decoded,
    )


__all__ = [
    "AgentRunner",
    "CommandProbe",
    "CONTROLLER_EVENT_SINK_LIMIT",
    "ControllerEventSink",
    "EventSink",
    "ProbeResult",
    "emit_event",
    "parse_jsonl_event",
]
