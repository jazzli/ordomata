"""Provider-neutral runner contracts and shared parsing helpers."""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
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


EventSink = Callable[[AgentEvent], Awaitable[None] | None]


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
    """Bounded output from a non-model diagnostic subprocess."""

    command: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


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


async def emit_event(event_sink: EventSink, event: AgentEvent) -> None:
    result = event_sink(event)
    if inspect.isawaitable(result):
        await result


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
    "EventSink",
    "ProbeResult",
    "emit_event",
    "parse_jsonl_event",
]
