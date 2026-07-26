"""Subscription-only adapter for the first-party Claude Code CLI."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ..billing import fingerprint_account_identity
from ..environment import (
    CLOUD_ROUTE_ENVIRONMENT_NAMES,
    inspect_risky_environment,
)
from ..errors import ValidationError
from ..models import (
    AgentEvent,
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    CapacityState,
    EnvironmentValidation,
    PaidContinuationProtection,
    PaidCreditBalance,
    PermissionClass,
    RunRequest,
    RunnerCapabilities,
)
from ..redaction import Redactor
from ._harness import (
    FirstPartyHarnessRunner,
    add_environment_findings,
    clean_version,
    validate_override_text,
)
from .base import parse_jsonl_event


_ALLOWED_OVERRIDES = frozenset({"model", "effort", "max_turns"})
_EFFORT_LEVELS = frozenset({"low", "medium", "high"})
_PAID_SUBSCRIPTION_TYPES = frozenset(
    {
        "max",
        "claude_max",
        "pro",
        "claude_pro",
        "team",
        "enterprise",
    }
)


class ClaudeRunner(FirstPartyHarnessRunner):
    """Run Claude Code only when diagnostics prove a first-party login."""

    def __init__(self, **kwargs) -> None:
        super().__init__(binary=kwargs.pop("binary", "claude"), **kwargs)

    @property
    def runner_id(self) -> str:
        return "claude"

    async def detect_capabilities(self) -> RunnerCapabilities:
        executable = self._resolved_binary()
        if executable is None:
            return RunnerCapabilities(runner_id=self.runner_id, installed=False)

        version_result = await self._run_probe((executable, "--version"))
        help_result = await self._run_probe((executable, "--help"))
        help_text = ""
        if help_result is not None and help_result.exit_code == 0:
            help_text = f"{help_result.stdout}\n{help_result.stderr}".lower()

        required_flags = (
            "--print",
            "stream-json",
            "--permission-mode",
            "--json-schema",
            "--safe-mode",
            "--no-session-persistence",
            "--strict-mcp-config",
            "--tools",
        )
        structured = ("jsonl",) if "stream-json" in help_text else ()
        permissions = tuple(
            mode
            for mode in ("plan", "acceptEdits")
            if mode.casefold() in help_text
        )
        notes: list[str] = []
        if help_result is None or help_result.exit_code != 0:
            notes.append("Claude Code help could not be inspected.")
        return RunnerCapabilities(
            runner_id=self.runner_id,
            installed=True,
            version=(
                clean_version(version_result.stdout or version_result.stderr)
                if version_result is not None and version_result.exit_code == 0
                else None
            ),
            non_interactive=all(flag in help_text for flag in required_flags),
            structured_output_modes=structured,
            session_resume="--resume" in help_text,
            sandbox_modes=(),
            permission_modes=permissions,
            usage_telemetry="usage" in help_text or bool(structured),
            scheduler_support=False,
            notes=tuple(notes),
        )

    async def inspect_billing_route(self) -> BillingRouteAssessment:
        parent = self._parent_environment()
        risky = inspect_risky_environment(parent)
        cloud_names = tuple(
            name
            for name in risky
            if name.upper() in CLOUD_ROUTE_ENVIRONMENT_NAMES
        )
        warnings = _risk_warnings(risky)
        if cloud_names:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.CLOUD_PROVIDER_BILLING,
                confidence=AssessmentConfidence.HIGH,
                evidence=(
                    "A Claude Code cloud-provider route flag is present; policy "
                    "blocks execution regardless of its value.",
                ),
                warnings=warnings,
                risky_environment_names=risky,
            ))

        executable = self._resolved_binary()
        if executable is None:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.HIGH,
                evidence=("Claude Code executable was not found.",),
                warnings=warnings,
                risky_environment_names=risky,
            ))

        result = await self._run_probe((executable, "auth", "status", "--json"))
        if result is None or result.timed_out or result.exit_code != 0:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.LOW,
                evidence=("Claude Code authentication route could not be verified.",),
                warnings=warnings,
                risky_environment_names=risky,
            ))

        diagnostic = _parse_auth_diagnostic(result.stdout)
        if diagnostic is None:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.LOW,
                evidence=("Claude Code authentication diagnostic was not valid JSON.",),
                warnings=warnings,
                risky_environment_names=risky,
            ))
        route = _classify_auth_diagnostic(diagnostic)
        if route is BillingRoute.CLOUD_PROVIDER_BILLING:
            route = BillingRoute.CLOUD_PROVIDER_BILLING
            evidence = "Claude Code diagnostic reports a cloud-provider route."
        elif route is BillingRoute.SEPARATELY_BILLED_API:
            route = BillingRoute.SEPARATELY_BILLED_API
            evidence = "Claude Code diagnostic reports API-key authentication."
        elif route is BillingRoute.SUBSCRIPTION_OVERAGE:
            evidence = "Claude Code diagnostic reports enabled paid extra usage."
        elif route is BillingRoute.SUBSCRIPTION_INCLUDED:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                subscription_name="Claude",
                evidence=(
                    "Claude Code diagnostic reports first-party subscription/OAuth authentication.",
                    "Model API credentials are excluded from the child environment.",
                ),
                warnings=warnings,
                risky_environment_names=risky,
                capacity_state=CapacityState.UNKNOWN,
                paid_continuation_protection=PaidContinuationProtection.UNKNOWN,
                paid_credit_balance=PaidCreditBalance.NOT_APPLICABLE,
                account_identity_fingerprint=_diagnostic_account_fingerprint(
                    diagnostic
                ),
            ))
        else:
            return self._apply_billing_attestation(BillingRouteAssessment(
                runner_id=self.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.LOW,
                evidence=("Claude Code authentication diagnostic was ambiguous.",),
                warnings=warnings,
                risky_environment_names=risky,
            ))
        return self._apply_billing_attestation(BillingRouteAssessment(
            runner_id=self.runner_id,
            route=route,
            confidence=AssessmentConfidence.HIGH,
            evidence=(evidence,),
            warnings=warnings,
            risky_environment_names=risky,
            paid_credit_balance=PaidCreditBalance.NOT_APPLICABLE,
            account_identity_fingerprint=_diagnostic_account_fingerprint(diagnostic),
        ))

    async def validate_environment(
        self, request: RunRequest
    ) -> EnvironmentValidation:
        validation = await super().validate_environment(request)
        parent_names = {name.upper() for name in self._parent_environment()}
        cloud_names = tuple(sorted(parent_names & CLOUD_ROUTE_ENVIRONMENT_NAMES))
        errors: list[str] = []
        if cloud_names:
            errors.append(
                "Claude Code cloud-provider flags block subscription-only execution: "
                + ", ".join(cloud_names)
            )
        missing = [
            name
            for name in ("HOME", "PATH")
            if name not in validation.sanitized_environment
        ]
        if missing:
            errors.append(
                "Claude Code child environment requires " + ", ".join(missing) + "."
            )
        return add_environment_findings(validation, errors=tuple(errors))

    def build_command(self, request: RunRequest) -> tuple[str, ...]:
        _reject_unknown_overrides(request.runner_overrides)
        executable = self._resolved_binary() or self._binary
        # This first workflow is prompt-in / structured-output-out. Claude Code
        # does not currently provide the same OS filesystem sandbox boundary as
        # Codex, so built-in tools remain disabled even for a Class 1 local
        # draft. The deterministic controller writes accepted artifacts.
        tools = ""
        schema = json.dumps(
            request.output_schema,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        command = [
            executable,
            "--print",
            "--verbose",
            "--input-format",
            "text",
            "--output-format",
            "stream-json",
            "--permission-mode",
            "dontAsk",
            "--safe-mode",
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--disable-slash-commands",
            "--no-chrome",
            "--no-session-persistence",
            "--prompt-suggestions",
            "false",
            "--tools",
            tools,
            "--json-schema",
            schema,
        ]
        model = request.runner_overrides.get("model")
        if model is not None:
            command.extend(("--model", validate_override_text("model", model)))
        effort = request.runner_overrides.get("effort")
        if effort is not None:
            effort = validate_override_text("effort", effort)
            if effort not in _EFFORT_LEVELS:
                raise ValidationError("Unsupported Claude Code effort level.")
            command.extend(("--effort", effort))
        max_turns = request.runner_overrides.get("max_turns", 20)
        if isinstance(max_turns, bool) or not isinstance(max_turns, int):
            raise ValidationError("Claude Code max_turns must be an integer.")
        if not 1 <= max_turns <= 100:
            raise ValidationError("Claude Code max_turns must be between 1 and 100.")
        command.extend(("--max-turns", str(max_turns)))
        return tuple(command)

    def parse_event_line(self, line: str, redactor: Redactor) -> AgentEvent | None:
        return parse_jsonl_event(line, redactor=redactor)

    def execution_mode(self, request: RunRequest) -> str:
        del request
        return "claude_print_stream_json_safe_no_tools"

    def terminal_success(self, events: tuple[AgentEvent, ...] | list[AgentEvent]) -> bool:
        if not events or events[-1].event_type != "result":
            return False
        payload = events[-1].payload
        return payload.get("is_error") is False and payload.get("subtype") == "success"

    def _read_output(self, request: RunRequest, events: list[AgentEvent]) -> Any:
        del request
        for event in reversed(events):
            if event.event_type != "result":
                continue
            structured = event.payload.get("structured_output")
            if structured is not None:
                return structured
            result = event.payload.get("result")
            if isinstance(result, str):
                try:
                    return json.loads(result)
                except json.JSONDecodeError:
                    return result
            if result is not None:
                return result
        return None


def _parse_auth_diagnostic(stdout: str) -> Mapping[str, Any] | None:
    try:
        value = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, Mapping) else None


def _classify_auth_diagnostic(diagnostic: Mapping[str, Any]) -> BillingRoute:
    logged_in = diagnostic.get("loggedIn")
    method = diagnostic.get("authMethod")
    provider = diagnostic.get("apiProvider")
    if not isinstance(method, str) or not isinstance(provider, str):
        return BillingRoute.UNKNOWN
    normalized_method = method.casefold()
    normalized_provider = provider.casefold()
    if normalized_provider in {
        "aws",
        "bedrock",
        "gcp",
        "vertex",
        "azure",
        "foundry",
    }:
        return BillingRoute.CLOUD_PROVIDER_BILLING
    if normalized_method in {"api_key", "apikey", "api-key"}:
        return BillingRoute.SEPARATELY_BILLED_API
    paid_extra_usage = _paid_extra_usage_state(diagnostic)
    if paid_extra_usage is None:
        return BillingRoute.UNKNOWN
    if paid_extra_usage:
        return BillingRoute.SUBSCRIPTION_OVERAGE
    if (
        logged_in is True
        and normalized_provider == "firstparty"
        and normalized_method in {"claude.ai", "oauth"}
        and _paid_subscription_type(diagnostic) in _PAID_SUBSCRIPTION_TYPES
    ):
        return BillingRoute.SUBSCRIPTION_INCLUDED
    return BillingRoute.UNKNOWN


def _paid_subscription_type(diagnostic: Mapping[str, Any]) -> str | None:
    raw = diagnostic.get("subscriptionType")
    if not isinstance(raw, str):
        account = diagnostic.get("account")
        if isinstance(account, Mapping):
            raw = account.get("subscriptionType")
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip().casefold().replace("-", "_").replace(" ", "_")


def _paid_extra_usage_state(diagnostic: Mapping[str, Any]) -> bool | None:
    """Return paid-usage state, failing closed on malformed or conflicting data."""

    enabled_names = {
        "extrausageenabled",
        "usagecreditsenabled",
        "overageenabled",
        "paidusageenabled",
    }
    observed: list[bool | None] = []

    def inspect(value: Any, *, depth: int) -> None:
        if depth > 8 or len(observed) >= 100:
            return
        if isinstance(value, Mapping):
            for key, nested in value.items():
                normalized = "".join(
                    character
                    for character in str(key).casefold()
                    if character.isalnum()
                )
                if normalized in enabled_names:
                    observed.append(nested if type(nested) is bool else None)
                elif isinstance(nested, (Mapping, list, tuple)):
                    inspect(nested, depth=depth + 1)
        elif isinstance(value, (list, tuple)):
            for nested in value[:100]:
                inspect(nested, depth=depth + 1)

    inspect(diagnostic, depth=0)
    if any(value is None for value in observed):
        return None
    known = {value for value in observed if isinstance(value, bool)}
    if len(known) > 1:
        return None
    return True if known == {True} else False


def _diagnostic_account_fingerprint(
    diagnostic: Mapping[str, Any],
) -> str | None:
    for name in ("accountId", "account_id", "userId", "user_id", "email"):
        value = diagnostic.get(name)
        if isinstance(value, str) and value.strip():
            return fingerprint_account_identity("claude", value)
    account = diagnostic.get("account")
    if isinstance(account, Mapping):
        return _diagnostic_account_fingerprint(account)
    return None


def _risk_warnings(risky: tuple[str, ...]) -> tuple[str, ...]:
    relevant_names = {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        *CLOUD_ROUTE_ENVIRONMENT_NAMES,
    }
    relevant = tuple(name for name in risky if name.upper() in relevant_names)
    if not relevant:
        return ()
    return (
        "Risky Claude environment names were present in the parent and excluded: "
        + ", ".join(relevant),
    )


def _reject_unknown_overrides(overrides: Mapping[str, object]) -> None:
    unknown = sorted(set(overrides) - _ALLOWED_OVERRIDES)
    if unknown:
        raise ValidationError(
            "Unsupported Claude Code runner overrides: " + ", ".join(unknown)
        )


__all__ = ["ClaudeRunner"]
