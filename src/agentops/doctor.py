"""Read-only diagnostics for the local subscription-only control plane.

The doctor never executes a model.  Harness adapters are asked only for their
bounded, local capability and authentication diagnostics; no runner
``execute`` method is called.  Environment values are deliberately absent
from every public diagnostic type.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hmac
import math
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any

from .billing import (
    BillingPolicy,
    FileBillingAttestationLoader,
    LIVE_RUN_ENVIRONMENT_NAME,
)
from .environment import inspect_risky_environment, is_sensitive_environment_name
from .models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    EnvironmentValidation,
    PaidContinuationProtection,
    PaidCreditBalance,
    PermissionClass,
    RunRequest,
    RunnerCapabilities,
)
from .redaction import Redactor
from .runners import AgentRunner, ClaudeRunner, CodexRunner, MockRunner


@dataclass(frozen=True, slots=True)
class LiveGateDiagnostic:
    """The state of the exact live-run opt-in, without retaining its value."""

    environment_name: str
    enabled: bool
    state: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "environment_name": self.environment_name,
            "enabled": self.enabled,
            "state": self.state,
        }


@dataclass(frozen=True, slots=True)
class PathHealth:
    """Non-mutating health assessment for a workspace or run root."""

    role: str
    path: str
    exists: bool
    is_directory: bool
    readable: bool
    writable: bool
    creatable: bool
    ready: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "exists": self.exists,
            "is_directory": self.is_directory,
            "readable": self.readable,
            "writable": self.writable,
            "creatable": self.creatable,
            "ready": self.ready,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class SQLiteHealth:
    """Result of an isolated in-memory SQLite and FTS5 smoke check."""

    ready: bool
    sqlite_available: bool
    fts5_available: bool
    sqlite_version: str
    integrity_check: str | None
    errors: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "sqlite_available": self.sqlite_available,
            "fts5_available": self.fts5_available,
            "sqlite_version": self.sqlite_version,
            "integrity_check": self.integrity_check,
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class EnvironmentDiagnostic:
    """Safe projection of child-environment validation.

    Only names and adapter-authored findings are retained.  In particular,
    this type has no field capable of carrying the sanitized value mapping.
    """

    valid: bool
    sanitized_names: tuple[str, ...]
    excluded_names: tuple[str, ...]
    risky_names: tuple[str, ...]
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "sanitized_names": list(self.sanitized_names),
            "excluded_names": list(self.excluded_names),
            "risky_names": list(self.risky_names),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class RunnerDiagnostic:
    """Fail-closed readiness and capability report for one runner."""

    runner_id: str
    installed: bool
    version: str | None
    non_interactive: bool
    structured_output_modes: tuple[str, ...]
    session_resume: bool
    sandbox_modes: tuple[str, ...]
    permission_modes: tuple[str, ...]
    usage_telemetry: bool
    scheduler_support: bool
    capability_notes: tuple[str, ...]
    billing_route: str
    billing_confidence: str
    subscription_name: str | None
    subscription_auth_verified: bool
    subscription_verified: bool
    billing_route_allowed: bool
    billing_evidence: tuple[str, ...]
    billing_warnings: tuple[str, ...]
    capacity_state: CapacityState
    paid_continuation_protection: PaidContinuationProtection
    paid_credit_balance: PaidCreditBalance
    account_identity_fingerprint: str | None = field(repr=False)
    capacity_observed_at: float | None = field(repr=False)
    capacity_expires_at: float | None = field(repr=False)
    attestation: BillingSafetyAttestation | None = field(repr=False)
    capacity_evidence_status: str
    attestation_status: str
    environment: EnvironmentDiagnostic
    live_gate_required: bool
    ready_now: bool
    blockers: tuple[str, ...]
    diagnostic_errors: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "runner_id": self.runner_id,
            "installed": self.installed,
            "version": self.version,
            "capabilities": {
                "non_interactive": self.non_interactive,
                "structured_output_modes": list(self.structured_output_modes),
                "session_resume": self.session_resume,
                "sandbox_modes": list(self.sandbox_modes),
                "permission_modes": list(self.permission_modes),
                "usage_telemetry": self.usage_telemetry,
                "scheduler_support": self.scheduler_support,
                "notes": list(self.capability_notes),
            },
            "billing": {
                "route": self.billing_route,
                "confidence": self.billing_confidence,
                "subscription_name": self.subscription_name,
                "subscription_auth_verified": self.subscription_auth_verified,
                "subscription_included_only_verified": self.subscription_verified,
                "subscription_verified": self.subscription_verified,
                "route_allowed": self.billing_route_allowed,
                "evidence": list(self.billing_evidence),
                "warnings": list(self.billing_warnings),
                "capacity_state": self.capacity_state.value,
                "paid_continuation_protection": (
                    self.paid_continuation_protection.value
                ),
                "paid_credit_balance": self.paid_credit_balance.value,
                "account_identity_verified": (
                    _verified_fingerprint(self.account_identity_fingerprint)
                ),
                "capacity_evidence_status": self.capacity_evidence_status,
                "attestation_status": self.attestation_status,
            },
            "environment": self.environment.to_mapping(),
            "live_gate_required": self.live_gate_required,
            "ready_now": self.ready_now,
            "blockers": list(self.blockers),
            "diagnostic_errors": list(self.diagnostic_errors),
        }


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """JSON-safe, value-free snapshot of local readiness."""

    schema_version: int
    live_gate: LiveGateDiagnostic
    workspace: PathHealth
    run_root: PathHealth
    sqlite: SQLiteHealth
    runners: tuple[RunnerDiagnostic, ...]
    local_control_plane_ready: bool
    any_runner_ready_now: bool
    subscription_runner_ready_now: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "live_gate": self.live_gate.to_mapping(),
            "workspace": self.workspace.to_mapping(),
            "run_root": self.run_root.to_mapping(),
            "sqlite": self.sqlite.to_mapping(),
            "runners": [runner.to_mapping() for runner in self.runners],
            "summary": {
                "local_control_plane_ready": self.local_control_plane_ready,
                "any_runner_ready_now": self.any_runner_ready_now,
                "subscription_runner_ready_now": self.subscription_runner_ready_now,
            },
        }


async def collect_doctor_report(
    runners: Sequence[AgentRunner] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    workspace: str | Path | None = None,
    run_root: str | Path | None = None,
) -> DoctorReport:
    """Collect deterministic diagnostics without invoking models or APIs.

    When ``runners`` is omitted, first-party Codex and Claude adapters plus the
    deterministic mock adapter are checked.  Their probes are restricted to
    presence/version/help and local authentication-route inspection by the
    adapters.  The method never calls ``AgentRunner.execute``.
    """

    parent_environment = dict(os.environ if environment is None else environment)
    workspace_path = Path.cwd() if workspace is None else Path(workspace)
    run_root_path = (
        workspace_path / ".agentops" / "runs"
        if run_root is None
        else Path(run_root)
    )
    live_gate = _live_gate_diagnostic(parent_environment)
    workspace_health = _path_health(
        workspace_path, role="workspace", must_exist=True
    )
    run_root_health = _path_health(
        run_root_path, role="run_root", must_exist=False
    )
    sqlite_health = _sqlite_health()

    selected_runners: Sequence[AgentRunner]
    if runners is None:
        loader = FileBillingAttestationLoader(
            workspace_path / ".agentops" / "billing-attestations.json"
        )
        selected_runners = (
            CodexRunner(
                parent_environment=parent_environment,
                billing_attestation_loader=loader,
            ),
            ClaudeRunner(
                parent_environment=parent_environment,
                billing_attestation_loader=loader,
            ),
            MockRunner(),
        )
    else:
        selected_runners = tuple(runners)

    # Redaction is defense in depth for adapter-authored notes.  The report
    # never intentionally collects values, and distinctive parent values are
    # removed if a faulty adapter happens to echo one in a diagnostic string.
    redactor = Redactor(
        value
        for name, value in parent_environment.items()
        if is_sensitive_environment_name(name)
    )
    diagnostic_request = RunRequest(
        run_id="doctor-read-only",
        task_id="doctor",
        task_version="1",
        prompt="Local diagnostic only; this request must never be executed.",
        workspace=workspace_path,
        run_directory=run_root_path / "doctor-read-only",
        output_schema={"type": "object"},
        permission_class=PermissionClass.READ_ONLY,
        timeout_seconds=1,
    )
    reports = await asyncio.gather(
        *(
            _collect_runner_diagnostic(
                runner,
                request=diagnostic_request,
                parent_environment=parent_environment,
                live_gate=live_gate,
                workspace_health=workspace_health,
                run_root_health=run_root_health,
                sqlite_health=sqlite_health,
                redactor=redactor,
            )
            for runner in selected_runners
        )
    )
    local_ready = workspace_health.ready and run_root_health.ready and sqlite_health.ready
    return DoctorReport(
        schema_version=2,
        live_gate=live_gate,
        workspace=workspace_health,
        run_root=run_root_health,
        sqlite=sqlite_health,
        runners=tuple(reports),
        local_control_plane_ready=local_ready,
        any_runner_ready_now=any(report.ready_now for report in reports),
        subscription_runner_ready_now=any(
            report.ready_now and report.subscription_verified for report in reports
        ),
    )


async def _collect_runner_diagnostic(
    runner: AgentRunner,
    *,
    request: RunRequest,
    parent_environment: Mapping[str, str],
    live_gate: LiveGateDiagnostic,
    workspace_health: PathHealth,
    run_root_health: PathHealth,
    sqlite_health: SQLiteHealth,
    redactor: Redactor,
) -> RunnerDiagnostic:
    raw_runner_id = _safe_runner_id(runner)
    runner_id = str(redactor.redact(raw_runner_id))
    errors: list[str] = []

    try:
        capabilities = await runner.detect_capabilities()
    except Exception as exc:  # A doctor must report one broken adapter, not crash.
        errors.append(f"capability_probe_failed:{type(exc).__name__}")
        capabilities = RunnerCapabilities(runner_id=raw_runner_id, installed=False)

    try:
        assessment = await runner.inspect_billing_route()
    except Exception as exc:  # See above; exception text could contain credentials.
        errors.append(f"billing_probe_failed:{type(exc).__name__}")
        assessment = BillingRouteAssessment(
            runner_id=raw_runner_id,
            route=BillingRoute.UNKNOWN,
            confidence=AssessmentConfidence.LOW,
            evidence=("Billing route diagnostic failed closed.",),
        )

    try:
        validation = await runner.validate_environment(request)
    except Exception as exc:
        errors.append(f"environment_validation_failed:{type(exc).__name__}")
        validation = EnvironmentValidation(
            valid=False,
            sanitized_environment={},
            errors=("Child-environment validation failed closed.",),
        )

    if capabilities.runner_id != raw_runner_id:
        errors.append("capability_runner_id_mismatch")
    if assessment.runner_id != raw_runner_id:
        errors.append("billing_runner_id_mismatch")
    capabilities = _sanitize_capabilities(capabilities, redactor)
    assessment = _sanitize_assessment(assessment, redactor)
    environment_diagnostic = _safe_environment_diagnostic(
        validation,
        assessment=assessment,
        parent_environment=parent_environment,
        redactor=redactor,
    )

    blockers: list[str] = []
    if not capabilities.installed:
        blockers.append("runner_not_installed")
    if capabilities.version is None:
        blockers.append("runner_version_unverified")
    if not capabilities.non_interactive:
        blockers.append("non_interactive_capability_missing")
    required_output_mode = (
        "memory" if assessment.route is BillingRoute.MOCK else "jsonl"
    )
    if required_output_mode not in capabilities.structured_output_modes:
        blockers.append("structured_output_capability_missing")
    if assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
        if runner_id == "codex" and (
            "read-only" not in capabilities.sandbox_modes
            or "ask-for-approval" not in capabilities.permission_modes
        ):
            blockers.append("read_only_control_unverified")
        elif runner_id == "claude" and not capabilities.permission_modes:
            blockers.append("read_only_control_unverified")
        elif (
            runner_id not in {"codex", "claude"}
            and not capabilities.sandbox_modes
            and not capabilities.permission_modes
        ):
            blockers.append("read_only_control_unverified")

    checked_at = time.time()
    route_allowed = BillingPolicy.route_is_allowed(assessment, now=checked_at)
    if not route_allowed:
        blockers.append("billing_route_not_allowed")
        if assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
            blockers.extend(
                BillingPolicy.subscription_blockers(
                    assessment,
                    now=checked_at,
                )
            )
    if not environment_diagnostic.valid:
        blockers.append("environment_validation_failed")
    live_gate_required = runner_id in {"codex", "claude"}
    if live_gate_required and not live_gate.enabled:
        blockers.append("live_subscription_gate_disabled")
    if not workspace_health.ready:
        blockers.append("workspace_not_ready")
    if not run_root_health.ready:
        blockers.append("run_root_not_ready")
    if not sqlite_health.ready:
        blockers.append("sqlite_fts5_unavailable")
    if errors:
        blockers.append("runner_diagnostic_failed")

    subscription_auth_verified = (
        assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
        and assessment.confidence is AssessmentConfidence.HIGH
    )
    subscription_verified = subscription_auth_verified and route_allowed
    return RunnerDiagnostic(
        runner_id=runner_id,
        installed=capabilities.installed,
        version=capabilities.version,
        non_interactive=capabilities.non_interactive,
        structured_output_modes=capabilities.structured_output_modes,
        session_resume=capabilities.session_resume,
        sandbox_modes=capabilities.sandbox_modes,
        permission_modes=capabilities.permission_modes,
        usage_telemetry=capabilities.usage_telemetry,
        scheduler_support=capabilities.scheduler_support,
        capability_notes=capabilities.notes,
        billing_route=assessment.route.value,
        billing_confidence=assessment.confidence.value,
        subscription_name=assessment.subscription_name,
        subscription_auth_verified=subscription_auth_verified,
        subscription_verified=subscription_verified,
        billing_route_allowed=route_allowed,
        billing_evidence=assessment.evidence,
        billing_warnings=assessment.warnings,
        capacity_state=assessment.capacity_state,
        paid_continuation_protection=assessment.paid_continuation_protection,
        paid_credit_balance=assessment.paid_credit_balance,
        account_identity_fingerprint=assessment.account_identity_fingerprint,
        capacity_observed_at=assessment.capacity_observed_at,
        capacity_expires_at=assessment.capacity_expires_at,
        attestation=assessment.attestation,
        capacity_evidence_status=_evidence_window_status(
            assessment.capacity_observed_at,
            assessment.capacity_expires_at,
            checked_at,
            not_applicable=(
                assessment.route in {BillingRoute.LOCAL_NON_AI, BillingRoute.MOCK}
            ),
        ),
        attestation_status=_attestation_status(assessment, checked_at),
        environment=environment_diagnostic,
        live_gate_required=live_gate_required,
        ready_now=not blockers,
        blockers=tuple(dict.fromkeys(blockers)),
        diagnostic_errors=tuple(errors),
    )


def _safe_runner_id(runner: AgentRunner) -> str:
    try:
        value = runner.runner_id
    except Exception:
        return "unidentified-runner"
    if not isinstance(value, str) or not value:
        return "unidentified-runner"
    return value[:100]


def _sanitize_capabilities(
    capabilities: RunnerCapabilities, redactor: Redactor
) -> RunnerCapabilities:
    return RunnerCapabilities(
        runner_id=str(redactor.redact(capabilities.runner_id)),
        installed=capabilities.installed,
        version=(
            str(redactor.redact(capabilities.version))
            if capabilities.version is not None
            else None
        ),
        non_interactive=capabilities.non_interactive,
        structured_output_modes=tuple(
            str(redactor.redact(value)) for value in capabilities.structured_output_modes
        ),
        session_resume=capabilities.session_resume,
        sandbox_modes=tuple(
            str(redactor.redact(value)) for value in capabilities.sandbox_modes
        ),
        permission_modes=tuple(
            str(redactor.redact(value)) for value in capabilities.permission_modes
        ),
        usage_telemetry=capabilities.usage_telemetry,
        scheduler_support=capabilities.scheduler_support,
        notes=tuple(str(redactor.redact(value)) for value in capabilities.notes),
    )


def _sanitize_assessment(
    assessment: BillingRouteAssessment, redactor: Redactor
) -> BillingRouteAssessment:
    return BillingRouteAssessment(
        runner_id=str(redactor.redact(assessment.runner_id)),
        route=assessment.route,
        confidence=assessment.confidence,
        subscription_name=(
            str(redactor.redact(assessment.subscription_name))
            if assessment.subscription_name is not None
            else None
        ),
        evidence=tuple(str(redactor.redact(value)) for value in assessment.evidence),
        warnings=tuple(str(redactor.redact(value)) for value in assessment.warnings),
        risky_environment_names=tuple(
            sorted(
                {
                    str(redactor.redact(str(name)))
                    for name in assessment.risky_environment_names
                },
                key=str.upper,
            )
        ),
        capacity_state=assessment.capacity_state,
        paid_continuation_protection=assessment.paid_continuation_protection,
        paid_credit_balance=assessment.paid_credit_balance,
        account_identity_fingerprint=assessment.account_identity_fingerprint,
        capacity_observed_at=assessment.capacity_observed_at,
        capacity_expires_at=assessment.capacity_expires_at,
        attestation=_sanitize_attestation(assessment.attestation, redactor),
    )


def _sanitize_attestation(
    attestation: BillingSafetyAttestation | None,
    redactor: Redactor,
) -> BillingSafetyAttestation | None:
    if not isinstance(attestation, BillingSafetyAttestation):
        return None
    return BillingSafetyAttestation(
        runner_id=str(redactor.redact(attestation.runner_id)),
        account_identity_fingerprint=attestation.account_identity_fingerprint,
        billing_route=attestation.billing_route,
        capacity_state=attestation.capacity_state,
        paid_continuation_protection=attestation.paid_continuation_protection,
        observed_at=attestation.observed_at,
        expires_at=attestation.expires_at,
        confidence=attestation.confidence,
        evidence=tuple(str(redactor.redact(value)) for value in attestation.evidence),
    )


def _evidence_window_status(
    observed_at: float | None,
    expires_at: float | None,
    now: float,
    *,
    not_applicable: bool = False,
) -> str:
    if not_applicable:
        return "not_applicable"
    if not _finite_timestamp(observed_at) or not _finite_timestamp(expires_at):
        return "missing"
    assert observed_at is not None and expires_at is not None
    if expires_at <= observed_at:
        return "invalid"
    if now < observed_at:
        return "not_yet_valid"
    if now >= expires_at:
        return "expired"
    return "current"


def _finite_timestamp(value: float | None) -> bool:
    return (
        value is not None
        and not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and value >= 0
    )


def _verified_fingerprint(value: str | None) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _attestation_status(
    assessment: BillingRouteAssessment,
    now: float,
) -> str:
    if assessment.route in {BillingRoute.LOCAL_NON_AI, BillingRoute.MOCK}:
        return "not_applicable"
    attestation = assessment.attestation
    if attestation is None:
        return "missing"
    window = _evidence_window_status(
        attestation.observed_at,
        attestation.expires_at,
        now,
    )
    if window != "current":
        return window
    fingerprint = assessment.account_identity_fingerprint
    if (
        not _verified_fingerprint(fingerprint)
        or not _verified_fingerprint(attestation.account_identity_fingerprint)
        or not hmac.compare_digest(
            fingerprint,
            attestation.account_identity_fingerprint,
        )
        or attestation.runner_id != assessment.runner_id
        or attestation.billing_route is not assessment.route
        or attestation.capacity_state is not assessment.capacity_state
        or attestation.paid_continuation_protection
        is not assessment.paid_continuation_protection
        or attestation.confidence is not AssessmentConfidence.HIGH
        or not attestation.evidence
    ):
        return "mismatched"
    return "current_matched"


def _safe_environment_diagnostic(
    validation: EnvironmentValidation,
    *,
    assessment: BillingRouteAssessment,
    parent_environment: Mapping[str, str],
    redactor: Redactor,
) -> EnvironmentDiagnostic:
    risky_names = {
        *inspect_risky_environment(parent_environment),
        *assessment.risky_environment_names,
    }
    # Derive names from the actual sanitized mapping rather than trusting a
    # redundant list supplied by an adapter.  Values are never copied.
    sanitized_names = tuple(
        sorted(
            (
                str(redactor.redact(str(name)))
                for name in validation.sanitized_environment
            ),
            key=str.upper,
        )
    )
    excluded_names = tuple(
        sorted(
            (str(redactor.redact(str(name))) for name in validation.excluded_names),
            key=str.upper,
        )
    )
    errors = [str(redactor.redact(value)) for value in validation.errors]
    prohibited_child_names = tuple(
        name
        for name in sanitized_names
        if is_sensitive_environment_name(name)
        or name.upper() == LIVE_RUN_ENVIRONMENT_NAME
    )
    if prohibited_child_names:
        errors.append(
            "Sanitized child environment contains prohibited names: "
            + ", ".join(prohibited_child_names)
        )
    return EnvironmentDiagnostic(
        valid=bool(validation.valid) and not errors,
        sanitized_names=sanitized_names,
        excluded_names=excluded_names,
        risky_names=tuple(sorted(risky_names, key=str.upper)),
        errors=tuple(errors),
        warnings=tuple(str(redactor.redact(value)) for value in validation.warnings),
    )


def _live_gate_diagnostic(environment: Mapping[str, str]) -> LiveGateDiagnostic:
    if LIVE_RUN_ENVIRONMENT_NAME not in environment:
        state = "unset"
    elif environment.get(LIVE_RUN_ENVIRONMENT_NAME) == "1":
        state = "enabled_exactly"
    else:
        state = "set_but_not_exactly_enabled"
    return LiveGateDiagnostic(
        environment_name=LIVE_RUN_ENVIRONMENT_NAME,
        enabled=BillingPolicy.live_run_enabled(environment),
        state=state,
    )


def _path_health(path: Path, *, role: str, must_exist: bool) -> PathHealth:
    absolute = path.absolute()
    exists = absolute.exists()
    is_directory = absolute.is_dir()
    errors: list[str] = []
    warnings: list[str] = []

    if exists:
        readable = is_directory and os.access(absolute, os.R_OK | os.X_OK)
        writable = is_directory and os.access(absolute, os.W_OK | os.X_OK)
        creatable = is_directory and writable
        if not is_directory:
            errors.append(f"{role} path exists but is not a directory")
        elif not readable:
            errors.append(f"{role} directory is not readable")
        if not writable:
            errors.append(f"{role} directory is not writable")
        ready = is_directory and readable and writable
    else:
        readable = False
        writable = False
        parent = _nearest_existing_parent(absolute)
        creatable = bool(
            parent is not None
            and parent.is_dir()
            and os.access(parent, os.W_OK | os.X_OK)
        )
        if must_exist:
            errors.append(f"{role} directory does not exist")
            ready = False
        elif creatable:
            warnings.append(f"{role} directory does not exist and can be created lazily")
            ready = True
        else:
            errors.append(f"{role} directory does not exist and is not creatable")
            ready = False

    return PathHealth(
        role=role,
        path=str(absolute),
        exists=exists,
        is_directory=is_directory,
        readable=readable,
        writable=writable,
        creatable=creatable,
        ready=ready,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def _nearest_existing_parent(path: Path) -> Path | None:
    candidate = path.parent
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent
    return candidate


def _sqlite_health() -> SQLiteHealth:
    connection: sqlite3.Connection | None = None
    sqlite_available = False
    fts5_available = False
    integrity: str | None = None
    errors: list[str] = []
    try:
        connection = sqlite3.connect(":memory:")
        sqlite_available = True
        connection.execute("CREATE TABLE doctor_values (value TEXT NOT NULL)")
        connection.execute("INSERT INTO doctor_values(value) VALUES (?)", ("ok",))
        connection.execute(
            "CREATE VIRTUAL TABLE doctor_fts USING fts5(content, tokenize='unicode61')"
        )
        connection.execute(
            "INSERT INTO doctor_fts(content) VALUES (?)", ("agentops diagnostic",)
        )
        match = connection.execute(
            "SELECT content FROM doctor_fts WHERE doctor_fts MATCH ?", ("diagnostic",)
        ).fetchone()
        fts5_available = match is not None and match[0] == "agentops diagnostic"
        row = connection.execute("PRAGMA integrity_check").fetchone()
        integrity = str(row[0]) if row is not None else None
        if not fts5_available:
            errors.append("SQLite FTS5 query did not return the expected result")
        if integrity != "ok":
            errors.append("SQLite in-memory integrity check did not return ok")
    except sqlite3.Error as exc:
        # Exception text is intentionally omitted: the class is sufficient for
        # a safe diagnostic, and this path must never echo unexpected values.
        errors.append(f"SQLite/FTS5 diagnostic failed:{type(exc).__name__}")
    finally:
        if connection is not None:
            connection.close()
    return SQLiteHealth(
        ready=sqlite_available and fts5_available and integrity == "ok" and not errors,
        sqlite_available=sqlite_available,
        fts5_available=fts5_available,
        sqlite_version=sqlite3.sqlite_version,
        integrity_check=integrity,
        errors=tuple(errors),
    )


__all__ = [
    "DoctorReport",
    "EnvironmentDiagnostic",
    "LiveGateDiagnostic",
    "PathHealth",
    "RunnerDiagnostic",
    "SQLiteHealth",
    "collect_doctor_report",
]
