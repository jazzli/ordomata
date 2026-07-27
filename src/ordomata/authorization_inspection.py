"""Read-only inspection of non-authoritative authorization shadow evidence.

The inspector intentionally does not use :class:`SQLiteStateStore`: opening a
state store initialises schema and WAL state, while this module must never
mutate an inspected repository.  It exposes only a bounded, whitelisted
projection of the audit stream.  Raw authorization requests, decisions,
reason details, obligation values, paths, profiles, and evidence source
identifiers never leave this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
from typing import Any, Iterator

from .authorization import (
    ActionAttributes,
    ActionVerb,
    AuthorizationEffect,
    BlastRadius,
    ConsequenceVector,
    EvidenceSource,
    ImpactLevel,
    ObligationKind,
    Reach,
    ReceiptOutcome,
    ResourceAttributes,
    canonical_digest,
    derive_permission_class_from_attributes,
)
from .errors import ConfigurationError
from .models import (
    AssessmentConfidence,
    BillingRoute,
    CapacityState,
    IncrementalAICharge,
    PaidContinuationProtection,
    PaidCapacityConsumed,
    PaidCreditBalance,
    PermissionClass,
    RunStatus,
    UsageObservation,
)
from .state import (
    RecordNotFoundError,
    _BASELINE_TABLE_NAMES,
    _state_schema_integrity_issues,
)


AUTHORIZATION_SHADOW_EVENT_TYPE = "authorization_shadow_decision"
COMPARISON_TRIAL_BINDING_EVENT_TYPE = "comparison_trial_binding"
COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE = (
    "comparison_review_artifact_intent"
)
COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE = (
    "comparison_review_artifact_observed"
)
COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE = (
    "comparison_review_artifact_action_receipt"
)
COMPARISON_RUN_KIND = "controlled_comparison_trial"
COMPARISON_SHADOW_COVERAGE = "partial_admission_dispatch_shadow"
COMPARISON_FULL_SHADOW_COVERAGE = (
    "comparison_admission_dispatch_publication_shadow"
)
COMPARISON_ACTION_RECEIPT_COVERAGE = (
    "comparison_private_review_artifact_pre_effect_action_receipt"
)
TASK_ATTEMPT_RUN_KIND = "task_attempt"
TASK_ATTEMPT_SHADOW_COVERAGE = (
    "task_attempt_admission_dispatch_publication_shadow"
)
ADMISSION_SCOPE = "task_attempt_admission_only"
DISPATCH_SCOPE = "runner_model_dispatch_only"
PUBLICATION_SCOPE = "local_candidate_publication_only"
KNOWN_ACTION_SCOPES = frozenset(
    {ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE}
)
SUPPORTED_SHADOW_SCHEMA_VERSIONS = frozenset({1, 2, 3, 4})

_FLOW_STATE_BY_SCOPE = {
    ADMISSION_SCOPE: "admission_proposed",
    DISPATCH_SCOPE: "runner_dispatch_proposed",
    PUBLICATION_SCOPE: "local_candidate_publication_proposed",
}

_KNOWN_ATTRIBUTES = frozenset(
    {"subject", "action", "resource", "environment", "consequences"}
)
_KNOWN_EVIDENCE_SOURCES = frozenset(item.value for item in EvidenceSource)
_KNOWN_EFFECTS = frozenset(item.value for item in AuthorizationEffect)
_KNOWN_STATUSES = frozenset(item.value for item in RunStatus)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_BARE_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_AUTHORIZATION_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}")
_SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SENSITIVE_IDENTIFIER_MARKERS = (
    "access_token",
    "api_key",
    "client_secret",
    "credential",
    "github_pat_",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_token",
)
_SENSITIVE_IDENTIFIER_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "sk-", "xox")
_MAX_RUNS = 250
_MAX_SHADOW_EVENTS_PER_RUN = 16
_MAX_COMPARISON_BINDING_EVENTS_PER_RUN = 2
_MAX_COMPARISON_BILLING_EVENTS_PER_RUN = 2
_MAX_COMPARISON_ACCOUNTING_EVENTS_PER_RUN = 2
_MAX_COMPARISON_ARTIFACT_EVENTS_PER_TYPE_PER_RUN = 2
_MAX_EVIDENCE_RECORDS = 32
_MAX_OBLIGATION_RESULTS = 32
_MAX_PAYLOAD_BYTES = 512 * 1024
_SHADOW_EVIDENCE_LIFETIME_SECONDS = 120.0
_MISSING = object()

_COMPARISON_ACCOUNTING_KEYS = frozenset(
    {
        "billing_circuit_breaker_required",
        "billing_disposition_digest",
        "billing_disposition_reason_codes",
        "billing_matches",
        "billing_quarantine_required",
        "capacity_state",
        "failure_code",
        "harness_process_started",
        "identity_matches",
        "incremental_ai_charge",
        "live_model_execution_occurred",
        "paid_capacity_consumed",
        "result_observed",
        "result_status",
        "runner_event_count",
        "schema_version",
        "subscription_capacity_consumed",
        "usage_observation",
        "wall_seconds",
    }
)


@dataclass(frozen=True, slots=True)
class EvidenceFreshnessInspection:
    """A secret-free temporal projection of one attribute-evidence record."""

    attribute: str | None
    source: str | None
    authenticated: bool | None
    observed_at: float | None
    expires_at: float | None
    fresh_at_evaluation: bool | None
    fresh_now: bool | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "attribute": self.attribute,
            "source": self.source,
            "authenticated": self.authenticated,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "fresh_at_evaluation": self.fresh_at_evaluation,
            "fresh_now": self.fresh_now,
        }


@dataclass(frozen=True, slots=True)
class ShadowDecisionInspection:
    """Sanitized integrity and parity findings for one shadow event."""

    sequence: int
    occurred_at: float | None
    action_scope: str | None
    effect: str | None
    derived_permission_class: int | None
    recomputed_derived_permission_class: int | None
    requested_permission_class: int | None
    legacy_executable: bool | None
    recomputed_legacy_executable: bool | None
    reported_execution_parity: bool | None
    recomputed_execution_parity: bool | None
    reported_authority_ceiling_parity: bool | None
    recomputed_authority_ceiling_parity: bool | None
    request_digest_valid: bool | None
    decision_digest_valid: bool | None
    evidence: tuple[EvidenceFreshnessInspection, ...]
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return (
            self.recomputed_execution_parity is not True
            or bool(self.integrity_issues)
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "occurred_at": self.occurred_at,
            "action_scope": self.action_scope,
            "effect": self.effect,
            "derived_permission_class": self.derived_permission_class,
            "recomputed_derived_permission_class": (
                self.recomputed_derived_permission_class
            ),
            "requested_permission_class": self.requested_permission_class,
            "legacy_executable": self.legacy_executable,
            "recomputed_legacy_executable": self.recomputed_legacy_executable,
            "reported_execution_parity": self.reported_execution_parity,
            "recomputed_execution_parity": self.recomputed_execution_parity,
            "reported_authority_ceiling_parity": (
                self.reported_authority_ceiling_parity
            ),
            "recomputed_authority_ceiling_parity": (
                self.recomputed_authority_ceiling_parity
            ),
            "request_digest_valid": self.request_digest_valid,
            "decision_digest_valid": self.decision_digest_valid,
            "evidence": [item.to_mapping() for item in self.evidence],
            "integrity_issues": list(self.integrity_issues),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True, slots=True)
class RunAuthorizationInspection:
    """Coverage and shadow-decision findings for one immutable run."""

    run_id: str | None
    run_ref: str
    run_kind: str
    authorization_shadow_coverage: str
    authorization_action_receipt_coverage: str | None
    permission_class: int | None
    attempt: int | None
    latest_status: str | None
    expected_scopes: tuple[str, ...]
    observed_scopes: tuple[str, ...]
    missing_scopes: tuple[str, ...]
    events: tuple[ShadowDecisionInspection, ...]
    integrity_issues: tuple[str, ...]

    @property
    def attention_required(self) -> bool:
        return (
            bool(self.missing_scopes)
            or bool(self.integrity_issues)
            or any(event.attention_required for event in self.events)
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "run_ref": self.run_ref,
            "run_kind": self.run_kind,
            "authorization_shadow_coverage": (
                self.authorization_shadow_coverage
            ),
            "authorization_action_receipt_coverage": (
                self.authorization_action_receipt_coverage
            ),
            "permission_class": self.permission_class,
            "attempt": self.attempt,
            "latest_status": self.latest_status,
            "expected_scopes": list(self.expected_scopes),
            "observed_scopes": list(self.observed_scopes),
            "missing_scopes": list(self.missing_scopes),
            "events": [event.to_mapping() for event in self.events],
            "integrity_issues": list(self.integrity_issues),
            "attention_required": self.attention_required,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationInspectionReport:
    """Bounded, CLI-ready authorization inspection result."""

    generated_at: float
    database_present: bool
    mismatches_only: bool
    truncated: bool
    inspected_run_count: int
    inspected_event_count: int
    parity_mismatch_count: int
    authority_ceiling_mismatch_count: int
    coverage_gap_count: int
    integrity_issue_count: int
    integrity_issues: tuple[str, ...]
    runs: tuple[RunAuthorizationInspection, ...]

    @property
    def clean(self) -> bool:
        return (
            self.parity_mismatch_count == 0
            and self.authority_ceiling_mismatch_count == 0
            and self.coverage_gap_count == 0
            and self.integrity_issue_count == 0
            and not self.truncated
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "database_present": self.database_present,
            "mismatches_only": self.mismatches_only,
            "truncated": self.truncated,
            "clean": self.clean,
            "inspected_run_count": self.inspected_run_count,
            "inspected_event_count": self.inspected_event_count,
            "parity_mismatch_count": self.parity_mismatch_count,
            "authority_ceiling_mismatch_count": (
                self.authority_ceiling_mismatch_count
            ),
            "coverage_gap_count": self.coverage_gap_count,
            "integrity_issue_count": self.integrity_issue_count,
            "integrity_issues": list(self.integrity_issues),
            "runs": [run.to_mapping() for run in self.runs],
        }


@dataclass(frozen=True, slots=True)
class _RunFacts:
    raw_run_id: str
    raw_task_id: Any
    raw_task_version: Any
    raw_runner_id: Any
    raw_context_digest: Any
    timeout_seconds: int | None
    run_id: str | None
    run_ref: str
    permission_class: int | None
    attempt: int | None
    latest_status: str | None
    terminal_artifact_observed: bool | None
    running_observed: bool
    succeeded_observed: bool
    artifact_observed: bool
    shadow_event_count: int
    comparison_binding_event_count: int
    comparison_billing_event_count: int
    comparison_accounting_event_count: int
    comparison_artifact_intent_event_count: int
    comparison_artifact_observed_event_count: int
    comparison_artifact_action_receipt_event_count: int
    created_sequence: int | None
    billing_sequence: int | None
    running_sequence: int | None
    accounting_sequence: int | None
    runner_event_sequence: int | None
    terminal_sequence: int | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ComparisonBindingFacts:
    """Validated, private comparison binding used only during inspection."""

    observed: bool
    sequence: int | None
    binding: Mapping[str, Any] | None
    binding_digest: str | None
    issues: tuple[str, ...]
    schema_version: int | None = None
    authorization_shadow_coverage: str = COMPARISON_SHADOW_COVERAGE
    authorization_action_receipt_coverage: str | None = None


@dataclass(frozen=True, slots=True)
class _ComparisonBillingFacts:
    """Validated, private billing evidence used only during inspection."""

    payload: Mapping[str, Any] | None
    assessment_digest: str | None
    evidence_window: tuple[float, float] | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ComparisonAccountingFacts:
    """Validated durable execution accounting used only during inspection."""

    sequence: int | None
    payload: Mapping[str, Any] | None
    billing_disposition_digest: str | None
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ComparisonArtifactReceiptFacts:
    """Validated private publication receipts retained only for inspection."""

    pre_effect_sequence: int | None
    pre_effect: Mapping[str, Any] | None
    pre_effect_receipt_digest: str | None
    action_sequence: int | None
    action: Mapping[str, Any] | None
    action_receipt_digest: str | None
    issues: tuple[str, ...]


def inspect_authorization_shadows(
    database_path: str | Path,
    *,
    run_id: str | None = None,
    mismatches_only: bool = False,
    now: float | None = None,
) -> AuthorizationInspectionReport:
    """Inspect bounded shadow evidence without creating or changing state.

    A missing database is a clean empty result for an unfiltered inspection.
    A specifically requested missing run raises :class:`RecordNotFoundError`.
    Database, schema, and read failures are reported as a fixed
    :class:`ConfigurationError` so SQLite text or private paths cannot leak.
    """

    evaluated_now = _finite_timestamp(time.time() if now is None else now)
    requested_run_id = _validate_requested_run_id(run_id)
    path = Path(database_path)

    try:
        exists = path.exists()
    except OSError as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error
    if not exists:
        if requested_run_id is not None:
            raise RecordNotFoundError("requested authorization run was not found")
        return _empty_report(evaluated_now, mismatches_only=mismatches_only)
    try:
        if path.is_symlink() or not path.is_file():
            raise ConfigurationError(
                "authorization inspection database is unreadable or malformed"
            )
        resolved = path.resolve(strict=True)
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error

    try:
        with _read_only_database_uri(resolved) as database_uri:
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(
                    database_uri,
                    uri=True,
                    timeout=1.0,
                    isolation_level=None,
                )
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                query_only = connection.execute("PRAGMA query_only").fetchone()
                if query_only is None or int(query_only[0]) != 1:
                    raise sqlite3.DatabaseError(
                        "query-only mode was not established"
                    )
                connection.execute("PRAGMA temp_store = MEMORY")
                connection.execute("BEGIN")
                schema_issues = _state_schema_integrity_issues(connection)
                tables = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                baseline_projection_safe = not {
                    "baseline_schema_missing",
                    "baseline_schema_mismatch",
                }.intersection(schema_issues)
                if (
                    baseline_projection_safe
                    and _BASELINE_TABLE_NAMES.issubset(tables)
                ):
                    facts, run_truncated = _read_run_facts(
                        connection,
                        requested_run_id=requested_run_id,
                    )
                    if requested_run_id is not None and not facts:
                        raise RecordNotFoundError(
                            "requested authorization run was not found"
                        )
                    event_rows = _read_shadow_events(connection, facts)
                    comparison_binding_rows = _read_comparison_binding_events(
                        connection,
                        facts,
                    )
                    comparison_billing_rows = _read_comparison_billing_events(
                        connection,
                        facts,
                    )
                    comparison_accounting_rows = (
                        _read_comparison_accounting_events(
                            connection,
                            facts,
                        )
                    )
                    comparison_artifact_rows = (
                        _read_comparison_artifact_receipt_events(
                            connection,
                            facts,
                        )
                    )
                else:
                    facts = ()
                    event_rows = ()
                    comparison_binding_rows = ()
                    comparison_billing_rows = ()
                    comparison_accounting_rows = ()
                    comparison_artifact_rows = ()
                    run_truncated = False
                connection.rollback()
            finally:
                if connection is not None:
                    connection.close()
    except RecordNotFoundError:
        raise
    except ConfigurationError:
        raise
    except (sqlite3.Error, ValueError, TypeError, OverflowError) as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error

    rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in event_rows:
        raw_event_run_id = row["run_id"]
        if isinstance(raw_event_run_id, str) and raw_event_run_id in rows_by_run:
            rows_by_run[raw_event_run_id].append(row)

    binding_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_binding_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in binding_rows_by_run
        ):
            binding_rows_by_run[raw_event_run_id].append(row)

    billing_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_billing_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in billing_rows_by_run
        ):
            billing_rows_by_run[raw_event_run_id].append(row)

    accounting_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_accounting_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in accounting_rows_by_run
        ):
            accounting_rows_by_run[raw_event_run_id].append(row)

    artifact_rows_by_run: dict[str, list[sqlite3.Row]] = {
        fact.raw_run_id: [] for fact in facts
    }
    for row in comparison_artifact_rows:
        raw_event_run_id = row["run_id"]
        if (
            isinstance(raw_event_run_id, str)
            and raw_event_run_id in artifact_rows_by_run
        ):
            artifact_rows_by_run[raw_event_run_id].append(row)

    all_runs: list[RunAuthorizationInspection] = []
    event_truncated = False
    for fact in facts:
        event_rows_for_run = rows_by_run[fact.raw_run_id]
        comparison_binding = _inspect_comparison_binding(
            fact,
            binding_rows_by_run[fact.raw_run_id],
        )
        valid_comparison_binding = (
            comparison_binding.binding is not None
            and not comparison_binding.issues
        )
        if valid_comparison_binding:
            comparison_billing = _inspect_comparison_billing(
                fact,
                comparison_binding,
                billing_rows_by_run[fact.raw_run_id],
            )
        else:
            comparison_billing = _ComparisonBillingFacts(
                None,
                None,
                None,
                (),
            )
        comparison_accounting = _inspect_comparison_accounting(
            fact,
            comparison_binding,
            accounting_rows_by_run[fact.raw_run_id],
        )
        comparison_artifact_receipts = _inspect_comparison_artifact_receipts(
            fact,
            comparison_binding,
            comparison_accounting,
            artifact_rows_by_run[fact.raw_run_id],
        )
        events = tuple(
            _inspect_event(
                row,
                now=evaluated_now,
                expected_run_id=fact.raw_run_id,
                expected_task_id=fact.raw_task_id,
                expected_task_version=fact.raw_task_version,
                expected_permission_class=fact.permission_class,
                comparison_binding=comparison_binding,
                comparison_billing=comparison_billing,
                comparison_accounting=comparison_accounting,
                comparison_artifact_receipts=comparison_artifact_receipts,
            )
            for row in event_rows_for_run
        )
        expected = {ADMISSION_SCOPE}
        if fact.running_observed:
            expected.add(DISPATCH_SCOPE)
        if fact.succeeded_observed or fact.artifact_observed:
            expected.add(PUBLICATION_SCOPE)
        observed_counts: dict[str, int] = {}
        for event in events:
            if event.action_scope is not None:
                observed_counts[event.action_scope] = (
                    observed_counts.get(event.action_scope, 0) + 1
                )
        run_issues = [
            *fact.issues,
            *comparison_binding.issues,
            *comparison_billing.issues,
            *comparison_accounting.issues,
            *comparison_artifact_receipts.issues,
            *_inspect_comparison_action_terminal_linkage(
                fact,
                comparison_artifact_receipts,
            ),
        ]
        if (
            not comparison_binding.observed
            and any(
                "comparison_shadow_binding_digest_mismatch"
                in event.integrity_issues
                for event in events
            )
        ):
            run_issues.append("comparison_binding_missing")
        if any(count > 1 for count in observed_counts.values()):
            run_issues.append("duplicate_boundary_event")
        pre_effect_payload = comparison_artifact_receipts.pre_effect
        if isinstance(pre_effect_payload, Mapping):
            publication_shadow_persisted = pre_effect_payload.get(
                "publication_shadow_persisted"
            )
            if publication_shadow_persisted != (
                observed_counts.get(PUBLICATION_SCOPE, 0) == 1
            ):
                run_issues.append(
                    "comparison_publication_shadow_persistence_mismatch"
                )
        if fact.shadow_event_count > _MAX_SHADOW_EVENTS_PER_RUN:
            run_issues.append("shadow_event_limit_exceeded")
            event_truncated = True
        sequences_by_scope = {
            event.action_scope: event.sequence
            for event in events
            if event.action_scope is not None
        }
        admission_sequence = sequences_by_scope.get(ADMISSION_SCOPE)
        if (
            comparison_binding.observed
            and comparison_binding.sequence is not None
        ):
            if (
                (
                    fact.created_sequence is not None
                    and comparison_binding.sequence <= fact.created_sequence
                )
                or (
                    admission_sequence is not None
                    and comparison_binding.sequence >= admission_sequence
                )
                or (
                    fact.billing_sequence is not None
                    and comparison_binding.sequence >= fact.billing_sequence
                )
                or (
                    fact.running_sequence is not None
                    and comparison_binding.sequence >= fact.running_sequence
                )
            ):
                run_issues.append("comparison_binding_order_invalid")
        if admission_sequence is not None:
            if (
                fact.billing_sequence is not None
                and admission_sequence >= fact.billing_sequence
            ) or (
                fact.running_sequence is not None
                and admission_sequence >= fact.running_sequence
            ):
                run_issues.append("admission_boundary_order_invalid")
        dispatch_sequence = sequences_by_scope.get(DISPATCH_SCOPE)
        if dispatch_sequence is not None:
            if (
                fact.running_sequence is None
                or dispatch_sequence <= fact.running_sequence
                or (
                    fact.accounting_sequence is not None
                    and dispatch_sequence >= fact.accounting_sequence
                )
                or (
                    fact.runner_event_sequence is not None
                    and dispatch_sequence >= fact.runner_event_sequence
                )
            ):
                run_issues.append("dispatch_boundary_order_invalid")
        publication_sequence = sequences_by_scope.get(PUBLICATION_SCOPE)
        if publication_sequence is not None:
            if (
                comparison_binding.schema_version == 2
                and comparison_artifact_receipts.pre_effect is None
            ):
                run_issues.append(
                    "comparison_publication_pre_effect_receipt_missing"
                )
            if (
                comparison_binding.schema_version == 2
                and comparison_artifact_receipts.action is None
            ):
                run_issues.append(
                    "comparison_publication_action_receipt_missing"
                )
            if (
                fact.accounting_sequence is None
                or publication_sequence <= fact.accounting_sequence
                or (
                    fact.terminal_sequence is not None
                    and publication_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append("publication_boundary_order_invalid")
        pre_effect_sequence = comparison_artifact_receipts.pre_effect_sequence
        action_receipt_sequence = comparison_artifact_receipts.action_sequence
        if pre_effect_sequence is not None:
            if (
                fact.accounting_sequence is None
                or pre_effect_sequence <= fact.accounting_sequence
                or publication_sequence is None
                or pre_effect_sequence <= publication_sequence
                or (
                    fact.terminal_sequence is not None
                    and pre_effect_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "comparison_publication_pre_effect_order_invalid"
                )
        if action_receipt_sequence is not None:
            if (
                pre_effect_sequence is None
                or action_receipt_sequence <= pre_effect_sequence
                or (
                    fact.terminal_sequence is not None
                    and action_receipt_sequence >= fact.terminal_sequence
                )
            ):
                run_issues.append(
                    "comparison_publication_action_receipt_order_invalid"
                )
        observed = tuple(sorted(observed_counts))
        missing = tuple(sorted(expected.difference(observed_counts)))
        all_runs.append(
            RunAuthorizationInspection(
                run_id=fact.run_id,
                run_ref=fact.run_ref,
                run_kind=(
                    COMPARISON_RUN_KIND
                    if valid_comparison_binding
                    else TASK_ATTEMPT_RUN_KIND
                ),
                authorization_shadow_coverage=(
                    comparison_binding.authorization_shadow_coverage
                    if valid_comparison_binding
                    else TASK_ATTEMPT_SHADOW_COVERAGE
                ),
                authorization_action_receipt_coverage=(
                    comparison_binding.authorization_action_receipt_coverage
                    if valid_comparison_binding
                    else None
                ),
                permission_class=fact.permission_class,
                attempt=fact.attempt,
                latest_status=fact.latest_status,
                expected_scopes=tuple(sorted(expected)),
                observed_scopes=observed,
                missing_scopes=missing,
                events=events,
                integrity_issues=tuple(sorted(set(run_issues))),
            )
        )

    inspected_event_count = sum(len(run.events) for run in all_runs)
    parity_mismatch_count = sum(
        event.recomputed_execution_parity is False
        for run in all_runs
        for event in run.events
    )
    authority_ceiling_mismatch_count = sum(
        event.recomputed_authority_ceiling_parity is False
        for run in all_runs
        for event in run.events
    )
    coverage_gap_count = sum(len(run.missing_scopes) for run in all_runs)
    integrity_issue_count = len(schema_issues) + sum(
        len(run.integrity_issues)
        + sum(len(event.integrity_issues) for event in run.events)
        for run in all_runs
    )
    projected_runs = (
        tuple(run for run in all_runs if run.attention_required)
        if mismatches_only
        else tuple(all_runs)
    )
    return AuthorizationInspectionReport(
        generated_at=evaluated_now,
        database_present=True,
        mismatches_only=mismatches_only,
        truncated=run_truncated or event_truncated,
        inspected_run_count=len(all_runs),
        inspected_event_count=inspected_event_count,
        parity_mismatch_count=parity_mismatch_count,
        authority_ceiling_mismatch_count=authority_ceiling_mismatch_count,
        coverage_gap_count=coverage_gap_count,
        integrity_issue_count=integrity_issue_count,
        integrity_issues=schema_issues,
        runs=projected_runs,
    )


def _empty_report(
    generated_at: float,
    *,
    mismatches_only: bool,
) -> AuthorizationInspectionReport:
    return AuthorizationInspectionReport(
        generated_at=generated_at,
        database_present=False,
        mismatches_only=mismatches_only,
        truncated=False,
        inspected_run_count=0,
        inspected_event_count=0,
        parity_mismatch_count=0,
        authority_ceiling_mismatch_count=0,
        coverage_gap_count=0,
        integrity_issue_count=0,
        integrity_issues=(),
        runs=(),
    )


@contextmanager
def _read_only_database_uri(database: Path) -> Iterator[str]:
    """Yield a read-only URI without creating sidecars beside the source.

    SQLite may create ``-shm`` and ``-wal`` files even for a ``mode=ro``
    connection to a WAL database.  A quiescent database is therefore opened
    with ``immutable=1`` and checked for concurrent changes.  If a WAL is
    present, the main file and WAL are copied into an owner-private temporary
    directory after a before/after consistency check; SQLite may create its
    coordination sidecars only there.
    """

    before = _database_signature(database)
    if before[1] is None:
        try:
            yield database.as_uri() + "?mode=ro&immutable=1"
        finally:
            if _database_signature(database) != before:
                raise ConfigurationError(
                    "authorization inspection database changed during inspection"
                )
        return

    with tempfile.TemporaryDirectory(prefix="ordomata-auth-inspect-") as temporary:
        snapshot = Path(temporary) / "state.sqlite3"
        snapshot_wal = Path(str(snapshot) + "-wal")
        source_wal = Path(str(database) + "-wal")
        try:
            shutil.copyfile(database, snapshot)
            shutil.copyfile(source_wal, snapshot_wal)
        except OSError as error:
            raise ConfigurationError(
                "authorization inspection database is unreadable or malformed"
            ) from error
        if _database_signature(database) != before:
            raise ConfigurationError(
                "authorization inspection database changed during inspection"
            )
        yield snapshot.as_uri() + "?mode=ro"


def _database_signature(
    database: Path,
) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int] | None]:
    main = _file_signature(database, required=True)
    assert main is not None
    wal = _file_signature(Path(str(database) + "-wal"), required=False)
    return main, wal


def _file_signature(
    path: Path,
    *,
    required: bool,
) -> tuple[int, int, int, int] | None:
    try:
        if path.is_symlink():
            raise ConfigurationError(
                "authorization inspection database is unreadable or malformed"
            )
        metadata = path.stat()
    except FileNotFoundError:
        if not required:
            return None
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from None
    except ConfigurationError:
        raise
    except OSError as error:
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        ) from error
    if not path.is_file():
        raise ConfigurationError(
            "authorization inspection database is unreadable or malformed"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _read_run_facts(
    connection: sqlite3.Connection,
    *,
    requested_run_id: str | None,
) -> tuple[tuple[_RunFacts, ...], bool]:
    where = "" if requested_run_id is None else "WHERE r.run_id = ?"
    parameters: tuple[Any, ...] = (
        (_MAX_RUNS + 1,)
        if requested_run_id is None
        else (requested_run_id, 2)
    )
    rows = connection.execute(
        f"""
        SELECT
            r.run_id,
            r.task_id,
            r.task_version,
            r.runner_id,
            r.context_digest,
            r.permission_class,
            r.timeout_seconds,
            r.attempt,
            EXISTS (
                SELECT 1 FROM run_events running
                WHERE running.run_id = r.run_id AND running.status = 'running'
            ) AS running_observed,
            EXISTS (
                SELECT 1 FROM run_events succeeded
                WHERE succeeded.run_id = r.run_id AND succeeded.status = 'succeeded'
            ) AS succeeded_observed,
            (
                EXISTS (
                    SELECT 1 FROM run_artifacts artifact
                    WHERE artifact.run_id = r.run_id
                )
                OR EXISTS (
                    SELECT 1 FROM run_events comparison_artifact
                    WHERE comparison_artifact.run_id = r.run_id
                      AND comparison_artifact.event_type IN (?, ?, ?)
                )
            ) AS artifact_observed,
            (
                SELECT latest.status FROM run_events latest
                WHERE latest.run_id = r.run_id AND latest.status IS NOT NULL
                ORDER BY latest.sequence DESC LIMIT 1
            ) AS latest_status,
            (
                SELECT CASE
                    WHEN json_valid(terminal.payload_json) THEN
                        CASE json_type(
                            terminal.payload_json,
                            '$.artifact_observed'
                        )
                            WHEN 'true' THEN 1
                            WHEN 'false' THEN 0
                            ELSE NULL
                        END
                    ELSE NULL
                END
                FROM run_events terminal
                WHERE terminal.run_id = r.run_id
                  AND terminal.status IN (
                      'succeeded', 'failed', 'blocked',
                      'quarantined', 'cancelled'
                  )
                ORDER BY terminal.sequence DESC LIMIT 1
            ) AS terminal_artifact_observed,
            (
                SELECT COUNT(*) FROM run_events shadow
                WHERE shadow.run_id = r.run_id
                  AND shadow.event_type = ?
            ) AS shadow_event_count
            ,(
                SELECT COUNT(*) FROM run_events binding
                WHERE binding.run_id = r.run_id
                  AND binding.event_type = ?
            ) AS comparison_binding_event_count
            ,(
                SELECT COUNT(*) FROM run_events comparison_billing
                WHERE comparison_billing.run_id = r.run_id
                  AND comparison_billing.event_type = 'billing_assessment'
            ) AS comparison_billing_event_count
            ,(
                SELECT COUNT(*) FROM run_events comparison_accounting
                WHERE comparison_accounting.run_id = r.run_id
                  AND comparison_accounting.event_type = 'execution_accounting'
            ) AS comparison_accounting_event_count
            ,(
                SELECT COUNT(*) FROM run_events artifact_intent
                WHERE artifact_intent.run_id = r.run_id
                  AND artifact_intent.event_type = ?
            ) AS comparison_artifact_intent_event_count
            ,(
                SELECT COUNT(*) FROM run_events artifact_observed
                WHERE artifact_observed.run_id = r.run_id
                  AND artifact_observed.event_type = ?
            ) AS comparison_artifact_observed_event_count
            ,(
                SELECT COUNT(*) FROM run_events artifact_receipt
                WHERE artifact_receipt.run_id = r.run_id
                  AND artifact_receipt.event_type = ?
            ) AS comparison_artifact_action_receipt_event_count
            ,(
                SELECT MIN(created.sequence) FROM run_events created
                WHERE created.run_id = r.run_id
                  AND created.status = 'created'
            ) AS created_sequence
            ,(
                SELECT MIN(billing.sequence) FROM run_events billing
                WHERE billing.run_id = r.run_id
                  AND billing.event_type = 'billing_assessment'
            ) AS billing_sequence
            ,(
                SELECT MIN(running.sequence) FROM run_events running
                WHERE running.run_id = r.run_id
                  AND running.status = 'running'
            ) AS running_sequence
            ,(
                SELECT MIN(accounting.sequence) FROM run_events accounting
                WHERE accounting.run_id = r.run_id
                  AND accounting.event_type = 'execution_accounting'
            ) AS accounting_sequence
            ,(
                SELECT MIN(observed.sequence) FROM run_events observed
                WHERE observed.run_id = r.run_id
                  AND observed.event_type = 'runner_event_observed'
            ) AS runner_event_sequence
            ,(
                SELECT MIN(terminal.sequence) FROM run_events terminal
                WHERE terminal.run_id = r.run_id
                  AND terminal.status IN (
                      'succeeded', 'failed', 'blocked', 'quarantined', 'cancelled'
                  )
            ) AS terminal_sequence
        FROM runs r
        {where}
        ORDER BY r.created_at DESC, r.run_id DESC
        LIMIT ?
        """,
        (
            COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            AUTHORIZATION_SHADOW_EVENT_TYPE,
            COMPARISON_TRIAL_BINDING_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE,
            COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
            *parameters,
        ),
    ).fetchall()
    truncated = requested_run_id is None and len(rows) > _MAX_RUNS
    selected = rows[:_MAX_RUNS]
    facts: list[_RunFacts] = []
    for row in selected:
        raw_run_id = row["run_id"]
        if not isinstance(raw_run_id, str):
            raise sqlite3.DatabaseError("invalid run identity")
        issues: list[str] = []
        safe_run_id = _safe_run_identifier(raw_run_id)
        if safe_run_id is None:
            issues.append("run_identifier_unsafe")
        permission_class = _permission_class(row["permission_class"])
        if permission_class is None:
            issues.append("run_permission_class_invalid")
        timeout_seconds = row["timeout_seconds"]
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds <= 0
        ):
            timeout_seconds = None
            issues.append("run_timeout_invalid")
        attempt = row["attempt"]
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0:
            attempt = None
            issues.append("run_attempt_invalid")
        latest_status = row["latest_status"]
        if latest_status is not None and latest_status not in _KNOWN_STATUSES:
            latest_status = None
            issues.append("run_status_invalid")
        raw_terminal_artifact_observed = row[
            "terminal_artifact_observed"
        ]
        terminal_artifact_observed = (
            bool(raw_terminal_artifact_observed)
            if raw_terminal_artifact_observed in {0, 1}
            and not isinstance(raw_terminal_artifact_observed, bool)
            else None
        )
        shadow_event_count = row["shadow_event_count"]
        if (
            isinstance(shadow_event_count, bool)
            or not isinstance(shadow_event_count, int)
            or shadow_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid shadow event count")
        comparison_binding_event_count = row["comparison_binding_event_count"]
        if (
            isinstance(comparison_binding_event_count, bool)
            or not isinstance(comparison_binding_event_count, int)
            or comparison_binding_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid comparison binding event count")
        comparison_billing_event_count = row["comparison_billing_event_count"]
        if (
            isinstance(comparison_billing_event_count, bool)
            or not isinstance(comparison_billing_event_count, int)
            or comparison_billing_event_count < 0
        ):
            raise sqlite3.DatabaseError("invalid comparison billing event count")
        comparison_accounting_event_count = row[
            "comparison_accounting_event_count"
        ]
        if (
            isinstance(comparison_accounting_event_count, bool)
            or not isinstance(comparison_accounting_event_count, int)
            or comparison_accounting_event_count < 0
        ):
            raise sqlite3.DatabaseError(
                "invalid comparison accounting event count"
            )
        comparison_artifact_intent_event_count = row[
            "comparison_artifact_intent_event_count"
        ]
        comparison_artifact_observed_event_count = row[
            "comparison_artifact_observed_event_count"
        ]
        comparison_artifact_action_receipt_event_count = row[
            "comparison_artifact_action_receipt_event_count"
        ]
        for value in (
            comparison_artifact_intent_event_count,
            comparison_artifact_observed_event_count,
            comparison_artifact_action_receipt_event_count,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise sqlite3.DatabaseError(
                    "invalid comparison artifact event count"
                )
        created_sequence = _optional_sequence(row["created_sequence"])
        billing_sequence = _optional_sequence(row["billing_sequence"])
        running_sequence = _optional_sequence(row["running_sequence"])
        accounting_sequence = _optional_sequence(row["accounting_sequence"])
        runner_event_sequence = _optional_sequence(row["runner_event_sequence"])
        terminal_sequence = _optional_sequence(row["terminal_sequence"])
        facts.append(
            _RunFacts(
                raw_run_id=raw_run_id,
                raw_task_id=row["task_id"],
                raw_task_version=row["task_version"],
                raw_runner_id=row["runner_id"],
                raw_context_digest=row["context_digest"],
                timeout_seconds=timeout_seconds,
                run_id=safe_run_id,
                run_ref=canonical_digest({"run_id": raw_run_id}),
                permission_class=permission_class,
                attempt=attempt,
                latest_status=latest_status,
                terminal_artifact_observed=terminal_artifact_observed,
                running_observed=bool(row["running_observed"]),
                succeeded_observed=bool(row["succeeded_observed"]),
                artifact_observed=bool(row["artifact_observed"]),
                shadow_event_count=shadow_event_count,
                comparison_binding_event_count=comparison_binding_event_count,
                comparison_billing_event_count=comparison_billing_event_count,
                comparison_accounting_event_count=(
                    comparison_accounting_event_count
                ),
                comparison_artifact_intent_event_count=(
                    comparison_artifact_intent_event_count
                ),
                comparison_artifact_observed_event_count=(
                    comparison_artifact_observed_event_count
                ),
                comparison_artifact_action_receipt_event_count=(
                    comparison_artifact_action_receipt_event_count
                ),
                created_sequence=created_sequence,
                billing_sequence=billing_sequence,
                running_sequence=running_sequence,
                accounting_sequence=accounting_sequence,
                runner_event_sequence=runner_event_sequence,
                terminal_sequence=terminal_sequence,
                issues=tuple(issues),
            )
        )
    return tuple(facts), truncated


def _read_shadow_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        AUTHORIZATION_SHADOW_EVENT_TYPE,
        *(fact.raw_run_id for fact in facts),
        _MAX_SHADOW_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_shadow_events AS (
            SELECT
                run_id,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS boundary_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT run_id, sequence, occurred_at, payload_json
        FROM ranked_shadow_events
        WHERE boundary_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_binding_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two bindings per run so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        COMPARISON_TRIAL_BINDING_EVENT_TYPE,
        *(fact.raw_run_id for fact in facts),
        _MAX_COMPARISON_BINDING_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_comparison_bindings AS (
            SELECT
                run_id,
                sequence,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS binding_rank
            FROM run_events
            WHERE event_type = ? AND run_id IN ({placeholders})
        )
        SELECT run_id, sequence, payload_json
        FROM ranked_comparison_bindings
        WHERE binding_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_billing_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two billing assessments so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        "billing_assessment",
        _MAX_COMPARISON_BILLING_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_billing_events AS (
            SELECT
                run_id,
                sequence,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS billing_rank
            FROM run_events
            WHERE run_id IN ({placeholders}) AND event_type = ?
        )
        SELECT run_id, sequence, payload_json
        FROM ranked_billing_events
        WHERE billing_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_accounting_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read at most two accounting records so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        _MAX_COMPARISON_ACCOUNTING_EVENTS_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_accounting_events AS (
            SELECT
                run_id,
                sequence,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id ORDER BY sequence
                ) AS accounting_rank
            FROM run_events
            WHERE run_id IN ({placeholders})
              AND event_type = 'execution_accounting'
        )
        SELECT run_id, sequence, payload_json
        FROM ranked_accounting_events
        WHERE accounting_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _read_comparison_artifact_receipt_events(
    connection: sqlite3.Connection,
    facts: tuple[_RunFacts, ...],
) -> tuple[sqlite3.Row, ...]:
    """Read two events of each receipt kind so duplicates remain detectable."""

    if not facts:
        return ()
    placeholders = ",".join("?" for _ in facts)
    event_types = (
        COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE,
        COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE,
        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    )
    parameters: tuple[Any, ...] = (
        *(fact.raw_run_id for fact in facts),
        *event_types,
        _MAX_COMPARISON_ARTIFACT_EVENTS_PER_TYPE_PER_RUN,
    )
    rows = connection.execute(
        f"""
        WITH ranked_artifact_events AS (
            SELECT
                run_id,
                event_type,
                sequence,
                occurred_at,
                payload_json,
                ROW_NUMBER() OVER (
                    PARTITION BY run_id, event_type ORDER BY sequence
                ) AS artifact_event_rank
            FROM run_events
            WHERE run_id IN ({placeholders})
              AND event_type IN (?, ?, ?)
        )
        SELECT run_id, event_type, sequence, occurred_at, payload_json
        FROM ranked_artifact_events
        WHERE artifact_event_rank <= ?
        ORDER BY run_id, sequence
        """,
        parameters,
    ).fetchall()
    return tuple(rows)


def _inspect_comparison_binding(
    fact: _RunFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonBindingFacts:
    """Validate one digest-only controller binding without projecting it."""

    if fact.comparison_binding_event_count == 0:
        return _ComparisonBindingFacts(False, None, None, None, ())
    if fact.comparison_binding_event_count != 1 or len(rows) != 1:
        return _ComparisonBindingFacts(
            True,
            None,
            None,
            None,
            ("comparison_binding_duplicate",),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    if len(payload_json.encode("utf-8", errors="replace")) > _MAX_PAYLOAD_BYTES:
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    if not isinstance(payload, Mapping):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    schema_version = payload.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version not in {1, 2}
    ):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    expected_outer_keys = (
        {
            "authorization_shadow_coverage",
            "binding",
            "binding_digest",
            "schema_version",
        }
        if schema_version == 1
        else {
            "authorization_action_receipt_coverage",
            "authorization_shadow_coverage",
            "binding",
            "binding_digest",
            "schema_version",
        }
        if schema_version == 2
        else set()
    )
    if set(payload) != expected_outer_keys:
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    if schema_version == 1:
        authorization_shadow_coverage = payload.get(
            "authorization_shadow_coverage"
        )
        authorization_action_receipt_coverage = None
        if authorization_shadow_coverage != COMPARISON_SHADOW_COVERAGE:
            return _invalid_comparison_binding(
                sequence,
                "comparison_binding_payload_invalid",
            )
    else:
        authorization_shadow_coverage = payload.get(
            "authorization_shadow_coverage"
        )
        authorization_action_receipt_coverage = payload.get(
            "authorization_action_receipt_coverage"
        )
        if (
            authorization_shadow_coverage != COMPARISON_FULL_SHADOW_COVERAGE
            or authorization_action_receipt_coverage
            != COMPARISON_ACTION_RECEIPT_COVERAGE
        ):
            return _invalid_comparison_binding(
                sequence,
                "comparison_binding_payload_invalid",
            )

    binding = payload.get("binding")
    if not _is_comparison_binding_shape(binding):
        return _invalid_comparison_binding(
            sequence,
            "comparison_binding_payload_invalid",
        )
    assert isinstance(binding, Mapping)
    binding_digest = payload.get("binding_digest")
    if not _digest_matches(binding_digest, binding):
        return _ComparisonBindingFacts(
            True,
            sequence,
            None,
            None,
            ("comparison_binding_digest_mismatch",),
        )

    issues: list[str] = []
    if (
        binding.get("runner_id") != fact.raw_runner_id
        or binding.get("permission_class") != fact.permission_class
        or binding.get("timeout_seconds") != fact.timeout_seconds
        or binding.get("attempt") != fact.attempt
        or _normalize_sha256_digest(binding.get("context_digest"))
        != _normalize_sha256_digest(fact.raw_context_digest)
    ):
        issues.append("comparison_binding_record_mismatch")
    return _ComparisonBindingFacts(
        True,
        sequence,
        binding,
        binding_digest,
        tuple(issues),
        schema_version=schema_version,
        authorization_shadow_coverage=authorization_shadow_coverage,
        authorization_action_receipt_coverage=(
            authorization_action_receipt_coverage
        ),
    )


def _invalid_comparison_binding(
    sequence: int | None,
    issue: str,
) -> _ComparisonBindingFacts:
    return _ComparisonBindingFacts(True, sequence, None, None, (issue,))


def _inspect_comparison_billing(
    fact: _RunFacts,
    comparison_binding: _ComparisonBindingFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonBillingFacts:
    """Validate the persisted billing assessment bound to a comparison."""

    if fact.comparison_billing_event_count == 0:
        return _ComparisonBillingFacts(
            None,
            None,
            None,
            ("comparison_billing_payload_missing",),
        )
    if fact.comparison_billing_event_count != 1 or len(rows) != 1:
        return _ComparisonBillingFacts(
            None,
            None,
            None,
            ("comparison_billing_duplicate",),
        )
    payload_json = rows[0]["payload_json"]
    if not isinstance(payload_json, str) or len(
        payload_json.encode("utf-8", errors="replace")
    ) > _MAX_PAYLOAD_BYTES:
        return _invalid_comparison_billing("comparison_billing_payload_invalid")
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_comparison_billing("comparison_billing_payload_invalid")
    if not _is_comparison_billing_shape(payload):
        return _invalid_comparison_billing("comparison_billing_payload_invalid")
    assert isinstance(payload, Mapping)

    assessment_digest = payload["assessment_digest"]
    assessment_body = dict(payload)
    del assessment_body["assessment_digest"]
    if not _digest_matches(assessment_digest, assessment_body):
        return _invalid_comparison_billing("comparison_billing_digest_mismatch")

    binding = comparison_binding.binding
    assert isinstance(binding, Mapping)
    issues: list[str] = []
    if (
        binding["billing_assessment_digest"] != assessment_digest
        or payload["runner_id"] != binding["runner_id"]
        or payload["runner_id"] != fact.raw_runner_id
    ):
        issues.append("comparison_billing_binding_mismatch")
    return _ComparisonBillingFacts(
        payload,
        assessment_digest,
        _comparison_billing_evidence_window(payload),
        tuple(issues),
    )


def _invalid_comparison_billing(issue: str) -> _ComparisonBillingFacts:
    return _ComparisonBillingFacts(None, None, None, (issue,))


def _inspect_comparison_accounting(
    fact: _RunFacts,
    comparison_binding: _ComparisonBindingFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonAccountingFacts:
    """Validate v2 execution accounting and its canonical disposition link."""

    if comparison_binding.schema_version != 2:
        return _ComparisonAccountingFacts(None, None, None, ())
    if fact.comparison_accounting_event_count == 0:
        return _ComparisonAccountingFacts(
            None,
            None,
            None,
            ("comparison_execution_accounting_missing",),
        )
    if fact.comparison_accounting_event_count != 1 or len(rows) != 1:
        return _ComparisonAccountingFacts(
            None,
            None,
            None,
            ("comparison_execution_accounting_duplicate",),
        )

    row = rows[0]
    sequence = _optional_sequence(row["sequence"])
    payload_json = row["payload_json"]
    if (
        sequence is None
        or not isinstance(payload_json, str)
        or len(payload_json.encode("utf-8", errors="replace"))
        > _MAX_PAYLOAD_BYTES
    ):
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    try:
        payload = json.loads(
            payload_json,
            object_pairs_hook=_unique_json_object,
        )
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    if not _is_comparison_accounting_shape(payload):
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    assert isinstance(payload, Mapping)
    disposition_digest = payload.get("billing_disposition_digest")
    if disposition_digest is None:
        if (
            payload.get("capacity_state") != CapacityState.UNKNOWN.value
            or payload.get("billing_disposition_reason_codes") != []
        ):
            return _invalid_comparison_accounting(
                sequence,
                "comparison_execution_accounting_invalid",
            )
        return _ComparisonAccountingFacts(sequence, payload, None, ())

    projection = _comparison_accounting_billing_projection(payload)
    if projection is None:
        return _invalid_comparison_accounting(
            sequence,
            "comparison_execution_accounting_invalid",
        )
    if disposition_digest != canonical_digest(projection):
        return _ComparisonAccountingFacts(
            sequence,
            payload,
            disposition_digest,
            ("comparison_execution_accounting_digest_mismatch",),
        )
    return _ComparisonAccountingFacts(
        sequence,
        payload,
        disposition_digest,
        (),
    )


def _is_comparison_accounting_shape(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != _COMPARISON_ACCOUNTING_KEYS:
        return False
    reason_codes = value.get("billing_disposition_reason_codes")
    failure_code = value.get("failure_code")
    wall_seconds = value.get("wall_seconds")
    optional_boolean_keys = (
        "billing_circuit_breaker_required",
        "billing_matches",
        "billing_quarantine_required",
        "harness_process_started",
        "identity_matches",
        "live_model_execution_occurred",
        "subscription_capacity_consumed",
    )
    return (
        isinstance(value.get("schema_version"), int)
        and not isinstance(value.get("schema_version"), bool)
        and value.get("schema_version") == 2
        and isinstance(value.get("result_observed"), bool)
        and all(
            value.get(key) is None or isinstance(value.get(key), bool)
            for key in optional_boolean_keys
        )
        and _is_optional_digest(value.get("billing_disposition_digest"))
        and _is_optional_non_negative_integer(value.get("runner_event_count"))
        and value.get("runner_event_count") is not None
        and isinstance(value.get("result_status"), str)
        and value.get("result_status")
        in _KNOWN_STATUSES | {"invalid", "unknown"}
        and isinstance(value.get("capacity_state"), str)
        and value.get("capacity_state")
        in {item.value for item in CapacityState}
        and isinstance(value.get("paid_capacity_consumed"), str)
        and value.get("paid_capacity_consumed")
        in {item.value for item in PaidCapacityConsumed}
        and isinstance(value.get("incremental_ai_charge"), str)
        and value.get("incremental_ai_charge")
        in {item.value for item in IncrementalAICharge}
        and isinstance(value.get("usage_observation"), str)
        and value.get("usage_observation")
        in {item.value for item in UsageObservation}
        and isinstance(reason_codes, list)
        and len(reason_codes) <= _MAX_EVIDENCE_RECORDS
        and all(
            isinstance(item, str)
            and _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(item) is not None
            for item in reason_codes
        )
        and (
            failure_code is None
            or (
                isinstance(failure_code, str)
                and _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(failure_code)
                is not None
            )
        )
        and (
            wall_seconds is None
            or _optional_timestamp(wall_seconds) is not None
        )
    )


def _comparison_accounting_billing_projection(
    payload: Mapping[str, Any],
) -> dict[str, Any] | None:
    identity_matches = payload.get("identity_matches")
    billing_matches = payload.get("billing_matches")
    capacity_state = payload.get("capacity_state")
    paid_capacity_consumed = payload.get("paid_capacity_consumed")
    incremental_ai_charge = payload.get("incremental_ai_charge")
    quarantine_required = payload.get("billing_quarantine_required")
    circuit_breaker_required = payload.get(
        "billing_circuit_breaker_required"
    )
    reason_codes = payload.get("billing_disposition_reason_codes")
    if (
        not isinstance(identity_matches, bool)
        or not isinstance(billing_matches, bool)
        or capacity_state not in {item.value for item in CapacityState}
        or paid_capacity_consumed
        not in {item.value for item in PaidCapacityConsumed}
        or incremental_ai_charge
        not in {item.value for item in IncrementalAICharge}
        or not isinstance(quarantine_required, bool)
        or not isinstance(circuit_breaker_required, bool)
        or not isinstance(reason_codes, list)
        or len(reason_codes) > _MAX_EVIDENCE_RECORDS
        or any(
            not isinstance(value, str)
            or _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(value) is None
            for value in reason_codes
        )
    ):
        return None
    return {
        "identity_matches": identity_matches is True,
        "billing_matches": billing_matches is True,
        "capacity_state": capacity_state,
        "paid_capacity_consumed": paid_capacity_consumed,
        "incremental_ai_charge": incremental_ai_charge,
        "quarantine_required": quarantine_required,
        "circuit_breaker_required": circuit_breaker_required,
        "reason_codes": reason_codes,
    }


def _invalid_comparison_accounting(
    sequence: int | None,
    issue: str,
) -> _ComparisonAccountingFacts:
    return _ComparisonAccountingFacts(sequence, None, None, (issue,))


def _inspect_comparison_artifact_receipts(
    fact: _RunFacts,
    comparison_binding: _ComparisonBindingFacts,
    comparison_accounting: _ComparisonAccountingFacts,
    rows: list[sqlite3.Row],
) -> _ComparisonArtifactReceiptFacts:
    """Validate the digest-only Class 1 publication receipt chain."""

    rows_by_type: dict[str, list[sqlite3.Row]] = {
        COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE: [],
        COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE: [],
        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE: [],
    }
    for row in rows:
        event_type = row["event_type"]
        if isinstance(event_type, str) and event_type in rows_by_type:
            rows_by_type[event_type].append(row)

    pre_rows = rows_by_type[COMPARISON_REVIEW_ARTIFACT_INTENT_EVENT_TYPE]
    legacy_observed_rows = rows_by_type[
        COMPARISON_REVIEW_ARTIFACT_OBSERVED_EVENT_TYPE
    ]
    action_rows = rows_by_type[
        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE
    ]
    has_v2_pre = any(_artifact_event_schema(row) == 2 for row in pre_rows)
    has_new_receipt_evidence = has_v2_pre or bool(action_rows)

    if comparison_binding.schema_version != 2:
        issues = (
            ("comparison_publication_receipt_binding_invalid",)
            if has_new_receipt_evidence
            else ()
        )
        return _ComparisonArtifactReceiptFacts(
            None,
            None,
            None,
            None,
            None,
            None,
            issues,
        )

    issues: list[str] = []
    publication_expected = (
        fact.succeeded_observed
        or fact.shadow_event_count > 2
        or fact.comparison_artifact_intent_event_count > 0
        or fact.comparison_artifact_observed_event_count > 0
        or fact.comparison_artifact_action_receipt_event_count > 0
    )
    if fact.comparison_artifact_observed_event_count > 0 or legacy_observed_rows:
        issues.append("comparison_publication_legacy_observation_unexpected")

    pre_effect: Mapping[str, Any] | None = None
    pre_sequence: int | None = None
    pre_digest: str | None = None
    if fact.comparison_artifact_intent_event_count == 0:
        if publication_expected:
            issues.append("comparison_publication_pre_effect_receipt_missing")
    elif fact.comparison_artifact_intent_event_count != 1 or len(pre_rows) != 1:
        issues.append("comparison_publication_pre_effect_receipt_duplicate")
    else:
        pre_sequence, pre_effect, pre_digest, pre_issues = (
            _inspect_comparison_pre_effect_receipt(
                pre_rows[0],
                comparison_binding=comparison_binding,
            )
        )
        issues.extend(pre_issues)

    action: Mapping[str, Any] | None = None
    action_sequence: int | None = None
    action_digest: str | None = None
    if fact.comparison_artifact_action_receipt_event_count == 0:
        if publication_expected:
            issues.append("comparison_publication_action_receipt_missing")
    elif (
        fact.comparison_artifact_action_receipt_event_count != 1
        or len(action_rows) != 1
    ):
        issues.append("comparison_publication_action_receipt_duplicate")
    else:
        action_sequence, action, action_digest, action_issues = (
            _inspect_comparison_action_receipt(
                action_rows[0],
                comparison_binding=comparison_binding,
            )
        )
        issues.extend(action_issues)

    if pre_effect is None and action is not None:
        issues.append("comparison_publication_action_receipt_orphaned")
    if pre_effect is not None and action is not None:
        issues.extend(
            _inspect_comparison_receipt_linkage(
                pre_effect,
                pre_effect_receipt_digest=pre_digest,
                action=action,
            )
        )
    if pre_rows or action_rows:
        accounting_digest = comparison_accounting.billing_disposition_digest
        if (
            not _is_digest(accounting_digest)
            or (
                pre_effect is not None
                and pre_effect.get("billing_disposition_digest")
                != accounting_digest
            )
            or (
                action is not None
                and action.get("billing_disposition_digest")
                != accounting_digest
            )
        ):
            issues.append(
                "comparison_publication_billing_disposition_mismatch"
            )
    return _ComparisonArtifactReceiptFacts(
        pre_sequence,
        pre_effect,
        pre_digest,
        action_sequence,
        action,
        action_digest,
        tuple(sorted(set(issues))),
    )


def _artifact_event_schema(row: sqlite3.Row) -> int | None:
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str) or len(
        payload_json.encode("utf-8", errors="replace")
    ) > _MAX_PAYLOAD_BYTES:
        return None
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        return None
    return schema_version


def _bounded_artifact_event_payload(
    row: sqlite3.Row,
) -> tuple[int | None, Mapping[str, Any] | None]:
    sequence = _optional_sequence(row["sequence"])
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str) or len(
        payload_json.encode("utf-8", errors="replace")
    ) > _MAX_PAYLOAD_BYTES:
        return sequence, None
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return sequence, None
    return sequence, payload if isinstance(payload, Mapping) else None


def _inspect_comparison_pre_effect_receipt(
    row: sqlite3.Row,
    *,
    comparison_binding: _ComparisonBindingFacts,
) -> tuple[
    int | None,
    Mapping[str, Any] | None,
    str | None,
    tuple[str, ...],
]:
    sequence, payload = _bounded_artifact_event_payload(row)
    if payload is None or set(payload) != {
        "action_digest",
        "artifact_digest",
        "artifact_kind",
        "artifact_size_bytes",
        "authority_basis",
        "authorization_enforced",
        "billing_disposition_digest",
        "comparison_binding_digest",
        "destination_digest",
        "mode",
        "output_withheld",
        "publication_decision_digest",
        "publication_request_digest",
        "publication_shadow_persisted",
        "receipt_digest",
        "receipt_kind",
        "requested_permission_class",
        "schema_version",
        "started_at",
    }:
        return (
            sequence,
            None,
            None,
            ("comparison_publication_pre_effect_receipt_invalid",),
        )

    issues: list[str] = []
    receipt_digest = payload.get("receipt_digest")
    receipt_body = dict(payload)
    del receipt_body["receipt_digest"]
    if not _digest_matches(receipt_digest, receipt_body):
        issues.append("comparison_publication_pre_effect_digest_mismatch")
    if (
        payload.get("schema_version") != 2
        or payload.get("mode") != "shadow"
        or payload.get("receipt_kind") != "pre_effect"
        or payload.get("authorization_enforced") is not False
        or payload.get("authority_basis")
        != "legacy_class_1_local_draft_gate"
        or payload.get("requested_permission_class")
        != int(PermissionClass.LOCAL_DRAFT)
        or payload.get("artifact_kind") != "private_review_output"
        or not isinstance(payload.get("publication_shadow_persisted"), bool)
        or not isinstance(payload.get("output_withheld"), bool)
        or not _is_digest(payload.get("comparison_binding_digest"))
        or not _is_digest(payload.get("destination_digest"))
        or not _is_digest(payload.get("artifact_digest"))
        or not _is_digest(payload.get("billing_disposition_digest"))
        or not _is_positive_integer(payload.get("artifact_size_bytes"))
        or _optional_timestamp(payload.get("started_at")) is None
        or not _is_optional_digest(payload.get("publication_request_digest"))
        or not _is_optional_digest(payload.get("publication_decision_digest"))
        or not _is_optional_digest(payload.get("action_digest"))
    ):
        issues.append("comparison_publication_pre_effect_receipt_invalid")
    if payload.get("comparison_binding_digest") != (
        comparison_binding.binding_digest
    ):
        issues.append("comparison_publication_pre_effect_binding_mismatch")
    if (
        (payload.get("publication_request_digest") is None)
        != (payload.get("action_digest") is None)
        or (
            payload.get("publication_decision_digest") is not None
            and payload.get("publication_request_digest") is None
        )
    ):
        issues.append("comparison_publication_pre_effect_linkage_invalid")
    return (
        sequence,
        payload,
        receipt_digest if _is_digest(receipt_digest) else None,
        tuple(sorted(set(issues))),
    )


def _inspect_comparison_action_receipt(
    row: sqlite3.Row,
    *,
    comparison_binding: _ComparisonBindingFacts,
) -> tuple[
    int | None,
    Mapping[str, Any] | None,
    str | None,
    tuple[str, ...],
]:
    sequence, payload = _bounded_artifact_event_payload(row)
    if payload is None or set(payload) != {
        "action_digest",
        "artifact_kind",
        "authority_basis",
        "authorization_enforced",
        "billing_disposition_digest",
        "completed_at",
        "comparison_binding_digest",
        "destination_digest",
        "executor_id",
        "failure_code",
        "intended_artifact_digest",
        "intended_artifact_size_bytes",
        "mode",
        "obligation_results",
        "observed_artifact_size_bytes",
        "outcome",
        "output_withheld",
        "pre_effect_receipt_digest",
        "publication_decision_digest",
        "publication_request_digest",
        "publication_shadow_persisted",
        "receipt_digest",
        "receipt_id",
        "receipt_kind",
        "result_digest",
        "schema_version",
        "started_at",
    }:
        return (
            sequence,
            None,
            None,
            ("comparison_publication_action_receipt_invalid",),
        )

    issues: list[str] = []
    receipt_digest = payload.get("receipt_digest")
    receipt_body = dict(payload)
    del receipt_body["receipt_digest"]
    if not _digest_matches(receipt_digest, receipt_body):
        issues.append("comparison_publication_action_receipt_digest_mismatch")
    started_at = _optional_timestamp(payload.get("started_at"))
    completed_at = _optional_timestamp(payload.get("completed_at"))
    if (
        payload.get("schema_version") != 2
        or payload.get("mode") != "shadow"
        or payload.get("receipt_kind") != "action"
        or payload.get("authorization_enforced") is not False
        or payload.get("authority_basis")
        != "legacy_class_1_local_draft_gate"
        or payload.get("executor_id") != "ordomata:local-controller"
        or payload.get("artifact_kind") != "private_review_output"
        or not isinstance(payload.get("publication_shadow_persisted"), bool)
        or not isinstance(payload.get("output_withheld"), bool)
        or not _is_digest(payload.get("receipt_id"))
        or not _is_digest(payload.get("comparison_binding_digest"))
        or not _is_digest(payload.get("pre_effect_receipt_digest"))
        or not _is_digest(payload.get("destination_digest"))
        or not _is_digest(payload.get("intended_artifact_digest"))
        or not _is_digest(payload.get("billing_disposition_digest"))
        or not _is_positive_integer(payload.get("intended_artifact_size_bytes"))
        or not _is_optional_digest(payload.get("publication_request_digest"))
        or not _is_optional_digest(payload.get("publication_decision_digest"))
        or not _is_optional_digest(payload.get("action_digest"))
        or not _is_optional_digest(payload.get("result_digest"))
        or not _is_optional_non_negative_integer(
            payload.get("observed_artifact_size_bytes")
        )
        or started_at is None
        or completed_at is None
        or (
            started_at is not None
            and completed_at is not None
            and completed_at < started_at
        )
    ):
        issues.append("comparison_publication_action_receipt_invalid")
    if payload.get("comparison_binding_digest") != (
        comparison_binding.binding_digest
    ):
        issues.append("comparison_publication_action_receipt_binding_mismatch")
    expected_receipt_id = canonical_digest(
        {
            "comparison_binding_digest": payload.get(
                "comparison_binding_digest"
            ),
            "destination_digest": payload.get("destination_digest"),
            "pre_effect_receipt_digest": payload.get(
                "pre_effect_receipt_digest"
            ),
        }
    )
    if payload.get("receipt_id") != expected_receipt_id:
        issues.append("comparison_publication_action_receipt_identifier_mismatch")
    if (
        (payload.get("publication_request_digest") is None)
        != (payload.get("action_digest") is None)
        or (
            payload.get("publication_decision_digest") is not None
            and payload.get("publication_request_digest") is None
        )
    ):
        issues.append("comparison_publication_action_receipt_linkage_invalid")
    issues.extend(_inspect_comparison_obligation_results(payload))
    issues.extend(_inspect_comparison_action_outcome(payload))
    return (
        sequence,
        payload,
        receipt_digest if _is_digest(receipt_digest) else None,
        tuple(sorted(set(issues))),
    )


def _inspect_comparison_obligation_results(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    values = payload.get("obligation_results")
    if not isinstance(values, list) or len(values) > _MAX_OBLIGATION_RESULTS:
        return ("comparison_publication_obligation_results_invalid",)
    allowed_kinds = {item.value for item in ObligationKind}
    canonical_values: list[tuple[str, str]] = []
    for value in values:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"kind", "satisfied", "value_digest"}
            or value.get("kind") not in allowed_kinds
            or value.get("satisfied") is not True
            or not _is_digest(value.get("value_digest"))
        ):
            return ("comparison_publication_obligation_results_invalid",)
        canonical_values.append((value["kind"], value["value_digest"]))
    if (
        canonical_values != sorted(canonical_values)
        or len(canonical_values) != len(set(canonical_values))
    ):
        return ("comparison_publication_obligation_results_invalid",)
    return ()


def _inspect_comparison_action_outcome(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    outcome = payload.get("outcome")
    failure_code = payload.get("failure_code")
    result_digest = payload.get("result_digest")
    observed_size = payload.get("observed_artifact_size_bytes")
    intended_digest = payload.get("intended_artifact_digest")
    intended_size = payload.get("intended_artifact_size_bytes")
    expected_failure_codes = {
        ReceiptOutcome.FAILED.value: "artifact_persistence_failed",
        ReceiptOutcome.CANCELLED.value: "artifact_persistence_interrupted",
        ReceiptOutcome.UNKNOWN.value: "artifact_publication_outcome_unknown",
    }
    if outcome == ReceiptOutcome.SUCCEEDED.value:
        valid = (
            failure_code is None
            and result_digest == intended_digest
            and observed_size == intended_size
        )
    elif outcome in expected_failure_codes:
        valid = (
            failure_code == expected_failure_codes[outcome]
            and result_digest is None
            and observed_size is None
        )
    else:
        valid = False
    return () if valid else ("comparison_publication_action_outcome_invalid",)


def _inspect_comparison_action_terminal_linkage(
    fact: _RunFacts,
    receipts: _ComparisonArtifactReceiptFacts,
) -> tuple[str, ...]:
    """Reject impossible artifact-receipt and terminal-status pairings."""

    action = receipts.action
    if not isinstance(action, Mapping):
        return ()
    terminal_statuses = {
        RunStatus.SUCCEEDED.value,
        RunStatus.FAILED.value,
        RunStatus.BLOCKED.value,
        RunStatus.QUARANTINED.value,
        RunStatus.CANCELLED.value,
    }
    terminal_status = fact.latest_status
    if terminal_status not in terminal_statuses:
        return ("comparison_action_receipt_terminal_missing",)
    outcome = action.get("outcome")
    if (
        outcome == ReceiptOutcome.SUCCEEDED.value
        and fact.terminal_artifact_observed is not True
    ):
        return ("comparison_action_receipt_terminal_mismatch",)
    allowed_terminal_statuses = {
        ReceiptOutcome.SUCCEEDED.value: terminal_statuses,
        ReceiptOutcome.FAILED.value: {
            RunStatus.BLOCKED.value,
            RunStatus.FAILED.value,
            RunStatus.QUARANTINED.value,
        },
        ReceiptOutcome.CANCELLED.value: {
            RunStatus.CANCELLED.value,
            RunStatus.QUARANTINED.value,
        },
        ReceiptOutcome.UNKNOWN.value: {RunStatus.QUARANTINED.value},
    }
    allowed = allowed_terminal_statuses.get(outcome)
    if allowed is not None and terminal_status not in allowed:
        return ("comparison_action_receipt_terminal_mismatch",)
    return ()


def _inspect_comparison_receipt_linkage(
    pre_effect: Mapping[str, Any],
    *,
    pre_effect_receipt_digest: str | None,
    action: Mapping[str, Any],
) -> tuple[str, ...]:
    comparisons = (
        ("pre_effect_receipt_digest", pre_effect_receipt_digest),
        ("comparison_binding_digest", pre_effect.get("comparison_binding_digest")),
        (
            "publication_shadow_persisted",
            pre_effect.get("publication_shadow_persisted"),
        ),
        ("publication_request_digest", pre_effect.get("publication_request_digest")),
        ("publication_decision_digest", pre_effect.get("publication_decision_digest")),
        ("action_digest", pre_effect.get("action_digest")),
        ("started_at", pre_effect.get("started_at")),
        ("artifact_kind", pre_effect.get("artifact_kind")),
        ("destination_digest", pre_effect.get("destination_digest")),
        ("output_withheld", pre_effect.get("output_withheld")),
        ("billing_disposition_digest", pre_effect.get("billing_disposition_digest")),
    )
    if any(action.get(key, _MISSING) != expected for key, expected in comparisons):
        return ("comparison_publication_receipt_linkage_mismatch",)
    if (
        action.get("intended_artifact_digest")
        != pre_effect.get("artifact_digest")
        or action.get("intended_artifact_size_bytes")
        != pre_effect.get("artifact_size_bytes")
    ):
        return ("comparison_publication_receipt_linkage_mismatch",)
    return ()


def _inspect_event(
    row: sqlite3.Row,
    *,
    now: float,
    expected_run_id: str,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    comparison_binding: _ComparisonBindingFacts,
    comparison_billing: _ComparisonBillingFacts,
    comparison_accounting: _ComparisonAccountingFacts,
    comparison_artifact_receipts: _ComparisonArtifactReceiptFacts,
) -> ShadowDecisionInspection:
    issues: list[str] = []
    sequence = row["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        sequence = 0
        issues.append("event_sequence_invalid")
    occurred_at = _optional_timestamp(row["occurred_at"])
    if occurred_at is None:
        issues.append("event_timestamp_invalid")
    payload_json = row["payload_json"]
    if not isinstance(payload_json, str):
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_json_invalid"],
        )
    if len(payload_json.encode("utf-8", errors="replace")) > _MAX_PAYLOAD_BYTES:
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_too_large"],
        )
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError, UnicodeError):
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_json_invalid"],
        )
    if not isinstance(payload, Mapping):
        return _invalid_event(
            sequence,
            occurred_at,
            issues + ["payload_shape_invalid"],
        )

    schema_version = payload.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version not in SUPPORTED_SHADOW_SCHEMA_VERSIONS
    ):
        issues.append("schema_version_invalid")
    if payload.get("mode") != "shadow":
        issues.append("mode_invalid")
    raw_scope = payload.get("action_scope")
    action_scope = _known_string(raw_scope, KNOWN_ACTION_SCOPES)
    if action_scope is None:
        issues.append("action_scope_invalid")
    comparison_publication_projection = (
        schema_version == 4
        and action_scope == PUBLICATION_SCOPE
        and comparison_binding.schema_version == 2
        and comparison_binding.binding is not None
        and not comparison_binding.issues
    )
    comparison_trial_projection = schema_version == 3

    raw_effect = payload.get("effect")
    effect = _known_string(raw_effect, _KNOWN_EFFECTS)
    if effect is None:
        issues.append("effect_invalid")
    derived_permission_class = _permission_class(
        payload.get("derived_permission_class")
    )
    if (
        derived_permission_class is None
        and payload.get("derived_permission_class") is not None
    ):
        issues.append("derived_permission_class_invalid")
    requested_permission_class = _permission_class(
        payload.get("requested_permission_class")
    )
    if schema_version in {2, 3, 4}:
        expected_requested_permission_class = (
            int(PermissionClass.LOCAL_DRAFT)
            if comparison_publication_projection
            else expected_permission_class
        )
        if requested_permission_class is None:
            issues.append("requested_permission_class_invalid")
        elif (
            expected_requested_permission_class is not None
            and requested_permission_class
            != expected_requested_permission_class
        ):
            issues.append("requested_permission_class_run_mismatch")
    legacy_executable = _optional_boolean(payload.get("legacy_executable"))
    if legacy_executable is None:
        issues.append("legacy_executable_invalid")
    recomputed_legacy_executable = (
        True
        if comparison_publication_projection
        and expected_permission_class == int(PermissionClass.READ_ONLY)
        else (
            expected_permission_class
            in {
                int(PermissionClass.READ_ONLY),
                int(PermissionClass.LOCAL_DRAFT),
            }
            if expected_permission_class is not None
            else None
        )
    )
    if (
        schema_version == 4
        and expected_permission_class != int(PermissionClass.READ_ONLY)
    ):
        issues.append("comparison_publication_run_class_invalid")
    if (
        legacy_executable is not None
        and recomputed_legacy_executable is not None
        and legacy_executable != recomputed_legacy_executable
    ):
        issues.append("legacy_executable_run_mismatch")
    reported_parity = _optional_boolean(payload.get("execution_parity"))
    if reported_parity is None:
        issues.append("execution_parity_invalid")
    reported_authority_ceiling_parity = _optional_boolean(
        payload.get("authority_ceiling_parity")
    )
    if (
        schema_version in {2, 3, 4}
        and reported_authority_ceiling_parity is None
        and not (
            effect == AuthorizationEffect.INDETERMINATE.value
            and payload.get("failure_stage")
            in {"request_construction", "evaluation"}
        )
    ):
        issues.append("authority_ceiling_parity_invalid")

    request = payload.get("request")
    request_digest = payload.get("request_digest")
    failure_stage = payload.get("failure_stage")
    task_intent_projection_issues: tuple[str, ...] = ()
    if schema_version in {2, 3, 4}:
        task_intent_projection_issues = _inspect_task_intent_projection(
            payload,
            request=request,
            failure_stage=failure_stage,
            action_scope=action_scope,
            comparison_projection=comparison_trial_projection,
            comparison_publication_projection=(
                comparison_publication_projection
            ),
        )
        issues.extend(task_intent_projection_issues)
    request_failure = (
        effect == AuthorizationEffect.INDETERMINATE.value
        and failure_stage == "request_construction"
        and request is None
        and request_digest is None
    )
    request_digest_valid: bool | None = None
    if not request_failure:
        if not _is_request_shape(request):
            issues.append("request_shape_invalid")
        if isinstance(request, Mapping):
            request_digest_valid = _digest_matches(request_digest, request)
            if request_digest_valid is not True:
                issues.append("request_digest_mismatch")
        else:
            request_digest_valid = False
            issues.append("request_digest_mismatch")

    boundary_projection_issues: tuple[str, ...] = ()
    if (
        schema_version in {2, 3, 4}
        and action_scope is not None
        and isinstance(request, Mapping)
    ):
        boundary_projection_issues = _inspect_boundary_projection(
            request,
            action_scope=action_scope,
            expected_run_id=expected_run_id,
        )
        issues.extend(boundary_projection_issues)

    comparison_publication_binding_issues: tuple[str, ...] = ()
    if schema_version == 3:
        issues.extend(
            _inspect_comparison_shadow_binding(
                payload,
                request=request,
                action_scope=action_scope,
                expected_task_id=expected_task_id,
                expected_task_version=expected_task_version,
                expected_permission_class=expected_permission_class,
                comparison_binding=comparison_binding,
                comparison_billing=comparison_billing,
            )
        )
    elif schema_version == 4:
        comparison_publication_binding_issues = (
            _inspect_comparison_publication_shadow_binding(
                payload,
                request=request,
                action_scope=action_scope,
                expected_task_id=expected_task_id,
                expected_task_version=expected_task_version,
                expected_permission_class=expected_permission_class,
                comparison_binding=comparison_binding,
                comparison_accounting=comparison_accounting,
                comparison_artifact_receipts=(
                    comparison_artifact_receipts
                ),
            )
        )
        issues.extend(comparison_publication_binding_issues)
    elif comparison_binding.observed and action_scope in {
        ADMISSION_SCOPE,
        DISPATCH_SCOPE,
    }:
        issues.append("comparison_shadow_schema_invalid")

    recomputed_derived_permission_class: int | None = None
    class_derivation_issues: tuple[str, ...] = ()
    if isinstance(request, Mapping):
        (
            recomputed_derived_permission_class,
            class_derivation_issues,
        ) = _recompute_derived_permission_class(request)
        issues.extend(class_derivation_issues)

    decision = payload.get("decision")
    decision_digest = payload.get("decision_digest")
    evaluation_failure = (
        effect == AuthorizationEffect.INDETERMINATE.value
        and isinstance(failure_stage, str)
        and failure_stage in {"request_construction", "evaluation"}
        and decision is None
        and decision_digest is None
    )
    decision_digest_valid: bool | None = None
    if not evaluation_failure:
        if not _is_decision_shape(decision):
            issues.append("decision_shape_invalid")
        if isinstance(decision, Mapping):
            decision_digest_valid = _digest_matches(decision_digest, decision)
            if decision_digest_valid is not True:
                issues.append("decision_digest_mismatch")
        else:
            decision_digest_valid = False
            issues.append("decision_digest_mismatch")

    if isinstance(request, Mapping) and isinstance(decision, Mapping):
        if decision.get("request_digest") != request_digest:
            issues.append("decision_request_digest_mismatch")
        if decision.get("request_id") != request.get("request_id"):
            issues.append("decision_request_identifier_mismatch")
    if isinstance(decision, Mapping):
        projection_keys = (
            "effect",
            "policy_bundle_id",
            "policy_version",
            "policy_digest",
            "derived_permission_class",
            "reason_codes",
            "matched_rule_ids",
            "evidence_refs",
            "obligations",
        )
        if any(
            payload.get(key, _MISSING) != decision.get(key, _MISSING)
            for key in projection_keys
        ):
            issues.append("top_level_decision_projection_mismatch")
    if (
        not evaluation_failure
        and derived_permission_class is not None
        and recomputed_derived_permission_class is not None
        and derived_permission_class != recomputed_derived_permission_class
    ):
        issues.append("derived_permission_class_mismatch")

    evidence, evidence_issues = _inspect_evidence(request, now=now)
    issues.extend(evidence_issues)
    recomputed_parity = (
        None
        if effect is None or recomputed_legacy_executable is None
        else (
            effect == AuthorizationEffect.PERMIT.value
        ) == recomputed_legacy_executable
    )
    if (
        reported_parity is not None
        and recomputed_parity is not None
        and reported_parity != recomputed_parity
    ):
        issues.append("execution_parity_mismatch")
    comparison_publication_authority_exception = (
        comparison_publication_projection
        and expected_permission_class == int(PermissionClass.READ_ONLY)
        and payload.get("requested_permission_class")
        == int(PermissionClass.LOCAL_DRAFT)
        and _is_request_shape(request)
        and request_digest_valid is True
        and recomputed_derived_permission_class
        == int(PermissionClass.LOCAL_DRAFT)
        and not class_derivation_issues
        and not task_intent_projection_issues
        and not boundary_projection_issues
        and not comparison_publication_binding_issues
    )
    authority_ceiling = (
        int(PermissionClass.LOCAL_DRAFT)
        if comparison_publication_authority_exception
        else expected_permission_class
    )
    recomputed_authority_ceiling_parity = (
        recomputed_derived_permission_class <= authority_ceiling
        if (
            recomputed_derived_permission_class is not None
            and authority_ceiling is not None
        )
        else None
    )
    if (
        reported_authority_ceiling_parity is not None
        and recomputed_authority_ceiling_parity is not None
        and reported_authority_ceiling_parity
        != recomputed_authority_ceiling_parity
    ):
        issues.append("authority_ceiling_parity_mismatch")
    if recomputed_authority_ceiling_parity is False:
        issues.append("derived_class_exceeds_run_authority")
    return ShadowDecisionInspection(
        sequence=sequence,
        occurred_at=occurred_at,
        action_scope=action_scope,
        effect=effect,
        derived_permission_class=derived_permission_class,
        recomputed_derived_permission_class=(
            recomputed_derived_permission_class
        ),
        requested_permission_class=requested_permission_class,
        legacy_executable=legacy_executable,
        recomputed_legacy_executable=recomputed_legacy_executable,
        reported_execution_parity=reported_parity,
        recomputed_execution_parity=recomputed_parity,
        reported_authority_ceiling_parity=(
            reported_authority_ceiling_parity
        ),
        recomputed_authority_ceiling_parity=(
            recomputed_authority_ceiling_parity
        ),
        request_digest_valid=request_digest_valid,
        decision_digest_valid=decision_digest_valid,
        evidence=evidence,
        integrity_issues=tuple(sorted(set(issues))),
    )


def _inspect_task_intent_projection(
    payload: Mapping[str, Any],
    *,
    request: Any,
    failure_stage: Any,
    action_scope: str | None,
    comparison_projection: bool,
    comparison_publication_projection: bool,
) -> tuple[str, ...]:
    """Validate the safe schema-v2/v3 intent projection without emitting it."""

    intent = payload.get("task_authorization_intent")
    intent_digest = payload.get("intent_digest")
    intent_source = payload.get("intent_source")
    if (
        failure_stage == "request_construction"
        and intent is None
        and intent_digest is None
        and intent_source is None
    ):
        return ()

    issues: list[str] = []
    if comparison_publication_projection:
        allowed_sources = {"comparison_review_artifact_projection"}
    elif comparison_projection:
        allowed_sources = {"comparison_trial_projection"}
    elif action_scope == PUBLICATION_SCOPE:
        allowed_sources = {"controller_boundary_projection"}
    else:
        allowed_sources = {"legacy_permission_class_fallback", "task_contract"}
    if intent_source not in allowed_sources:
        issues.append("task_intent_source_invalid")
    if not _is_task_intent_shape(intent):
        issues.append("task_intent_shape_invalid")
        return tuple(issues)
    assert isinstance(intent, Mapping)
    if not _digest_matches(intent_digest, intent):
        issues.append("task_intent_digest_mismatch")
    if isinstance(request, Mapping):
        request_action = request.get("action")
        request_resource = request.get("resource")
        request_consequences = request.get("consequences")
        intent_action = intent["action"]
        intent_resource = intent["resource"]
        intent_consequences = intent["consequences"]
        assert isinstance(intent_action, Mapping)
        assert isinstance(intent_resource, Mapping)
        action_matches = isinstance(request_action, Mapping) and all(
            request_action.get(key, _MISSING) == value
            for key, value in intent_action.items()
        )
        resource_matches = isinstance(request_resource, Mapping) and all(
            request_resource.get(key, _MISSING) == value
            for key, value in intent_resource.items()
        )
        if (
            not action_matches
            or not resource_matches
            or request_consequences != intent_consequences
        ):
            issues.append("task_intent_request_projection_mismatch")
    if comparison_projection:
        issues.extend(_inspect_comparison_intent(intent, action_scope=action_scope))
    elif comparison_publication_projection:
        issues.extend(_inspect_comparison_publication_intent(intent))
    elif action_scope == PUBLICATION_SCOPE:
        issues.extend(_inspect_publication_intent(intent))
    return tuple(issues)


def _inspect_comparison_intent(
    intent: Mapping[str, Any],
    *,
    action_scope: str | None,
) -> tuple[str, ...]:
    """Validate the fixed Class 0 comparison admission/dispatch projection."""

    action = intent["action"]
    resource = intent["resource"]
    consequences = intent["consequences"]
    assert isinstance(action, Mapping)
    assert isinstance(resource, Mapping)
    assert isinstance(consequences, Mapping)
    if action_scope not in {ADMISSION_SCOPE, DISPATCH_SCOPE}:
        return ("comparison_intent_invalid",)
    if (
        action.get("verb") != ActionVerb.READ.value
        or action.get("operation")
        != "comparison.evaluate_immutable_snapshot"
        or action.get("intended_effect")
        != "evaluate_immutable_comparison_snapshot"
        or resource.get("resource_type") != "comparison_snapshot"
        or resource.get("trust_boundary") != "isolated_run_workspace"
        or consequences.get("reach") != Reach.LOCAL.value
        or consequences.get("destructive") is not False
        or consequences.get("reversible") is not True
        or consequences.get("blast_radius")
        != BlastRadius.SINGLE_RESOURCE.value
    ):
        return ("comparison_intent_invalid",)
    return ()


def _inspect_comparison_publication_intent(
    intent: Mapping[str, Any],
) -> tuple[str, ...]:
    """Validate the fixed owner-private Class 1 publication projection."""

    action = intent["action"]
    resource = intent["resource"]
    consequences = intent["consequences"]
    assert isinstance(action, Mapping)
    assert isinstance(resource, Mapping)
    assert isinstance(consequences, Mapping)
    if (
        action.get("verb") != ActionVerb.CREATE.value
        or action.get("operation") != "artifact.publish_private_review"
        or action.get("intended_effect")
        != "create_owner_private_review_artifact"
        or resource.get("resource_type") != "private_review_artifact"
        or resource.get("trust_boundary") != "isolated_run_workspace"
        or consequences.get("reach") != Reach.LOCAL.value
        or consequences.get("destructive") is not False
        or consequences.get("reversible") is not True
        or consequences.get("blast_radius")
        != BlastRadius.SINGLE_RESOURCE.value
    ):
        return ("comparison_publication_intent_invalid",)
    return ()


def _inspect_comparison_shadow_binding(
    payload: Mapping[str, Any],
    *,
    request: Any,
    action_scope: str | None,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    comparison_binding: _ComparisonBindingFacts,
    comparison_billing: _ComparisonBillingFacts,
) -> tuple[str, ...]:
    """Bind a schema-v3 shadow to its controller-authored trial metadata."""

    issues: list[str] = []
    if action_scope not in {ADMISSION_SCOPE, DISPATCH_SCOPE}:
        issues.append("comparison_shadow_schema_invalid")
    if expected_permission_class != int(PermissionClass.READ_ONLY):
        issues.append("comparison_request_binding_mismatch")
    reported_binding_digest = payload.get("comparison_binding_digest")
    if (
        comparison_binding.binding_digest is None
        or reported_binding_digest != comparison_binding.binding_digest
    ):
        issues.append("comparison_shadow_binding_digest_mismatch")

    binding = comparison_binding.binding
    if not isinstance(binding, Mapping) or not isinstance(request, Mapping):
        return tuple(issues)

    subject = request.get("subject")
    resource = request.get("resource")
    action = request.get("action")
    if (
        not isinstance(subject, Mapping)
        or subject.get("profile_id") != binding["profile_ref"]
        or subject.get("runner_id") != binding["runner_id"]
        or not isinstance(resource, Mapping)
        or resource.get("repository_id") != binding["repository_ref"]
        or resource.get("version") != binding["snapshot_digest"]
        or resource.get("content_digest")
        != (
            binding["context_digest"]
            if action_scope == ADMISSION_SCOPE
            else binding["prompt_digest"]
        )
        or not isinstance(action, Mapping)
    ):
        issues.append("comparison_request_binding_mismatch")
        return tuple(issues)

    if action_scope == ADMISSION_SCOPE:
        boundary_parameters = {
            "comparison_binding_digest": comparison_binding.binding_digest,
            "context_digest": binding["context_digest"],
            "snapshot_digest": binding["snapshot_digest"],
        }
    elif action_scope == DISPATCH_SCOPE:
        boundary_parameters = {
            "comparison_binding_digest": comparison_binding.binding_digest,
            "prompt_digest": binding["prompt_digest"],
            "snapshot_digest": binding["snapshot_digest"],
        }
    else:
        return tuple(issues)
    expected_parameters_digest = canonical_digest(
        {
            "action_scope": action_scope,
            "intent_digest": payload.get("intent_digest"),
            "intent_source": "comparison_trial_projection",
            "legacy_permission_class": int(PermissionClass.READ_ONLY),
            "output_schema_digest": binding["output_schema_digest"],
            "parameters": boundary_parameters,
            "profile_ref": binding["profile_ref"],
            "runner_id": binding["runner_id"],
            "task_definition_digest": binding["task_definition_digest"],
            "task_id": expected_task_id,
            "task_version": expected_task_version,
        }
    )
    if action.get("parameters_digest") != expected_parameters_digest:
        issues.append("comparison_request_binding_mismatch")
    issues.extend(
        _inspect_comparison_request_environment(
            request,
            comparison_billing=comparison_billing,
        )
    )
    return tuple(issues)


def _inspect_comparison_publication_shadow_binding(
    payload: Mapping[str, Any],
    *,
    request: Any,
    action_scope: str | None,
    expected_task_id: Any,
    expected_task_version: Any,
    expected_permission_class: int | None,
    comparison_binding: _ComparisonBindingFacts,
    comparison_accounting: _ComparisonAccountingFacts,
    comparison_artifact_receipts: _ComparisonArtifactReceiptFacts,
) -> tuple[str, ...]:
    """Bind a schema-v4 Class 1 shadow to its exact private artifact."""

    issues: list[str] = []
    if (
        action_scope != PUBLICATION_SCOPE
        or comparison_binding.schema_version != 2
        or comparison_binding.binding is None
    ):
        issues.append("comparison_publication_shadow_schema_invalid")
    if expected_permission_class != int(PermissionClass.READ_ONLY):
        issues.append("comparison_publication_run_class_invalid")
    if payload.get("requested_permission_class") != int(
        PermissionClass.LOCAL_DRAFT
    ):
        issues.append("comparison_publication_requested_class_invalid")
    if payload.get("comparison_binding_digest") != (
        comparison_binding.binding_digest
    ):
        issues.append("comparison_publication_shadow_binding_mismatch")

    accounting_digest = comparison_accounting.billing_disposition_digest
    if not _is_digest(accounting_digest):
        issues.append("comparison_publication_billing_disposition_mismatch")

    pre_effect = comparison_artifact_receipts.pre_effect
    if not isinstance(pre_effect, Mapping):
        return tuple(issues)
    if pre_effect.get("billing_disposition_digest") != accounting_digest:
        issues.append("comparison_publication_billing_disposition_mismatch")
    if pre_effect.get("publication_shadow_persisted") is not True:
        issues.append("comparison_publication_shadow_receipt_mismatch")
    if (
        pre_effect.get("publication_request_digest")
        != payload.get("request_digest")
        or pre_effect.get("publication_decision_digest")
        != payload.get("decision_digest")
    ):
        issues.append("comparison_publication_shadow_receipt_mismatch")

    binding = comparison_binding.binding
    if not isinstance(binding, Mapping) or not isinstance(request, Mapping):
        return tuple(issues)
    subject = request.get("subject")
    resource = request.get("resource")
    action = request.get("action")
    environment = request.get("environment")
    if (
        not isinstance(subject, Mapping)
        or subject.get("profile_id") != binding["profile_ref"]
        or subject.get("runner_id") != binding["runner_id"]
        or not isinstance(resource, Mapping)
        or resource.get("repository_id") != binding["repository_ref"]
        or resource.get("version") != pre_effect.get("artifact_digest")
        or resource.get("content_digest") != pre_effect.get("artifact_digest")
        or not isinstance(action, Mapping)
        or not isinstance(environment, Mapping)
        or environment.get("isolation_state") != "verified"
        or environment.get("network_state") != "disabled"
        or environment.get("billing_route") != BillingRoute.LOCAL_NON_AI.value
        or environment.get("capacity_state")
        != CapacityState.NOT_APPLICABLE.value
        or environment.get("paid_continuation_protection")
        != PaidContinuationProtection.NOT_APPLICABLE.value
        or environment.get("circuit_state") != "closed"
    ):
        issues.append("comparison_publication_request_binding_mismatch")
        return tuple(issues)

    expected_action_digest = canonical_digest(
        {
            "action": action,
            "resource": resource,
        }
    )
    if pre_effect.get("action_digest") != expected_action_digest:
        issues.append("comparison_publication_action_digest_mismatch")
    parameters = {
        "artifact_digest": pre_effect.get("artifact_digest"),
        "artifact_kind": pre_effect.get("artifact_kind"),
        "artifact_size_bytes": pre_effect.get("artifact_size_bytes"),
        "billing_disposition_digest": accounting_digest,
        "comparison_binding_digest": comparison_binding.binding_digest,
        "destination_digest": pre_effect.get("destination_digest"),
        "output_withheld": pre_effect.get("output_withheld"),
    }
    expected_parameters_digest = canonical_digest(
        {
            "action_scope": PUBLICATION_SCOPE,
            "intent_digest": payload.get("intent_digest"),
            "intent_source": "comparison_review_artifact_projection",
            "legacy_permission_class": int(PermissionClass.LOCAL_DRAFT),
            "output_schema_digest": binding["output_schema_digest"],
            "parameters": parameters,
            "profile_ref": binding["profile_ref"],
            "runner_id": binding["runner_id"],
            "task_definition_digest": binding["task_definition_digest"],
            "task_id": expected_task_id,
            "task_version": expected_task_version,
        }
    )
    if action.get("parameters_digest") != expected_parameters_digest:
        issues.append("comparison_publication_request_binding_mismatch")

    action_receipt = comparison_artifact_receipts.action
    decision = payload.get("decision")
    if isinstance(action_receipt, Mapping) and isinstance(decision, Mapping):
        issues.extend(
            _inspect_comparison_receipt_obligation_linkage(
                decision,
                action_receipt=action_receipt,
            )
        )
    return tuple(issues)


def _inspect_comparison_receipt_obligation_linkage(
    decision: Mapping[str, Any],
    *,
    action_receipt: Mapping[str, Any],
) -> tuple[str, ...]:
    obligations = decision.get("obligations")
    results = action_receipt.get("obligation_results")
    if not isinstance(obligations, list) or not isinstance(results, list):
        return ("comparison_publication_obligation_linkage_mismatch",)
    if any(
        not isinstance(item, Mapping)
        or set(item) != {"kind", "value"}
        or not isinstance(item.get("kind"), str)
        or not isinstance(item.get("value"), str)
        for item in obligations
    ) or any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("kind"), str)
        or not _is_digest(item.get("value_digest"))
        for item in results
    ):
        return ("comparison_publication_obligation_linkage_mismatch",)
    expected = sorted(
        (
            item.get("kind"),
            canonical_digest({"value": item.get("value")}),
        )
        for item in obligations
    )
    observed = sorted(
        (item.get("kind"), item.get("value_digest"))
        for item in results
    )
    if expected != observed:
        return ("comparison_publication_obligation_linkage_mismatch",)
    return ()


def _inspect_comparison_request_environment(
    request: Mapping[str, Any],
    *,
    comparison_billing: _ComparisonBillingFacts,
) -> tuple[str, ...]:
    """Compare v3 environment attributes with bound billing evidence."""

    payload = comparison_billing.payload
    if not isinstance(payload, Mapping):
        return ()
    environment = request.get("environment")
    if not isinstance(environment, Mapping):
        return ("comparison_billing_environment_mismatch",)
    issues: list[str] = []
    expected_route = payload["route"]
    expected_capacity_state = payload["capacity_state"]
    expected_paid_continuation = payload["paid_continuation_protection"]
    if payload["runner_id"] == "mock":
        expected_route = BillingRoute.MOCK.value
        expected_capacity_state = CapacityState.NOT_APPLICABLE.value
        expected_paid_continuation = (
            PaidContinuationProtection.NOT_APPLICABLE.value
        )
    if (
        environment.get("billing_route") != expected_route
        or environment.get("capacity_state") != expected_capacity_state
        or environment.get("paid_continuation_protection")
        != expected_paid_continuation
    ):
        issues.append("comparison_billing_environment_mismatch")

    evaluated_at = _optional_timestamp(environment.get("evaluated_at"))
    expected_window = comparison_billing.evidence_window
    if payload["runner_id"] == "mock" and evaluated_at is not None:
        expected_window = (
            evaluated_at,
            evaluated_at + _SHADOW_EVIDENCE_LIFETIME_SECONDS,
        )
    evidence = request.get("evidence")
    environment_evidence = (
        [
            item
            for item in evidence
            if isinstance(item, Mapping)
            and item.get("attribute") == "environment"
        ]
        if isinstance(evidence, list)
        else []
    )
    if expected_window is None:
        if environment_evidence:
            issues.append("comparison_billing_evidence_window_mismatch")
    elif (
        len(environment_evidence) != 1
        or _optional_timestamp(environment_evidence[0].get("observed_at"))
        != expected_window[0]
        or _optional_timestamp(environment_evidence[0].get("expires_at"))
        != expected_window[1]
    ):
        issues.append("comparison_billing_evidence_window_mismatch")
    return tuple(issues)


def _recompute_derived_permission_class(
    request: Mapping[str, Any],
) -> tuple[int | None, tuple[str, ...]]:
    """Derive the class from validated canonical request attributes."""

    try:
        action_value = request["action"]
        resource_value = request["resource"]
        consequences_value = request["consequences"]
        if not all(
            isinstance(value, Mapping)
            for value in (action_value, resource_value, consequences_value)
        ):
            raise ValueError("invalid class derivation projection")
        assert isinstance(action_value, Mapping)
        assert isinstance(resource_value, Mapping)
        assert isinstance(consequences_value, Mapping)
        if action_value.get("descriptive_claims") != []:
            raise ValueError("shadow class derivation does not accept claims")
        action = ActionAttributes(
            verb=ActionVerb(action_value["verb"]),
            operation=action_value["operation"],
            parameters_digest=action_value["parameters_digest"],
            intended_effect=action_value["intended_effect"],
            tool_id=action_value.get("tool_id"),
            descriptive_claims=(),
        )
        resource = ResourceAttributes(
            resource_type=resource_value["resource_type"],
            identifier=resource_value["identifier"],
            version=resource_value["version"],
            owner=resource_value["owner"],
            trust_boundary=resource_value["trust_boundary"],
            protected=resource_value["protected"],
            sensitivity=ImpactLevel(resource_value["sensitivity"]),
            repository_id=resource_value.get("repository_id"),
            content_digest=resource_value.get("content_digest"),
        )
        consequences = ConsequenceVector(
            confidentiality=ImpactLevel(
                consequences_value["confidentiality"]
            ),
            integrity=ImpactLevel(consequences_value["integrity"]),
            availability=ImpactLevel(consequences_value["availability"]),
            reach=Reach(consequences_value["reach"]),
            destructive=consequences_value["destructive"],
            reversible=consequences_value["reversible"],
            sensitivity=ImpactLevel(consequences_value["sensitivity"]),
            blast_radius=BlastRadius(consequences_value["blast_radius"]),
        )
        derived = derive_permission_class_from_attributes(
            action,
            resource,
            consequences,
        )
    except (KeyError, TypeError, ValueError):
        return None, ("class_derivation_input_invalid",)
    return int(derived), ()


def _inspect_publication_intent(
    intent: Mapping[str, Any],
) -> tuple[str, ...]:
    """Validate controller-owned facts in the local-publication projection."""

    action = intent["action"]
    resource = intent["resource"]
    consequences = intent["consequences"]
    assert isinstance(action, Mapping)
    assert isinstance(resource, Mapping)
    assert isinstance(consequences, Mapping)
    issues: list[str] = []
    if (
        action.get("verb") != ActionVerb.CREATE.value
        or action.get("operation") != "artifact.publish_local_candidate"
        or action.get("intended_effect")
        != "create_isolated_local_candidate"
    ):
        issues.append("publication_intent_action_invalid")
    if (
        resource.get("resource_type") != "local_candidate_artifact"
        or resource.get("trust_boundary") != "isolated_run_workspace"
    ):
        issues.append("publication_intent_resource_invalid")
    if (
        consequences.get("reach") != Reach.LOCAL.value
        or consequences.get("destructive") is not False
        or consequences.get("reversible") is not True
        or consequences.get("blast_radius")
        != BlastRadius.SINGLE_RESOURCE.value
    ):
        issues.append("publication_intent_consequences_invalid")
    return tuple(issues)


def _inspect_boundary_projection(
    request: Mapping[str, Any],
    *,
    action_scope: str,
    expected_run_id: str,
) -> tuple[str, ...]:
    """Bind a v2 boundary label to controller-owned request attributes."""

    issues: list[str] = []
    if request.get("request_id") != f"{action_scope}:{expected_run_id}":
        issues.append("boundary_request_identifier_mismatch")
    subject = request.get("subject")
    if (
        not isinstance(subject, Mapping)
        or subject.get("session_id") != f"attempt:{expected_run_id}"
    ):
        issues.append("boundary_session_identifier_mismatch")
    environment = request.get("environment")
    if (
        not isinstance(environment, Mapping)
        or environment.get("flow_state") != _FLOW_STATE_BY_SCOPE[action_scope]
    ):
        issues.append("boundary_flow_state_mismatch")
    resource = request.get("resource")
    if isinstance(resource, Mapping) and isinstance(
        resource.get("resource_type"), str
    ):
        expected_identifier = canonical_digest(
            {
                "action_scope": action_scope,
                "resource_type": resource["resource_type"],
                "run_id": expected_run_id,
            }
        )
        if resource.get("identifier") != expected_identifier:
            issues.append("boundary_resource_identifier_mismatch")
    else:
        issues.append("boundary_resource_identifier_mismatch")
    return tuple(issues)


def _inspect_evidence(
    request: Any,
    *,
    now: float,
) -> tuple[tuple[EvidenceFreshnessInspection, ...], tuple[str, ...]]:
    if not isinstance(request, Mapping):
        return (), ()
    raw_evidence = request.get("evidence")
    if not isinstance(raw_evidence, list):
        return (), ("evidence_shape_invalid",)
    issues: list[str] = []
    if len(raw_evidence) > _MAX_EVIDENCE_RECORDS:
        issues.append("evidence_limit_exceeded")
    environment = request.get("environment")
    evaluated_at = (
        _optional_timestamp(environment.get("evaluated_at"))
        if isinstance(environment, Mapping)
        else None
    )
    if evaluated_at is None:
        issues.append("evidence_evaluation_timestamp_invalid")
    seen_identifiers: set[str] = set()
    results: list[EvidenceFreshnessInspection] = []
    for record in raw_evidence[:_MAX_EVIDENCE_RECORDS]:
        if not isinstance(record, Mapping):
            issues.append("evidence_record_invalid")
            results.append(
                EvidenceFreshnessInspection(None, None, None, None, None, None, None)
            )
            continue
        if set(record) != {
            "attribute",
            "authenticated",
            "evidence_id",
            "expires_at",
            "observed_at",
            "source",
            "source_id",
            "value_digest",
        }:
            issues.append("evidence_record_shape_invalid")
        raw_attribute = record.get("attribute")
        attribute = _known_string(raw_attribute, _KNOWN_ATTRIBUTES)
        if attribute is None:
            issues.append("evidence_attribute_invalid")
        raw_source = record.get("source")
        source = _known_string(raw_source, _KNOWN_EVIDENCE_SOURCES)
        if source is None:
            issues.append("evidence_source_invalid")
        authenticated = _optional_boolean(record.get("authenticated"))
        if authenticated is None:
            issues.append("evidence_authentication_invalid")
        elif authenticated is False:
            issues.append("evidence_unauthenticated")
        observed_at = _optional_timestamp(record.get("observed_at"))
        expires_at = _optional_timestamp(record.get("expires_at"))
        if observed_at is None or expires_at is None or expires_at <= observed_at:
            issues.append("evidence_interval_invalid")
            valid_interval = False
        else:
            valid_interval = True
        evidence_id = record.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            issues.append("evidence_identifier_invalid")
        elif evidence_id in seen_identifiers:
            issues.append("evidence_identifier_duplicate")
        else:
            seen_identifiers.add(evidence_id)
        source_id = record.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            issues.append("evidence_source_identifier_invalid")
        value_digest = record.get("value_digest")
        if not _is_digest(value_digest):
            issues.append("evidence_value_digest_invalid")
        elif attribute is not None:
            expected_value = request.get(attribute, _MISSING)
            try:
                expected_digest = canonical_digest(expected_value)
            except (TypeError, ValueError, RecursionError):
                issues.append("evidence_value_digest_unverifiable")
            else:
                if value_digest != expected_digest:
                    issues.append("evidence_value_digest_mismatch")
        fresh_at_evaluation = (
            observed_at <= evaluated_at < expires_at
            if valid_interval and evaluated_at is not None
            else None
        )
        if fresh_at_evaluation is False:
            if (
                observed_at is not None
                and evaluated_at is not None
                and observed_at > evaluated_at
            ):
                issues.append("evidence_from_future_at_evaluation")
            else:
                issues.append("evidence_stale_at_evaluation")
        fresh_now = (
            observed_at <= now < expires_at if valid_interval else None
        )
        results.append(
            EvidenceFreshnessInspection(
                attribute=attribute,
                source=source,
                authenticated=authenticated,
                observed_at=observed_at,
                expires_at=expires_at,
                fresh_at_evaluation=fresh_at_evaluation,
                fresh_now=fresh_now,
            )
        )
    if seen_identifiers and len(seen_identifiers) != len(
        raw_evidence[:_MAX_EVIDENCE_RECORDS]
    ):
        issues.append("evidence_identifier_coverage_invalid")
    observed_attributes = {
        result.attribute for result in results if result.attribute is not None
    }
    if observed_attributes != _KNOWN_ATTRIBUTES:
        issues.append("evidence_attribute_coverage_invalid")
    return tuple(results), tuple(sorted(set(issues)))


def _invalid_event(
    sequence: int,
    occurred_at: float | None,
    issues: list[str],
) -> ShadowDecisionInspection:
    return ShadowDecisionInspection(
        sequence=sequence,
        occurred_at=occurred_at,
        action_scope=None,
        effect=None,
        derived_permission_class=None,
        recomputed_derived_permission_class=None,
        requested_permission_class=None,
        legacy_executable=None,
        recomputed_legacy_executable=None,
        reported_execution_parity=None,
        recomputed_execution_parity=None,
        reported_authority_ceiling_parity=None,
        recomputed_authority_ceiling_parity=None,
        request_digest_valid=None,
        decision_digest_valid=None,
        evidence=(),
        integrity_issues=tuple(sorted(set(issues))),
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _is_request_shape(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value) != {
        "action",
        "consequences",
        "environment",
        "evidence",
        "request_id",
        "resource",
        "subject",
    }:
        return False
    action = value.get("action")
    consequences = value.get("consequences")
    environment = value.get("environment")
    resource = value.get("resource")
    subject = value.get("subject")
    return (
        isinstance(action, Mapping)
        and set(action)
        == {
            "descriptive_claims",
            "intended_effect",
            "operation",
            "parameters_digest",
            "tool_id",
            "verb",
        }
        and isinstance(consequences, Mapping)
        and set(consequences)
        == {
            "availability",
            "blast_radius",
            "confidentiality",
            "destructive",
            "integrity",
            "reach",
            "reversible",
            "sensitivity",
        }
        and isinstance(environment, Mapping)
        and set(environment)
        == {
            "approval_grants",
            "billing_route",
            "capacity_state",
            "circuit_state",
            "evaluated_at",
            "flow_state",
            "isolation_state",
            "network_state",
            "paid_continuation_protection",
        }
        and isinstance(value.get("evidence"), list)
        and isinstance(value.get("request_id"), str)
        and isinstance(resource, Mapping)
        and set(resource)
        == {
            "content_digest",
            "identifier",
            "owner",
            "protected",
            "repository_id",
            "resource_type",
            "sensitivity",
            "trust_boundary",
            "version",
        }
        and isinstance(subject, Mapping)
        and set(subject)
        == {
            "controller_id",
            "principal_id",
            "profile_id",
            "role",
            "role_version",
            "runner_id",
            "session_id",
        }
    )


def _is_task_intent_shape(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "action",
        "consequences",
        "resource",
    }:
        return False
    action = value.get("action")
    resource = value.get("resource")
    consequences = value.get("consequences")
    if not isinstance(action, Mapping) or set(action) != {
        "intended_effect",
        "operation",
        "verb",
    }:
        return False
    if not isinstance(resource, Mapping) or set(resource) != {
        "protected",
        "resource_type",
        "sensitivity",
        "trust_boundary",
    }:
        return False
    if not isinstance(consequences, Mapping) or set(consequences) != {
        "availability",
        "blast_radius",
        "confidentiality",
        "destructive",
        "integrity",
        "reach",
        "reversible",
        "sensitivity",
    }:
        return False
    impact_values = frozenset(item.value for item in ImpactLevel)
    return (
        action.get("verb") in {item.value for item in ActionVerb}
        and _bounded_authorization_identifier(action.get("operation"))
        and _bounded_authorization_identifier(action.get("intended_effect"))
        and _bounded_authorization_identifier(resource.get("resource_type"))
        and _bounded_authorization_identifier(resource.get("trust_boundary"))
        and isinstance(resource.get("protected"), bool)
        and resource.get("sensitivity") in impact_values
        and consequences.get("availability") in impact_values
        and consequences.get("confidentiality") in impact_values
        and consequences.get("integrity") in impact_values
        and consequences.get("sensitivity") in impact_values
        and consequences.get("reach") in {item.value for item in Reach}
        and consequences.get("blast_radius")
        in {item.value for item in BlastRadius}
        and isinstance(consequences.get("destructive"), bool)
        and isinstance(consequences.get("reversible"), bool)
    )


def _is_comparison_binding_shape(value: Any) -> bool:
    """Accept only the fixed, digest-only comparison binding schema."""

    if not isinstance(value, Mapping) or set(value) != {
        "attempt",
        "billing_assessment_digest",
        "comparison_ref",
        "context_digest",
        "controls_digest",
        "kind",
        "order_index",
        "output_schema_digest",
        "permission_class",
        "plan_digest",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "prompt_digest",
        "repetition",
        "repository_ref",
        "runner_id",
        "runner_overrides_digest",
        "snapshot_digest",
        "task_definition_digest",
        "timeout_seconds",
        "trial_ref",
    }:
        return False
    digest_fields = {
        "billing_assessment_digest",
        "comparison_ref",
        "context_digest",
        "controls_digest",
        "output_schema_digest",
        "plan_digest",
        "profile_configuration_digest",
        "profile_ref",
        "profile_version_ref",
        "prompt_digest",
        "repository_ref",
        "runner_overrides_digest",
        "snapshot_digest",
        "task_definition_digest",
        "trial_ref",
    }
    if any(not _is_digest(value.get(field)) for field in digest_fields):
        return False
    repetition = value.get("repetition")
    order_index = value.get("order_index")
    timeout_seconds = value.get("timeout_seconds")
    attempt = value.get("attempt")
    permission_class = value.get("permission_class")
    return (
        value.get("kind") == COMPARISON_RUN_KIND
        and _bounded_authorization_identifier(value.get("runner_id"))
        and isinstance(permission_class, int)
        and not isinstance(permission_class, bool)
        and permission_class == int(PermissionClass.READ_ONLY)
        and isinstance(repetition, int)
        and not isinstance(repetition, bool)
        and repetition > 0
        and isinstance(order_index, int)
        and not isinstance(order_index, bool)
        and order_index >= 0
        and isinstance(timeout_seconds, int)
        and not isinstance(timeout_seconds, bool)
        and timeout_seconds > 0
        and isinstance(attempt, int)
        and not isinstance(attempt, bool)
        and attempt > 0
    )


def _is_comparison_billing_shape(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "account_identity_ref",
        "assessment_digest",
        "attestation",
        "capacity_expires_at",
        "capacity_observed_at",
        "capacity_state",
        "confidence",
        "paid_continuation_protection",
        "paid_credit_balance",
        "route",
        "runner_id",
        "schema_version",
        "subscription_ref",
    }:
        return False
    if (
        value.get("schema_version") != 1
        or not _is_digest(value.get("assessment_digest"))
        or not _bounded_authorization_identifier(value.get("runner_id"))
        or value.get("route") not in {item.value for item in BillingRoute}
        or value.get("confidence")
        not in {item.value for item in AssessmentConfidence}
        or value.get("capacity_state")
        not in {item.value for item in CapacityState}
        or value.get("paid_continuation_protection")
        not in {item.value for item in PaidContinuationProtection}
        or value.get("paid_credit_balance")
        not in {item.value for item in PaidCreditBalance}
        or not _is_optional_digest(value.get("subscription_ref"))
        or not _is_optional_digest(value.get("account_identity_ref"))
        or not _is_optional_timestamp_value(value.get("capacity_observed_at"))
        or not _is_optional_timestamp_value(value.get("capacity_expires_at"))
    ):
        return False
    capacity_observed_at = value.get("capacity_observed_at")
    capacity_expires_at = value.get("capacity_expires_at")
    if (
        capacity_observed_at is not None
        and capacity_expires_at is not None
        and float(capacity_expires_at) <= float(capacity_observed_at)
    ):
        return False

    attestation = value.get("attestation")
    if attestation is None:
        return True
    if not isinstance(attestation, Mapping) or set(attestation) != {
        "account_identity_ref",
        "billing_route",
        "capacity_state",
        "confidence",
        "expires_at",
        "observed_at",
        "paid_continuation_protection",
        "runner_id",
    }:
        return False
    observed_at = attestation.get("observed_at")
    expires_at = attestation.get("expires_at")
    return (
        attestation.get("runner_id") == value.get("runner_id")
        and attestation.get("billing_route") == value.get("route")
        and attestation.get("capacity_state") == value.get("capacity_state")
        and attestation.get("paid_continuation_protection")
        == value.get("paid_continuation_protection")
        and attestation.get("account_identity_ref")
        == value.get("account_identity_ref")
        and attestation.get("confidence")
        in {item.value for item in AssessmentConfidence}
        and _is_required_timestamp_value(observed_at)
        and _is_required_timestamp_value(expires_at)
        and float(expires_at) > float(observed_at)
    )


def _comparison_billing_evidence_window(
    payload: Mapping[str, Any],
) -> tuple[float, float] | None:
    observations: list[float] = []
    expiries: list[float] = []
    capacity_observed_at = payload["capacity_observed_at"]
    capacity_expires_at = payload["capacity_expires_at"]
    if capacity_observed_at is not None:
        observations.append(float(capacity_observed_at))
    if capacity_expires_at is not None:
        expiries.append(float(capacity_expires_at))
    attestation = payload["attestation"]
    if isinstance(attestation, Mapping):
        observations.append(float(attestation["observed_at"]))
        expiries.append(float(attestation["expires_at"]))
    if not observations or not expiries:
        return None
    return min(observations), min(expiries)


def _bounded_authorization_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _AUTHORIZATION_IDENTIFIER_PATTERN.fullmatch(value) is not None
    )


def _is_decision_shape(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value) != {
        "derived_permission_class",
        "effect",
        "evidence_refs",
        "expires_at",
        "issued_at",
        "matched_rule_ids",
        "obligations",
        "policy_bundle_id",
        "policy_digest",
        "policy_version",
        "reason_codes",
        "reason_details",
        "request_digest",
        "request_id",
    }:
        return False
    return (
        _known_string(value.get("effect"), _KNOWN_EFFECTS) is not None
        and _permission_class(value.get("derived_permission_class")) is not None
        and isinstance(value.get("evidence_refs"), list)
        and isinstance(value.get("matched_rule_ids"), list)
        and isinstance(value.get("obligations"), list)
        and isinstance(value.get("reason_codes"), list)
        and isinstance(value.get("reason_details"), list)
        and isinstance(value.get("policy_bundle_id"), str)
        and isinstance(value.get("policy_version"), str)
        and _is_digest(value.get("policy_digest"))
        and _is_digest(value.get("request_digest"))
        and isinstance(value.get("request_id"), str)
        and _optional_timestamp(value.get("issued_at")) is not None
        and _optional_timestamp(value.get("expires_at")) is not None
    )


def _digest_matches(reported: Any, value: Mapping[str, Any]) -> bool:
    if not _is_digest(reported):
        return False
    try:
        return reported == canonical_digest(value)
    except (TypeError, ValueError, RecursionError):
        return False


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _is_optional_digest(value: Any) -> bool:
    return value is None or _is_digest(value)


def _is_required_timestamp_value(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _is_optional_timestamp_value(value: Any) -> bool:
    return value is None or _is_required_timestamp_value(value)


def _normalize_sha256_digest(value: Any) -> str | None:
    if _is_digest(value):
        assert isinstance(value, str)
        return value
    if isinstance(value, str) and _BARE_SHA256_PATTERN.fullmatch(value) is not None:
        return f"sha256:{value}"
    return None


def _known_string(value: Any, allowed: frozenset[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _safe_run_identifier(value: str) -> str | None:
    folded = value.casefold()
    if _SAFE_IDENTIFIER_PATTERN.fullmatch(value) is None:
        return None
    if any(marker in folded for marker in _SENSITIVE_IDENTIFIER_MARKERS):
        return None
    if folded.startswith(_SENSITIVE_IDENTIFIER_PREFIXES):
        return None
    return value


def _permission_class(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return int(PermissionClass(value))
    except ValueError:
        return None


def _is_positive_integer(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    )


def _is_optional_non_negative_integer(value: Any) -> bool:
    return value is None or (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def _optional_sequence(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise sqlite3.DatabaseError("invalid event sequence")
    return value


def _optional_boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) and numeric >= 0 else None


def _finite_timestamp(value: Any) -> float:
    timestamp = _optional_timestamp(value)
    if timestamp is None:
        raise ConfigurationError("authorization inspection time must be finite")
    return timestamp


def _validate_requested_run_id(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or "\x00" in value
        or any(
            ord(character) < 32 and character not in "\t\n\r"
            for character in value
        )
    ):
        raise ConfigurationError("authorization inspection run identifier is invalid")
    return value


__all__ = [
    "ADMISSION_SCOPE",
    "AUTHORIZATION_SHADOW_EVENT_TYPE",
    "AuthorizationInspectionReport",
    "COMPARISON_ACTION_RECEIPT_COVERAGE",
    "COMPARISON_FULL_SHADOW_COVERAGE",
    "COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE",
    "COMPARISON_RUN_KIND",
    "COMPARISON_SHADOW_COVERAGE",
    "DISPATCH_SCOPE",
    "EvidenceFreshnessInspection",
    "KNOWN_ACTION_SCOPES",
    "PUBLICATION_SCOPE",
    "RunAuthorizationInspection",
    "ShadowDecisionInspection",
    "SUPPORTED_SHADOW_SCHEMA_VERSIONS",
    "TASK_ATTEMPT_RUN_KIND",
    "TASK_ATTEMPT_SHADOW_COVERAGE",
    "inspect_authorization_shadows",
]
