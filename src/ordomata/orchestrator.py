"""Deterministic orchestration for the first controlled workflow.

The control plane owns task loading, context selection, permissions, state,
validation, and artifact promotion.  Runners receive an immutable prompt and an
isolated per-run workspace; a successful harness exit is never sufficient on
its own to publish an artifact.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any
from uuid import uuid4

from .approval import ApprovalPolicy
from .authorization import canonical_digest
from .billing import BillingPolicy, BillingPostRunDisposition
from .context import (
    ContextPack,
    LocalContextIndex,
    build_context_pack,
    load_source_documents,
    render_synthesis_prompt,
)
from .contracts import TaskContract, load_task_contract
from .errors import (
    OrdomataError,
    BillingRouteBlocked,
    ConfigurationError,
    ValidationError,
)
from .evaluation import (
    EvaluationResult,
    evaluate_chief_of_staff,
    load_evaluation_expectations,
)
from .models import (
    AgentEvent,
    BillingRoute,
    BillingRouteAssessment,
    CapacityState,
    CircuitBreakerState,
    IncrementalAICharge,
    PaidCapacityConsumed,
    RunRequest,
    RunnerExecutionResult,
    RunStatus,
)
from .paths import resolve_state_root
from .runners.base import AgentRunner
from .runners.mock import MockRunner
from .redaction import contains_credential_material
from .schema import parse_json_document
from .shadow_authorization import (
    build_local_candidate_publication_shadow_event,
    build_runner_model_dispatch_shadow_event,
    build_task_admission_shadow_event,
)
from .state import ArtifactRecord, SQLiteStateStore


DEFAULT_TASK = Path("tasks/chief-of-staff-lite.json")
DEFAULT_EXPECTATIONS = Path("fixtures/chief_of_staff/expectations.json")
DEFAULT_MOCK_OUTPUT = Path("fixtures/chief_of_staff/valid-output.json")


@dataclass(frozen=True, slots=True)
class PreparedTask:
    """An immutable, runner-neutral input snapshot."""

    contract: TaskContract
    context_pack: ContextPack
    prompt: str
    expectations: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TaskRunReport:
    """Safe run summary; prompt, transcript, and artifact contents are omitted."""

    run_id: str
    runner_id: str
    status: RunStatus
    task_id: str
    task_version: str
    prompt_version: str
    context_snapshot: str
    context_sources: int
    events_seen: int
    artifact_path: str | None
    artifact_sha256: str | None
    evaluation: EvaluationResult | None
    usage_observation: str
    error_count: int
    billing_route: str
    billing_confidence: str
    subscription_name: str | None
    artifact_credential_scan_passed: bool | None
    runner_version: str | None
    execution_mode: str | None
    harness_process_started: bool
    live_model_execution_occurred: bool | None
    incremental_api_charge: str
    incremental_ai_charge: str
    subscription_capacity_consumed: bool | None
    paid_capacity_consumed: str
    included_capacity_state: str
    billing_quarantine_required: bool
    billing_circuit_breaker_required: bool
    billing_disposition_reasons: tuple[str, ...]
    wall_seconds: float | None

    @property
    def accepted(self) -> bool:
        return bool(
            self.status is RunStatus.SUCCEEDED
            and self.evaluation
            and self.evaluation.accepted
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "runner_id": self.runner_id,
            "status": self.status.value,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "prompt_version": self.prompt_version,
            "context_snapshot": self.context_snapshot,
            "context_sources": self.context_sources,
            "events_seen": self.events_seen,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "evaluation": (
                None if self.evaluation is None else self.evaluation.to_mapping()
            ),
            "usage_observation": self.usage_observation,
            "error_count": self.error_count,
            "billing_route": self.billing_route,
            "billing_confidence": self.billing_confidence,
            "subscription_name": self.subscription_name,
            "artifact_credential_scan_passed": self.artifact_credential_scan_passed,
            "runner_version": self.runner_version,
            "execution_mode": self.execution_mode,
            "harness_process_started": self.harness_process_started,
            "live_model_execution_occurred": self.live_model_execution_occurred,
            "incremental_api_charge": self.incremental_api_charge,
            "incremental_ai_charge": self.incremental_ai_charge,
            "subscription_capacity_consumed": self.subscription_capacity_consumed,
            "paid_capacity_consumed": self.paid_capacity_consumed,
            "included_capacity_state": self.included_capacity_state,
            "billing_quarantine_required": self.billing_quarantine_required,
            "billing_circuit_breaker_required": self.billing_circuit_breaker_required,
            "billing_disposition_reasons": list(self.billing_disposition_reasons),
            "wall_seconds": self.wall_seconds,
        }


def prepare_chief_of_staff(
    project_root: str | Path,
    *,
    operator_instructions: Iterable[str] = (),
) -> PreparedTask:
    """Load sanitized fixtures and construct a bounded immutable context pack."""

    root = Path(project_root).resolve()
    task_path = _project_path(root, DEFAULT_TASK)
    contract = load_task_contract(task_path)
    source_path = _fixture_path_for_kind(root, task_path, contract, "local_documents")
    expectations_path = _expectations_path(root, task_path, contract)

    documents = load_source_documents(source_path)
    with LocalContextIndex() as index:
        index.ingest_many(documents)
        pack = build_context_pack(
            index,
            contract.context_selection,
            task_id=contract.task_id,
            task_version=contract.version,
            prompt_version=contract.prompt_version,
        )
    if not pack.verify_snapshot_hash():
        raise ValidationError("constructed context pack failed its integrity check")
    prompt = render_synthesis_prompt(
        contract,
        pack,
        operator_instructions=tuple(operator_instructions),
    )
    return PreparedTask(
        contract=contract,
        context_pack=pack,
        prompt=prompt,
        expectations=load_evaluation_expectations(expectations_path),
    )


def load_mock_chief_of_staff_output(
    project_root: str | Path,
    prepared: PreparedTask,
) -> dict[str, Any]:
    """Load the deterministic fixture and bind it to the prepared snapshot."""

    path = _project_path(Path(project_root).resolve(), DEFAULT_MOCK_OUTPUT)
    try:
        parsed = parse_json_document(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"cannot read mock output fixture {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValidationError("mock output fixture must be a JSON object")
    # Copy through a JSON round-trip so the checked-in fixture cannot be
    # mutated by a caller or reused with stale snapshot metadata.
    output = json.loads(json.dumps(parsed, ensure_ascii=False, allow_nan=False))
    output["metadata"] = {
        "task_id": prepared.contract.task_id,
        "task_version": prepared.contract.version,
        "prompt_version": prepared.contract.prompt_version,
        "snapshot_hash": prepared.context_pack.snapshot_hash,
    }
    return output


async def run_chief_of_staff(
    project_root: str | Path,
    *,
    runner: AgentRunner | None = None,
    runner_overrides: dict[str, Any] | None = None,
    operator_instructions: Iterable[str] = (),
    run_id: str | None = None,
    state_path: str | Path | None = None,
    run_root: str | Path | None = None,
    profile_id: str | None = None,
) -> TaskRunReport:
    """Execute one bounded Chief of Staff Lite attempt.

    Passing no runner selects the deterministic mock.  Live runners remain
    subject to their own high-confidence subscription checks and the exact
    ``ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1`` gate.
    """

    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ConfigurationError(f"project root is not a directory: {root}")
    prepared = prepare_chief_of_staff(
        root, operator_instructions=operator_instructions
    )
    approval_policy = ApprovalPolicy()
    approval_policy.assert_executable(prepared.contract.permission_class)
    legacy_executable = approval_policy.classify(
        prepared.contract.permission_class
    ).executable_now

    selected_run_id = run_id or f"cos-{uuid4().hex}"
    _validate_run_identifier(selected_run_id)
    if profile_id is not None:
        _validate_profile_identifier(profile_id)
    ordomata_root = _contained_path(root, resolve_state_root(root))
    selected_run_root = _contained_path(
        root, Path(run_root).resolve() if run_root is not None else ordomata_root / "runs"
    )
    selected_state_path = _contained_path(
        root,
        Path(state_path).resolve()
        if state_path is not None
        else ordomata_root / "state.sqlite3",
    )
    run_directory = _contained_path(root, selected_run_root / selected_run_id)
    isolated_workspace = _contained_path(root, run_directory / "workspace")
    selected_run_root.mkdir(parents=True, exist_ok=True)
    run_directory.mkdir(mode=0o700, exist_ok=False)
    isolated_workspace.mkdir(mode=0o700, exist_ok=False)
    selected_state_path.parent.mkdir(parents=True, exist_ok=True)

    active_runner: AgentRunner
    if runner is None:
        active_runner = MockRunner(
            output=load_mock_chief_of_staff_output(root, prepared)
        )
    else:
        active_runner = runner

    request = RunRequest(
        run_id=selected_run_id,
        task_id=prepared.contract.task_id,
        task_version=prepared.contract.version,
        prompt=prepared.prompt,
        workspace=isolated_workspace,
        run_directory=run_directory,
        output_schema=prepared.contract.output_schema,
        permission_class=prepared.contract.permission_class,
        timeout_seconds=prepared.contract.timeout_seconds,
        attempt=1,
        runner_overrides=dict(runner_overrides or {}),
    )
    prompt_digest = (
        "sha256:" + hashlib.sha256(prepared.prompt.encode("utf-8")).hexdigest()
    )

    with SQLiteStateStore(selected_state_path) as state:
        state.create_run_from_request(
            request,
            runner_id=active_runner.runner_id,
            context_digest=prepared.context_pack.snapshot_hash,
        )
        _best_effort_shadow_observation(
            state,
            selected_run_id,
            lambda: build_task_admission_shadow_event(
                contract=prepared.contract,
                run_id=selected_run_id,
                runner_id=active_runner.runner_id,
                profile_id=profile_id,
                context_digest=prepared.context_pack.snapshot_hash,
                prompt_digest=prompt_digest,
                project_root=root,
                evaluated_at=time.time(),
                legacy_executable=legacy_executable,
            ),
        )
        try:
            preflight_assessment = await active_runner.inspect_billing_route()
            _assert_runner_billing_route(active_runner.runner_id, preflight_assessment)
        except OrdomataError:
            state.append_event(
                selected_run_id,
                "status",
                {"phase": "billing_preflight"},
                status=RunStatus.BLOCKED,
            )
            raise
        except BaseException:
            state.append_event(
                selected_run_id,
                "status",
                {"phase": "billing_preflight"},
                status=RunStatus.FAILED,
            )
            raise
        state.append_event(
            selected_run_id,
            "billing_assessment",
            _billing_metadata(preflight_assessment),
        )
        state.append_event(
            selected_run_id,
            "status",
            {"phase": "runner_execution"},
            status=RunStatus.RUNNING,
        )
        _best_effort_shadow_observation(
            state,
            selected_run_id,
            lambda: build_runner_model_dispatch_shadow_event(
                contract=prepared.contract,
                run_id=selected_run_id,
                runner_id=active_runner.runner_id,
                profile_id=profile_id,
                context_digest=prepared.context_pack.snapshot_hash,
                prompt_digest=prompt_digest,
                project_root=root,
                runner_overrides=request.runner_overrides,
                timeout_seconds=request.timeout_seconds,
                attempt=request.attempt,
                billing_assessment=preflight_assessment,
                evaluated_at=time.time(),
                legacy_executable=legacy_executable,
            ),
        )
        event_count = 0

        async def event_sink(_: AgentEvent) -> None:
            nonlocal event_count
            event_count += 1
            # Model-controlled event content is deliberately not persisted.
            state.append_event(
                selected_run_id,
                "runner_event_observed",
                {"ordinal": event_count},
            )

        try:
            result = await active_runner.execute(request, event_sink)
        except OrdomataError:
            state.append_event(
                selected_run_id,
                "status",
                {"phase": "preflight_or_execution"},
                status=RunStatus.BLOCKED,
            )
            raise
        except BaseException:
            billing_failure = (
                preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
            )
            if billing_failure:
                _record_billing_outcome(
                    state,
                    run_id=selected_run_id,
                    profile_id=profile_id,
                    preflight_assessment=preflight_assessment,
                    postflight_assessment=None,
                    disposition=_unknown_billing_disposition(
                        "harness_execution_outcome_unknown"
                    ),
                    billing_matches=False,
                )
            state.append_event(
                selected_run_id,
                "status",
                {"phase": "execution"},
                status=(
                    RunStatus.QUARANTINED
                    if billing_failure
                    else RunStatus.FAILED
                ),
            )
            raise

        if not isinstance(result, RunnerExecutionResult):
            if preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
                _record_billing_outcome(
                    state,
                    run_id=selected_run_id,
                    profile_id=profile_id,
                    preflight_assessment=preflight_assessment,
                    postflight_assessment=None,
                    disposition=_unknown_billing_disposition(
                        "post_run_billing_disposition_inconsistent"
                    ),
                    billing_matches=False,
                )
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=RunStatus.QUARANTINED,
                phase="runner_result_validation",
            )
            raise ValidationError("runner returned an invalid result type")

        try:
            return _finalize_result(
                root=root,
                prepared=prepared,
                request=request,
                result=result,
                state=state,
                event_count=event_count,
                preflight_assessment=preflight_assessment,
                expected_runner_id=active_runner.runner_id,
                profile_id=profile_id,
                legacy_executable=legacy_executable,
            )
        except ValidationError:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=RunStatus.QUARANTINED,
                phase="result_finalization",
            )
            raise
        except BaseException:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=RunStatus.FAILED,
                phase="result_finalization",
            )
            raise


def _finalize_result(
    *,
    root: Path,
    prepared: PreparedTask,
    request: RunRequest,
    result: RunnerExecutionResult,
    state: SQLiteStateStore,
    event_count: int,
    preflight_assessment: BillingRouteAssessment,
    expected_runner_id: str,
    profile_id: str | None,
    legacy_executable: bool,
) -> TaskRunReport:
    persisted_runner_id = state.get_run(request.run_id).runner_id
    if (
        result.run_id != request.run_id
        or result.runner_id != expected_runner_id
        or persisted_runner_id != expected_runner_id
    ):
        if preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
            _record_billing_outcome(
                state,
                run_id=request.run_id,
                profile_id=profile_id,
                preflight_assessment=preflight_assessment,
                postflight_assessment=result.postflight_billing_assessment,
                disposition=_unknown_billing_disposition(
                    "post_run_billing_identity_changed"
                ),
                billing_matches=False,
            )
        _best_effort_terminal_status(
            state,
            request.run_id,
            status=RunStatus.QUARANTINED,
            phase="runner_result_validation",
        )
        raise ValidationError("runner returned mismatched result identity")

    if not isinstance(result.billing_assessment, BillingRouteAssessment):
        if preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
            _record_billing_outcome(
                state,
                run_id=request.run_id,
                profile_id=profile_id,
                preflight_assessment=preflight_assessment,
                postflight_assessment=result.postflight_billing_assessment,
                disposition=_unknown_billing_disposition(
                    "post_run_billing_disposition_inconsistent"
                ),
                billing_matches=False,
            )
        _best_effort_terminal_status(
            state,
            request.run_id,
            status=RunStatus.QUARANTINED,
            phase="runner_result_validation",
        )
        raise ValidationError("runner returned an invalid billing assessment")

    try:
        billing_matches = _billing_assessments_match(
            result.billing_assessment, preflight_assessment
        )
    except Exception:
        billing_matches = False
    billing_disposition = _resolve_billing_disposition(
        result=result,
        preflight_assessment=preflight_assessment,
        billing_matches=billing_matches,
    )
    if preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
        _record_billing_outcome(
            state,
            run_id=request.run_id,
            profile_id=profile_id,
            preflight_assessment=preflight_assessment,
            postflight_assessment=result.postflight_billing_assessment,
            disposition=billing_disposition,
            billing_matches=billing_matches,
        )
    incremental_api_charge = _incremental_api_charge(
        result=result,
        preflight_assessment=preflight_assessment,
        disposition=billing_disposition,
        billing_matches=billing_matches,
    )
    state.append_event(
        request.run_id,
        "execution_accounting",
        {
            "runner_version": result.runner_version,
            "execution_mode": result.execution_mode,
            "harness_process_started": result.harness_process_started,
            "live_model_execution_occurred": result.live_model_execution_occurred,
            "incremental_api_charge": incremental_api_charge,
            "incremental_ai_charge": billing_disposition.incremental_ai_charge.value,
            "subscription_capacity_consumed": (
                result.subscription_capacity_consumed if billing_matches else None
            ),
            "paid_capacity_consumed": billing_disposition.paid_capacity_consumed.value,
            "included_capacity_state": billing_disposition.capacity_state.value,
            "billing_quarantine_required": billing_disposition.quarantine_required,
            "billing_circuit_breaker_required": (
                billing_disposition.circuit_breaker_required
            ),
            "billing_disposition_reasons": list(billing_disposition.reasons),
            "usage_observation": result.usage_observation.value,
            "wall_seconds": result.wall_seconds,
        },
    )
    evaluation: EvaluationResult | None = None
    artifact_path: Path | None = None
    artifact_digest: str | None = None
    credential_scan_passed: bool | None = None
    final_status = result.status
    if not billing_matches or billing_disposition.quarantine_required:
        final_status = RunStatus.QUARANTINED
    elif result.status is RunStatus.SUCCEEDED:
        evaluation = evaluate_chief_of_staff(
            result.output,
            prepared.contract.output_schema,
            prepared.context_pack,
            prepared.expectations,
        )
        if evaluation.accepted:
            credential_scan_passed = (
                not result.credential_material_detected
                and not contains_credential_material(result.output)
            )
        final_status = (
            RunStatus.SUCCEEDED
            if evaluation.accepted and credential_scan_passed is True
            else RunStatus.QUARANTINED
        )
        if final_status is RunStatus.SUCCEEDED:
            candidate_artifact_path = _contained_path(
                root,
                request.run_directory / prepared.contract.expected_output.local_destination,
            )
            artifact_bytes = _canonical_artifact_bytes(result.output)
            artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
            _best_effort_shadow_observation(
                state,
                request.run_id,
                lambda: build_local_candidate_publication_shadow_event(
                    contract=prepared.contract,
                    run_id=request.run_id,
                    runner_id=expected_runner_id,
                    profile_id=profile_id,
                    project_root=root,
                    artifact_digest="sha256:" + artifact_digest,
                    artifact_size_bytes=len(artifact_bytes),
                    artifact_kind=(
                        prepared.contract.expected_output.artifact_kind
                    ),
                    destination_digest=canonical_digest(
                        {
                            "local_destination": (
                                prepared.contract.expected_output.local_destination
                            )
                        }
                    ),
                    evaluation_accepted=evaluation.accepted,
                    credential_scan_passed=credential_scan_passed,
                    billing_disposition={
                        "billing_matches": billing_matches,
                        "capacity_state": billing_disposition.capacity_state.value,
                        "circuit_breaker_required": (
                            billing_disposition.circuit_breaker_required
                        ),
                        "incremental_ai_charge": (
                            billing_disposition.incremental_ai_charge.value
                        ),
                        "paid_capacity_consumed": (
                            billing_disposition.paid_capacity_consumed.value
                        ),
                        "quarantine_required": (
                            billing_disposition.quarantine_required
                        ),
                        "reason_codes": list(billing_disposition.reasons),
                    },
                    evaluated_at=time.time(),
                    legacy_executable=legacy_executable,
                ),
            )
            staged_path = _stage_artifact(candidate_artifact_path, artifact_bytes)
            try:
                # Record the immutable metadata before the final artifact name
                # becomes visible. If publication fails, the terminal failed
                # event makes the incomplete metadata record auditable; the
                # inverse (an artifact with no metadata) cannot occur.
                state.append_artifact(
                    ArtifactRecord(
                        artifact_id=f"{request.run_id}:chief-of-staff",
                        run_id=request.run_id,
                        kind=prepared.contract.expected_output.artifact_kind,
                        path=str(candidate_artifact_path),
                        sha256=artifact_digest,
                        media_type="application/json",
                        size_bytes=len(artifact_bytes),
                        created_at=time.time(),
                    )
                )
                _promote_staged_artifact(staged_path, candidate_artifact_path)
                artifact_path = candidate_artifact_path
            finally:
                staged_path.unlink(missing_ok=True)
    elif result.status not in {
        RunStatus.FAILED,
        RunStatus.BLOCKED,
        RunStatus.QUARANTINED,
        RunStatus.CANCELLED,
    }:
        final_status = RunStatus.FAILED

    state.append_event(
        request.run_id,
        "status",
        {
            "accepted": bool(evaluation and evaluation.accepted),
            "artifact_recorded": artifact_path is not None,
            "runner_status": result.status.value,
            "billing_assessment_matched_preflight": billing_matches,
            "billing_quarantine_required": billing_disposition.quarantine_required,
            "billing_circuit_breaker_required": (
                billing_disposition.circuit_breaker_required
            ),
            "artifact_credential_scan_passed": credential_scan_passed,
        },
        status=final_status,
    )
    return TaskRunReport(
        run_id=request.run_id,
        runner_id=result.runner_id,
        status=final_status,
        task_id=prepared.contract.task_id,
        task_version=prepared.contract.version,
        prompt_version=prepared.contract.prompt_version,
        context_snapshot=prepared.context_pack.snapshot_hash,
        context_sources=prepared.context_pack.sources_included,
        events_seen=event_count,
        artifact_path=None if artifact_path is None else str(artifact_path),
        artifact_sha256=artifact_digest,
        evaluation=evaluation,
        usage_observation=result.usage_observation.value,
        error_count=len(result.errors)
        + int(not billing_matches or billing_disposition.quarantine_required),
        billing_route=result.billing_assessment.route.value,
        billing_confidence=result.billing_assessment.confidence.value,
        subscription_name=_safe_subscription_name(result.billing_assessment),
        artifact_credential_scan_passed=credential_scan_passed,
        runner_version=result.runner_version,
        execution_mode=result.execution_mode,
        harness_process_started=result.harness_process_started,
        live_model_execution_occurred=result.live_model_execution_occurred,
        incremental_api_charge=incremental_api_charge,
        incremental_ai_charge=billing_disposition.incremental_ai_charge.value,
        subscription_capacity_consumed=(
            result.subscription_capacity_consumed if billing_matches else None
        ),
        paid_capacity_consumed=billing_disposition.paid_capacity_consumed.value,
        included_capacity_state=billing_disposition.capacity_state.value,
        billing_quarantine_required=billing_disposition.quarantine_required,
        billing_circuit_breaker_required=(
            billing_disposition.circuit_breaker_required
        ),
        billing_disposition_reasons=billing_disposition.reasons,
        wall_seconds=result.wall_seconds,
    )


def _assert_runner_billing_route(
    runner_id: str,
    assessment: BillingRouteAssessment,
) -> None:
    if assessment.runner_id != runner_id:
        raise BillingRouteBlocked("billing assessment runner identity mismatch")
    expected = {
        "mock": BillingRoute.MOCK,
        "codex": BillingRoute.SUBSCRIPTION_INCLUDED,
        "claude": BillingRoute.SUBSCRIPTION_INCLUDED,
    }.get(runner_id)
    if expected is not None and assessment.route is not expected:
        raise BillingRouteBlocked(
            f"runner {runner_id!r} requires billing route {expected.value!r}"
        )
    BillingPolicy.assert_route_allowed(assessment)


def _billing_assessments_match(
    first: BillingRouteAssessment,
    second: BillingRouteAssessment,
) -> bool:
    """Compare security semantics while ignoring regenerated observation times."""

    if not isinstance(first, BillingRouteAssessment) or not isinstance(
        second, BillingRouteAssessment
    ):
        return False
    stable_fields = (
        "runner_id",
        "route",
        "confidence",
        "subscription_name",
        "capacity_state",
        "paid_continuation_protection",
        "paid_credit_balance",
    )
    if any(getattr(first, name) != getattr(second, name) for name in stable_fields):
        return False
    if _safe_fingerprint(first.account_identity_fingerprint) != _safe_fingerprint(
        second.account_identity_fingerprint
    ):
        return False
    return _attestation_security_semantics(first.attestation) == (
        _attestation_security_semantics(second.attestation)
    )


def _attestation_security_semantics(attestation: Any) -> tuple[Any, ...] | None:
    if attestation is None:
        return None
    return (
        getattr(attestation, "runner_id", None),
        _safe_fingerprint(
            getattr(attestation, "account_identity_fingerprint", None)
        ),
        getattr(attestation, "billing_route", None),
        getattr(attestation, "capacity_state", None),
        getattr(attestation, "paid_continuation_protection", None),
        getattr(attestation, "confidence", None),
        tuple(getattr(attestation, "evidence", ())),
    )


def _billing_metadata(assessment: BillingRouteAssessment) -> dict[str, Any]:
    """Return the only billing fields safe and necessary for immutable audit."""

    return {
        "runner_id": assessment.runner_id,
        "route": assessment.route.value,
        "confidence": assessment.confidence.value,
        "subscription_name": _safe_subscription_name(assessment),
        "capacity_state": assessment.capacity_state.value,
        "paid_continuation_protection": (
            assessment.paid_continuation_protection.value
        ),
        "paid_credit_balance": assessment.paid_credit_balance.value,
        "account_identity_verified": _safe_fingerprint(
            assessment.account_identity_fingerprint
        )
        is not None,
        "attestation_present": assessment.attestation is not None,
    }


_BILLING_DISPOSITION_REASON_CODES = frozenset(
    {
        "harness_execution_outcome_unknown",
        "harness_launch_outcome_unknown",
        "included_capacity_exhausted",
        "post_run_account_changed",
        "post_run_billing_disposition_inconsistent",
        "post_run_billing_evidence_unknown",
        "post_run_billing_identity_changed",
        "post_run_paid_capacity_consumed",
        "post_run_paid_route_possible",
    }
)


def _resolve_billing_disposition(
    *,
    result: RunnerExecutionResult,
    preflight_assessment: BillingRouteAssessment,
    billing_matches: bool,
) -> BillingPostRunDisposition:
    """Independently reconcile adapter accounting with postflight evidence."""

    if (
        not isinstance(result.paid_capacity_consumed, PaidCapacityConsumed)
        or not isinstance(result.incremental_ai_charge, IncrementalAICharge)
        or not isinstance(result.billing_quarantine_required, bool)
        or not isinstance(result.billing_circuit_breaker_required, bool)
        or not isinstance(result.harness_process_started, bool)
        or (
            result.live_model_execution_occurred is not None
            and not isinstance(result.live_model_execution_occurred, bool)
        )
        or not isinstance(result.billing_disposition_reasons, tuple)
        or any(
            not isinstance(reason, str)
            for reason in result.billing_disposition_reasons
        )
        or (
            result.postflight_billing_assessment is not None
            and not isinstance(
                result.postflight_billing_assessment, BillingRouteAssessment
            )
        )
        or not isinstance(result.events, tuple)
        or any(not isinstance(event, AgentEvent) for event in result.events)
    ):
        return _unknown_billing_disposition(
            "post_run_billing_disposition_inconsistent",
            circuit_breaker_required=(
                preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
            ),
        )
    if not billing_matches:
        return _unknown_billing_disposition(
            "post_run_billing_identity_changed",
            circuit_breaker_required=(
                preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
            ),
        )
    if preflight_assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
        return BillingPostRunDisposition(
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_capacity_consumed=result.paid_capacity_consumed,
            incremental_ai_charge=result.incremental_ai_charge,
            quarantine_required=result.billing_quarantine_required,
            circuit_breaker_required=result.billing_circuit_breaker_required,
            reasons=tuple(
                reason
                for reason in result.billing_disposition_reasons
                if reason in _BILLING_DISPOSITION_REASON_CODES
            ),
        )

    reported_reasons = tuple(dict.fromkeys(result.billing_disposition_reasons))
    if any(
        reason not in _BILLING_DISPOSITION_REASON_CODES
        for reason in reported_reasons
    ):
        return _unknown_billing_disposition(
            "post_run_billing_disposition_inconsistent"
        )
    if result.billing_circuit_breaker_required and not (
        result.billing_quarantine_required
    ):
        return _unknown_billing_disposition(
            "post_run_billing_disposition_inconsistent"
        )
    unknown_reasons = {
        "harness_execution_outcome_unknown",
        "harness_launch_outcome_unknown",
        "post_run_account_changed",
        "post_run_billing_disposition_inconsistent",
        "post_run_billing_evidence_unknown",
        "post_run_billing_identity_changed",
    }
    if unknown_reasons.intersection(reported_reasons):
        return _unknown_billing_disposition(reported_reasons[0])
    if "post_run_paid_capacity_consumed" in reported_reasons:
        return BillingPostRunDisposition(
            capacity_state=CapacityState.UNKNOWN,
            paid_capacity_consumed=PaidCapacityConsumed.YES,
            incremental_ai_charge=IncrementalAICharge.CONFIRMED,
            quarantine_required=True,
            circuit_breaker_required=True,
            reasons=("post_run_paid_capacity_consumed",),
        )
    if "post_run_paid_route_possible" in reported_reasons:
        return BillingPostRunDisposition(
            capacity_state=CapacityState.UNKNOWN,
            paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
            incremental_ai_charge=IncrementalAICharge.POSSIBLE,
            quarantine_required=True,
            circuit_breaker_required=True,
            reasons=("post_run_paid_route_possible",),
        )

    no_launch_observed = (
        not result.harness_process_started
        and result.live_model_execution_occurred is False
        and not result.billing_quarantine_required
        and not result.billing_circuit_breaker_required
        and not reported_reasons
        and result.paid_capacity_consumed is PaidCapacityConsumed.NO
        and result.incremental_ai_charge is IncrementalAICharge.NONE
    )
    if no_launch_observed:
        return BillingPostRunDisposition(
            capacity_state=preflight_assessment.capacity_state,
            paid_capacity_consumed=PaidCapacityConsumed.NO,
            incremental_ai_charge=IncrementalAICharge.NONE,
            quarantine_required=False,
            circuit_breaker_required=False,
        )

    try:
        computed = BillingPolicy.assess_post_run(
            preflight_assessment,
            result.postflight_billing_assessment,
            result.events,
        )
    except Exception:
        return _unknown_billing_disposition(
            "post_run_billing_disposition_inconsistent"
        )
    if (
        "included_capacity_exhausted" in reported_reasons
        and "included_capacity_exhausted" not in computed.reasons
    ):
        return _unknown_billing_disposition(
            "post_run_billing_disposition_inconsistent"
        )
    paid_capacity = _more_conservative_paid_capacity(
        computed.paid_capacity_consumed,
        result.paid_capacity_consumed,
    )
    ai_charge = _more_conservative_ai_charge(
        computed.incremental_ai_charge,
        result.incremental_ai_charge,
    )
    reasons = tuple(dict.fromkeys((*computed.reasons, *reported_reasons)))
    unsafe_charge = ai_charge is not IncrementalAICharge.NONE
    unsafe_paid_capacity = paid_capacity is not PaidCapacityConsumed.NO
    quarantine_required = (
        computed.quarantine_required
        or result.billing_quarantine_required
        or unsafe_charge
        or unsafe_paid_capacity
    )
    circuit_breaker_required = (
        computed.circuit_breaker_required
        or result.billing_circuit_breaker_required
        or unsafe_charge
        or unsafe_paid_capacity
    )
    if (
        result.billing_quarantine_required
        and not computed.quarantine_required
        and not reported_reasons
    ) or (quarantine_required and not reasons):
        reasons = ("post_run_billing_disposition_inconsistent",)
        circuit_breaker_required = True
        paid_capacity = PaidCapacityConsumed.UNKNOWN
        ai_charge = IncrementalAICharge.UNKNOWN
    return BillingPostRunDisposition(
        capacity_state=(
            CapacityState.UNKNOWN
            if reasons == ("post_run_billing_disposition_inconsistent",)
            else computed.capacity_state
        ),
        paid_capacity_consumed=paid_capacity,
        incremental_ai_charge=ai_charge,
        quarantine_required=quarantine_required,
        circuit_breaker_required=circuit_breaker_required,
        reasons=reasons,
    )


def _more_conservative_paid_capacity(
    first: PaidCapacityConsumed,
    second: PaidCapacityConsumed,
) -> PaidCapacityConsumed:
    if PaidCapacityConsumed.YES in {first, second}:
        return PaidCapacityConsumed.YES
    if PaidCapacityConsumed.UNKNOWN in {first, second}:
        return PaidCapacityConsumed.UNKNOWN
    if PaidCapacityConsumed.NOT_APPLICABLE in {first, second}:
        return PaidCapacityConsumed.UNKNOWN
    return PaidCapacityConsumed.NO


def _more_conservative_ai_charge(
    first: IncrementalAICharge,
    second: IncrementalAICharge,
) -> IncrementalAICharge:
    if IncrementalAICharge.CONFIRMED in {first, second}:
        return IncrementalAICharge.CONFIRMED
    if IncrementalAICharge.POSSIBLE in {first, second}:
        return IncrementalAICharge.POSSIBLE
    if IncrementalAICharge.UNKNOWN in {first, second}:
        return IncrementalAICharge.UNKNOWN
    return IncrementalAICharge.NONE


def _unknown_billing_disposition(
    reason: str,
    *,
    circuit_breaker_required: bool = True,
) -> BillingPostRunDisposition:
    return BillingPostRunDisposition(
        capacity_state=CapacityState.UNKNOWN,
        paid_capacity_consumed=PaidCapacityConsumed.UNKNOWN,
        incremental_ai_charge=IncrementalAICharge.UNKNOWN,
        quarantine_required=True,
        circuit_breaker_required=circuit_breaker_required,
        reasons=(reason,),
    )


def _incremental_api_charge(
    *,
    result: RunnerExecutionResult,
    preflight_assessment: BillingRouteAssessment,
    disposition: BillingPostRunDisposition,
    billing_matches: bool,
) -> str:
    """Return only the narrower API-charge axis, never an AI-cost inference."""

    if (
        not billing_matches
        or result.runner_id not in {"mock", "codex", "claude"}
        or preflight_assessment.route
        not in {
            BillingRoute.MOCK,
            BillingRoute.LOCAL_NON_AI,
            BillingRoute.SUBSCRIPTION_INCLUDED,
        }
    ):
        return "unknown"
    if preflight_assessment.route in {BillingRoute.MOCK, BillingRoute.LOCAL_NON_AI}:
        return "none"
    postflight = result.postflight_billing_assessment
    if not result.harness_process_started and result.live_model_execution_occurred is False:
        return "none"
    if postflight is None:
        return "unknown"
    if not isinstance(postflight, BillingRouteAssessment):
        return "unknown"
    if postflight.route in {
        BillingRoute.PURCHASED_PRODUCT_CREDIT,
        BillingRoute.SUBSCRIPTION_OVERAGE,
        BillingRoute.SUBSCRIPTION_INCLUDED,
    } and not any(
        reason
        in {
            "harness_execution_outcome_unknown",
            "harness_launch_outcome_unknown",
            "post_run_account_changed",
            "post_run_billing_disposition_inconsistent",
            "post_run_billing_evidence_unknown",
            "post_run_billing_identity_changed",
        }
        for reason in disposition.reasons
    ):
        return "none"
    return "unknown"


def _record_billing_outcome(
    state: SQLiteStateStore,
    *,
    run_id: str,
    profile_id: str | None,
    preflight_assessment: BillingRouteAssessment,
    postflight_assessment: BillingRouteAssessment | None,
    disposition: BillingPostRunDisposition,
    billing_matches: bool,
) -> None:
    if not isinstance(postflight_assessment, BillingRouteAssessment):
        postflight_assessment = None
    trusted_fingerprint = _safe_fingerprint(
        preflight_assessment.account_identity_fingerprint
    )
    state.append_billing_capacity_event(
        runner_id=preflight_assessment.runner_id,
        account_identity_fingerprint=trusted_fingerprint,
        profile_id=profile_id,
        run_id=run_id,
        capacity_state=disposition.capacity_state,
        reason_code=_capacity_reason(disposition),
    )
    if not disposition.circuit_breaker_required:
        return

    postflight_fingerprint = _safe_fingerprint(
        None
        if postflight_assessment is None
        else postflight_assessment.account_identity_fingerprint
    )
    scopes: list[tuple[str | None, str | None]] = [
        (trusted_fingerprint, profile_id),
        (trusted_fingerprint, None),
    ]
    if (
        not billing_matches
        or trusted_fingerprint is None
        or postflight_fingerprint is None
        or postflight_fingerprint != trusted_fingerprint
        or any(
            reason
            in {
                "harness_execution_outcome_unknown",
                "harness_launch_outcome_unknown",
                "post_run_account_changed",
                "post_run_billing_disposition_inconsistent",
                "post_run_billing_evidence_unknown",
                "post_run_billing_identity_changed",
            }
            for reason in disposition.reasons
        )
    ):
        scopes.extend(((None, profile_id), (None, None)))
    reason_code = _circuit_reason(disposition)
    for fingerprint, selected_profile_id in tuple(dict.fromkeys(scopes)):
        state.append_billing_circuit_event(
            runner_id=preflight_assessment.runner_id,
            account_identity_fingerprint=fingerprint,
            profile_id=selected_profile_id,
            run_id=run_id,
            state=CircuitBreakerState.OPEN,
            reason_code=reason_code,
        )


def _capacity_reason(disposition: BillingPostRunDisposition) -> str:
    if disposition.capacity_state is CapacityState.AVAILABLE:
        return "post_run_capacity_available"
    if disposition.capacity_state in {
        CapacityState.LIMIT_REACHED,
        CapacityState.BLOCKED_UNTIL_RESET,
    }:
        return "included_capacity_exhausted"
    if disposition.capacity_state is CapacityState.COOLDOWN:
        return "post_run_capacity_cooldown"
    return "post_run_billing_unknown"


def _circuit_reason(disposition: BillingPostRunDisposition) -> str:
    if disposition.paid_capacity_consumed is PaidCapacityConsumed.YES:
        return "post_run_paid_capacity_consumed"
    if disposition.incremental_ai_charge in {
        IncrementalAICharge.POSSIBLE,
        IncrementalAICharge.CONFIRMED,
    }:
        return "post_run_paid_route_possible"
    for reason in disposition.reasons:
        if reason in _BILLING_DISPOSITION_REASON_CODES:
            return reason
    return "post_run_billing_evidence_unknown"


def _safe_fingerprint(value: str | None) -> str | None:
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return None


def _safe_subscription_name(assessment: BillingRouteAssessment) -> str | None:
    allowed = {
        "ChatGPT": "ChatGPT",
        "Claude": "Claude",
    }
    return allowed.get(assessment.subscription_name or "")


def _fixture_path_for_kind(
    root: Path,
    task_path: Path,
    contract: TaskContract,
    kind: str,
) -> Path:
    candidates = [item for item in contract.inputs if item.kind == kind]
    if len(candidates) != 1 or candidates[0].fixture_path is None:
        raise ConfigurationError(f"task must define exactly one fixture for {kind!r}")
    return _contained_path(root, task_path.parent / candidates[0].fixture_path)


def _expectations_path(root: Path, task_path: Path, contract: TaskContract) -> Path:
    for criterion in contract.evaluation_criteria:
        fixture = criterion.parameters.get("expectations_fixture")
        if isinstance(fixture, str):
            return _contained_path(root, task_path.parent / fixture)
    return _project_path(root, DEFAULT_EXPECTATIONS)


def _project_path(root: Path, relative: Path) -> Path:
    return _contained_path(root, root / relative)


def _contained_path(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ConfigurationError(f"path escapes the project root: {candidate}") from exc
    return resolved


def _validate_run_identifier(run_id: str) -> None:
    if not run_id or len(run_id) > 160:
        raise ValidationError("run identifier must contain 1-160 characters")
    if any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in run_id):
        raise ValidationError("run identifier contains unsupported characters")


def _validate_profile_identifier(profile_id: str) -> None:
    if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 160:
        raise ValidationError("profile identifier must contain 1-160 characters")
    if any(
        character
        not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in profile_id
    ):
        raise ValidationError("profile identifier contains unsupported characters")


def _canonical_artifact_bytes(output: Any) -> bytes:
    try:
        encoded = json.dumps(
            output,
            sort_keys=True,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("accepted output could not be encoded as strict JSON") from exc
    return (encoded + "\n").encode("utf-8")


def _stage_artifact(path: Path, content: bytes) -> Path:
    """Durably stage content without exposing it at its final artifact path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ValidationError("artifact destination already exists")
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _promote_staged_artifact(staged_path: Path, artifact_path: Path) -> None:
    """Publish a staged file without overwriting an existing filesystem entry."""

    if artifact_path.exists() or artifact_path.is_symlink():
        raise ValidationError("artifact destination already exists")
    try:
        os.link(staged_path, artifact_path, follow_symlinks=False)
    except OSError as exc:
        raise ConfigurationError("staged artifact could not be published safely") from exc
    # The final path is now a hard link to the already-fsynced bytes. Failure to
    # remove the staging name does not invalidate the published artifact.
    try:
        staged_path.unlink()
    except OSError:
        pass


def _best_effort_terminal_status(
    state: SQLiteStateStore,
    run_id: str,
    *,
    status: RunStatus,
    phase: str,
) -> bool:
    """Append one terminal event when possible without masking the root failure."""

    try:
        if state.current_status(run_id) is not RunStatus.RUNNING:
            return False
        state.append_event(
            run_id,
            "status",
            {"phase": phase},
            status=status,
        )
    except BaseException:
        return False
    return True


def _best_effort_shadow_observation(
    state: SQLiteStateStore,
    run_id: str,
    builder: Callable[[], dict[str, Any]],
) -> bool:
    """Append non-authoritative evidence without changing legacy behavior."""

    try:
        payload = builder()
        state.append_event(run_id, "authorization_shadow_decision", payload)
    except Exception:
        return False
    return True


__all__ = [
    "PreparedTask",
    "TaskRunReport",
    "load_mock_chief_of_staff_output",
    "prepare_chief_of_staff",
    "run_chief_of_staff",
]
