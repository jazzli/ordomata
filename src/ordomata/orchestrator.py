"""Deterministic orchestration for the first controlled workflow.

The control plane owns task loading, context selection, permissions, state,
validation, and artifact promotion.  Runners receive an immutable prompt and an
isolated per-run workspace; a successful harness exit is never sufficient on
its own to publish an artifact.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Any
from uuid import uuid4

from .approval import ApprovalPolicy
from .admission_authorization import (
    TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
    TASK_ADMISSION_DECISION_EVENT_TYPE,
    TaskAdmissionAuthorization,
    assert_task_admission_authorized,
    build_task_admission_action_receipt,
    build_task_admission_failure_payload,
    evaluate_task_admission_authorization,
    task_admission_authorization_intent_digest,
)
from .artifact_filesystem import (
    ARTIFACT_ABSENT,
    ARTIFACT_MATCHES,
    ARTIFACT_UNVERIFIABLE,
    StagedArtifact,
    fsync_artifact_parent,
    publish_staged_artifact,
    published_artifact_state,
    remove_owned_published_artifact,
    stage_artifact,
)
from .authorization import ReceiptOutcome, canonical_digest
from .billing import (
    BillingPolicy,
    BillingPostRunDisposition,
    LIVE_RUN_EVIDENCE_MARGIN_SECONDS,
)
from .context import (
    ContextPack,
    LocalContextIndex,
    build_context_pack,
    load_source_documents,
    render_synthesis_prompt,
)
from .contracts import TaskContract, load_task_contract
from .dispatch_authorization import (
    MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
    MOCK_DISPATCH_DECISION_EVENT_TYPE,
    MockDispatchAuthorization,
    assert_mock_dispatch_authorized,
    assert_mock_dispatch_fresh_at_action_start,
    build_mock_dispatch_action_receipt,
    build_mock_dispatch_failure_payload,
    evaluate_mock_dispatch_authorization,
)
from .publication_authorization import (
    LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
    LocalCandidatePublicationAuthorization,
    assert_local_candidate_publication_authorized,
    build_local_candidate_publication_enforcement_receipt,
    build_local_candidate_publication_failure_payload,
    evaluate_local_candidate_publication_authorization,
)
from .errors import (
    AuthorizationBlocked,
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
from .execution_selection import (
    ExecutionSelection,
    TASK_EXECUTION_SELECTION_EVENT_TYPE,
    build_execution_selection,
    execution_profile_configuration_digest,
    task_routing_features_digest,
    validate_execution_selection_payload,
)
from .models import (
    AgentEvent,
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    CapacityState,
    CircuitBreakerState,
    IncrementalAICharge,
    PaidCapacityConsumed,
    PermissionClass,
    RunRequest,
    RunnerExecutionResult,
    RunStatus,
    UsageObservation,
)
from .paths import resolve_state_root
from .runners.base import AgentRunner, EventSink
from .runners.mock import MockRunner
from .redaction import contains_credential_material
from .routing import (
    ExecutionProfile,
    RuntimeProfileState,
    TaskRoutingFeatures,
    load_execution_profiles,
    runner_overrides_for_profile,
)
from .schema import parse_json_document
from .shadow_authorization import (
    build_local_candidate_publication_shadow_event,
    build_runner_model_dispatch_shadow_event,
    build_task_admission_shadow_event,
    task_authorization_intent_digest,
)
from .state import ArtifactRecord, SQLiteStateStore
from .task_evidence import (
    TASK_ATTEMPT_AUTHORIZATION_BINDING_EVENT_TYPE,
    TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
    artifact_record_digest,
    build_candidate_artifact_action_receipt,
    build_candidate_artifact_pre_effect_receipt,
    build_task_attempt_binding_event,
    build_task_execution_accounting,
    task_publication_billing_digest,
    task_publication_billing_projection,
    task_execution_mode,
    task_runner_version_reference,
)


DEFAULT_TASK = Path("tasks/chief-of-staff-lite.json")
DEFAULT_EXPECTATIONS = Path("fixtures/chief_of_staff/expectations.json")
DEFAULT_MOCK_OUTPUT = Path("fixtures/chief_of_staff/valid-output.json")
DEFAULT_PROFILE_PATH = Path("profiles/default.json")
DEFAULT_MOCK_PROFILE_ID = "mock.deterministic.local-draft"

_MOCK_RUNNER_INSTANCE_BOUNDARIES = frozenset(
    {
        "cancel",
        "detect_capabilities",
        "execute",
        "inspect_billing_route",
        "runner_id",
        "validate_environment",
    }
)
_CONTROLLER_MOCK_RUNNER_TYPE = MockRunner
_CONTROLLER_MOCK_RUNNER_CLASS_ATTRIBUTES = dict(vars(MockRunner))


def _is_controller_owned_mock_runner(runner: AgentRunner) -> bool:
    """Require the shipped class plus unchanged class/instance boundaries."""

    if type(runner) is not _CONTROLLER_MOCK_RUNNER_TYPE:
        return False
    try:
        instance_attributes = vars(runner)
        class_attributes = vars(_CONTROLLER_MOCK_RUNNER_TYPE)
    except TypeError:
        return False
    return bool(
        not _MOCK_RUNNER_INSTANCE_BOUNDARIES.intersection(instance_attributes)
        and set(class_attributes) == set(
            _CONTROLLER_MOCK_RUNNER_CLASS_ATTRIBUTES
        )
        and all(
            class_attributes[name] is expected
            for name, expected in (
                _CONTROLLER_MOCK_RUNNER_CLASS_ATTRIBUTES.items()
            )
        )
    )


async def _inspect_runner_billing_route(
    runner: AgentRunner,
) -> BillingRouteAssessment:
    """Invoke the runner billing boundary through one controller seam."""

    return await runner.inspect_billing_route()


async def _execute_runner(
    runner: AgentRunner,
    request: RunRequest,
    event_sink: EventSink,
) -> RunnerExecutionResult:
    """Invoke the runner effect boundary through one controller seam."""

    return await runner.execute(request, event_sink)


class _CandidateArtifactPublicationUncertain(ConfigurationError):
    """The local effect may exist without a complete durable audit chain."""

    def __init__(
        self,
        message: str,
        *,
        artifact_observed: bool = True,
    ) -> None:
        super().__init__(message)
        self.artifact_observed = artifact_observed


class _LocalCandidatePublicationFreshnessBlocked(AuthorizationBlocked):
    """A persisted publication permit stopped before its first mutation."""


@dataclass(frozen=True, slots=True)
class _LocalCandidatePublicationEnforcementContext:
    """Immutable upstream evidence for the exact mock publication PEP."""

    execution_selection_digest: str
    mock_dispatch_request_digest: str
    mock_dispatch_decision_digest: str
    mock_dispatch_action_receipt_digest: str
    mock_dispatch_succeeded: bool


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


def chief_of_staff_routing_features(
    prepared: PreparedTask,
    *,
    lane: str,
) -> TaskRoutingFeatures:
    """Return the controller-owned feature snapshot for this workflow lane."""

    if not isinstance(prepared, PreparedTask):
        raise ValidationError("prepared must be a PreparedTask")
    if lane == "mock":
        allowed_routes = frozenset({BillingRoute.MOCK})
        roles = frozenset({"test"})
    elif lane == "subscription":
        allowed_routes = frozenset({BillingRoute.SUBSCRIPTION_INCLUDED})
        roles = frozenset({"synthesis"})
    else:
        raise ConfigurationError(f"unsupported routing lane: {lane}")
    return TaskRoutingFeatures(
        task_kind="chief_of_staff",
        permission_class=prepared.contract.permission_class,
        required_capabilities=frozenset(
            {"structured_output", "local_draft", "isolated_workspace"}
        ),
        allowed_roles=roles,
        allowed_billing_routes=allowed_routes,
        context_bytes=prepared.context_pack.raw_bytes,
        risk=1,
    )


def _default_mock_execution_selection(
    root: Path,
    *,
    prepared: PreparedTask,
    run_id: str,
) -> tuple[ExecutionSelection, str, dict[str, Any]] | None:
    """Resolve the checked-in default profile when the project provides it.

    Projects created before versioned profiles remain compatible: absence of
    the profile document keeps their historical schema-v1 task binding.  A
    present but invalid profile document always fails closed.
    """

    profile_path = root / DEFAULT_PROFILE_PATH
    if not profile_path.exists():
        return None
    profiles = load_execution_profiles(profile_path)
    matches = [
        profile
        for profile in profiles
        if profile.profile_id == DEFAULT_MOCK_PROFILE_ID
    ]
    if len(matches) != 1 or matches[0].runner_id != "mock":
        raise ConfigurationError("default mock execution profile is unavailable")
    profile = matches[0]
    overrides = runner_overrides_for_profile(profile)
    evaluated_at = time.time()
    selection = build_execution_selection(
        run_id=run_id,
        selection_mode="controller_default",
        task=chief_of_staff_routing_features(prepared, lane="mock"),
        candidates=(
            RuntimeProfileState(
                profile=profile,
                billing_assessment=BillingRouteAssessment(
                    runner_id="mock",
                    route=BillingRoute.MOCK,
                    confidence=AssessmentConfidence.HIGH,
                ),
                available=True,
            ),
        ),
        task_definition_digest=prepared.contract.definition_hash,
        context_digest=prepared.context_pack.snapshot_hash,
        authorization_intent_digest=task_authorization_intent_digest(
            prepared.contract
        ),
        evaluated_at=evaluated_at,
    )
    return selection, profile.profile_id, overrides


def _assert_execution_selection_matches(
    selection: ExecutionSelection,
    *,
    prepared: PreparedTask,
    run_id: str,
    runner_id: str,
    profile_id: str,
    runner_overrides: Mapping[str, Any],
    project_root: Path,
    source_profiles: tuple[ExecutionProfile, ...],
) -> None:
    """Fail before state creation when selected and executable inputs drift."""

    lane = "mock" if runner_id == "mock" else "subscription"
    expected_task_features = task_routing_features_digest(
        chief_of_staff_routing_features(prepared, lane=lane)
    )
    expected_profile_ref = canonical_digest({"profile_id": profile_id})
    expected_overrides_digest = canonical_digest(dict(runner_overrides))
    if not source_profiles or any(
        not isinstance(profile, ExecutionProfile) for profile in source_profiles
    ):
        raise ValidationError("execution selection source profiles are invalid")
    selected_sources = [
        profile for profile in source_profiles if profile.profile_id == profile_id
    ]
    if len(selected_sources) != 1:
        raise ValidationError("execution selection source profile is invalid")
    source_profile = selected_sources[0]
    expected_profile_version_ref = canonical_digest(
        {"profile_version": source_profile.version}
    )
    expected_profile_configuration_digest = (
        execution_profile_configuration_digest(source_profile)
    )
    configured_profiles = load_execution_profiles(
        project_root / DEFAULT_PROFILE_PATH
    )
    configured_by_id = {
        profile.profile_id: profile for profile in configured_profiles
    }
    configured_matches = [configured_by_id.get(profile_id)]
    if (
        configured_matches[0] is None
        or any(
            configured_by_id.get(profile.profile_id) is None
            or execution_profile_configuration_digest(
                configured_by_id[profile.profile_id]
            )
            != execution_profile_configuration_digest(profile)
            for profile in source_profiles
        )
        or execution_profile_configuration_digest(configured_matches[0])
        != expected_profile_configuration_digest
        or runner_overrides_for_profile(source_profile)
        != dict(runner_overrides)
    ):
        raise ValidationError(
            "execution selection does not match the configured profile"
        )
    expected_definition_digest = prepared.contract.definition_hash
    if not expected_definition_digest.startswith("sha256:"):
        expected_definition_digest = f"sha256:{expected_definition_digest}"
    if (
        selection.run_ref != canonical_digest({"run_id": run_id})
        or selection.task_features_digest != expected_task_features
        or selection.task_definition_digest != expected_definition_digest
        or selection.context_digest != prepared.context_pack.snapshot_hash
        or selection.authorization_intent_digest
        != task_authorization_intent_digest(prepared.contract)
        or selection.permission_class != int(prepared.contract.permission_class)
        or selection.selected_profile_ref != expected_profile_ref
        or selection.selected_profile_id != profile_id
        or selection.selected_profile_version_ref
        != expected_profile_version_ref
        or selection.selected_profile_configuration_digest
        != expected_profile_configuration_digest
        or selection.selected_runner_id != runner_id
        or selection.selected_runner_overrides_digest
        != expected_overrides_digest
    ):
        raise ValidationError(
            "execution selection does not match the immutable attempt inputs"
        )
    if (
        runner_id != "mock"
        and selection.required_valid_until
        < selection.evaluated_at
        + prepared.contract.timeout_seconds
        + LIVE_RUN_EVIDENCE_MARGIN_SECONDS
    ):
        raise ValidationError(
            "execution selection billing evidence horizon is insufficient"
        )


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
    prepared_task: PreparedTask | None = None,
    execution_selection: ExecutionSelection | None = None,
) -> TaskRunReport:
    """Execute one bounded Chief of Staff Lite attempt.

    Passing no runner selects the deterministic mock.  Live runners remain
    subject to their own high-confidence subscription checks and the exact
    ``ORDOMATA_ALLOW_SUBSCRIPTION_RUNS=1`` gate.
    """

    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ConfigurationError(f"project root is not a directory: {root}")
    if prepared_task is None:
        prepared = prepare_chief_of_staff(
            root, operator_instructions=operator_instructions
        )
    else:
        if not isinstance(prepared_task, PreparedTask):
            raise ValidationError("prepared_task must be a PreparedTask")
        prepared = prepared_task
        if not prepared.context_pack.verify_snapshot_hash():
            raise ValidationError("prepared task context snapshot is invalid")
    approval_policy = ApprovalPolicy()
    approval_policy.assert_executable(prepared.contract.permission_class)
    legacy_executable = approval_policy.classify(
        prepared.contract.permission_class
    ).executable_now

    selected_run_id = run_id or f"cos-{uuid4().hex}"
    _validate_run_identifier(selected_run_id)
    selected_profile_id = profile_id
    if selected_profile_id is not None:
        _validate_profile_identifier(selected_profile_id)

    active_runner: AgentRunner
    default_runner_selected = runner is None
    if runner is None:
        active_runner = MockRunner(
            output=load_mock_chief_of_staff_output(root, prepared)
        )
    else:
        active_runner = runner
    initial_controller_owned_mock_runner = _is_controller_owned_mock_runner(
        active_runner
    )
    if (
        type(active_runner) is _CONTROLLER_MOCK_RUNNER_TYPE
        and not initial_controller_owned_mock_runner
    ):
        raise ValidationError(
            "mock execution requires the unchanged controller-owned mock runner"
        )
    active_runner_id = (
        "mock"
        if initial_controller_owned_mock_runner
        else active_runner.runner_id
    )

    selected_runner_overrides = dict(runner_overrides or {})
    selected_execution = execution_selection
    selected_source_billing_assessment: BillingRouteAssessment | None = None
    if selected_execution is None and default_runner_selected:
        default_selection = _default_mock_execution_selection(
            root,
            prepared=prepared,
            run_id=selected_run_id,
        )
        if default_selection is not None:
            (
                selected_execution,
                selected_profile_id,
                selected_runner_overrides,
            ) = default_selection
    profile_catalog_present = (root / DEFAULT_PROFILE_PATH).exists()
    if selected_execution is None and profile_catalog_present:
        raise ValidationError(
            "configured profile execution requires selection evidence"
        )
    if selected_execution is not None:
        validated_execution = validate_execution_selection_payload(
            selected_execution.to_event_payload()
        )
        rebuilt_execution = selected_execution.rebuild_from_controller_sources()
        if (
            rebuilt_execution.to_event_payload()
            != validated_execution.to_event_payload()
        ):
            raise ValidationError(
                "execution selection does not match controller-owned sources"
            )
        selected_execution = validated_execution
        if selected_profile_id is None:
            raise ValidationError(
                "execution selection requires an explicit profile identity"
            )
        _assert_execution_selection_matches(
            selected_execution,
            prepared=prepared,
            run_id=selected_run_id,
            runner_id=active_runner_id,
            profile_id=selected_profile_id,
            runner_overrides=selected_runner_overrides,
            project_root=root,
            source_profiles=rebuilt_execution.controller_source_profiles,
        )
        selected_source_billing_assessment = (
            rebuilt_execution.selected_source_billing_assessment
        )
    if (
        active_runner_id == "mock"
        and selected_execution is not None
        and not _is_controller_owned_mock_runner(active_runner)
    ):
        raise ValidationError(
            "selected mock execution requires the controller-owned mock runner"
        )
    enforce_mock_dispatch = (
        initial_controller_owned_mock_runner
        and selected_execution is not None
    )
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
        runner_overrides=selected_runner_overrides,
    )
    prompt_digest = (
        "sha256:" + hashlib.sha256(prepared.prompt.encode("utf-8")).hexdigest()
    )
    resolved_task_authorization_intent_digest = (
        task_authorization_intent_digest(prepared.contract)
    )

    with SQLiteStateStore(selected_state_path) as state:
        state.create_run_from_request(
            request,
            runner_id=active_runner_id,
            context_digest=prepared.context_pack.snapshot_hash,
        )
        execution_selection_digest: str | None = None
        if selected_execution is not None:
            execution_selection_payload = selected_execution.to_event_payload()
            execution_selection_digest = selected_execution.selection_digest
            try:
                _append_required_event(
                    state,
                    selected_run_id,
                    TASK_EXECUTION_SELECTION_EVENT_TYPE,
                    execution_selection_payload,
                    event_id=execution_selection_digest,
                )
                _require_exact_event_readback(
                    state,
                    selected_run_id,
                    TASK_EXECUTION_SELECTION_EVENT_TYPE,
                    execution_selection_payload,
                    event_id=execution_selection_digest,
                )
            except BaseException as selection_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=(
                        RunStatus.CANCELLED
                        if not isinstance(selection_error, Exception)
                        else RunStatus.FAILED
                    ),
                    phase="execution_selection",
                )
                raise
        task_binding = build_task_attempt_binding_event(
            contract=prepared.contract,
            request=request,
            runner_id=active_runner_id,
            context_digest=prepared.context_pack.snapshot_hash,
            prompt_digest=prompt_digest,
            project_root=str(root),
            profile_id=selected_profile_id,
            authorization_intent_digest=(
                resolved_task_authorization_intent_digest
            ),
            execution_selection_digest=execution_selection_digest,
            profile_version_ref=(
                None
                if selected_execution is None
                else selected_execution.selected_profile_version_ref
            ),
            profile_configuration_digest=(
                None
                if selected_execution is None
                else selected_execution.selected_profile_configuration_digest
            ),
            enforce_mock_dispatch=enforce_mock_dispatch,
            enforce_local_candidate_publication=enforce_mock_dispatch,
            enforce_task_admission=enforce_mock_dispatch,
        )
        task_binding_digest = task_binding["binding_digest"]
        assert isinstance(task_binding_digest, str)
        try:
            _append_required_event(
                state,
                selected_run_id,
                TASK_ATTEMPT_AUTHORIZATION_BINDING_EVENT_TYPE,
                task_binding,
                event_id=task_binding_digest,
            )
            _require_exact_event_readback(
                state,
                selected_run_id,
                TASK_ATTEMPT_AUTHORIZATION_BINDING_EVENT_TYPE,
                task_binding,
                event_id=task_binding_digest,
            )
        except BaseException as binding_error:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=(
                    RunStatus.CANCELLED
                    if not isinstance(binding_error, Exception)
                    else RunStatus.FAILED
                ),
                phase="task_attempt_binding",
            )
            raise
        task_admission_authorization: TaskAdmissionAuthorization | None = None
        if enforce_mock_dispatch:
            assert selected_execution is not None
            assert execution_selection_digest is not None
            assert selected_profile_id is not None
            controller_owned_mock_runner = _is_controller_owned_mock_runner(
                active_runner
            )
            admission_run_ref = canonical_digest(
                {"run_id": selected_run_id}
            )
            admission_profile_ref = canonical_digest(
                {"profile_id": selected_profile_id}
            )
            admission_profile_version_ref = (
                selected_execution.selected_profile_version_ref
            )
            admission_profile_configuration_digest = (
                selected_execution.selected_profile_configuration_digest
            )
            admission_pre_run_approval_required = (
                prepared.contract.approval_requirements.required_before_run
            )
            admission_pre_run_approver_ref = canonical_digest(
                {
                    "approver": (
                        prepared.contract.approval_requirements.approver
                    )
                }
            )
            admission_evaluated_at = time.time()
            admission_evaluation_error: BaseException | None = None
            admission_intent_digest = ""
            try:
                admission_intent_digest = (
                    task_admission_authorization_intent_digest(
                        prepared.contract
                    )
                )
                task_admission_authorization = (
                    evaluate_task_admission_authorization(
                        contract=prepared.contract,
                        request=request,
                        runner_id=active_runner_id,
                        profile_id=selected_profile_id,
                        project_root=root,
                        controller_owned_mock_runner=(
                            controller_owned_mock_runner
                        ),
                        task_attempt_binding_digest=task_binding_digest,
                        execution_selection_digest=(
                            execution_selection_digest
                        ),
                        profile_version_ref=admission_profile_version_ref,
                        profile_configuration_digest=(
                            admission_profile_configuration_digest
                        ),
                        context_digest=(
                            prepared.context_pack.snapshot_hash
                        ),
                        prompt_digest=prompt_digest,
                        evaluated_at=admission_evaluated_at,
                        legacy_executable=legacy_executable,
                    )
                )
                admission_payload = (
                    task_admission_authorization.to_event_payload()
                )
            except Exception:
                task_admission_authorization = None
                admission_payload = build_task_admission_failure_payload(
                    run_ref=admission_run_ref,
                    profile_ref=admission_profile_ref,
                    task_attempt_binding_digest=task_binding_digest,
                    execution_selection_digest=execution_selection_digest,
                    profile_version_ref=admission_profile_version_ref,
                    profile_configuration_digest=(
                        admission_profile_configuration_digest
                    ),
                    context_digest=prepared.context_pack.snapshot_hash,
                    prompt_digest=prompt_digest,
                    task_authorization_intent_digest=(
                        resolved_task_authorization_intent_digest
                    ),
                    admission_authorization_intent_digest=(
                        admission_intent_digest
                    ),
                    requested_permission_class=request.permission_class,
                    controller_owned_mock_runner=(
                        controller_owned_mock_runner
                    ),
                    legacy_executable=legacy_executable,
                    pre_run_approval_required=(
                        admission_pre_run_approval_required
                    ),
                    pre_run_approver_ref=admission_pre_run_approver_ref,
                    evaluated_at=admission_evaluated_at,
                )
            except BaseException as cancellation_error:
                task_admission_authorization = None
                admission_evaluation_error = cancellation_error
                admission_payload = build_task_admission_failure_payload(
                    run_ref=admission_run_ref,
                    profile_ref=admission_profile_ref,
                    task_attempt_binding_digest=task_binding_digest,
                    execution_selection_digest=execution_selection_digest,
                    profile_version_ref=admission_profile_version_ref,
                    profile_configuration_digest=(
                        admission_profile_configuration_digest
                    ),
                    context_digest=prepared.context_pack.snapshot_hash,
                    prompt_digest=prompt_digest,
                    task_authorization_intent_digest=(
                        resolved_task_authorization_intent_digest
                    ),
                    admission_authorization_intent_digest=(
                        admission_intent_digest
                    ),
                    requested_permission_class=request.permission_class,
                    controller_owned_mock_runner=(
                        controller_owned_mock_runner
                    ),
                    legacy_executable=legacy_executable,
                    pre_run_approval_required=(
                        admission_pre_run_approval_required
                    ),
                    pre_run_approver_ref=admission_pre_run_approver_ref,
                    evaluated_at=admission_evaluated_at,
                )
            admission_event_id = _controller_event_id(
                selected_run_id,
                TASK_ADMISSION_DECISION_EVENT_TYPE,
                admission_payload,
            )
            try:
                _append_required_event(
                    state,
                    selected_run_id,
                    TASK_ADMISSION_DECISION_EVENT_TYPE,
                    admission_payload,
                    event_id=admission_event_id,
                )
                _require_exact_event_readback(
                    state,
                    selected_run_id,
                    TASK_ADMISSION_DECISION_EVENT_TYPE,
                    admission_payload,
                    event_id=admission_event_id,
                )
            except BaseException as admission_evidence_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=(
                        RunStatus.CANCELLED
                        if admission_evaluation_error is not None
                        or not isinstance(
                            admission_evidence_error,
                            Exception,
                        )
                        else RunStatus.FAILED
                    ),
                    phase="task_admission_authorization_persistence",
                )
                if admission_evaluation_error is not None:
                    raise admission_evaluation_error from (
                        admission_evidence_error
                    )
                raise
            if admission_evaluation_error is not None:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=RunStatus.CANCELLED,
                    phase="task_admission_authorization_evaluation",
                )
                raise admission_evaluation_error
            if (
                task_admission_authorization is None
                or not task_admission_authorization.authorized_at_evaluation
            ):
                _append_terminal_event(
                    state,
                    selected_run_id,
                    {"phase": "task_admission_authorization"},
                    status=RunStatus.BLOCKED,
                )
                raise AuthorizationBlocked(
                    "task admission requires a fresh exact Class 1 authorization permit"
                )

            admission_action_started_at = time.time()
            try:
                assert_task_admission_authorized(
                    task_admission_authorization,
                    action_started_at=admission_action_started_at,
                    persisted_payload=admission_payload,
                    contract=prepared.contract,
                    request=request,
                    runner_id=active_runner_id,
                    profile_id=selected_profile_id,
                    project_root=root,
                    controller_owned_mock_runner=(
                        controller_owned_mock_runner
                    ),
                    task_attempt_binding_digest=task_binding_digest,
                    execution_selection_digest=execution_selection_digest,
                    profile_version_ref=admission_profile_version_ref,
                    profile_configuration_digest=(
                        admission_profile_configuration_digest
                    ),
                    context_digest=prepared.context_pack.snapshot_hash,
                    prompt_digest=prompt_digest,
                    legacy_executable=legacy_executable,
                )
                admission_receipt_payload = (
                    build_task_admission_action_receipt(
                        authorization=task_admission_authorization,
                        action_started_at=admission_action_started_at,
                        completed_at=time.time(),
                    )
                )
            except AuthorizationBlocked:
                _append_terminal_event(
                    state,
                    selected_run_id,
                    {
                        "phase": (
                            "task_admission_authorization_freshness"
                        )
                    },
                    status=RunStatus.BLOCKED,
                )
                raise
            except BaseException as admission_receipt_build_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=(
                        RunStatus.CANCELLED
                        if not isinstance(
                            admission_receipt_build_error,
                            Exception,
                        )
                        else RunStatus.FAILED
                    ),
                    phase="task_admission_action_receipt_persistence",
                )
                raise
            admission_receipt = admission_receipt_payload.get("receipt")
            admission_receipt_id = (
                admission_receipt.get("receipt_id")
                if isinstance(admission_receipt, Mapping)
                else None
            )
            if not isinstance(admission_receipt_id, str):
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=RunStatus.FAILED,
                    phase="task_admission_action_receipt_persistence",
                )
                raise ValidationError(
                    "task admission action receipt identifier is missing"
                )
            try:
                _append_required_event(
                    state,
                    selected_run_id,
                    TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
                    admission_receipt_payload,
                    event_id=admission_receipt_id,
                )
                _require_exact_event_readback(
                    state,
                    selected_run_id,
                    TASK_ADMISSION_ACTION_RECEIPT_EVENT_TYPE,
                    admission_receipt_payload,
                    event_id=admission_receipt_id,
                )
            except BaseException as admission_receipt_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=(
                        RunStatus.CANCELLED
                        if not isinstance(
                            admission_receipt_error,
                            Exception,
                        )
                        else RunStatus.FAILED
                    ),
                    phase="task_admission_action_receipt_persistence",
                )
                raise
        _best_effort_shadow_observation(
            state,
            selected_run_id,
            lambda: build_task_admission_shadow_event(
                contract=prepared.contract,
                run_id=selected_run_id,
                runner_id=active_runner_id,
                profile_id=selected_profile_id,
                context_digest=prepared.context_pack.snapshot_hash,
                prompt_digest=prompt_digest,
                project_root=root,
                task_attempt_binding_digest=task_binding_digest,
                execution_selection_digest=execution_selection_digest,
                evaluated_at=time.time(),
                legacy_executable=legacy_executable,
            ),
        )
        if (
            enforce_mock_dispatch
            and not _is_controller_owned_mock_runner(active_runner)
        ):
            _append_terminal_event(
                state,
                selected_run_id,
                {"phase": "mock_dispatch_authorization_freshness"},
                status=RunStatus.BLOCKED,
            )
            raise AuthorizationBlocked(
                "mock dispatch requires the unchanged controller-owned runner"
            )
        try:
            preflight_assessment = await _inspect_runner_billing_route(
                active_runner
            )
            preflight_checked_at = time.time()
            if (
                selected_execution is not None
                and active_runner_id != "mock"
                and selected_execution.required_valid_until
                < preflight_checked_at + request.timeout_seconds
            ):
                raise BillingRouteBlocked(
                    "execution selection billing horizon elapsed before dispatch"
                )
            _assert_runner_billing_route(
                active_runner_id,
                preflight_assessment,
                now=preflight_checked_at,
                required_valid_until=(
                    None
                    if selected_execution is None
                    else selected_execution.required_valid_until
                ),
            )
            if (
                selected_source_billing_assessment is not None
                and not _billing_assessments_match(
                    selected_source_billing_assessment,
                    preflight_assessment,
                )
            ):
                raise BillingRouteBlocked(
                    "fresh billing evidence does not match execution selection"
                )
        except OrdomataError:
            _append_terminal_event(
                state,
                selected_run_id,
                {"phase": "billing_preflight"},
                status=RunStatus.BLOCKED,
            )
            raise
        except BaseException:
            _append_terminal_event(
                state,
                selected_run_id,
                {"phase": "billing_preflight"},
                status=RunStatus.FAILED,
            )
            raise
        billing_metadata = _billing_metadata(preflight_assessment)
        billing_event_id = _controller_event_id(
            selected_run_id,
            "billing_assessment",
            billing_metadata,
        )
        try:
            _append_required_event(
                state,
                selected_run_id,
                "billing_assessment",
                billing_metadata,
                event_id=billing_event_id,
            )
            if enforce_mock_dispatch:
                _require_exact_event_readback(
                    state,
                    selected_run_id,
                    "billing_assessment",
                    billing_metadata,
                    event_id=billing_event_id,
                )
        except BaseException as billing_evidence_error:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=(
                    RunStatus.CANCELLED
                    if not isinstance(billing_evidence_error, Exception)
                    else RunStatus.FAILED
                ),
                phase="billing_assessment_persistence",
            )
            raise
        mock_dispatch_authorization: MockDispatchAuthorization | None = None
        mock_dispatch_authorization_payload: dict[str, Any] | None = None
        mock_dispatch_authorization_event_id: str | None = None
        mock_dispatch_action_started_at: float | None = None
        mock_dispatch_action_receipt_payload: dict[str, Any] | None = None
        if enforce_mock_dispatch:
            assert execution_selection_digest is not None
            assert selected_profile_id is not None
            authorization_evaluated_at = time.time()
            authorization_evaluation_error: BaseException | None = None
            try:
                if not _is_controller_owned_mock_runner(active_runner):
                    raise ValidationError(
                        "mock dispatch requires the controller-owned mock runner"
                    )
                mock_dispatch_authorization = (
                    evaluate_mock_dispatch_authorization(
                        contract=prepared.contract,
                        request=request,
                        runner_id=active_runner_id,
                        profile_id=selected_profile_id,
                        project_root=root,
                        task_attempt_binding_digest=task_binding_digest,
                        execution_selection_digest=(
                            execution_selection_digest
                        ),
                        context_digest=prepared.context_pack.snapshot_hash,
                        prompt_digest=prompt_digest,
                        billing_assessment=preflight_assessment,
                        billing_assessment_payload=billing_metadata,
                        billing_assessment_digest=billing_metadata[
                            "assessment_digest"
                        ],
                        evaluated_at=authorization_evaluated_at,
                        legacy_executable=legacy_executable,
                    )
                )
                mock_dispatch_authorization_payload = (
                    mock_dispatch_authorization.to_event_payload()
                )
            except Exception:
                mock_dispatch_authorization = None
                mock_dispatch_authorization_payload = (
                    build_mock_dispatch_failure_payload(
                        task_attempt_binding_digest=task_binding_digest,
                        execution_selection_digest=(
                            execution_selection_digest
                        ),
                        billing_assessment_digest=billing_metadata[
                            "assessment_digest"
                        ],
                        task_authorization_intent_digest=(
                            resolved_task_authorization_intent_digest
                        ),
                        requested_permission_class=request.permission_class,
                        legacy_executable=legacy_executable,
                        evaluated_at=authorization_evaluated_at,
                    )
                )
            except BaseException as cancellation_error:
                authorization_evaluation_error = cancellation_error
                mock_dispatch_authorization_payload = (
                    build_mock_dispatch_failure_payload(
                        task_attempt_binding_digest=task_binding_digest,
                        execution_selection_digest=(
                            execution_selection_digest
                        ),
                        billing_assessment_digest=billing_metadata[
                            "assessment_digest"
                        ],
                        task_authorization_intent_digest=(
                            resolved_task_authorization_intent_digest
                        ),
                        requested_permission_class=request.permission_class,
                        legacy_executable=legacy_executable,
                        evaluated_at=authorization_evaluated_at,
                    )
                )
            mock_dispatch_authorization_event_id = _controller_event_id(
                selected_run_id,
                MOCK_DISPATCH_DECISION_EVENT_TYPE,
                mock_dispatch_authorization_payload,
            )
            try:
                _append_required_event(
                    state,
                    selected_run_id,
                    MOCK_DISPATCH_DECISION_EVENT_TYPE,
                    mock_dispatch_authorization_payload,
                    event_id=mock_dispatch_authorization_event_id,
                )
                _require_exact_event_readback(
                    state,
                    selected_run_id,
                    MOCK_DISPATCH_DECISION_EVENT_TYPE,
                    mock_dispatch_authorization_payload,
                    event_id=mock_dispatch_authorization_event_id,
                )
            except BaseException as authorization_evidence_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=(
                        RunStatus.CANCELLED
                        if authorization_evaluation_error is not None
                        or not isinstance(
                            authorization_evidence_error,
                            Exception,
                        )
                        else RunStatus.FAILED
                    ),
                    phase="mock_dispatch_authorization_persistence",
                )
                if authorization_evaluation_error is not None:
                    raise authorization_evaluation_error from (
                        authorization_evidence_error
                    )
                raise
            if authorization_evaluation_error is not None:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=RunStatus.CANCELLED,
                    phase="mock_dispatch_authorization_evaluation",
                )
                raise authorization_evaluation_error
            if (
                mock_dispatch_authorization is None
                or not mock_dispatch_authorization.authorized_at_evaluation
            ):
                _append_terminal_event(
                    state,
                    selected_run_id,
                    {"phase": "mock_dispatch_authorization"},
                    status=RunStatus.BLOCKED,
                )
                raise AuthorizationBlocked(
                    "mock dispatch requires a fresh exact Class 0/1 authorization permit"
                )

        def require_current_mock_dispatch_authorization(
            *,
            action_started_at: float,
        ) -> None:
            if (
                mock_dispatch_authorization is None
                or mock_dispatch_authorization_payload is None
                or mock_dispatch_authorization_event_id is None
                or execution_selection_digest is None
                or selected_profile_id is None
            ):
                raise AuthorizationBlocked(
                    "mock dispatch requires an exact persisted authorization permit"
                )
            _require_exact_event_readback(
                state,
                selected_run_id,
                MOCK_DISPATCH_DECISION_EVENT_TYPE,
                mock_dispatch_authorization_payload,
                event_id=mock_dispatch_authorization_event_id,
            )
            assert_mock_dispatch_authorized(
                mock_dispatch_authorization,
                action_started_at=action_started_at,
                persisted_payload=mock_dispatch_authorization_payload,
                contract=prepared.contract,
                request=request,
                runner_id=active_runner_id,
                profile_id=selected_profile_id,
                project_root=root,
                controller_owned_mock_runner=(
                    _is_controller_owned_mock_runner(active_runner)
                ),
                task_attempt_binding_digest=task_binding_digest,
                execution_selection_digest=execution_selection_digest,
                context_digest=prepared.context_pack.snapshot_hash,
                prompt_digest=prompt_digest,
                billing_assessment=preflight_assessment,
                billing_assessment_payload=billing_metadata,
                billing_assessment_digest=billing_metadata[
                    "assessment_digest"
                ],
                legacy_executable=legacy_executable,
            )

        if mock_dispatch_authorization is not None:
            try:
                require_current_mock_dispatch_authorization(
                    action_started_at=time.time(),
                )
            except AuthorizationBlocked:
                _append_terminal_event(
                    state,
                    selected_run_id,
                    {"phase": "mock_dispatch_authorization_freshness"},
                    status=RunStatus.BLOCKED,
                )
                raise
            except BaseException as freshness_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=(
                        RunStatus.CANCELLED
                        if not isinstance(freshness_error, Exception)
                        else RunStatus.FAILED
                    ),
                    phase="mock_dispatch_authorization_freshness",
                )
                raise
        running_payload = {"phase": "runner_execution"}
        running_event_id = _controller_event_id(
            selected_run_id,
            "status",
            running_payload,
            status=RunStatus.RUNNING,
        )
        try:
            _append_required_event(
                state,
                selected_run_id,
                "status",
                running_payload,
                event_id=running_event_id,
                status=RunStatus.RUNNING,
            )
            if enforce_mock_dispatch:
                _require_exact_event_readback(
                    state,
                    selected_run_id,
                    "status",
                    running_payload,
                    event_id=running_event_id,
                    status=RunStatus.RUNNING,
                )
        except BaseException as running_evidence_error:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=(
                    RunStatus.CANCELLED
                    if not isinstance(running_evidence_error, Exception)
                    else RunStatus.FAILED
                ),
                phase="runner_execution_transition",
            )
            raise
        _best_effort_shadow_observation(
            state,
            selected_run_id,
            lambda: build_runner_model_dispatch_shadow_event(
                contract=prepared.contract,
                run_id=selected_run_id,
                runner_id=active_runner_id,
                profile_id=selected_profile_id,
                context_digest=prepared.context_pack.snapshot_hash,
                prompt_digest=prompt_digest,
                project_root=root,
                task_attempt_binding_digest=task_binding_digest,
                execution_selection_digest=execution_selection_digest,
                runner_overrides=request.runner_overrides,
                timeout_seconds=request.timeout_seconds,
                attempt=request.attempt,
                billing_assessment=preflight_assessment,
                billing_assessment_digest=billing_metadata[
                    "assessment_digest"
                ],
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

        if mock_dispatch_authorization is not None:
            try:
                require_current_mock_dispatch_authorization(
                    action_started_at=time.time(),
                )
                mock_dispatch_action_started_at = time.time()
                assert_mock_dispatch_fresh_at_action_start(
                    mock_dispatch_authorization,
                    action_started_at=mock_dispatch_action_started_at,
                )
            except AuthorizationBlocked:
                _append_terminal_event(
                    state,
                    selected_run_id,
                    {"phase": "mock_dispatch_authorization_freshness"},
                    status=RunStatus.BLOCKED,
                )
                raise
            except BaseException as freshness_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=(
                        RunStatus.CANCELLED
                        if not isinstance(freshness_error, Exception)
                        else RunStatus.FAILED
                    ),
                    phase="mock_dispatch_authorization_freshness",
                )
                raise

        try:
            result = await _execute_runner(
                active_runner,
                request,
                event_sink,
            )
        except BaseException as execution_error:
            if (
                mock_dispatch_authorization is not None
                and mock_dispatch_action_started_at is not None
            ):
                try:
                    _append_mock_dispatch_action_receipt(
                        state,
                        run_id=selected_run_id,
                        authorization=mock_dispatch_authorization,
                        contract=prepared.contract,
                        action_started_at=mock_dispatch_action_started_at,
                        outcome=(
                            ReceiptOutcome.FAILED
                            if isinstance(execution_error, Exception)
                            else ReceiptOutcome.CANCELLED
                        ),
                        result_digest=None,
                    )
                except BaseException as receipt_error:
                    _best_effort_terminal_status(
                        state,
                        selected_run_id,
                        status=RunStatus.QUARANTINED,
                        phase="mock_dispatch_action_receipt",
                    )
                    raise receipt_error from execution_error
            if isinstance(execution_error, OrdomataError):
                _append_terminal_event(
                    state,
                    selected_run_id,
                    {"phase": "preflight_or_execution"},
                    status=RunStatus.BLOCKED,
                )
                raise
            billing_failure = (
                preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
            )
            if billing_failure:
                _record_billing_outcome(
                    state,
                    run_id=selected_run_id,
                    profile_id=selected_profile_id,
                    preflight_assessment=preflight_assessment,
                    postflight_assessment=None,
                    disposition=_unknown_billing_disposition(
                        "harness_execution_outcome_unknown"
                    ),
                    billing_matches=False,
                )
            _append_terminal_event(
                state,
                selected_run_id,
                {"phase": "execution"},
                status=(
                    RunStatus.QUARANTINED
                    if billing_failure
                    else RunStatus.CANCELLED
                    if not isinstance(execution_error, Exception)
                    else RunStatus.FAILED
                ),
            )
            raise

        if (
            mock_dispatch_authorization is not None
            and mock_dispatch_action_started_at is not None
        ):
            mock_dispatch_result_valid = _mock_dispatch_result_is_valid(
                result,
                request=request,
                preflight_assessment=preflight_assessment,
                runner_event_count=event_count,
            )
            try:
                mock_dispatch_action_receipt_payload = (
                    _append_mock_dispatch_action_receipt(
                        state,
                        run_id=selected_run_id,
                        authorization=mock_dispatch_authorization,
                        contract=prepared.contract,
                        action_started_at=mock_dispatch_action_started_at,
                        outcome=_mock_dispatch_receipt_outcome(
                            result,
                            result_valid=mock_dispatch_result_valid,
                        ),
                        result_digest=(
                            _mock_dispatch_result_digest(
                                result,
                                runner_event_count=event_count,
                            )
                            if mock_dispatch_result_valid
                            else None
                        ),
                    )
                )
            except BaseException as receipt_error:
                _best_effort_terminal_status(
                    state,
                    selected_run_id,
                    status=RunStatus.QUARANTINED,
                    phase="mock_dispatch_action_receipt",
                )
                raise

        publication_enforcement_context: (
            _LocalCandidatePublicationEnforcementContext | None
        ) = None
        try:
            if enforce_mock_dispatch:
                if (
                    mock_dispatch_authorization is None
                    or mock_dispatch_action_receipt_payload is None
                ):
                    raise ValidationError(
                        "mock publication enforcement context is unavailable"
                    )
                dispatch_receipt = mock_dispatch_action_receipt_payload.get(
                    "receipt"
                )
                dispatch_receipt_digest = (
                    mock_dispatch_action_receipt_payload.get("receipt_digest")
                )
                if not isinstance(
                    dispatch_receipt,
                    Mapping,
                ) or not isinstance(dispatch_receipt_digest, str):
                    raise ValidationError(
                        "mock publication dispatch receipt is invalid"
                    )
                publication_enforcement_context = (
                    _LocalCandidatePublicationEnforcementContext(
                        execution_selection_digest=(
                            mock_dispatch_authorization.execution_selection_digest
                        ),
                        mock_dispatch_request_digest=(
                            mock_dispatch_authorization.request.digest
                        ),
                        mock_dispatch_decision_digest=(
                            mock_dispatch_authorization.decision.digest
                        ),
                        mock_dispatch_action_receipt_digest=(
                            dispatch_receipt_digest
                        ),
                        mock_dispatch_succeeded=(
                            dispatch_receipt.get("outcome")
                            == ReceiptOutcome.SUCCEEDED.value
                        ),
                    )
                )
        except BaseException:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=RunStatus.QUARANTINED,
                phase="mock_dispatch_action_receipt",
            )
            raise

        if not isinstance(result, RunnerExecutionResult):
            if preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED:
                _record_billing_outcome(
                    state,
                    run_id=selected_run_id,
                    profile_id=selected_profile_id,
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
                expected_runner_id=active_runner_id,
                profile_id=selected_profile_id,
                legacy_executable=legacy_executable,
                task_attempt_binding_digest=task_binding_digest,
                task_authorization_intent_digest=(
                    resolved_task_authorization_intent_digest
                ),
                publication_enforcement_context=(
                    publication_enforcement_context
                ),
            )
        except _LocalCandidatePublicationFreshnessBlocked:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=RunStatus.BLOCKED,
                phase="local_candidate_publication_authorization_freshness",
            )
            raise
        except AuthorizationBlocked:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=RunStatus.BLOCKED,
                phase="local_candidate_publication_authorization",
            )
            raise
        except ValidationError:
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=RunStatus.QUARANTINED,
                phase="result_finalization",
            )
            raise
        except BaseException as finalization_error:
            uncertainty = _candidate_publication_uncertainty(
                finalization_error
            )
            _best_effort_terminal_status(
                state,
                selected_run_id,
                status=(
                    RunStatus.QUARANTINED
                    if uncertainty is not None
                    else RunStatus.CANCELLED
                    if not isinstance(finalization_error, Exception)
                    else RunStatus.FAILED
                ),
                phase="result_finalization",
                details={
                    "artifact_observed": (
                        uncertainty.artifact_observed
                        if uncertainty is not None
                        else False
                    )
                },
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
    task_attempt_binding_digest: str,
    task_authorization_intent_digest: str,
    publication_enforcement_context: (
        _LocalCandidatePublicationEnforcementContext | None
    ),
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
    publication_billing_digest = task_publication_billing_digest(
        identity_matches=True,
        billing_matches=billing_matches,
        billing_disposition=billing_disposition,
    )
    accounting_payload = build_task_execution_accounting(
        result=result,
        billing_matches=billing_matches,
        billing_disposition=billing_disposition,
        runner_event_count=event_count,
        incremental_api_charge=incremental_api_charge,
    )
    execution_accounting_digest = canonical_digest(accounting_payload)
    execution_accounting_event_id = _controller_event_id(
        request.run_id,
        "execution_accounting",
        accounting_payload,
    )
    _append_required_event(
        state,
        request.run_id,
        "execution_accounting",
        accounting_payload,
        event_id=execution_accounting_event_id,
    )
    _require_exact_event_readback(
        state,
        request.run_id,
        "execution_accounting",
        accounting_payload,
        event_id=execution_accounting_event_id,
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
            candidate_artifact_path = _candidate_artifact_path(
                root=root,
                run_directory=request.run_directory,
                local_destination=(
                    prepared.contract.expected_output.local_destination
                ),
            )
            artifact_bytes = _canonical_artifact_bytes(result.output)
            artifact_digest = _publish_candidate_artifact(
                state=state,
                path=candidate_artifact_path,
                content=artifact_bytes,
                contract=prepared.contract,
                request=request,
                run_id=request.run_id,
                runner_id=expected_runner_id,
                profile_id=profile_id,
                project_root=root,
                task_attempt_binding_digest=(
                    task_attempt_binding_digest
                ),
                task_authorization_intent_digest=(
                    task_authorization_intent_digest
                ),
                requested_permission_class=request.permission_class,
                artifact_kind=(
                    prepared.contract.expected_output.artifact_kind
                ),
                billing_disposition=billing_disposition,
                billing_matches=billing_matches,
                billing_disposition_digest=publication_billing_digest,
                legacy_executable=legacy_executable,
                execution_accounting_digest=execution_accounting_digest,
                publication_enforcement_context=(
                    publication_enforcement_context
                ),
            )
            artifact_path = candidate_artifact_path
    elif result.status not in {
        RunStatus.FAILED,
        RunStatus.BLOCKED,
        RunStatus.QUARANTINED,
        RunStatus.CANCELLED,
    }:
        final_status = RunStatus.FAILED

    terminal_payload = {
        "accepted": bool(evaluation and evaluation.accepted),
        "artifact_recorded": artifact_path is not None,
        "artifact_observed": artifact_path is not None,
        "runner_status": result.status.value,
        "billing_assessment_matched_preflight": billing_matches,
        "billing_quarantine_required": (
            billing_disposition.quarantine_required
        ),
        "billing_circuit_breaker_required": (
            billing_disposition.circuit_breaker_required
        ),
        "artifact_credential_scan_passed": credential_scan_passed,
    }
    try:
        _append_terminal_event(
            state,
            request.run_id,
            terminal_payload,
            status=final_status,
        )
    except BaseException as terminal_error:
        if artifact_path is not None:
            terminal_error.add_note(
                "Ordomata preserved a verified candidate artifact after the "
                "terminal audit write failed."
            )
            raise terminal_error from _CandidateArtifactPublicationUncertain(
                "candidate artifact terminal evidence is uncertain",
                artifact_observed=True,
            )
        raise
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
        runner_version=task_runner_version_reference(result.runner_version),
        execution_mode=task_execution_mode(result),
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
    *,
    now: float | None = None,
    required_valid_until: float | None = None,
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
    BillingPolicy.assert_route_allowed(
        assessment,
        now=now,
        required_valid_until=required_valid_until,
    )


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

    payload = {
        "schema_version": 1,
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
    payload["assessment_digest"] = canonical_digest(payload)
    return payload


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
    if preflight_assessment.route in {
        BillingRoute.MOCK,
        BillingRoute.LOCAL_NON_AI,
    }:
        if not _non_ai_result_is_consistent(
            result,
            preflight_assessment=preflight_assessment,
        ):
            return _unknown_billing_disposition(
                "post_run_billing_disposition_inconsistent"
            )
        return BillingPostRunDisposition(
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_capacity_consumed=PaidCapacityConsumed.NOT_APPLICABLE,
            incremental_ai_charge=IncrementalAICharge.NONE,
            quarantine_required=False,
            circuit_breaker_required=False,
            reasons=(),
        )

    if (
        preflight_assessment.route is BillingRoute.SUBSCRIPTION_INCLUDED
        and task_execution_mode(result) is None
    ):
        return _unknown_billing_disposition(
            "post_run_billing_disposition_inconsistent"
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


def _non_ai_result_is_consistent(
    result: RunnerExecutionResult,
    *,
    preflight_assessment: BillingRouteAssessment,
) -> bool:
    """Require explicit no-AI accounting before any local publication."""

    return bool(
        result.live_model_execution_occurred is False
        and result.subscription_capacity_consumed is False
        and result.paid_capacity_consumed
        is PaidCapacityConsumed.NOT_APPLICABLE
        and result.incremental_ai_charge is IncrementalAICharge.NONE
        and result.billing_quarantine_required is False
        and result.billing_circuit_breaker_required is False
        and result.billing_disposition_reasons == ()
        and result.usage_observation is UsageObservation.NOT_APPLICABLE
        and result.postflight_billing_assessment is None
        and task_execution_mode(result) is not None
        and (
            preflight_assessment.route is not BillingRoute.MOCK
            or result.harness_process_started is False
        )
    )


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
    if preflight_assessment.route in {
        BillingRoute.MOCK,
        BillingRoute.LOCAL_NON_AI,
    }:
        return (
            "none"
            if not disposition.quarantine_required
            and _non_ai_result_is_consistent(
                result,
                preflight_assessment=preflight_assessment,
            )
            else "unknown"
        )
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


def _candidate_artifact_path(
    *,
    root: Path,
    run_directory: Path,
    local_destination: str,
) -> Path:
    """Resolve a run-local destination lexically without following its name."""

    candidate = Path(
        os.path.abspath(run_directory / Path(local_destination))
    )
    try:
        candidate.relative_to(root)
        relative_parent = candidate.parent.relative_to(run_directory)
    except ValueError as exc:
        raise ConfigurationError(
            "candidate artifact destination escapes the isolated run"
        ) from exc
    current = run_directory
    for component in relative_parent.parts:
        current = current / component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as exc:
            raise ConfigurationError(
                "candidate artifact parent is not safely inspectable"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise ConfigurationError(
                "candidate artifact parent is not an ordinary directory"
            )
    return candidate


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


def _publish_candidate_artifact(
    *,
    state: SQLiteStateStore,
    path: Path,
    content: bytes,
    contract: TaskContract,
    request: RunRequest,
    run_id: str,
    runner_id: str,
    profile_id: str | None,
    project_root: Path,
    task_attempt_binding_digest: str,
    task_authorization_intent_digest: str,
    requested_permission_class: PermissionClass,
    artifact_kind: str,
    billing_disposition: BillingPostRunDisposition,
    billing_matches: bool,
    billing_disposition_digest: str,
    legacy_executable: bool,
    execution_accounting_digest: str,
    publication_enforcement_context: (
        _LocalCandidatePublicationEnforcementContext | None
    ),
) -> str:
    """Publish one local candidate with a reconciled receipt chain.

    Schema-v4 exact-mock attempts require a fresh ABAC permit immediately
    before staging, independently of the existing Class 0/1 gate.  Historical
    paths retain their non-enforcing receipt semantics.  Neither path can
    widen authority beyond an isolated local candidate.
    """

    artifact_sha256 = hashlib.sha256(content).hexdigest()
    canonical_artifact_digest = "sha256:" + artifact_sha256
    artifact_size_bytes = len(content)
    destination_digest = canonical_digest({"artifact_path": str(path)})
    started_at = time.time()
    record = ArtifactRecord(
        artifact_id=f"{run_id}:chief-of-staff",
        run_id=run_id,
        kind=artifact_kind,
        path=str(path),
        sha256=artifact_sha256,
        media_type="application/json",
        size_bytes=artifact_size_bytes,
        created_at=started_at,
    )
    metadata_digest = artifact_record_digest(record)
    billing_projection = task_publication_billing_projection(
        identity_matches=True,
        billing_matches=billing_matches,
        billing_disposition=billing_disposition,
    )
    billing_projection["billing_disposition_digest"] = (
        billing_disposition_digest
    )
    publication_shadow = build_local_candidate_publication_shadow_event(
        contract=contract,
        run_id=run_id,
        runner_id=runner_id,
        profile_id=profile_id,
        project_root=project_root,
        artifact_digest=canonical_artifact_digest,
        artifact_size_bytes=artifact_size_bytes,
        artifact_kind=artifact_kind,
        destination_digest=destination_digest,
        task_attempt_binding_digest=task_attempt_binding_digest,
        evaluation_accepted=True,
        credential_scan_passed=True,
        billing_disposition=billing_projection,
        evaluated_at=started_at,
        legacy_executable=legacy_executable,
    )
    shadow_persisted = _best_effort_shadow_observation(
        state,
        run_id,
        lambda: publication_shadow,
    )
    publication_authorization: (
        LocalCandidatePublicationAuthorization | None
    ) = None
    publication_authorization_payload: dict[str, Any] | None = None
    publication_authorization_event_id: str | None = None
    if publication_enforcement_context is not None:
        if runner_id != "mock" or profile_id is None:
            raise ValidationError(
                "local candidate publication enforcement requires a selected mock profile"
            )
        safe_publication_prerequisites = bool(
            publication_enforcement_context.mock_dispatch_succeeded
            and billing_matches
            and billing_disposition.capacity_state
            is CapacityState.NOT_APPLICABLE
            and billing_disposition.paid_capacity_consumed
            is PaidCapacityConsumed.NOT_APPLICABLE
            and billing_disposition.incremental_ai_charge
            is IncrementalAICharge.NONE
            and not billing_disposition.quarantine_required
            and not billing_disposition.circuit_breaker_required
            and not billing_disposition.reasons
        )
        authorization_evaluated_at = time.time()
        authorization_evaluation_error: BaseException | None = None
        publication_intent_digest = publication_shadow.get("intent_digest")
        if not isinstance(publication_intent_digest, str):
            publication_intent_digest = ""
        try:
            publication_authorization = (
                evaluate_local_candidate_publication_authorization(
                    contract=contract,
                    request=request,
                    runner_id=runner_id,
                    profile_id=profile_id,
                    project_root=project_root,
                    controller_owned_mock_runner=True,
                    task_attempt_binding_digest=(
                        task_attempt_binding_digest
                    ),
                    execution_selection_digest=(
                        publication_enforcement_context.execution_selection_digest
                    ),
                    dispatch_request_digest=(
                        publication_enforcement_context.mock_dispatch_request_digest
                    ),
                    dispatch_decision_digest=(
                        publication_enforcement_context.mock_dispatch_decision_digest
                    ),
                    dispatch_action_receipt_digest=(
                        publication_enforcement_context.mock_dispatch_action_receipt_digest
                    ),
                    execution_accounting_digest=(
                        execution_accounting_digest
                    ),
                    billing_disposition_digest=(
                        billing_disposition_digest
                    ),
                    artifact_digest=canonical_artifact_digest,
                    destination_digest=destination_digest,
                    artifact_metadata_digest=metadata_digest,
                    artifact_kind=artifact_kind,
                    artifact_size_bytes=artifact_size_bytes,
                    evaluation_accepted=True,
                    credential_scan_passed=True,
                    safe_publication_prerequisites=(
                        safe_publication_prerequisites
                    ),
                    evaluated_at=authorization_evaluated_at,
                    legacy_executable=legacy_executable,
                )
            )
            publication_authorization_payload = (
                publication_authorization.to_event_payload()
            )
        except Exception:
            publication_authorization = None
            publication_authorization_payload = (
                build_local_candidate_publication_failure_payload(
                    task_attempt_binding_digest=(
                        task_attempt_binding_digest
                    ),
                    execution_selection_digest=(
                        publication_enforcement_context.execution_selection_digest
                    ),
                    task_authorization_intent_digest=(
                        task_authorization_intent_digest
                    ),
                    publication_authorization_intent_digest=(
                        publication_intent_digest
                    ),
                    dispatch_request_digest=(
                        publication_enforcement_context.mock_dispatch_request_digest
                    ),
                    dispatch_decision_digest=(
                        publication_enforcement_context.mock_dispatch_decision_digest
                    ),
                    dispatch_action_receipt_digest=(
                        publication_enforcement_context.mock_dispatch_action_receipt_digest
                    ),
                    execution_accounting_digest=(
                        execution_accounting_digest
                    ),
                    billing_disposition_digest=(
                        billing_disposition_digest
                    ),
                    artifact_digest=canonical_artifact_digest,
                    destination_digest=destination_digest,
                    artifact_metadata_digest=metadata_digest,
                    requested_permission_class=(
                        requested_permission_class
                    ),
                    controller_owned_mock_runner=True,
                    legacy_executable=legacy_executable,
                    safe_publication_prerequisites=(
                        safe_publication_prerequisites
                    ),
                    evaluation_accepted=True,
                    credential_scan_passed=True,
                    evaluated_at=authorization_evaluated_at,
                )
            )
        except BaseException as cancellation_error:
            publication_authorization = None
            authorization_evaluation_error = cancellation_error
            publication_authorization_payload = (
                build_local_candidate_publication_failure_payload(
                    task_attempt_binding_digest=(
                        task_attempt_binding_digest
                    ),
                    execution_selection_digest=(
                        publication_enforcement_context.execution_selection_digest
                    ),
                    task_authorization_intent_digest=(
                        task_authorization_intent_digest
                    ),
                    publication_authorization_intent_digest=(
                        publication_intent_digest
                    ),
                    dispatch_request_digest=(
                        publication_enforcement_context.mock_dispatch_request_digest
                    ),
                    dispatch_decision_digest=(
                        publication_enforcement_context.mock_dispatch_decision_digest
                    ),
                    dispatch_action_receipt_digest=(
                        publication_enforcement_context.mock_dispatch_action_receipt_digest
                    ),
                    execution_accounting_digest=(
                        execution_accounting_digest
                    ),
                    billing_disposition_digest=(
                        billing_disposition_digest
                    ),
                    artifact_digest=canonical_artifact_digest,
                    destination_digest=destination_digest,
                    artifact_metadata_digest=metadata_digest,
                    requested_permission_class=(
                        requested_permission_class
                    ),
                    controller_owned_mock_runner=True,
                    legacy_executable=legacy_executable,
                    safe_publication_prerequisites=(
                        safe_publication_prerequisites
                    ),
                    evaluation_accepted=True,
                    credential_scan_passed=True,
                    evaluated_at=authorization_evaluated_at,
                )
            )
        publication_authorization_event_id = _controller_event_id(
            run_id,
            LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
            publication_authorization_payload,
        )
        try:
            _append_required_event(
                state,
                run_id,
                LOCAL_CANDIDATE_PUBLICATION_DECISION_EVENT_TYPE,
                publication_authorization_payload,
                event_id=publication_authorization_event_id,
            )
        except BaseException as authorization_evidence_error:
            if authorization_evaluation_error is not None:
                raise authorization_evaluation_error from (
                    authorization_evidence_error
                )
            raise
        if authorization_evaluation_error is not None:
            raise authorization_evaluation_error
        if (
            publication_authorization is None
            or not publication_authorization.authorized_at_evaluation
        ):
            raise AuthorizationBlocked(
                "local candidate publication requires a fresh exact Class 1 authorization permit"
            )

    pre_effect_receipt = build_candidate_artifact_pre_effect_receipt(
        task_attempt_binding_digest=task_attempt_binding_digest,
        publication_shadow=publication_shadow,
        publication_shadow_persisted=shadow_persisted,
        requested_permission_class=requested_permission_class,
        artifact_kind=artifact_kind,
        destination_digest=destination_digest,
        artifact_digest=canonical_artifact_digest,
        artifact_size_bytes=artifact_size_bytes,
        artifact_metadata_digest=metadata_digest,
        billing_disposition_digest=billing_disposition_digest,
        started_at=started_at,
        publication_authorization=publication_authorization_payload,
        publication_authorization_event_id=(
            publication_authorization_event_id
        ),
    )
    pre_effect_event_id = pre_effect_receipt["receipt_digest"]
    assert isinstance(pre_effect_event_id, str)
    _append_required_event(
        state,
        run_id,
        TASK_CANDIDATE_ARTIFACT_INTENT_EVENT_TYPE,
        pre_effect_receipt,
        event_id=pre_effect_event_id,
    )

    stage = StagedArtifact(
        path.with_name(
            f".{path.name}.{pre_effect_event_id.removeprefix('sha256:')}.tmp"
        )
    )
    effect_started_at: float | None = None

    def build_action_receipt(
        *,
        completed_at: float,
        outcome: str,
        result_digest: str | None,
        observed_artifact_size_bytes: int | None,
        failure_code: str | None,
    ) -> dict[str, Any]:
        enforcement_receipt: Mapping[str, Any] | None = None
        if publication_authorization is not None:
            if effect_started_at is None:
                raise ValidationError(
                    "candidate publication effect start is unavailable"
                )
            enforcement_wrapper = (
                build_local_candidate_publication_enforcement_receipt(
                    authorization=publication_authorization,
                    action_started_at=effect_started_at,
                    completed_at=completed_at,
                    outcome=ReceiptOutcome(outcome),
                    result_digest=result_digest,
                )
            )
            candidate = enforcement_wrapper.get("receipt")
            if not isinstance(candidate, Mapping):
                raise ValidationError(
                    "candidate publication enforcement receipt is invalid"
                )
            enforcement_receipt = candidate
        return build_candidate_artifact_action_receipt(
            task_attempt_binding_digest=task_attempt_binding_digest,
            pre_effect_receipt=pre_effect_receipt,
            publication_shadow=publication_shadow,
            publication_shadow_persisted=shadow_persisted,
            requested_permission_class=requested_permission_class,
            artifact_kind=artifact_kind,
            destination_digest=destination_digest,
            intended_artifact_digest=canonical_artifact_digest,
            intended_artifact_size_bytes=artifact_size_bytes,
            artifact_metadata_digest=metadata_digest,
            billing_disposition_digest=billing_disposition_digest,
            started_at=started_at,
            completed_at=completed_at,
            outcome=outcome,
            result_digest=result_digest,
            observed_artifact_size_bytes=(
                observed_artifact_size_bytes
            ),
            failure_code=failure_code,
            publication_authorization=publication_authorization_payload,
            publication_authorization_event_id=(
                publication_authorization_event_id
            ),
            effect_started_at=(
                effect_started_at
                if publication_authorization is not None
                else None
            ),
            enforcement_receipt=enforcement_receipt,
        )

    effect_started_at = time.time()
    if publication_authorization is not None:
        try:
            assert_local_candidate_publication_authorized(
                publication_authorization,
                action_started_at=effect_started_at,
                persisted_payload=publication_authorization_payload,
                contract=contract,
                request=request,
                runner_id=runner_id,
                profile_id=profile_id,
                project_root=project_root,
                controller_owned_mock_runner=True,
                task_attempt_binding_digest=task_attempt_binding_digest,
                execution_selection_digest=(
                    publication_enforcement_context.execution_selection_digest
                ),
                dispatch_request_digest=(
                    publication_enforcement_context.mock_dispatch_request_digest
                ),
                dispatch_decision_digest=(
                    publication_enforcement_context.mock_dispatch_decision_digest
                ),
                dispatch_action_receipt_digest=(
                    publication_enforcement_context.mock_dispatch_action_receipt_digest
                ),
                execution_accounting_digest=execution_accounting_digest,
                billing_disposition_digest=billing_disposition_digest,
                artifact_digest=canonical_artifact_digest,
                destination_digest=destination_digest,
                artifact_metadata_digest=metadata_digest,
                artifact_kind=artifact_kind,
                artifact_size_bytes=artifact_size_bytes,
                evaluation_accepted=True,
                credential_scan_passed=True,
                safe_publication_prerequisites=(
                    safe_publication_prerequisites
                ),
                legacy_executable=legacy_executable,
            )
        except AuthorizationBlocked as freshness_error:
            raise _LocalCandidatePublicationFreshnessBlocked(
                "local candidate publication permit was not current at effect start"
            ) from freshness_error
    try:
        _stage_artifact(path, content, stage=stage)
        if stage.identity is None:
            raise ConfigurationError(
                "candidate artifact staging verification failed"
            )
        if not fsync_artifact_parent(stage.path):
            raise ConfigurationError(
                "candidate artifact staging namespace sync failed"
            )
        _append_artifact_with_readback(state, record)
        _promote_staged_artifact(stage, path)
        if not fsync_artifact_parent(path):
            raise ConfigurationError(
                "candidate artifact namespace sync failed"
            )
        if published_artifact_state(
            path,
            content,
            expected_identity=stage.identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        ) != ARTIFACT_MATCHES:
            raise ConfigurationError(
                "candidate artifact verification failed"
            )
        # Publication already removes and verifies the staging name while the
        # parent and inode descriptors are leased.  Keep those leases through
        # action-receipt reconciliation; no second pathname cleanup is needed.
    except BaseException as publication_error:
        final_effect_absent = _safe_remove_owned_artifact(
            path,
            staged_identity=stage.identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        staged_effect_absent = _safe_remove_owned_artifact(
            stage.path,
            staged_identity=stage.identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        stage.close()
        effect_unknown = not (
            final_effect_absent and staged_effect_absent
        )
        if effect_unknown:
            outcome = "unknown"
            failure_code = "artifact_publication_outcome_unknown"
        elif not isinstance(publication_error, Exception):
            outcome = "cancelled"
            failure_code = "artifact_persistence_interrupted"
        else:
            outcome = "failed"
            failure_code = "artifact_persistence_failed"
        try:
            receipt = build_action_receipt(
                completed_at=time.time(),
                outcome=outcome,
                result_digest=None,
                observed_artifact_size_bytes=None,
                failure_code=failure_code,
            )
        except BaseException as receipt_build_error:
            if effect_unknown:
                uncertain = _CandidateArtifactPublicationUncertain(
                    "candidate artifact failure receipt is unavailable",
                    artifact_observed=True,
                )
                if isinstance(receipt_build_error, Exception):
                    raise uncertain from receipt_build_error
                receipt_build_error.add_note(
                    "Ordomata could not build the interruption receipt."
                )
                raise receipt_build_error from uncertain
            raise
        _append_action_receipt_or_raise(
            state,
            run_id,
            receipt,
            artifact_observed=effect_unknown,
        )
        if effect_unknown:
            raise _CandidateArtifactPublicationUncertain(
                "candidate artifact publication outcome is uncertain",
                artifact_observed=True,
            ) from publication_error
        raise
    try:
        success_receipt = build_action_receipt(
            completed_at=time.time(),
            outcome="succeeded",
            result_digest=canonical_artifact_digest,
            observed_artifact_size_bytes=artifact_size_bytes,
            failure_code=None,
        )
    except BaseException as receipt_build_error:
        final_effect_absent = _safe_remove_owned_artifact(
            path,
            staged_identity=stage.identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        staged_effect_absent = _safe_remove_owned_artifact(
            stage.path,
            staged_identity=stage.identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        stage.close()
        if not (final_effect_absent and staged_effect_absent):
            uncertain = _CandidateArtifactPublicationUncertain(
                "candidate artifact receipt construction is uncertain",
                artifact_observed=True,
            )
            if isinstance(receipt_build_error, Exception):
                raise uncertain from receipt_build_error
            receipt_build_error.add_note(
                "Ordomata could not reconcile the published candidate."
            )
            raise receipt_build_error from uncertain
        raise
    try:
        _append_action_receipt(state, run_id, success_receipt)
    except BaseException as receipt_error:
        try:
            receipt_persistence = _event_persistence_state(
                state,
                run_id,
                TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                success_receipt,
                event_id=success_receipt.get("receipt_id"),
            )
        except BaseException as readback_error:
            stage.close()
            readback_error.add_note(
                "Ordomata candidate action receipt readback was interrupted."
            )
            raise readback_error from _CandidateArtifactPublicationUncertain(
                "candidate artifact action receipt readback is uncertain",
                artifact_observed=True,
            )
        if receipt_persistence is True:
            if _safe_published_artifact_state(
                path,
                content,
                expected_identity=stage.identity,
                expected_parent_identity=stage.parent_identity,
                stage=stage,
            ) != ARTIFACT_MATCHES:
                stage.close()
                raise _CandidateArtifactPublicationUncertain(
                    "candidate artifact receipt and effect disagree",
                    artifact_observed=True,
                ) from receipt_error
            if isinstance(receipt_error, Exception):
                stage.close()
                return artifact_sha256
            stage.close()
            receipt_error.add_note(
                "Ordomata reconciled the interrupted candidate receipt."
            )
            raise receipt_error from _CandidateArtifactPublicationUncertain(
                "candidate artifact committed before interruption",
                artifact_observed=True,
            )
        if receipt_persistence is None:
            observed_state = _safe_published_artifact_state(
                path,
                content,
                expected_identity=stage.identity,
                expected_parent_identity=stage.parent_identity,
                stage=stage,
            )
            stage.close()
            raise _CandidateArtifactPublicationUncertain(
                "candidate artifact action receipt is uncertain",
                artifact_observed=(observed_state != ARTIFACT_ABSENT),
            ) from receipt_error
        removed = _safe_remove_owned_artifact(
            path,
            staged_identity=stage.identity,
            expected_parent_identity=stage.parent_identity,
            stage=stage,
        )
        stage.close()
        if not removed:
            raise _CandidateArtifactPublicationUncertain(
                "candidate artifact action receipt is missing",
                artifact_observed=True,
            ) from receipt_error
        failure_receipt = build_action_receipt(
            completed_at=time.time(),
            outcome=(
                "cancelled"
                if not isinstance(receipt_error, Exception)
                else "failed"
            ),
            result_digest=None,
            observed_artifact_size_bytes=None,
            failure_code=(
                "artifact_persistence_interrupted"
                if not isinstance(receipt_error, Exception)
                else "artifact_persistence_failed"
            ),
        )
        _append_action_receipt_or_raise(
            state,
            run_id,
            failure_receipt,
            artifact_observed=False,
        )
        raise
    if _safe_published_artifact_state(
        path,
        content,
        expected_identity=stage.identity,
        expected_parent_identity=stage.parent_identity,
        stage=stage,
    ) != ARTIFACT_MATCHES:
        stage.close()
        raise _CandidateArtifactPublicationUncertain(
            "candidate artifact changed after action receipt",
            artifact_observed=True,
        )
    stage.close()
    return artifact_sha256


def _safe_published_artifact_state(
    path: Path,
    content: bytes,
    *,
    expected_identity: tuple[int, int] | None,
    expected_parent_identity: tuple[int, int] | None,
    stage: StagedArtifact,
) -> str:
    """Classify an effect without allowing interruption to look absent."""

    try:
        return published_artifact_state(
            path,
            content,
            expected_identity=expected_identity,
            expected_parent_identity=expected_parent_identity,
            stage=stage,
        )
    except BaseException:
        return ARTIFACT_UNVERIFIABLE


def _safe_remove_owned_artifact(
    path: Path,
    *,
    staged_identity: tuple[int, int] | None,
    expected_parent_identity: tuple[int, int] | None,
    stage: StagedArtifact,
) -> bool:
    """Return false whenever inode-owned cleanup cannot be proven complete."""

    try:
        return remove_owned_published_artifact(
            path,
            staged_identity=staged_identity,
            expected_parent_identity=expected_parent_identity,
            stage=stage,
        )
    except BaseException:
        return False


def _stage_artifact(
    path: Path,
    content: bytes,
    *,
    stage: StagedArtifact,
) -> None:
    """Patchable controller wrapper around shared durable staging."""

    stage_artifact(path, content, stage=stage)


def _promote_staged_artifact(
    stage: StagedArtifact,
    artifact_path: Path,
) -> None:
    """Patchable wrapper around descriptor-anchored publication."""

    publish_staged_artifact(artifact_path, stage=stage)


def _append_required_event(
    state: SQLiteStateStore,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    event_id: str,
    status: RunStatus | None = None,
) -> None:
    """Append an idempotent event, accepting only exact committed readback."""

    try:
        state.append_event(
            run_id,
            event_type,
            payload,
            event_id=event_id,
            status=status,
        )
    except BaseException as append_error:
        persisted = _event_persistence_state(
            state,
            run_id,
            event_type,
            payload,
            event_id=event_id,
            status=status,
        )
        if persisted is True and isinstance(append_error, Exception):
            return
        if persisted is None:
            raise ConfigurationError(
                "required controller evidence persistence is uncertain"
            ) from append_error
        raise


def _mock_dispatch_result_is_valid(
    result: Any,
    *,
    request: RunRequest,
    preflight_assessment: BillingRouteAssessment,
    runner_event_count: int,
) -> bool:
    """Validate the exact no-process mock result before claiming success."""

    if (
        not isinstance(result, RunnerExecutionResult)
        or result.run_id != request.run_id
        or result.runner_id != "mock"
        or result.status
        not in {
            RunStatus.SUCCEEDED,
            RunStatus.FAILED,
            RunStatus.BLOCKED,
            RunStatus.QUARANTINED,
            RunStatus.CANCELLED,
        }
        or not isinstance(result.billing_assessment, BillingRouteAssessment)
        or not isinstance(result.events, tuple)
        or any(not isinstance(event, AgentEvent) for event in result.events)
        or len(result.events) != runner_event_count
        or task_execution_mode(result) != "in_memory_mock"
        or not _non_ai_result_is_consistent(
            result,
            preflight_assessment=preflight_assessment,
        )
    ):
        return False
    try:
        return _billing_assessments_match(
            result.billing_assessment,
            preflight_assessment,
        )
    except Exception:
        return False


def _mock_dispatch_receipt_outcome(
    result: Any,
    *,
    result_valid: bool,
) -> ReceiptOutcome:
    """Classify only the bounded invocation outcome, not artifact acceptance."""

    if not result_valid or not isinstance(result, RunnerExecutionResult):
        return ReceiptOutcome.UNKNOWN
    if result.status is RunStatus.SUCCEEDED:
        return ReceiptOutcome.SUCCEEDED
    if result.status is RunStatus.CANCELLED:
        return ReceiptOutcome.CANCELLED
    if result.status in {
        RunStatus.FAILED,
        RunStatus.BLOCKED,
        RunStatus.QUARANTINED,
    }:
        return ReceiptOutcome.FAILED
    return ReceiptOutcome.UNKNOWN


def _mock_dispatch_result_digest(
    result: Any,
    *,
    runner_event_count: int,
) -> str | None:
    """Bind a privacy-safe result projection without retaining runner output."""

    if not isinstance(result, RunnerExecutionResult):
        return None
    return canonical_digest(
        {
            "harness_process_started": result.harness_process_started,
            "live_model_execution_occurred": (
                result.live_model_execution_occurred
            ),
            "run_ref": canonical_digest({"run_id": result.run_id}),
            "runner_event_count": runner_event_count,
            "runner_id": result.runner_id,
            "status": result.status.value,
        }
    )


def _append_mock_dispatch_action_receipt(
    state: SQLiteStateStore,
    *,
    run_id: str,
    authorization: MockDispatchAuthorization,
    contract: TaskContract,
    action_started_at: float,
    outcome: ReceiptOutcome,
    result_digest: str | None,
) -> dict[str, Any]:
    payload = build_mock_dispatch_action_receipt(
        authorization=authorization,
        contract=contract,
        action_started_at=action_started_at,
        completed_at=time.time(),
        outcome=outcome,
        result_digest=result_digest,
    )
    receipt = payload.get("receipt")
    receipt_id = (
        receipt.get("receipt_id") if isinstance(receipt, Mapping) else None
    )
    if not isinstance(receipt_id, str):
        raise ValidationError("mock dispatch action receipt identifier is missing")
    _append_required_event(
        state,
        run_id,
        MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
        payload,
        event_id=receipt_id,
    )
    _require_exact_event_readback(
        state,
        run_id,
        MOCK_DISPATCH_ACTION_RECEIPT_EVENT_TYPE,
        payload,
        event_id=receipt_id,
    )
    return payload


def _append_terminal_event(
    state: SQLiteStateStore,
    run_id: str,
    payload: dict[str, Any],
    *,
    status: RunStatus,
) -> None:
    """Append a deterministic terminal event with exact post-error readback."""

    event_id = _controller_event_id(
        run_id,
        "status",
        payload,
        status=status,
    )
    try:
        state.append_event(
            run_id,
            "status",
            payload,
            status=status,
            event_id=event_id,
        )
    except BaseException as append_error:
        persisted = _event_persistence_state(
            state,
            run_id,
            "status",
            payload,
            event_id=event_id,
            status=status,
        )
        if persisted is True and isinstance(append_error, Exception):
            return
        if persisted is None:
            raise ConfigurationError(
                "terminal controller evidence persistence is uncertain"
            ) from append_error
        raise


def _controller_event_id(
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    status: RunStatus | None = None,
) -> str:
    """Content-address one controller event within its immutable run."""

    material: dict[str, Any] = {
        "event_type": event_type,
        "payload": payload,
        "run_id": run_id,
    }
    if status is not None:
        material["status"] = status.value
    return canonical_digest(material)


def _append_action_receipt(
    state: SQLiteStateStore,
    run_id: str,
    payload: dict[str, Any],
) -> None:
    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str):
        raise ValidationError("candidate action receipt identifier is missing")
    state.append_event(
        run_id,
        TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
        payload,
        event_id=receipt_id,
    )


def _append_action_receipt_or_raise(
    state: SQLiteStateStore,
    run_id: str,
    payload: dict[str, Any],
    *,
    artifact_observed: bool,
) -> None:
    """Persist a terminal action receipt or surface conservative uncertainty."""

    try:
        _append_action_receipt(state, run_id, payload)
    except BaseException as receipt_error:
        try:
            persisted = _event_persistence_state(
                state,
                run_id,
                TASK_CANDIDATE_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                payload,
                event_id=payload.get("receipt_id"),
            )
        except BaseException as readback_error:
            readback_error.add_note(
                "Ordomata candidate receipt readback was interrupted."
            )
            raise readback_error from _CandidateArtifactPublicationUncertain(
                "candidate artifact receipt readback is uncertain",
                artifact_observed=artifact_observed,
            )
        if persisted is True and isinstance(receipt_error, Exception):
            return
        if persisted is True:
            receipt_error.add_note(
                "Ordomata reconciled the interrupted candidate receipt."
            )
            raise receipt_error from (
                _CandidateArtifactPublicationUncertain(
                    "candidate artifact receipt committed before interruption",
                    artifact_observed=artifact_observed,
                )
            )
        if persisted is None or artifact_observed:
            raise _CandidateArtifactPublicationUncertain(
                "candidate artifact receipt persistence is uncertain",
                artifact_observed=artifact_observed,
            ) from receipt_error
        raise ConfigurationError(
            "candidate artifact action receipt could not be persisted"
        ) from receipt_error


def _event_persistence_state(
    state: SQLiteStateStore,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    event_id: Any,
    status: RunStatus | None = None,
) -> bool | None:
    """Return true/false for exact readback, or null when unprovable."""

    if not isinstance(event_id, str):
        return None
    try:
        matches = tuple(
            event
            for event in state.list_events(run_id)
            if event.event_id == event_id
        )
    except Exception:
        return None
    if not matches:
        return False
    if (
        len(matches) == 1
        and matches[0].event_type == event_type
        and matches[0].status is status
        and matches[0].payload == payload
    ):
        return True
    return None


def _require_exact_event_readback(
    state: SQLiteStateStore,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    event_id: str,
    status: RunStatus | None = None,
) -> None:
    """Require one exact durable event before crossing an enforcement seam."""

    if (
        _event_persistence_state(
            state,
            run_id,
            event_type,
            payload,
            event_id=event_id,
            status=status,
        )
        is not True
    ):
        raise ConfigurationError(
            "required controller evidence could not be read back exactly"
        )


def _append_artifact_with_readback(
    state: SQLiteStateStore,
    record: ArtifactRecord,
) -> None:
    """Append immutable metadata, reconciling a commit-then-raise failure."""

    try:
        state.append_artifact(record)
    except BaseException as append_error:
        persisted = _artifact_record_persistence_state(state, record)
        if persisted is True and isinstance(append_error, Exception):
            return
        if persisted is None:
            raise _CandidateArtifactPublicationUncertain(
                "candidate artifact metadata persistence is uncertain",
                artifact_observed=False,
            ) from append_error
        raise


def _artifact_record_persistence_state(
    state: SQLiteStateStore,
    record: ArtifactRecord,
) -> bool | None:
    try:
        matches = tuple(
            candidate
            for candidate in state.list_artifacts(record.run_id)
            if candidate.artifact_id == record.artifact_id
        )
    except Exception:
        return None
    if not matches:
        return False
    if len(matches) == 1 and matches[0] == record:
        return True
    return None


def _candidate_publication_uncertainty(
    error: BaseException,
) -> _CandidateArtifactPublicationUncertain | None:
    """Find a bounded publication uncertainty in a direct exception chain."""

    current: BaseException | None = error
    observed: set[int] = set()
    while current is not None and id(current) not in observed:
        observed.add(id(current))
        if isinstance(current, _CandidateArtifactPublicationUncertain):
            return current
        current = current.__cause__ or current.__context__
    return None


def _best_effort_terminal_status(
    state: SQLiteStateStore,
    run_id: str,
    *,
    status: RunStatus,
    phase: str,
    details: dict[str, Any] | None = None,
) -> bool:
    """Append one terminal event when possible without masking the root failure."""

    try:
        if state.current_status(run_id) not in {
            RunStatus.CREATED,
            RunStatus.RUNNING,
        }:
            return False
        _append_terminal_event(
            state,
            run_id,
            {"phase": phase, **dict(details or {})},
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

    payload: dict[str, Any] | None = None
    event_id: str | None = None
    try:
        payload = builder()
        event_id = canonical_digest(
            {
                "event_type": "authorization_shadow_decision",
                "payload": payload,
                "run_id": run_id,
            }
        )
        state.append_event(
            run_id,
            "authorization_shadow_decision",
            payload,
            event_id=event_id,
        )
    except Exception:
        return (
            _event_persistence_state(
                state,
                run_id,
                "authorization_shadow_decision",
                payload,
                event_id=event_id,
            )
            is True
            if payload is not None and event_id is not None
            else False
        )
    return True


__all__ = [
    "PreparedTask",
    "TaskRunReport",
    "load_mock_chief_of_staff_output",
    "prepare_chief_of_staff",
    "run_chief_of_staff",
]
