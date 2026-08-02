"""Operator CLI for the local subscription-only control plane."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
import time
from typing import Any, Sequence
from uuid import uuid4

from .attestation import refresh_billing_attestation
from .authorization_inspection import (
    AuthorizationInspectionReport,
    inspect_authorization_shadows,
)
from .comparison import (
    ComparisonPlan,
    ComparisonProfile,
    ComparisonSnapshot,
    ControlledComparisonPlan,
    comparison_snapshot_from_prepared,
    run_controlled_comparison,
)
from .billing import FileBillingAttestationLoader, LIVE_RUN_EVIDENCE_MARGIN_SECONDS
from .contracts import load_task_contract
from .doctor import DoctorReport, RunnerDiagnostic, collect_doctor_report
from .errors import OrdomataError, BillingRouteBlocked, ConfigurationError
from .execution_selection import build_execution_selection
from .models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    CapacityState,
    PaidContinuationProtection,
    PaidCreditBalance,
)
from .orchestrator import (
    PreparedTask,
    chief_of_staff_routing_features,
    load_mock_chief_of_staff_output,
    prepare_chief_of_staff,
    run_chief_of_staff,
)
from .paths import resolve_state_root
from .routing import (
    ExecutionProfile,
    ProfileRouter,
    RuntimeProfileState,
    TaskRoutingFeatures,
    load_execution_profiles,
    runner_overrides_for_profile,
)
from .runners import ClaudeRunner, CodexRunner, MockRunner
from .scheduler import IntervalSchedule, RunOnceScheduler
from .shadow_authorization import task_authorization_intent_digest
from .state import SQLiteBillingCircuitGuard, SQLiteStateStore
from .supervisor import (
    FlowSpec,
    ForegroundSupervisor,
    SQLiteSupervisorStore,
    SUPERVISOR_DISPATCH_BLOCKERS,
    SupervisorMode,
    inspect_pending_completions,
    inspect_reconciliation,
    inspect_supervisor_audit,
    inspect_supervisor_status,
)


DEFAULT_PROFILE_PATH = Path("profiles/default.json")
DEFAULT_TASK_PATH = Path("tasks/chief-of-staff-lite.json")
DEFAULT_COMPARISON_PROFILES = (
    "codex.subscription.local-draft-synthesis",
    "claude.subscription.local-draft-synthesis",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ordomata",
        description="A local control plane for governed autonomous work.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="project containing tasks/, profiles/, and fixtures/ (default: cwd)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser(
        "doctor", help="run non-model local capability and billing diagnostics"
    )
    doctor.add_argument("--json", action="store_true")

    billing_attest = subparsers.add_parser(
        "billing-attest",
        help="interactively attest provider billing controls without running a model",
    )
    billing_attest.add_argument(
        "--runner",
        required=True,
        choices=("codex", "claude"),
        help="first-party subscription harness to inspect",
    )

    profiles = subparsers.add_parser(
        "profiles", help="list versioned model/harness execution profiles"
    )
    profiles.add_argument("--json", action="store_true")

    validate = subparsers.add_parser(
        "task-validate", help="strictly validate a neutral task contract"
    )
    validate.add_argument("path", nargs="?", type=Path)
    validate.add_argument("--json", action="store_true")

    context = subparsers.add_parser(
        "context-inspect", help="build the local fixture context snapshot"
    )
    context.add_argument("--json", action="store_true")

    authorization_inspect = subparsers.add_parser(
        "auth-inspect",
        help="read-only inspection of authorization shadow parity and coverage",
    )
    authorization_inspect.add_argument("--run-id")
    authorization_inspect.add_argument("--mismatches-only", action="store_true")
    authorization_inspect.add_argument("--json", action="store_true")

    route = subparsers.add_parser(
        "route", help="diagnose and rank eligible execution profiles"
    )
    route.add_argument(
        "--lane",
        choices=("subscription", "mock"),
        default="subscription",
        help="explicit billing lane; mock is never a fallback for subscription",
    )
    route.add_argument("--json", action="store_true")

    demo = subparsers.add_parser(
        "demo", help="run the deterministic mock Chief of Staff workflow"
    )
    demo.add_argument("--run-id")
    demo.add_argument("--json", action="store_true")

    run = subparsers.add_parser(
        "run", help="run Chief of Staff with one explicit versioned profile"
    )
    run.add_argument("--profile", required=True)
    run.add_argument("--run-id")
    run.add_argument(
        "--operator-instruction",
        action="append",
        default=[],
        help="trusted instruction still bounded by task permission policy",
    )
    run.add_argument("--json", action="store_true")

    comparison = subparsers.add_parser(
        "compare-plan", help="create a no-execution randomized comparison plan"
    )
    comparison.add_argument(
        "--runners", nargs="+", default=("codex", "claude")
    )
    comparison.add_argument("--repetitions", type=int, default=3)
    comparison.add_argument("--seed", type=int, default=20260726)
    comparison.add_argument("--comparison-id")
    comparison.add_argument("--json", action="store_true")

    comparison_run = subparsers.add_parser(
        "compare-run",
        help="execute a controlled read-only named-profile comparison",
    )
    comparison_run.add_argument(
        "--profiles",
        nargs="+",
        default=DEFAULT_COMPARISON_PROFILES,
        help="two or more explicit versioned profile identifiers",
    )
    comparison_run.add_argument("--repetitions", type=int, default=3)
    comparison_run.add_argument("--seed", type=int, default=20260726)
    comparison_run.add_argument("--comparison-id")
    comparison_run.add_argument("--json", action="store_true")

    schedule = subparsers.add_parser(
        "schedule-inspect", help="inspect one fixed-interval slot without claiming it"
    )
    schedule.add_argument("--schedule-id", default="chief-of-staff-lite")
    schedule.add_argument("--interval-seconds", type=int, required=True)
    schedule.add_argument("--timeout-seconds", type=int, default=600)
    schedule.add_argument("--anchor-at", type=float, default=0.0)
    schedule.add_argument("--misfire-grace-seconds", type=int)
    schedule.add_argument("--now", type=float)
    schedule.add_argument("--json", action="store_true")

    supervise = subparsers.add_parser(
        "supervise",
        help="run the foreground control loop (worker dispatch remains disabled)",
    )
    supervise.add_argument("--once", action="store_true")
    supervise.add_argument(
        "--max-ticks",
        type=int,
        default=0,
        help="stop after this many ticks; 0 means until stopped",
    )
    supervise.add_argument("--poll-seconds", type=float, default=5.0)
    supervise.add_argument("--lease-ttl-seconds", type=float, default=30.0)
    supervise.add_argument("--json", action="store_true")

    supervisor = subparsers.add_parser(
        "supervisor", help="manage durable foreground-supervisor control state"
    )
    supervisor_commands = supervisor.add_subparsers(
        dest="supervisor_command", required=True
    )
    enqueue = supervisor_commands.add_parser(
        "enqueue", help="admit one immutable deterministic-mock flow"
    )
    enqueue.add_argument("--admission-key", required=True)
    enqueue.add_argument("--flow-id")
    enqueue.add_argument("--available-at", type=float)
    enqueue.add_argument("--deadline-at", type=float)
    enqueue.add_argument("--mandatory", action="store_true")
    enqueue.add_argument("--blocker", action="store_true")
    enqueue.add_argument("--value-priority", type=int, default=0)
    enqueue.add_argument("--evidence-priority", type=int, default=0)
    enqueue.add_argument("--capacity-fit-priority", type=int, default=0)
    enqueue.add_argument("--max-attempts", type=int, default=1)
    enqueue.add_argument("--attempt-timeout-seconds", type=int, default=600)
    enqueue.add_argument("--json", action="store_true")

    for command_name in ("start", "pause", "resume", "drain", "stop"):
        control = supervisor_commands.add_parser(
            command_name, help=f"request supervisor {command_name}"
        )
        control.add_argument("--expected-revision", type=int)
        control.add_argument("--actor", default="operator")
        control.add_argument("--json", action="store_true")

    status = supervisor_commands.add_parser(
        "status", help="inspect state without creating or changing it"
    )
    status.add_argument("--json", action="store_true")

    cancel = supervisor_commands.add_parser(
        "cancel", help="persist a sticky flow cancellation request"
    )
    cancel.add_argument("flow_id")
    cancel.add_argument("--actor", default="operator")
    cancel.add_argument("--reason", default="operator_cancelled")
    cancel.add_argument("--json", action="store_true")

    audit = supervisor_commands.add_parser(
        "audit",
        help="read-only audit of recovery state and authorization shadows",
    )
    audit.add_argument("--now", type=float)
    audit.add_argument("--json", action="store_true")

    reconcile = supervisor_commands.add_parser(
        "reconcile", help="preview or apply a digest-bound recovery plan"
    )
    reconcile.add_argument("--now", type=float)
    reconcile.add_argument("--apply", action="store_true")
    reconcile.add_argument("--plan-digest")
    reconcile.add_argument("--json", action="store_true")

    completions = supervisor_commands.add_parser(
        "completions", help="list pending internal completion intents read-only"
    )
    completions.add_argument("--json", action="store_true")

    acknowledge = supervisor_commands.add_parser(
        "ack-completion", help="append a local completion delivery receipt"
    )
    acknowledge.add_argument("outbox_id")
    acknowledge.add_argument("--consumer", required=True)
    acknowledge.add_argument("--result-digest", required=True)
    acknowledge.add_argument("--delivery-id", required=True)
    acknowledge.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        return asyncio.run(_dispatch(arguments))
    except KeyboardInterrupt:
        print("supervisor interrupted", file=sys.stderr)
        return 130
    except (OrdomataError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


async def _dispatch(arguments: argparse.Namespace) -> int:
    root = arguments.project_root.resolve()
    if arguments.command == "doctor":
        report = await collect_doctor_report(
            workspace=root,
            run_root=resolve_state_root(root) / "runs",
        )
        _emit(report.to_mapping(), json_output=arguments.json, human=_doctor_text(report))
        return 0 if report.local_control_plane_ready else 1

    if arguments.command == "billing-attest":
        result = await refresh_billing_attestation(
            root,
            _billing_attestation_runner(arguments.runner),
        )
        print(
            f"billing attestation refreshed: {result.runner_id}\n"
            f"maximum validity: {result.maximum_validity_seconds} seconds\n"
            f"path: {result.path}"
        )
        return 0

    if arguments.command == "profiles":
        profiles = _load_profiles(root)
        payload = {
            "profiles": [_profile_mapping(profile) for profile in profiles]
        }
        human = "\n".join(
            f"{profile.profile_id}  runner={profile.runner_id}  "
            f"model={profile.model_id or '<harness-default>'}  role={profile.role}"
            for profile in profiles
        )
        _emit(payload, json_output=arguments.json, human=human)
        return 0

    if arguments.command == "task-validate":
        path = (
            arguments.path.resolve()
            if arguments.path is not None
            else root / DEFAULT_TASK_PATH
        )
        contract = load_task_contract(path)
        payload = {
            "valid": True,
            "task_id": contract.task_id,
            "version": contract.version,
            "prompt_version": contract.prompt_version,
            "permission_class": int(contract.permission_class),
            "authorization_intent_present": (
                contract.authorization_intent is not None
            ),
            "authorization_intent_digest": (
                None
                if contract.authorization_intent is None
                else contract.authorization_intent.digest
            ),
            "definition_hash": contract.definition_hash,
            "output_schema_reference": contract.output_schema_reference,
        }
        _emit(
            payload,
            json_output=arguments.json,
            human=(
                f"valid: {contract.task_id} v{contract.version} "
                f"(prompt {contract.prompt_version}, Class {int(contract.permission_class)})"
            ),
        )
        return 0

    if arguments.command == "context-inspect":
        prepared = prepare_chief_of_staff(root)
        pack = prepared.context_pack
        payload = pack.to_mapping(include_content=False)
        human = (
            f"snapshot {pack.snapshot_hash}\n"
            f"sources: {pack.sources_included}/{pack.sources_considered}; "
            f"bytes: {pack.raw_bytes}; estimated tokens: {pack.approximate_context_tokens}"
        )
        _emit(payload, json_output=arguments.json, human=human)
        return 0

    if arguments.command == "auth-inspect":
        report = inspect_authorization_shadows(
            resolve_state_root(root) / "state.sqlite3",
            run_id=arguments.run_id,
            mismatches_only=arguments.mismatches_only,
        )
        _emit(
            report.to_mapping(),
            json_output=arguments.json,
            human=_authorization_inspection_text(report),
        )
        return 0 if report.clean else 1

    if arguments.command == "route":
        payload = await _route_profiles(root, lane=arguments.lane)
        selected = payload["selected_profile"] or "<blocked>"
        human = f"selected: {selected}\n" + "\n".join(
            f"{item['profile_id']}: {item['disposition']}"
            for item in payload["profiles"]
        )
        _emit(payload, json_output=arguments.json, human=human)
        return 0 if payload["selected_profile"] is not None else 1

    if arguments.command == "demo":
        report = await _run_profile(
            root,
            profile_id="mock.deterministic.local-draft",
            run_id=arguments.run_id,
            operator_instructions=(),
        )
        _emit(
            report,
            json_output=arguments.json,
            human=_run_text(report),
        )
        return 0 if report["status"] == "succeeded" else 1

    if arguments.command == "run":
        report = await _run_profile(
            root,
            profile_id=arguments.profile,
            run_id=arguments.run_id,
            operator_instructions=arguments.operator_instruction,
        )
        _emit(
            report,
            json_output=arguments.json,
            human=_run_text(report),
        )
        return 0 if report["status"] == "succeeded" else 1

    if arguments.command == "compare-plan":
        payload = _comparison_plan(
            root,
            runner_ids=tuple(arguments.runners),
            repetitions=arguments.repetitions,
            random_seed=arguments.seed,
            comparison_id=arguments.comparison_id,
        )
        human = (
            f"comparison: {payload['comparison_id']}\n"
            f"snapshot: {payload['snapshot_digest']}\n"
            f"trials: {len(payload['trials'])} (plan only; no models executed)"
        )
        _emit(payload, json_output=arguments.json, human=human)
        return 0

    if arguments.command == "compare-run":
        payload = await _run_controlled_profile_comparison(
            root,
            profile_ids=tuple(arguments.profiles),
            repetitions=arguments.repetitions,
            random_seed=arguments.seed,
            comparison_id=arguments.comparison_id,
        )
        human = (
            f"comparison: {payload['comparison_id']}\n"
            f"snapshot: {payload['snapshot_digest']}\n"
            f"trials: {len(payload['trials'])}; permission: read-only Class 0\n"
            f"report: {payload['report_path']}"
        )
        _emit(payload, json_output=arguments.json, human=human)
        return 0 if payload["automated_checks_succeeded"] else 1

    if arguments.command == "schedule-inspect":
        payload = _schedule_inspection(arguments)
        human = (
            f"schedule {payload['schedule_id']}: {payload['reason']}"
            + (
                f"; slot={payload['slot']['slot_id']}"
                if payload["slot"] is not None
                else ""
            )
        )
        _emit(payload, json_output=arguments.json, human=human)
        return 0

    if arguments.command == "supervise":
        payload = await _run_foreground_supervisor(root, arguments)
        _emit(
            payload,
            json_output=arguments.json,
            human=(
                f"supervisor: {payload['mode']}; ticks={payload['ticks']}; "
                "worker dispatch=disabled"
            ),
        )
        return 0

    if arguments.command == "supervisor":
        return _dispatch_supervisor_command(root, arguments)

    raise ConfigurationError(f"unsupported command: {arguments.command}")


def _supervisor_state_path(root: Path) -> Path:
    state_directory = resolve_state_root(root)
    if state_directory.is_symlink():
        raise ConfigurationError("supervisor state directory must not be a symlink")
    if state_directory.exists() and not state_directory.is_dir():
        raise ConfigurationError("supervisor state directory must be a directory")
    state_path = state_directory / "state.sqlite3"
    if state_path.is_symlink():
        raise ConfigurationError("supervisor state database must not be a symlink")
    if state_path.exists():
        metadata = state_path.stat()
        if not state_path.is_file() or metadata.st_nlink != 1:
            raise ConfigurationError(
                "supervisor state database must be one private regular file"
            )
    return state_path


def _ensure_supervisor_state_parent(state_path: Path) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)


def _digest_hex(value: str, field_name: str) -> str:
    prefix = "sha256:"
    selected = value[len(prefix) :] if value.startswith(prefix) else value
    if len(selected) != 64 or any(character not in "0123456789abcdef" for character in selected):
        raise ConfigurationError(f"{field_name} is not a canonical SHA-256 digest")
    return selected


async def _run_foreground_supervisor(
    root: Path,
    arguments: argparse.Namespace,
) -> dict[str, Any]:
    if arguments.max_ticks < 0:
        raise ConfigurationError("max-ticks must be zero or greater")
    if arguments.poll_seconds <= 0 or arguments.poll_seconds > 60:
        raise ConfigurationError("poll-seconds must be greater than zero and at most 60")
    if arguments.lease_ttl_seconds <= arguments.poll_seconds:
        raise ConfigurationError("lease TTL must be greater than the poll interval")
    state_path = _supervisor_state_path(root)
    _ensure_supervisor_state_parent(state_path)
    instance_owner = f"foreground/{uuid4().hex}"
    maximum = 1 if arguments.once else arguments.max_ticks
    ticks = 0
    last: dict[str, Any] = {
        "mode": SupervisorMode.STOPPED.value,
        "control_revision": 0,
        "dispatch_enabled": False,
        "claimed": False,
        "dispatch_blocker": SUPERVISOR_DISPATCH_BLOCKERS[0],
        "dispatch_blockers": list(SUPERVISOR_DISPATCH_BLOCKERS),
    }
    with SQLiteSupervisorStore(state_path) as store:
        supervisor = ForegroundSupervisor(
            store,
            instance_owner=instance_owner,
            lease_ttl_seconds=arguments.lease_ttl_seconds,
        )
        try:
            while maximum == 0 or ticks < maximum:
                last = supervisor.tick()
                ticks += 1
                if last["mode"] == SupervisorMode.STOPPED.value:
                    break
                if maximum != 0 and ticks >= maximum:
                    break
                await asyncio.sleep(arguments.poll_seconds)
        finally:
            supervisor.close()
    return {
        **last,
        "ticks": ticks,
        "foreground_only": True,
        "installed_os_schedule": False,
        "live_model_execution": False,
    }


def _dispatch_supervisor_command(
    root: Path,
    arguments: argparse.Namespace,
) -> int:
    state_path = _supervisor_state_path(root)
    command = arguments.supervisor_command
    if command == "status":
        status = inspect_supervisor_status(state_path)
        payload = status.to_mapping()
        _emit(
            payload,
            json_output=arguments.json,
            human=(
                f"supervisor: {payload['mode']} rev={payload['control_revision']}; "
                f"dispatch={'enabled' if payload['dispatch_enabled'] else 'disabled'}"
            ),
        )
        return 0

    if command == "audit":
        plan, authorization = inspect_supervisor_audit(
            state_path, now=arguments.now
        )
        payload = plan.to_mapping()
        payload["authorization"] = authorization.to_mapping()
        _emit(
            payload,
            json_output=arguments.json,
            human=(
                f"supervisor audit: findings={len(plan.findings)} "
                f"actionable={plan.actionable_count}; "
                f"authorization_findings={len(authorization.findings)}; "
                f"plan={plan.plan_digest}"
            ),
        )
        return 0 if not plan.findings and authorization.clean else 1

    if command == "completions":
        completions = inspect_pending_completions(state_path)
        payload = {
            "pending_count": len(completions),
            "completions": [
                {
                    "outbox_id": item.outbox_id,
                    "idempotency_key": item.idempotency_key,
                    "flow_id": item.flow_id,
                    "source_revision": item.source_revision,
                    "attempt_id": item.attempt_id,
                    "intent_digest": item.intent_digest,
                    "created_at": item.created_at,
                }
                for item in completions
            ],
        }
        _emit(
            payload,
            json_output=arguments.json,
            human=f"pending local completions: {len(completions)}",
        )
        return 0

    if command == "reconcile" and not arguments.apply:
        plan = inspect_reconciliation(state_path, now=arguments.now)
        _emit(
            {**plan.to_mapping(), "applied": False},
            json_output=arguments.json,
            human=(
                f"reconciliation preview: actionable={plan.actionable_count}; "
                f"plan={plan.plan_digest}"
            ),
        )
        return 0

    if command == "reconcile" and arguments.plan_digest is None:
        raise ConfigurationError(
            "--apply requires the plan digest from a prior reconciliation preview"
        )

    _ensure_supervisor_state_parent(state_path)
    with SQLiteSupervisorStore(state_path) as store:
        if command in {"start", "pause", "resume", "drain", "stop"}:
            target = {
                "start": SupervisorMode.RUNNING,
                "pause": SupervisorMode.PAUSED,
                "resume": SupervisorMode.RUNNING,
                "drain": SupervisorMode.DRAINING,
                "stop": SupervisorMode.STOP_REQUESTED,
            }[command]
            current = store.current_control()
            expected = (
                current.revision
                if arguments.expected_revision is None
                else arguments.expected_revision
            )
            updated = store.update_control(
                expected_revision=expected,
                mode=target,
                actor_id=arguments.actor,
                reason_code=f"operator_{command}",
            )
            payload = {
                "mode": updated.mode.value,
                "control_revision": updated.revision,
                "dispatch_enabled": False,
                "foreground_process_started": False,
            }
            _emit(
                payload,
                json_output=arguments.json,
                human=(
                    f"supervisor requested: {updated.mode.value} "
                    f"rev={updated.revision}; run `ordomata supervise` in foreground"
                ),
            )
            return 0

        if command == "enqueue":
            prepared = prepare_chief_of_staff(root)
            now = time.time()
            flow_id = arguments.flow_id or f"flow-{uuid4().hex}"
            available_at = 0.0 if arguments.available_at is None else arguments.available_at
            spec = FlowSpec(
                flow_id=flow_id,
                admission_key=arguments.admission_key,
                task_id=prepared.contract.task_id,
                task_version=prepared.contract.version,
                task_definition_digest=_digest_hex(
                    prepared.contract.definition_hash, "task definition digest"
                ),
                context_digest=_digest_hex(
                    prepared.context_pack.snapshot_hash, "context digest"
                ),
                runner_id="mock",
                profile_id="mock.deterministic.local-draft",
                permission_class=prepared.contract.permission_class,
                resource_keys=("task:chief-of-staff.lite",),
                available_at=available_at,
                deadline_at=arguments.deadline_at,
                attempt_timeout_seconds=arguments.attempt_timeout_seconds,
                mandatory_priority=int(arguments.mandatory),
                blocker_priority=int(arguments.blocker),
                value_priority=arguments.value_priority,
                evidence_priority=arguments.evidence_priority,
                capacity_fit_priority=arguments.capacity_fit_priority,
                max_attempts=arguments.max_attempts,
                created_at=now,
            )
            stored, created = store.admit_flow(spec)
            revision = store.current_flow_revision(stored.flow_id)
            payload = {
                "flow_id": stored.flow_id,
                "admission_key": stored.admission_key,
                "request_digest": stored.request_digest,
                "state": revision.state.value,
                "revision": revision.revision,
                "created": created,
                "runner_id": stored.runner_id,
                "permission_class": int(stored.permission_class),
                "dispatch_enabled": False,
            }
            _emit(
                payload,
                json_output=arguments.json,
                human=(
                    f"flow {stored.flow_id}: {revision.state.value}; "
                    f"{'admitted' if created else 'idempotent replay'}; dispatch disabled"
                ),
            )
            return 0

        if command == "cancel":
            revision = store.request_cancellation(
                arguments.flow_id,
                requested_by=arguments.actor,
                reason_code=arguments.reason,
            )
            payload = {
                "flow_id": revision.flow_id,
                "state": revision.state.value,
                "revision": revision.revision,
                "cancellation_requested": revision.cancellation_requested,
            }
            _emit(
                payload,
                json_output=arguments.json,
                human=(
                    f"flow {revision.flow_id}: cancellation persisted; "
                    f"state={revision.state.value} rev={revision.revision}"
                ),
            )
            return 0

        if command == "reconcile":
            applied = store.apply_reconciliation(
                plan_digest=arguments.plan_digest,
                now=arguments.now,
            )
            payload = {
                "applied": True,
                "applied_count": len(applied),
                "plan_digest": arguments.plan_digest,
                "actions": [finding.to_mapping() for finding in applied],
            }
            _emit(
                payload,
                json_output=arguments.json,
                human=f"reconciliation applied: {len(applied)} action(s)",
            )
            return 0

        if command == "ack-completion":
            receipt = store.acknowledge_completion(
                arguments.outbox_id,
                consumer_id=arguments.consumer,
                result_digest=arguments.result_digest,
                delivery_id=arguments.delivery_id,
            )
            payload = {
                "receipt_id": receipt.receipt_id,
                "outbox_id": receipt.outbox_id,
                "idempotency_key": receipt.idempotency_key,
                "consumer_id": receipt.consumer_id,
                "result_digest": receipt.result_digest,
                "delivered_at": receipt.delivered_at,
            }
            _emit(
                payload,
                json_output=arguments.json,
                human=f"completion acknowledged: {receipt.outbox_id}",
            )
            return 0

    raise ConfigurationError(f"unsupported supervisor command: {command}")


def _load_profiles(root: Path) -> tuple[ExecutionProfile, ...]:
    return load_execution_profiles(root / DEFAULT_PROFILE_PATH)


async def _route_profiles(root: Path, *, lane: str) -> dict[str, Any]:
    profiles = _load_profiles(root)
    prepared = prepare_chief_of_staff(root)
    if lane == "mock":
        relevant_runners = (MockRunner(),)
    else:
        loader = _billing_attestation_loader(root)
        relevant_runners = (
            CodexRunner(billing_attestation_loader=loader),
            ClaudeRunner(billing_attestation_loader=loader),
        )
    doctor = await collect_doctor_report(
        relevant_runners,
        workspace=root,
        run_root=resolve_state_root(root) / "runs",
    )
    diagnostics = {item.runner_id: item for item in doctor.runners}
    states: list[RuntimeProfileState] = []
    durable_blockers: dict[str, str] = {}
    for profile in profiles:
        diagnostic = diagnostics.get(profile.runner_id)
        if diagnostic is None:
            assessment = BillingRouteAssessment(
                runner_id=profile.runner_id,
                route=BillingRoute.UNKNOWN,
                confidence=AssessmentConfidence.LOW,
            )
            available = False
        else:
            assessment = _assessment_from_diagnostic(diagnostic)
            durable_blocker = _durable_billing_blocker(
                root,
                profile=profile,
                assessment=assessment,
            )
            if durable_blocker is not None:
                durable_blockers[profile.profile_id] = durable_blocker
            available = diagnostic.ready_now and durable_blocker is None
        states.append(
            RuntimeProfileState(
                profile=profile,
                billing_assessment=assessment,
                available=available,
            )
        )
    features = _chief_of_staff_routing_features(prepared, lane=lane)
    decision = ProfileRouter().route(features, states)
    ranked = {
        item.state.profile.profile_id: list(item.score_vector)
        for item in decision.ranked
    }
    rejected = {
        item.profile_id: list(item.reasons) for item in decision.rejected
    }
    rows: list[dict[str, Any]] = []
    for profile in profiles:
        diagnostic = diagnostics.get(profile.runner_id)
        runtime = (
            {
                "probed": False,
                "billing_route": "unknown",
                "billing_confidence": "low",
                "ready_now": False,
                "blockers": ["runner_not_probed_in_selected_lane"],
            }
            if diagnostic is None
            else {
                "probed": True,
                "billing_route": diagnostic.billing_route,
                "billing_confidence": diagnostic.billing_confidence,
                "ready_now": (
                    diagnostic.ready_now
                    and profile.profile_id not in durable_blockers
                ),
                "blockers": list(
                    dict.fromkeys(
                        (
                            *diagnostic.blockers,
                            *(
                                (durable_blockers[profile.profile_id],)
                                if profile.profile_id in durable_blockers
                                else ()
                            ),
                        )
                    )
                ),
            }
        )
        if profile.profile_id in ranked:
            rows.append(
                {
                    "profile_id": profile.profile_id,
                    "disposition": "eligible",
                    "score_vector": ranked[profile.profile_id],
                    "reasons": [],
                    "runtime": runtime,
                }
            )
        else:
            rows.append(
                {
                    "profile_id": profile.profile_id,
                    "disposition": "rejected",
                    "score_vector": None,
                    "reasons": rejected.get(profile.profile_id, ["not evaluated"]),
                    "runtime": runtime,
                }
            )
    return {
        "lane": lane,
        "task_id": prepared.contract.task_id,
        "context_snapshot": prepared.context_pack.snapshot_hash,
        "selected_profile": (
            None if decision.selected is None else decision.selected.profile.profile_id
        ),
        "score_dimensions": list(ProfileRouter.score_dimensions()),
        "profiles": rows,
    }


async def _run_profile(
    root: Path,
    *,
    profile_id: str,
    run_id: str | None,
    operator_instructions: Sequence[str],
) -> dict[str, Any]:
    selected_run_id = run_id or f"cos-{uuid4().hex}"
    profiles = _load_profiles(root)
    matches = [profile for profile in profiles if profile.profile_id == profile_id]
    if len(matches) != 1:
        raise ConfigurationError(f"unknown execution profile: {profile_id}")
    profile = matches[0]
    runner_overrides = runner_overrides_for_profile(profile)
    if profile.runner_id == "mock":
        runner = MockRunner()
        lane = "mock"
    elif profile.runner_id == "codex":
        runner = CodexRunner(
            billing_attestation_loader=_billing_attestation_loader(root)
        )
        lane = "subscription"
    elif profile.runner_id == "claude":
        runner = ClaudeRunner(
            billing_attestation_loader=_billing_attestation_loader(root)
        )
        lane = "subscription"
    else:
        raise ConfigurationError(
            f"runner adapter is not implemented: {profile.runner_id}"
        )

    # An explicit profile selection bypasses ranking, not eligibility.  Build
    # the exact task/context features and route the sole candidate through the
    # same hard filters used by `ordomata route` before any runner executes.
    prepared = prepare_chief_of_staff(
        root, operator_instructions=operator_instructions
    )
    if profile.runner_id == "mock":
        runner = MockRunner(
            output=load_mock_chief_of_staff_output(root, prepared)
        )
    doctor = await collect_doctor_report(
        (runner,),
        workspace=root,
        run_root=resolve_state_root(root) / "runs",
    )
    if len(doctor.runners) != 1:
        raise ConfigurationError("selected runner diagnostic failed closed")
    diagnostic = doctor.runners[0]
    assessment = _assessment_from_diagnostic(diagnostic)
    durable_blocker = _durable_billing_blocker(
        root,
        profile=profile,
        assessment=assessment,
    )
    state = RuntimeProfileState(
        profile=profile,
        billing_assessment=assessment,
        available=diagnostic.ready_now and durable_blocker is None,
    )
    routing_features = _chief_of_staff_routing_features(prepared, lane=lane)
    evaluated_at = time.time()
    required_valid_until = (
        evaluated_at
        + prepared.contract.timeout_seconds
        + LIVE_RUN_EVIDENCE_MARGIN_SECONDS
    )
    decision = ProfileRouter().route(
        routing_features,
        (state,),
        evaluated_at=evaluated_at,
        required_valid_until=required_valid_until,
    )
    if decision.blocked:
        reasons = list(decision.rejected[0].reasons)
        if diagnostic.blockers:
            reasons.append("diagnostic blockers: " + ", ".join(diagnostic.blockers))
        if durable_blocker is not None:
            reasons.append(durable_blocker)
        raise ConfigurationError(
            f"profile {profile.profile_id} is ineligible: " + "; ".join(reasons)
        )

    execution_selection = build_execution_selection(
        run_id=selected_run_id,
        selection_mode="operator_explicit",
        task=routing_features,
        candidates=(state,),
        task_definition_digest=prepared.contract.definition_hash,
        context_digest=prepared.context_pack.snapshot_hash,
        authorization_intent_digest=task_authorization_intent_digest(
            prepared.contract
        ),
        evaluated_at=evaluated_at,
        required_valid_until=required_valid_until,
    )

    if profile.runner_id == "mock":
        report = await run_chief_of_staff(
            root,
            runner=runner,
            runner_overrides=runner_overrides,
            run_id=selected_run_id,
            profile_id=profile.profile_id,
            prepared_task=prepared,
            execution_selection=execution_selection,
        )
        return report.to_mapping()

    state_path = _billing_state_path(root)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with SQLiteStateStore(state_path) as billing_state:
        billing_circuit_guard = SQLiteBillingCircuitGuard(
            billing_state,
            profile_id=profile.profile_id,
        )
        if profile.runner_id == "codex":
            runner = CodexRunner(
                billing_attestation_loader=_billing_attestation_loader(root),
                billing_circuit_guard=billing_circuit_guard,
            )
        else:
            runner = ClaudeRunner(
                billing_attestation_loader=_billing_attestation_loader(root),
                billing_circuit_guard=billing_circuit_guard,
            )
        report = await run_chief_of_staff(
            root,
            runner=runner,
            runner_overrides=runner_overrides,
            run_id=selected_run_id,
            profile_id=profile.profile_id,
            prepared_task=prepared,
            execution_selection=execution_selection,
        )
    return report.to_mapping()


def _chief_of_staff_routing_features(
    prepared: PreparedTask,
    *,
    lane: str,
) -> TaskRoutingFeatures:
    return chief_of_staff_routing_features(prepared, lane=lane)


def _assessment_from_diagnostic(
    diagnostic: RunnerDiagnostic,
) -> BillingRouteAssessment:
    return BillingRouteAssessment(
        runner_id=diagnostic.runner_id,
        route=BillingRoute(diagnostic.billing_route),
        confidence=AssessmentConfidence(diagnostic.billing_confidence),
        subscription_name=diagnostic.subscription_name,
        evidence=diagnostic.billing_evidence,
        warnings=diagnostic.billing_warnings,
        risky_environment_names=diagnostic.environment.risky_names,
        capacity_state=getattr(
            diagnostic, "capacity_state", CapacityState.UNKNOWN
        ),
        paid_continuation_protection=getattr(
            diagnostic,
            "paid_continuation_protection",
            PaidContinuationProtection.UNKNOWN,
        ),
        paid_credit_balance=getattr(
            diagnostic, "paid_credit_balance", PaidCreditBalance.UNKNOWN
        ),
        account_identity_fingerprint=getattr(
            diagnostic, "account_identity_fingerprint", None
        ),
        capacity_observed_at=getattr(
            diagnostic, "capacity_observed_at", None
        ),
        capacity_expires_at=getattr(
            diagnostic, "capacity_expires_at", None
        ),
        attestation=getattr(diagnostic, "attestation", None),
    )


def _profile_mapping(profile: ExecutionProfile) -> dict[str, Any]:
    return {
        "profile_id": profile.profile_id,
        "version": profile.version,
        "runner_id": profile.runner_id,
        "model_id": profile.model_id,
        "role": profile.role,
        "settings": dict(profile.settings),
        "capabilities": sorted(profile.capabilities),
        "task_kinds": sorted(profile.task_kinds),
        "allowed_billing_routes": sorted(
            route.value for route in profile.allowed_billing_routes
        ),
        "max_permission_class": int(profile.max_permission_class),
        "quality_prior": profile.quality_prior,
        "latency_prior_seconds": profile.latency_prior_seconds,
    }


def _comparison_plan(
    root: Path,
    *,
    runner_ids: tuple[str, ...],
    repetitions: int,
    random_seed: int,
    comparison_id: str | None,
) -> dict[str, Any]:
    prepared = prepare_chief_of_staff(root)
    snapshot = ComparisonSnapshot(
        task_id=prepared.contract.task_id,
        task_version=prepared.contract.version,
        task_text=prepared.prompt,
        repository_revision=f"local-fixture:{prepared.contract.definition_hash}",
        context_digest=prepared.context_pack.snapshot_hash,
        verification_commands=(("deterministic-evaluator", "chief-of-staff-lite"),),
        permission_class=prepared.contract.permission_class,
    )
    selected_id = comparison_id or f"cos-{snapshot.digest[:12]}-{random_seed}"
    plan = ComparisonPlan.create(
        comparison_id=selected_id,
        snapshot=snapshot,
        runner_ids=runner_ids,
        repetitions=repetitions,
        random_seed=random_seed,
    )
    return {
        "comparison_id": plan.comparison_id,
        "snapshot_digest": plan.snapshot.digest,
        "context_digest": plan.snapshot.context_digest,
        "runner_ids": list(plan.runner_ids),
        "repetitions": plan.repetitions,
        "random_seed": plan.random_seed,
        "fresh_session_per_trial": True,
        "no_execution_performed": True,
        "trials": [
            {
                "trial_id": trial.trial_id,
                "runner_id": trial.runner_id,
                "repetition": trial.repetition,
                "order_index": trial.order_index,
                "snapshot_digest": trial.snapshot_digest,
            }
            for trial in plan.trials
        ],
    }


async def _run_controlled_profile_comparison(
    root: Path,
    *,
    profile_ids: tuple[str, ...],
    repetitions: int,
    random_seed: int,
    comparison_id: str | None,
) -> dict[str, Any]:
    if len(profile_ids) < 2:
        raise ConfigurationError("compare-run requires at least two profiles")
    if len(set(profile_ids)) != len(profile_ids):
        raise ConfigurationError("compare-run profile identifiers must be unique")
    available_profiles = _load_profiles(root)
    by_id = {profile.profile_id: profile for profile in available_profiles}
    missing = [profile_id for profile_id in profile_ids if profile_id not in by_id]
    if missing:
        raise ConfigurationError(
            "unknown comparison profiles: " + ", ".join(missing)
        )
    selected_profiles = tuple(by_id[profile_id] for profile_id in profile_ids)
    runner_ids = {profile.runner_id for profile in selected_profiles}
    if "mock" in runner_ids and runner_ids != {"mock"}:
        raise ConfigurationError(
            "mock and live subscription profiles cannot share one comparison"
        )
    unsupported = sorted(runner_ids - {"codex", "claude", "mock"})
    if unsupported:
        raise ConfigurationError(
            "comparison runner adapters are not implemented: "
            + ", ".join(unsupported)
        )

    prepared = prepare_chief_of_staff(root)
    snapshot = comparison_snapshot_from_prepared(prepared)
    selected_id = comparison_id or f"compare-{snapshot.digest[:12]}-{random_seed}"
    plan = ControlledComparisonPlan.create(
        comparison_id=selected_id,
        snapshot=snapshot,
        profiles=tuple(
            ComparisonProfile.from_execution_profile(profile)
            for profile in selected_profiles
        ),
        repetitions=repetitions,
        random_seed=random_seed,
    )

    diagnostic_runners = tuple(
        _comparison_runner(runner_id, root=root, prepared=prepared)
        for runner_id in sorted(runner_ids)
    )
    doctor = await collect_doctor_report(
        diagnostic_runners,
        workspace=root,
        run_root=resolve_state_root(root) / "comparisons",
    )
    diagnostics = {item.runner_id: item for item in doctor.runners}
    allowed_route = (
        BillingRoute.MOCK
        if runner_ids == {"mock"}
        else BillingRoute.SUBSCRIPTION_INCLUDED
    )
    features = TaskRoutingFeatures(
        task_kind="chief_of_staff",
        permission_class=snapshot.permission_class,
        required_capabilities=frozenset(
            {"structured_output", "isolated_workspace"}
        ),
        allowed_roles=frozenset(profile.role for profile in selected_profiles),
        allowed_billing_routes=frozenset({allowed_route}),
        context_bytes=prepared.context_pack.raw_bytes,
        risk=0,
    )
    blockers: list[str] = []
    for profile in selected_profiles:
        diagnostic = diagnostics.get(profile.runner_id)
        if diagnostic is None:
            blockers.append(f"{profile.profile_id}: runner was not diagnosed")
            continue
        assessment = _assessment_from_diagnostic(diagnostic)
        durable_blocker = _durable_billing_blocker(
            root,
            profile=profile,
            assessment=assessment,
        )
        state = RuntimeProfileState(
            profile=profile,
            billing_assessment=assessment,
            available=diagnostic.ready_now and durable_blocker is None,
        )
        decision = ProfileRouter().route(features, (state,))
        if decision.blocked:
            reasons = list(decision.rejected[0].reasons)
            reasons.extend(diagnostic.blockers)
            if durable_blocker is not None:
                reasons.append(durable_blocker)
            blockers.append(
                f"{profile.profile_id}: " + ", ".join(dict.fromkeys(reasons))
            )
    if blockers:
        raise ConfigurationError(
            "controlled comparison is ineligible: " + "; ".join(blockers)
        )

    if runner_ids == {"mock"}:
        report = await run_controlled_comparison(
            root,
            prepared=prepared,
            plan=plan,
            profiles=selected_profiles,
            runner_factory=lambda profile: _comparison_runner(
                profile.runner_id,
                root=root,
                prepared=prepared,
            ),
        )
    else:
        state_path = _billing_state_path(root)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with SQLiteStateStore(state_path) as billing_state:
            report = await run_controlled_comparison(
                root,
                prepared=prepared,
                plan=plan,
                profiles=selected_profiles,
                runner_factory=lambda profile: _comparison_runner(
                    profile.runner_id,
                    root=root,
                    prepared=prepared,
                    billing_circuit_guard=SQLiteBillingCircuitGuard(
                        billing_state,
                        profile_id=profile.profile_id,
                    ),
                ),
            )
    return report.to_mapping()


def _comparison_runner(
    runner_id: str,
    *,
    root: Path,
    prepared: PreparedTask,
    billing_circuit_guard: SQLiteBillingCircuitGuard | None = None,
):
    if runner_id == "mock":
        return MockRunner(output=load_mock_chief_of_staff_output(root, prepared))
    if runner_id == "codex":
        return CodexRunner(
            billing_attestation_loader=_billing_attestation_loader(root),
            billing_circuit_guard=billing_circuit_guard,
        )
    if runner_id == "claude":
        return ClaudeRunner(
            billing_attestation_loader=_billing_attestation_loader(root),
            billing_circuit_guard=billing_circuit_guard,
        )
    raise ConfigurationError(f"runner adapter is not implemented: {runner_id}")


def _billing_attestation_loader(root: Path) -> FileBillingAttestationLoader:
    return FileBillingAttestationLoader(
        resolve_state_root(root) / "billing-attestations.json"
    )


def _billing_attestation_runner(runner_id: str):
    """Return an unadorned diagnostic adapter that cannot self-renew evidence."""

    if runner_id == "codex":
        return CodexRunner()
    if runner_id == "claude":
        return ClaudeRunner()
    raise ConfigurationError(f"billing attest runner is unsupported: {runner_id}")


def _billing_state_path(root: Path) -> Path:
    state_path = resolve_state_root(root) / "state.sqlite3"
    if state_path.is_symlink():
        raise ConfigurationError("billing state database must not be a symlink")
    return state_path


def _durable_billing_blocker(
    root: Path,
    *,
    profile: ExecutionProfile,
    assessment: BillingRouteAssessment,
) -> str | None:
    """Return a sanitized blocker when persisted billing state forbids dispatch."""

    if assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED:
        return None
    try:
        state_path = _billing_state_path(root)
        if not state_path.exists():
            return None
        with SQLiteStateStore(state_path) as billing_state:
            SQLiteBillingCircuitGuard(
                billing_state,
                profile_id=profile.profile_id,
            ).assert_closed(assessment)
    except BillingRouteBlocked:
        return "durable_billing_state_blocks_dispatch"
    except Exception:
        return "durable_billing_state_unverifiable"
    return None


def _schedule_inspection(arguments: argparse.Namespace) -> dict[str, Any]:
    schedule = IntervalSchedule(
        schedule_id=arguments.schedule_id,
        task_id="chief-of-staff.lite",
        interval_seconds=arguments.interval_seconds,
        timeout_seconds=arguments.timeout_seconds,
        anchor_at=arguments.anchor_at,
        misfire_grace_seconds=arguments.misfire_grace_seconds,
        resource_keys=("task:chief-of-staff.lite",),
    )
    now = time.time() if arguments.now is None else arguments.now
    with SQLiteStateStore(":memory:") as state:
        decision = RunOnceScheduler(state, clock=lambda: now).inspect(
            schedule, now=now
        )
    return {
        "schedule_id": schedule.schedule_id,
        "task_id": schedule.task_id,
        "now": now,
        "reason": decision.reason.value,
        "mutated_state": False,
        "installed_os_schedule": False,
        "slot": (
            None
            if decision.slot is None
            else {
                "slot_id": decision.slot.slot_id,
                "slot_index": decision.slot.slot_index,
                "scheduled_for": decision.slot.scheduled_for,
            }
        ),
    }


def _doctor_text(report: DoctorReport) -> str:
    lines = [
        "local control plane: "
        + ("ready" if report.local_control_plane_ready else "blocked"),
        "live subscription gate: "
        + ("enabled" if report.live_gate.enabled else "disabled"),
    ]
    for runner in report.runners:
        lines.append(
            f"{runner.runner_id}: "
            f"{'ready' if runner.ready_now else 'blocked'}; "
            f"billing={runner.billing_route}/{runner.billing_confidence}"
        )
    return "\n".join(lines)


def _run_text(report: dict[str, Any]) -> str:
    lines = [
        f"run {report['run_id']}: {report['status']}",
        f"runner: {report['runner_id']}",
        f"snapshot: {report['context_snapshot']}",
    ]
    if report.get("artifact_path"):
        lines.append(f"artifact: {report['artifact_path']}")
    return "\n".join(lines)


def _authorization_inspection_text(
    report: AuthorizationInspectionReport,
) -> str:
    state = "clean" if report.clean else "attention required"
    lines = [
        f"authorization shadow evidence: {state}",
        (
            f"runs={report.inspected_run_count} "
            f"events={report.inspected_event_count} "
            f"parity_mismatches={report.parity_mismatch_count} "
            f"authority_ceiling_mismatches="
            f"{report.authority_ceiling_mismatch_count} "
            f"coverage_gaps={report.coverage_gap_count} "
            f"integrity_issues={report.integrity_issue_count}"
        ),
    ]
    if not report.database_present:
        lines.append("state database absent; no runs inspected")
    if report.truncated:
        lines.append("inspection limit reached; narrow with --run-id")
    for run in report.runs:
        run_label = run.run_id if run.run_id is not None else run.run_ref
        missing = ",".join(run.missing_scopes) or "none"
        lines.append(
            f"{run_label}: status={run.latest_status or 'unknown'} "
            f"missing={missing} "
            f"attention={'yes' if run.attention_required else 'no'}"
        )
    return "\n".join(lines)


def _emit(payload: dict[str, Any], *, json_output: bool, human: str) -> None:
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(human)


if __name__ == "__main__":
    raise SystemExit(main())
