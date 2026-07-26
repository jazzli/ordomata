"""Versioned, runner-neutral task contracts.

Task definitions describe durable workflow intent.  Harness adapters may
translate the contract, but they do not own task policy, limits, evaluation,
or approval requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from .errors import ConfigurationError, ValidationError
from .authorization import ActionVerb, BlastRadius, ImpactLevel, Reach
from .models import PermissionClass
from .schema import SchemaValidator, parse_json_document, require_valid


_AUTHORIZATION_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]{0,119}")


def _validate_authorization_identifier(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or _AUTHORIZATION_IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError(f"{name} must be a bounded authorization identifier")


@dataclass(frozen=True, slots=True)
class TaskInputSpec:
    name: str
    kind: str
    description: str
    required: bool = True
    source_types: tuple[str, ...] = ()
    fixture_path: str | None = None


@dataclass(frozen=True, slots=True)
class ContextSelectionRules:
    strategy: str
    query: str
    max_candidates: int
    max_sources: int
    max_bytes: int
    max_approximate_tokens: int
    include_source_types: tuple[str, ...] = ()
    exclude_source_ids: tuple[str, ...] = ()
    selection_rules: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExpectedOutputSpec:
    artifact_kind: str
    format: str
    description: str
    local_destination: str


@dataclass(frozen=True, slots=True)
class TimeLimits:
    wall_seconds: int
    idle_seconds: int


@dataclass(frozen=True, slots=True)
class AttemptLimits:
    max_attempts: int
    max_repairs_per_attempt: int
    retry_backoff_seconds: int


@dataclass(frozen=True, slots=True)
class EvaluationCriterion:
    criterion_id: str
    description: str
    evaluator: str
    required: bool
    parameters: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ApprovalRequirements:
    required_before_run: bool
    required_before_promotion: bool
    approver: str
    allowed_permission_classes: tuple[PermissionClass, ...]


@dataclass(frozen=True, slots=True)
class SchedulingPolicy:
    mode: str
    enabled: bool
    interval_seconds: int | None
    max_concurrent_runs: int
    prevent_duplicate_runs: bool
    resource_guards: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TaskActionIntent:
    """Typed description of the task effect, independent of its legacy class."""

    verb: ActionVerb
    operation: str
    intended_effect: str

    def __post_init__(self) -> None:
        if not isinstance(self.verb, ActionVerb):
            raise ValueError("task action verb must be an ActionVerb")
        _validate_authorization_identifier("task operation", self.operation)
        _validate_authorization_identifier(
            "task intended effect", self.intended_effect
        )

    def to_canonical(self) -> dict[str, Any]:
        return {
            "intended_effect": self.intended_effect,
            "operation": self.operation,
            "verb": self.verb.value,
        }


@dataclass(frozen=True, slots=True)
class TaskResourceIntent:
    """Controller-resolved resource category for the intended task effect."""

    resource_type: str
    trust_boundary: str
    protected: bool
    sensitivity: ImpactLevel

    def __post_init__(self) -> None:
        _validate_authorization_identifier(
            "task resource type", self.resource_type
        )
        _validate_authorization_identifier(
            "task trust boundary", self.trust_boundary
        )
        if not isinstance(self.protected, bool):
            raise ValueError("task resource protected must be a boolean")
        if not isinstance(self.sensitivity, ImpactLevel):
            raise ValueError("task resource sensitivity must be an ImpactLevel")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "protected": self.protected,
            "resource_type": self.resource_type,
            "sensitivity": self.sensitivity.value,
            "trust_boundary": self.trust_boundary,
        }


@dataclass(frozen=True, slots=True)
class TaskAuthorizationIntent:
    """Explicit task-effect attributes consumed by the shadow ABAC bridge.

    Exact identifiers, versions, content digests, environment evidence, and
    enforcement-point scope remain controller-owned runtime facts.
    """

    action: TaskActionIntent
    resource: TaskResourceIntent
    consequences: "TaskConsequenceIntent"

    def __post_init__(self) -> None:
        if not isinstance(self.action, TaskActionIntent):
            raise ValueError("task authorization action intent is invalid")
        if not isinstance(self.resource, TaskResourceIntent):
            raise ValueError("task authorization resource intent is invalid")
        if not isinstance(self.consequences, TaskConsequenceIntent):
            raise ValueError("task authorization consequence intent is invalid")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "action": self.action.to_canonical(),
            "consequences": self.consequences.to_canonical(),
            "resource": self.resource.to_canonical(),
        }

    @property
    def digest(self) -> str:
        return _canonical_hash(self.to_canonical())


@dataclass(frozen=True, slots=True)
class TaskConsequenceIntent:
    """Project consequence vector using the adopted impact vocabulary."""

    confidentiality: ImpactLevel
    integrity: ImpactLevel
    availability: ImpactLevel
    reach: Reach
    destructive: bool
    reversible: bool
    sensitivity: ImpactLevel
    blast_radius: BlastRadius

    def __post_init__(self) -> None:
        for name, value in (
            ("confidentiality", self.confidentiality),
            ("integrity", self.integrity),
            ("availability", self.availability),
            ("sensitivity", self.sensitivity),
        ):
            if not isinstance(value, ImpactLevel):
                raise ValueError(f"task consequence {name} must be an ImpactLevel")
        if not isinstance(self.reach, Reach):
            raise ValueError("task consequence reach must be a Reach")
        if not isinstance(self.blast_radius, BlastRadius):
            raise ValueError("task consequence blast radius must be a BlastRadius")
        if not isinstance(self.destructive, bool) or not isinstance(
            self.reversible, bool
        ):
            raise ValueError(
                "task consequence destructive and reversible must be booleans"
            )

    def to_canonical(self) -> dict[str, Any]:
        return {
            "availability": self.availability.value,
            "blast_radius": self.blast_radius.value,
            "confidentiality": self.confidentiality.value,
            "destructive": self.destructive,
            "integrity": self.integrity.value,
            "reach": self.reach.value,
            "reversible": self.reversible,
            "sensitivity": self.sensitivity.value,
        }


@dataclass(frozen=True, slots=True)
class TaskContract:
    """Fully resolved neutral task definition."""

    task_id: str
    version: str
    prompt_version: str
    purpose: str
    inputs: tuple[TaskInputSpec, ...]
    context_selection: ContextSelectionRules
    expected_output: ExpectedOutputSpec
    output_schema_reference: str
    output_schema: Mapping[str, Any] = field(repr=False)
    permission_class: PermissionClass
    authorization_intent: TaskAuthorizationIntent | None
    time_limits: TimeLimits
    attempt_limits: AttemptLimits
    evaluation_criteria: tuple[EvaluationCriterion, ...]
    approval_requirements: ApprovalRequirements
    scheduling_policy: SchedulingPolicy
    instructions: tuple[str, ...]
    runner_overrides: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    definition_hash: str = ""

    @property
    def timeout_seconds(self) -> int:
        return self.time_limits.wall_seconds

    @property
    def max_attempts(self) -> int:
        return self.attempt_limits.max_attempts


_FORBIDDEN_OVERRIDE_FRAGMENTS = (
    "api_key",
    "apikey",
    "auth_token",
    "oauth_token",
    "endpoint",
    "base_url",
    "billing",
    "bedrock",
    "vertex",
    "foundry",
    "openrouter",
    "allow_api",
)


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        document = parse_json_document(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"cannot read JSON file {path}: {exc}") from exc
    except ValidationError as exc:
        raise ConfigurationError(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError(f"expected a JSON object in {path}")
    return document


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _validate_local_destination(value: str) -> None:
    destination = PurePosixPath(value)
    if destination.is_absolute() or ".." in destination.parts:
        raise ConfigurationError("expected_output.local_destination must be a relative local path without '..'")


def _validate_supported_execution_limits(
    time_limits: Mapping[str, Any], attempt_limits: Mapping[str, Any]
) -> None:
    """Fail closed when a task asks for control-plane behavior not implemented yet.

    The current executor has one wall-clock timeout and one attempt.  An idle
    limit at least as long as the wall limit is redundant and therefore safe;
    a shorter idle limit would promise enforcement that does not exist.
    """

    if time_limits["idle_seconds"] < time_limits["wall_seconds"]:
        raise ConfigurationError(
            "distinct idle timeout enforcement is not implemented; "
            "idle_seconds must be greater than or equal to wall_seconds"
        )
    if (
        attempt_limits["max_attempts"] != 1
        or attempt_limits["max_repairs_per_attempt"] != 0
        or attempt_limits["retry_backoff_seconds"] != 0
    ):
        raise ConfigurationError(
            "retry and repair execution is not implemented; require "
            "max_attempts=1, max_repairs_per_attempt=0, and retry_backoff_seconds=0"
        )


def _walk_override_keys(value: Any, prefix: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            location = f"{prefix}.{key}" if prefix else str(key)
            if any(fragment in normalized for fragment in _FORBIDDEN_OVERRIDE_FRAGMENTS):
                raise ConfigurationError(f"runner override {location!r} may alter credentials or billing route")
            _walk_override_keys(child, location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_override_keys(child, f"{prefix}[{index}]")


def _resolve_output_schema(specification: Mapping[str, Any], task_path: Path) -> tuple[str, dict[str, Any]]:
    if "path" in specification:
        reference = str(specification["path"])
        schema_path = (task_path.parent / reference).resolve()
        schema = _load_json_object(schema_path)
    else:
        reference = "inline"
        inline = specification.get("inline")
        if not isinstance(inline, dict):
            raise ConfigurationError("output_schema must contain either 'path' or 'inline'")
        schema = dict(inline)
    try:
        SchemaValidator(schema)
    except ValidationError as exc:
        raise ConfigurationError(f"invalid output schema {reference!r}: {exc}") from exc
    return reference, schema


def load_task_contract(
    path: str | Path,
    *,
    definition_schema_path: str | Path | None = None,
) -> TaskContract:
    """Load, strictly validate, resolve, and semantically check a task file."""

    task_path = Path(path).resolve()
    raw = _load_json_object(task_path)
    if definition_schema_path is None:
        definition_schema_path = task_path.parent.parent / "schemas" / "task-definition.schema.json"
    definition_schema = _load_json_object(Path(definition_schema_path).resolve())
    try:
        require_valid(raw, definition_schema)
    except ValidationError as exc:
        raise ConfigurationError(f"task definition {task_path} is invalid: {exc}") from exc

    permission_class = PermissionClass(raw["permission_class"])
    if permission_class not in (PermissionClass.READ_ONLY, PermissionClass.LOCAL_DRAFT):
        raise ConfigurationError("only permission classes 0 and 1 are enabled at this stage")

    approval_raw = raw["approval_requirements"]
    allowed_classes = tuple(PermissionClass(value) for value in approval_raw["allowed_permission_classes"])
    if any(value not in (PermissionClass.READ_ONLY, PermissionClass.LOCAL_DRAFT) for value in allowed_classes):
        raise ConfigurationError("approval requirements may enable only permission classes 0 and 1")
    if permission_class not in allowed_classes:
        raise ConfigurationError("task permission_class must appear in approval_requirements.allowed_permission_classes")

    output_reference, output_schema = _resolve_output_schema(raw["output_schema"], task_path)
    _validate_local_destination(raw["expected_output"]["local_destination"])
    _walk_override_keys(raw["runner_overrides"])

    context_raw = raw["context_selection"]
    time_raw = raw["time_limits"]
    attempts_raw = raw["attempt_limits"]
    schedule_raw = raw["scheduling_policy"]
    _validate_supported_execution_limits(time_raw, attempts_raw)
    if schedule_raw["mode"] == "fixed_interval" and schedule_raw["interval_seconds"] is None:
        raise ConfigurationError("fixed_interval scheduling requires interval_seconds")
    if schedule_raw["mode"] == "manual" and schedule_raw["interval_seconds"] is not None:
        raise ConfigurationError("manual scheduling must not define interval_seconds")

    inputs = tuple(
        TaskInputSpec(
            name=item["name"],
            kind=item["kind"],
            description=item["description"],
            required=item["required"],
            source_types=tuple(item["source_types"]),
            fixture_path=item.get("fixture_path"),
        )
        for item in raw["inputs"]
    )
    input_names = [item.name for item in inputs]
    if len(input_names) != len(set(input_names)):
        raise ConfigurationError("task input names must be unique")

    criteria = tuple(
        EvaluationCriterion(
            criterion_id=item["criterion_id"],
            description=item["description"],
            evaluator=item["evaluator"],
            required=item["required"],
            parameters=dict(item["parameters"]),
        )
        for item in raw["evaluation_criteria"]
    )
    criterion_ids = [item.criterion_id for item in criteria]
    if len(criterion_ids) != len(set(criterion_ids)):
        raise ConfigurationError("evaluation criterion identifiers must be unique")

    intent_raw = raw.get("authorization_intent")
    authorization_intent: TaskAuthorizationIntent | None = None
    if intent_raw is not None:
        action_raw = intent_raw["action"]
        resource_raw = intent_raw["resource"]
        consequences_raw = intent_raw["consequences"]
        authorization_intent = TaskAuthorizationIntent(
            action=TaskActionIntent(
                verb=ActionVerb(action_raw["verb"]),
                operation=action_raw["operation"],
                intended_effect=action_raw["intended_effect"],
            ),
            resource=TaskResourceIntent(
                resource_type=resource_raw["resource_type"],
                trust_boundary=resource_raw["trust_boundary"],
                protected=resource_raw["protected"],
                sensitivity=ImpactLevel(resource_raw["sensitivity"]),
            ),
            consequences=TaskConsequenceIntent(
                confidentiality=ImpactLevel(consequences_raw["confidentiality"]),
                integrity=ImpactLevel(consequences_raw["integrity"]),
                availability=ImpactLevel(consequences_raw["availability"]),
                reach=Reach(consequences_raw["reach"]),
                destructive=consequences_raw["destructive"],
                reversible=consequences_raw["reversible"],
                sensitivity=ImpactLevel(consequences_raw["sensitivity"]),
                blast_radius=BlastRadius(consequences_raw["blast_radius"]),
            ),
        )

    return TaskContract(
        task_id=raw["task_id"],
        version=raw["version"],
        prompt_version=raw["prompt_version"],
        purpose=raw["purpose"],
        inputs=inputs,
        context_selection=ContextSelectionRules(
            strategy=context_raw["strategy"],
            query=context_raw["query"],
            max_candidates=context_raw["max_candidates"],
            max_sources=context_raw["max_sources"],
            max_bytes=context_raw["max_bytes"],
            max_approximate_tokens=context_raw["max_approximate_tokens"],
            include_source_types=tuple(context_raw["include_source_types"]),
            exclude_source_ids=tuple(context_raw["exclude_source_ids"]),
            selection_rules=tuple(context_raw["selection_rules"]),
        ),
        expected_output=ExpectedOutputSpec(
            artifact_kind=raw["expected_output"]["artifact_kind"],
            format=raw["expected_output"]["format"],
            description=raw["expected_output"]["description"],
            local_destination=raw["expected_output"]["local_destination"],
        ),
        output_schema_reference=output_reference,
        output_schema=output_schema,
        permission_class=permission_class,
        authorization_intent=authorization_intent,
        time_limits=TimeLimits(
            wall_seconds=time_raw["wall_seconds"],
            idle_seconds=time_raw["idle_seconds"],
        ),
        attempt_limits=AttemptLimits(
            max_attempts=attempts_raw["max_attempts"],
            max_repairs_per_attempt=attempts_raw["max_repairs_per_attempt"],
            retry_backoff_seconds=attempts_raw["retry_backoff_seconds"],
        ),
        evaluation_criteria=criteria,
        approval_requirements=ApprovalRequirements(
            required_before_run=approval_raw["required_before_run"],
            required_before_promotion=approval_raw["required_before_promotion"],
            approver=approval_raw["approver"],
            allowed_permission_classes=allowed_classes,
        ),
        scheduling_policy=SchedulingPolicy(
            mode=schedule_raw["mode"],
            enabled=schedule_raw["enabled"],
            interval_seconds=schedule_raw["interval_seconds"],
            max_concurrent_runs=schedule_raw["max_concurrent_runs"],
            prevent_duplicate_runs=schedule_raw["prevent_duplicate_runs"],
            resource_guards=tuple(schedule_raw["resource_guards"]),
        ),
        instructions=tuple(raw["instructions"]),
        runner_overrides={runner: dict(overrides) for runner, overrides in raw["runner_overrides"].items()},
        definition_hash=_canonical_hash(raw),
    )
