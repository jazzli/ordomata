"""Deterministic evaluation for structured local workflow artifacts."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from .context import ContextPack
from .errors import ConfigurationError, ValidationError
from .schema import SchemaValidationResult, parse_json_document, validate_instance


@dataclass(frozen=True, slots=True)
class EvaluationMetric:
    criterion_id: str
    passed: bool
    details: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {"criterion_id": self.criterion_id, "passed": self.passed, "details": list(self.details)}


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """A transparent metric vector, intentionally not a single opaque score."""

    metrics: tuple[EvaluationMetric, ...]

    @property
    def accepted(self) -> bool:
        return all(metric.passed for metric in self.metrics)

    def metric(self, criterion_id: str) -> EvaluationMetric:
        for metric in self.metrics:
            if metric.criterion_id == criterion_id:
                return metric
        raise KeyError(criterion_id)

    def to_mapping(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "metrics": [metric.to_mapping() for metric in self.metrics]}


def load_evaluation_expectations(path: str | Path) -> dict[str, Any]:
    fixture_path = Path(path)
    try:
        parsed = parse_json_document(fixture_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"cannot read evaluation expectations {fixture_path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValidationError("evaluation expectations must be a JSON object")
    expected_keys = {"minimum_items", "required_source_ids", "forbidden_output_phrases", "maximum_permission_class"}
    if set(parsed) != expected_keys:
        raise ValidationError(f"evaluation expectations must contain exactly {sorted(expected_keys)}")
    minimum_items = parsed["minimum_items"]
    if not isinstance(minimum_items, dict) or any(
        not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool) or value < 0
        for key, value in minimum_items.items()
    ):
        raise ValidationError("minimum_items must map section names to non-negative integers")
    for key in ("required_source_ids", "forbidden_output_phrases"):
        value = parsed[key]
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
            raise ValidationError(f"{key} must be an array of non-empty strings")
        if len(value) != len(set(value)):
            raise ValidationError(f"{key} must not contain duplicates")
    maximum = parsed["maximum_permission_class"]
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum not in (0, 1):
        raise ValidationError("maximum_permission_class must be 0 or 1")
    return parsed


def _schema_metric(result: SchemaValidationResult) -> EvaluationMetric:
    if result.valid:
        return EvaluationMetric("schema_valid", True, ("output matches the versioned schema",))
    return EvaluationMetric(
        "schema_valid",
        False,
        tuple(str(issue) for issue in result.issues[:20]),
    )


def _dependency_failure(criterion_id: str) -> EvaluationMetric:
    return EvaluationMetric(criterion_id, False, ("not evaluated because structured output is invalid",))


def _collect_source_refs(value: Any) -> list[str]:
    references: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "source_refs" and isinstance(child, list):
                references.extend(item for item in child if isinstance(item, str))
            else:
                references.extend(_collect_source_refs(child))
    elif isinstance(value, list):
        for child in value:
            references.extend(_collect_source_refs(child))
    return references


def _snapshot_metric(output: Mapping[str, Any], pack: ContextPack) -> EvaluationMetric:
    metadata = output["metadata"]
    mismatches: list[str] = []
    expected = {
        "task_id": pack.task_id,
        "task_version": pack.task_version,
        "prompt_version": pack.prompt_version,
        "snapshot_hash": pack.snapshot_hash,
    }
    for key, expected_value in expected.items():
        if metadata[key] != expected_value:
            mismatches.append(f"metadata.{key} does not match the immutable input snapshot")
    if not pack.verify_snapshot_hash():
        mismatches.append("context pack failed its own snapshot-hash verification")
    return EvaluationMetric("snapshot_match", not mismatches, tuple(mismatches or ["task, prompt, and snapshot metadata match"]))


def _grounding_metric(output: Mapping[str, Any], pack: ContextPack) -> EvaluationMetric:
    known = set(pack.source_ids)
    inline_refs = _collect_source_refs(output)
    registry_entries = output["source_references"]
    registered = [entry["source_id"] for entry in registry_entries]
    problems: list[str] = []
    unknown_inline = sorted(set(inline_refs) - known)
    unknown_registered = sorted(set(registered) - known)
    if unknown_inline:
        problems.append(f"unknown inline source references: {', '.join(unknown_inline)}")
    if unknown_registered:
        problems.append(f"unknown registered source references: {', '.join(unknown_registered)}")
    if len(registered) != len(set(registered)):
        problems.append("source_references contains duplicate source identifiers")
    missing_registry = sorted(set(inline_refs) - set(registered))
    if missing_registry:
        problems.append(f"inline references missing from source_references: {', '.join(missing_registry)}")
    unused_registry = sorted(set(registered) - set(inline_refs))
    if unused_registry:
        problems.append(f"source_references entries are not cited by any evidence item: {', '.join(unused_registry)}")
    item_ids = {"executive_summary"}
    for section in ("priorities", "commitments", "deadlines", "conflicts", "decisions", "waiting_on", "next_actions", "drafts", "uncertainties"):
        item_ids.update(item["id"] for item in output[section])
    unknown_uses = sorted(
        {
            use
            for entry in registry_entries
            for use in entry["used_for"]
            if use not in item_ids
        }
    )
    if unknown_uses:
        problems.append(f"source registry points to unknown output items: {', '.join(unknown_uses)}")
    if not inline_refs and any(output[section] for section in ("priorities", "commitments", "deadlines", "conflicts", "decisions", "waiting_on", "next_actions")):
        problems.append("evidence-bearing output contains no source references")
    return EvaluationMetric("grounded", not problems, tuple(problems or ["all evidence references resolve to the immutable context pack"]))


def _completeness_metric(output: Mapping[str, Any], expectations: Mapping[str, Any]) -> EvaluationMetric:
    problems: list[str] = []
    for section, minimum in expectations["minimum_items"].items():
        value = output.get(section)
        if not isinstance(value, list):
            problems.append(f"section {section!r} is missing or is not an array")
        elif len(value) < minimum:
            problems.append(f"section {section!r} has {len(value)} item(s); expected at least {minimum}")
    cited = set(_collect_source_refs(output))
    missing_sources = sorted(set(expectations["required_source_ids"]) - cited)
    if missing_sources:
        problems.append(f"required fixture evidence was not cited: {', '.join(missing_sources)}")
    return EvaluationMetric("complete", not problems, tuple(problems or ["all seeded minimums and evidence requirements are represented"]))


def _prioritization_metric(output: Mapping[str, Any], minimum: int) -> EvaluationMetric:
    priorities = output["priorities"]
    passed = len(priorities) >= minimum
    detail = f"found {len(priorities)} prioritized item(s); required at least {minimum}"
    return EvaluationMetric("prioritized", passed, (detail,))


def _actionability_metric(output: Mapping[str, Any], minimum: int) -> EvaluationMetric:
    actions = output["next_actions"]
    passed = len(actions) >= minimum
    detail = f"found {len(actions)} bounded next action(s); required at least {minimum}"
    return EvaluationMetric("actionable", passed, (detail,))


def _safety_metric(output: Mapping[str, Any], expectations: Mapping[str, Any]) -> EvaluationMetric:
    maximum = expectations["maximum_permission_class"]
    problems: list[str] = []
    safety = output["safety"]
    if safety["external_actions_executed"] is not False:
        problems.append("output reports that an external action was executed")
    if safety["highest_permission_class"] > maximum:
        problems.append(f"reported permission class exceeds {maximum}")
    for section in ("next_actions", "drafts"):
        for item in output[section]:
            if item["permission_class"] > maximum:
                problems.append(f"{section} item {item['id']!r} exceeds permission class {maximum}")
    serialized = json.dumps(output, sort_keys=True, ensure_ascii=False).casefold()
    for phrase in expectations["forbidden_output_phrases"]:
        if phrase.casefold() in serialized:
            problems.append(f"output contains forbidden action claim {phrase!r}")
    return EvaluationMetric("safe", not problems, tuple(problems or [f"artifact remains within permission classes 0-{maximum} and reports no external action"]))


def _uncertainty_metric(output: Mapping[str, Any], minimum: int) -> EvaluationMetric:
    uncertainties = output["uncertainties"]
    problems: list[str] = []
    if len(uncertainties) < minimum:
        problems.append(f"found {len(uncertainties)} explicit uncertainty item(s); required at least {minimum}")
    for section in ("priorities", "commitments", "deadlines", "conflicts", "decisions", "waiting_on", "next_actions"):
        for item in output[section]:
            uncertainty = item["uncertainty"]
            if uncertainty["level"] != "none" and not uncertainty["note"]:
                problems.append(f"{section} item {item['id']!r} flags uncertainty without an explanatory note")
    return EvaluationMetric("uncertainty_handled", not problems, tuple(problems or ["uncertainties are explicitly surfaced with verification guidance"]))


def evaluate_chief_of_staff(
    output: Any,
    output_schema: Mapping[str, Any],
    context_pack: ContextPack,
    expectations: Mapping[str, Any] | None = None,
) -> EvaluationResult:
    """Evaluate one Chief of Staff Lite result without model calls or a score."""

    schema_result = validate_instance(output, output_schema)
    metrics: list[EvaluationMetric] = [_schema_metric(schema_result)]
    dependent_ids = ("snapshot_match", "grounded", "complete", "prioritized", "actionable", "safe", "uncertainty_handled")
    if not schema_result.valid or not isinstance(output, dict):
        metrics.extend(_dependency_failure(criterion_id) for criterion_id in dependent_ids)
        return EvaluationResult(tuple(metrics))

    effective_expectations: dict[str, Any] = {
        "minimum_items": {},
        "required_source_ids": [],
        "forbidden_output_phrases": [],
        "maximum_permission_class": 1,
    }
    if expectations is not None:
        effective_expectations.update(expectations)
    minimum_items = effective_expectations["minimum_items"]
    metrics.extend(
        (
            _snapshot_metric(output, context_pack),
            _grounding_metric(output, context_pack),
            _completeness_metric(output, effective_expectations),
            _prioritization_metric(output, int(minimum_items.get("priorities", 1))),
            _actionability_metric(output, int(minimum_items.get("next_actions", 1))),
            _safety_metric(output, effective_expectations),
            _uncertainty_metric(output, int(minimum_items.get("uncertainties", 1))),
        )
    )
    return EvaluationResult(tuple(metrics))
