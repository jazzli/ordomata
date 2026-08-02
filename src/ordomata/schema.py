"""Small, strict JSON Schema validator used at trust boundaries.

The project deliberately avoids a runtime dependency for structured-output
validation.  This module implements the JSON Schema vocabulary used by the
versioned project schemas and rejects unsupported schema keywords instead of
silently ignoring them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time
import json
import math
import re
from typing import Any, Mapping

from .errors import ValidationError


JSONValue = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One deterministic validation failure."""

    path: str
    keyword: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message} ({self.keyword})"


@dataclass(frozen=True, slots=True)
class SchemaValidationResult:
    """Validation result without exceptions for expected invalid model output."""

    issues: tuple[ValidationIssue, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.issues


_SUPPORTED_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "definitions",
        "title",
        "description",
        "comment",
        "$comment",
        "examples",
        "default",
        "deprecated",
        "readOnly",
        "writeOnly",
        "type",
        "enum",
        "const",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "required",
        "properties",
        "additionalProperties",
        "minProperties",
        "maxProperties",
        "items",
        "prefixItems",
        "minItems",
        "maxItems",
        "uniqueItems",
        "contains",
        "minContains",
        "maxContains",
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    }
)

_TYPE_NAMES = frozenset({"null", "boolean", "object", "array", "number", "integer", "string"})
_ANNOTATION_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$defs",
        "definitions",
        "title",
        "description",
        "comment",
        "$comment",
        "examples",
        "default",
        "deprecated",
        "readOnly",
        "writeOnly",
    }
)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValidationError(f"non-finite JSON number is not permitted: {value}")


def parse_json_document(text: str) -> JSONValue:
    """Parse strict JSON, rejecting duplicate keys and non-finite numbers."""

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValidationError(f"invalid JSON: {exc}") from exc


def _escape_path_component(component: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", component):
        return f".{component}"
    return f"[{json.dumps(component, ensure_ascii=False)}]"


def _is_integer(value: Any) -> bool:
    return not isinstance(value, bool) and (
        isinstance(value, int) or (isinstance(value, float) and math.isfinite(value) and value.is_integer())
    )


def _is_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def _matches_type(value: Any, type_name: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "number": _is_number(value),
        "integer": _is_integer(value),
        "string": isinstance(value, str),
    }[type_name]


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if _is_number(left) and _is_number(right):
        return float(left) == float(right)
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right, strict=True))
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_json_equal(left[key], right[key]) for key in left)
    return left == right


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _valid_format(value: str, format_name: str) -> bool:
    try:
        if format_name == "date-time":
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                value,
            ):
                return False
            parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
            return parsed.tzinfo is not None
        if format_name == "date":
            date.fromisoformat(value)
            return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value))
        if format_name == "time":
            normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed_time = time.fromisoformat(normalized)
            return parsed_time.tzinfo is not None
        if format_name == "sha256":
            return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value))
    except ValueError:
        return False
    raise ValidationError(f"unsupported format in schema: {format_name!r}")


class SchemaValidator:
    """Validate JSON-compatible values against a strict local schema subset."""

    def __init__(self, schema: Mapping[str, Any] | bool) -> None:
        if not isinstance(schema, (dict, bool)):
            raise ValidationError("schema root must be an object or boolean")
        self._root = schema
        self._check_schema(schema, "$schema", set())

    def validate(self, instance: Any) -> SchemaValidationResult:
        issues: list[ValidationIssue] = []
        self._validate(instance, self._root, "$", issues, depth=0)
        return SchemaValidationResult(tuple(issues))

    def require_valid(self, instance: Any) -> None:
        result = self.validate(instance)
        if result.valid:
            return
        preview = "; ".join(str(issue) for issue in result.issues[:10])
        extra = len(result.issues) - 10
        if extra:
            preview += f"; and {extra} more issue(s)"
        raise ValidationError(preview)

    def _resolve_ref(self, reference: str) -> Mapping[str, Any] | bool:
        if reference == "#":
            return self._root
        if not reference.startswith("#/"):
            raise ValidationError(f"only local JSON Pointer references are supported: {reference!r}")
        current: Any = self._root
        for raw_part in reference[2:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or part not in current:
                raise ValidationError(f"unresolvable schema reference: {reference!r}")
            current = current[part]
        if not isinstance(current, (dict, bool)):
            raise ValidationError(f"schema reference does not target a schema: {reference!r}")
        return current

    def _check_schema(self, schema: Any, path: str, visited: set[int]) -> None:
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            raise ValidationError(f"{path}: schema must be an object or boolean")
        if id(schema) in visited:
            return
        visited.add(id(schema))
        unknown = sorted(set(schema) - _SUPPORTED_KEYWORDS)
        if unknown:
            raise ValidationError(f"{path}: unsupported schema keyword(s): {', '.join(unknown)}")
        declared_type = schema.get("type")
        if declared_type is not None:
            type_names = [declared_type] if isinstance(declared_type, str) else declared_type
            if (
                not isinstance(type_names, list)
                or not type_names
                or any(not isinstance(item, str) or item not in _TYPE_NAMES for item in type_names)
                or len(set(type_names)) != len(type_names)
            ):
                raise ValidationError(f"{path}.type: expected a type name or unique non-empty list of type names")
        for key in ("required",):
            if key in schema and (
                not isinstance(schema[key], list)
                or any(not isinstance(item, str) for item in schema[key])
                or len(schema[key]) != len(set(schema[key]))
            ):
                raise ValidationError(f"{path}.{key}: expected a list of unique strings")
        if "properties" in schema:
            if not isinstance(schema["properties"], dict):
                raise ValidationError(f"{path}.properties: expected an object")
            for key, subschema in schema["properties"].items():
                self._check_schema(subschema, f"{path}.properties.{key}", visited)
        for definitions_key in ("$defs", "definitions"):
            if definitions_key in schema:
                if not isinstance(schema[definitions_key], dict):
                    raise ValidationError(f"{path}.{definitions_key}: expected an object")
                for key, subschema in schema[definitions_key].items():
                    self._check_schema(subschema, f"{path}.{definitions_key}.{key}", visited)
        for key in ("additionalProperties", "items", "contains", "not"):
            if key in schema and not isinstance(schema[key], (dict, bool)):
                raise ValidationError(f"{path}.{key}: expected a schema or boolean")
            if key in schema:
                self._check_schema(schema[key], f"{path}.{key}", visited)
        for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
            if key in schema:
                value = schema[key]
                if not isinstance(value, list) or (key != "prefixItems" and not value):
                    raise ValidationError(f"{path}.{key}: expected {'a list' if key == 'prefixItems' else 'a non-empty list'}")
                for index, subschema in enumerate(value):
                    self._check_schema(subschema, f"{path}.{key}[{index}]", visited)
        if "$ref" in schema:
            if not isinstance(schema["$ref"], str):
                raise ValidationError(f"{path}.$ref: expected a string")
            self._resolve_ref(schema["$ref"])
        if "pattern" in schema:
            if not isinstance(schema["pattern"], str):
                raise ValidationError(f"{path}.pattern: expected a string")
            try:
                re.compile(schema["pattern"])
            except re.error as exc:
                raise ValidationError(f"{path}.pattern: invalid regular expression: {exc}") from exc
        if "format" in schema and schema["format"] not in {"date-time", "date", "time", "sha256"}:
            raise ValidationError(f"{path}.format: unsupported format {schema['format']!r}")
        for key in ("minProperties", "maxProperties", "minItems", "maxItems", "minContains", "maxContains", "minLength", "maxLength"):
            if key in schema and (not isinstance(schema[key], int) or isinstance(schema[key], bool) or schema[key] < 0):
                raise ValidationError(f"{path}.{key}: expected a non-negative integer")
        for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"):
            if key in schema and not _is_number(schema[key]):
                raise ValidationError(f"{path}.{key}: expected a finite number")
        if "multipleOf" in schema and schema["multipleOf"] <= 0:
            raise ValidationError(f"{path}.multipleOf: expected a positive number")
        if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
            raise ValidationError(f"{path}.uniqueItems: expected a boolean")

    def _validate(
        self,
        instance: Any,
        schema: Mapping[str, Any] | bool,
        path: str,
        issues: list[ValidationIssue],
        *,
        depth: int,
    ) -> None:
        if depth > 128:
            issues.append(ValidationIssue(path, "depth", "validation nesting exceeds 128 levels"))
            return
        if schema is False:
            issues.append(ValidationIssue(path, "falseSchema", "value is forbidden by the schema"))
            return
        if schema is True:
            return
        if "$ref" in schema:
            self._validate(instance, self._resolve_ref(schema["$ref"]), path, issues, depth=depth + 1)
        declared_type = schema.get("type")
        if declared_type is not None:
            names = [declared_type] if isinstance(declared_type, str) else declared_type
            if not any(_matches_type(instance, name) for name in names):
                issues.append(ValidationIssue(path, "type", f"expected type {' or '.join(names)}"))
                return
        if "enum" in schema and not any(_json_equal(instance, candidate) for candidate in schema["enum"]):
            issues.append(ValidationIssue(path, "enum", "value is not one of the permitted values"))
        if "const" in schema and not _json_equal(instance, schema["const"]):
            issues.append(ValidationIssue(path, "const", "value does not match the required constant"))
        if "allOf" in schema:
            for subschema in schema["allOf"]:
                self._validate(instance, subschema, path, issues, depth=depth + 1)
        for keyword in ("anyOf", "oneOf"):
            if keyword in schema:
                matching = 0
                for subschema in schema[keyword]:
                    branch_issues: list[ValidationIssue] = []
                    self._validate(instance, subschema, path, branch_issues, depth=depth + 1)
                    matching += not branch_issues
                expected = matching >= 1 if keyword == "anyOf" else matching == 1
                if not expected:
                    message = "did not match any permitted schema" if keyword == "anyOf" else f"matched {matching} schemas; expected exactly one"
                    issues.append(ValidationIssue(path, keyword, message))
        if "not" in schema:
            branch_issues = []
            self._validate(instance, schema["not"], path, branch_issues, depth=depth + 1)
            if not branch_issues:
                issues.append(ValidationIssue(path, "not", "value matches a forbidden schema"))

        if isinstance(instance, dict):
            self._validate_object(instance, schema, path, issues, depth)
        elif isinstance(instance, list):
            self._validate_array(instance, schema, path, issues, depth)
        elif isinstance(instance, str):
            self._validate_string(instance, schema, path, issues)
        elif _is_number(instance):
            self._validate_number(instance, schema, path, issues)

    def _validate_object(self, instance: dict[str, Any], schema: Mapping[str, Any], path: str, issues: list[ValidationIssue], depth: int) -> None:
        required = schema.get("required", ())
        for name in required:
            if name not in instance:
                issues.append(ValidationIssue(path, "required", f"missing required property {name!r}"))
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for name, value in instance.items():
            child_path = path + _escape_path_component(name)
            if name in properties:
                self._validate(value, properties[name], child_path, issues, depth=depth + 1)
            elif additional is False:
                issues.append(ValidationIssue(child_path, "additionalProperties", "unexpected property"))
            elif isinstance(additional, dict):
                self._validate(value, additional, child_path, issues, depth=depth + 1)
        if len(instance) < schema.get("minProperties", 0):
            issues.append(ValidationIssue(path, "minProperties", f"expected at least {schema['minProperties']} properties"))
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            issues.append(ValidationIssue(path, "maxProperties", f"expected at most {schema['maxProperties']} properties"))

    def _validate_array(self, instance: list[Any], schema: Mapping[str, Any], path: str, issues: list[ValidationIssue], depth: int) -> None:
        if len(instance) < schema.get("minItems", 0):
            issues.append(ValidationIssue(path, "minItems", f"expected at least {schema['minItems']} items"))
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            issues.append(ValidationIssue(path, "maxItems", f"expected at most {schema['maxItems']} items"))
        if schema.get("uniqueItems"):
            seen: set[str] = set()
            for index, value in enumerate(instance):
                marker = _canonical_json(value)
                if marker in seen:
                    issues.append(ValidationIssue(f"{path}[{index}]", "uniqueItems", "duplicate array item"))
                seen.add(marker)
        prefix = schema.get("prefixItems", ())
        for index, subschema in enumerate(prefix):
            if index < len(instance):
                self._validate(instance[index], subschema, f"{path}[{index}]", issues, depth=depth + 1)
        if "items" in schema:
            start = len(prefix)
            for index in range(start, len(instance)):
                self._validate(instance[index], schema["items"], f"{path}[{index}]", issues, depth=depth + 1)
        if "contains" in schema:
            matches = 0
            for value in instance:
                candidate_issues: list[ValidationIssue] = []
                self._validate(value, schema["contains"], path, candidate_issues, depth=depth + 1)
                matches += not candidate_issues
            minimum = schema.get("minContains", 1)
            maximum = schema.get("maxContains")
            if matches < minimum or (maximum is not None and matches > maximum):
                issues.append(ValidationIssue(path, "contains", f"matching item count {matches} is outside permitted bounds"))

    @staticmethod
    def _validate_string(instance: str, schema: Mapping[str, Any], path: str, issues: list[ValidationIssue]) -> None:
        if len(instance) < schema.get("minLength", 0):
            issues.append(ValidationIssue(path, "minLength", f"expected at least {schema['minLength']} characters"))
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            issues.append(ValidationIssue(path, "maxLength", f"expected at most {schema['maxLength']} characters"))
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            issues.append(ValidationIssue(path, "pattern", "string does not match the required pattern"))
        if "format" in schema and not _valid_format(instance, schema["format"]):
            issues.append(ValidationIssue(path, "format", f"string is not a valid {schema['format']}"))

    @staticmethod
    def _validate_number(instance: int | float, schema: Mapping[str, Any], path: str, issues: list[ValidationIssue]) -> None:
        checks = (
            ("minimum", lambda value, bound: value >= bound, "greater than or equal to"),
            ("maximum", lambda value, bound: value <= bound, "less than or equal to"),
            ("exclusiveMinimum", lambda value, bound: value > bound, "greater than"),
            ("exclusiveMaximum", lambda value, bound: value < bound, "less than"),
        )
        for keyword, predicate, phrase in checks:
            if keyword in schema and not predicate(instance, schema[keyword]):
                issues.append(ValidationIssue(path, keyword, f"expected a number {phrase} {schema[keyword]}"))
        if "multipleOf" in schema:
            quotient = instance / schema["multipleOf"]
            if not math.isclose(quotient, round(quotient), rel_tol=1e-12, abs_tol=1e-12):
                issues.append(ValidationIssue(path, "multipleOf", f"expected a multiple of {schema['multipleOf']}"))


def validate_instance(instance: Any, schema: Mapping[str, Any] | bool) -> SchemaValidationResult:
    """Return all deterministic validation issues for ``instance``."""

    return SchemaValidator(schema).validate(instance)


def require_valid(instance: Any, schema: Mapping[str, Any] | bool) -> None:
    """Raise :class:`ValidationError` when ``instance`` does not match ``schema``."""

    SchemaValidator(schema).require_valid(instance)


def validate_json_text(text: str, schema: Mapping[str, Any] | bool) -> tuple[JSONValue, SchemaValidationResult]:
    """Strictly parse a model response and validate its resulting JSON value."""

    instance = parse_json_document(text)
    return instance, validate_instance(instance, schema)
