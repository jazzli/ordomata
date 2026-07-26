from __future__ import annotations

import json
from pathlib import Path
import unittest

from agentops.errors import ValidationError
from agentops.schema import SchemaValidator, parse_json_document, require_valid, validate_instance, validate_json_text


ROOT = Path(__file__).resolve().parents[1]


class StrictJsonTests(unittest.TestCase):
    def test_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(ValidationError, "duplicate JSON object key"):
            parse_json_document('{"answer": 1, "answer": 2}')

    def test_rejects_non_finite_numbers(self) -> None:
        with self.assertRaisesRegex(ValidationError, "non-finite"):
            parse_json_document('{"answer": NaN}')


class SchemaValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "items", "when"],
            "properties": {
                "name": {"type": "string", "minLength": 2},
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"$ref": "#/$defs/count"},
                },
                "when": {"type": ["string", "null"], "format": "date-time"},
            },
            "$defs": {"count": {"type": "integer", "minimum": 0}},
        }

    def test_validates_supported_nested_schema(self) -> None:
        value = {"name": "ok", "items": [0, 2], "when": "2026-07-26T10:00:00+08:00"}
        self.assertTrue(validate_instance(value, self.schema).valid)
        require_valid(value, self.schema)

    def test_reports_paths_and_multiple_failures(self) -> None:
        value = {"name": "x", "items": [True, True], "when": "tomorrow", "extra": 1}
        result = validate_instance(value, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("$.name", {issue.path for issue in result.issues})
        self.assertIn("$.items[0]", {issue.path for issue in result.issues})
        self.assertIn("$.when", {issue.path for issue in result.issues})
        self.assertIn("$.extra", {issue.path for issue in result.issues})

    def test_boolean_is_not_integer(self) -> None:
        result = validate_instance(True, {"type": "integer"})
        self.assertFalse(result.valid)

    def test_nullable_format_does_not_reject_null(self) -> None:
        self.assertTrue(validate_instance(None, {"type": ["string", "null"], "format": "date-time"}).valid)

    def test_rejects_unsupported_schema_keyword(self) -> None:
        with self.assertRaisesRegex(ValidationError, "unsupported schema keyword"):
            SchemaValidator({"type": "string", "transform": "trim"})

    def test_rejects_remote_reference(self) -> None:
        with self.assertRaisesRegex(ValidationError, "only local"):
            SchemaValidator({"$ref": "https://example.invalid/schema"})

    def test_validates_json_text(self) -> None:
        value, result = validate_json_text('{"name":"ok","items":[1],"when":null}', self.schema)
        self.assertEqual(value["items"], [1])
        self.assertTrue(result.valid)

    def test_chief_of_staff_fixture_matches_output_schema(self) -> None:
        schema = json.loads((ROOT / "schemas/chief-of-staff-lite.output.schema.json").read_text())
        output = json.loads((ROOT / "fixtures/chief_of_staff/valid-output.json").read_text())
        result = validate_instance(output, schema)
        self.assertTrue(result.valid, [str(issue) for issue in result.issues])


if __name__ == "__main__":
    unittest.main()
