from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from agentops.contracts import load_task_contract
from agentops.errors import ConfigurationError
from agentops.authorization import ActionVerb, ImpactLevel, Reach
from agentops.models import PermissionClass


ROOT = Path(__file__).resolve().parents[1]
TASK_PATH = ROOT / "tasks/chief-of-staff-lite.json"
TASK_SCHEMA_PATH = ROOT / "schemas/task-definition.schema.json"


class TaskContractTests(unittest.TestCase):
    def test_loads_complete_neutral_contract(self) -> None:
        task = load_task_contract(TASK_PATH)
        self.assertEqual(task.task_id, "chief-of-staff.lite")
        self.assertEqual(task.version, "1.0.0")
        self.assertEqual(task.prompt_version, "1.0.0")
        self.assertEqual(task.permission_class, PermissionClass.LOCAL_DRAFT)
        self.assertIsNotNone(task.authorization_intent)
        assert task.authorization_intent is not None
        self.assertIs(task.authorization_intent.action.verb, ActionVerb.CREATE)
        self.assertEqual(
            task.authorization_intent.action.operation,
            "artifact.publish_local_candidate",
        )
        self.assertEqual(
            task.authorization_intent.resource.resource_type,
            "local_candidate_artifact",
        )
        self.assertIs(
            task.authorization_intent.consequences.reach,
            Reach.LOCAL,
        )
        self.assertRegex(
            task.authorization_intent.digest,
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(task.context_selection.strategy, "sqlite_fts5")
        self.assertGreater(task.context_selection.max_bytes, 0)
        self.assertEqual(task.expected_output.format, "json")
        self.assertTrue(task.output_schema)
        self.assertEqual(task.max_attempts, 1)
        self.assertEqual(task.timeout_seconds, 600)
        self.assertEqual(task.time_limits.idle_seconds, task.timeout_seconds)
        self.assertTrue(task.approval_requirements.required_before_promotion)
        self.assertFalse(task.scheduling_policy.enabled)
        self.assertIn("codex", task.runner_overrides)
        self.assertRegex(task.definition_hash, r"^sha256:[0-9a-f]{64}$")

    def _write_mutated_task(self, mutate) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        task = json.loads(TASK_PATH.read_text())
        mutate(task)
        task["output_schema"] = {"inline": json.loads((ROOT / "schemas/chief-of-staff-lite.output.schema.json").read_text())}
        path = Path(temporary.name) / "task.json"
        path.write_text(json.dumps(task), encoding="utf-8")
        return temporary, path

    def test_rejects_permission_class_above_current_stage(self) -> None:
        temporary, path = self._write_mutated_task(lambda task: task.__setitem__("permission_class", 2))
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(ConfigurationError):
            load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)

    def test_rejects_credential_or_billing_override(self) -> None:
        def mutate(task):
            task["runner_overrides"]["codex"] = {"OPENAI_API_KEY": "must-not-be-accepted"}

        temporary, path = self._write_mutated_task(mutate)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ConfigurationError, "credentials or billing"):
            load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)

    def test_rejects_destination_escape(self) -> None:
        def mutate(task):
            task["expected_output"]["local_destination"] = "../outside.json"

        temporary, path = self._write_mutated_task(mutate)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ConfigurationError, "local_destination"):
            load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)

    def test_rejects_unknown_task_fields(self) -> None:
        temporary, path = self._write_mutated_task(lambda task: task.__setitem__("surprise", True))
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ConfigurationError, "unexpected property"):
            load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)

    def test_authorization_intent_is_optional_without_fabricating_one(self) -> None:
        def mutate(task):
            task.pop("authorization_intent")

        temporary, path = self._write_mutated_task(mutate)
        self.addCleanup(temporary.cleanup)
        task = load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)
        self.assertIsNone(task.authorization_intent)

    def test_authorization_intent_changes_definition_hash(self) -> None:
        baseline = load_task_contract(TASK_PATH)

        def mutate(task):
            task["authorization_intent"]["consequences"]["confidentiality"] = (
                "high"
            )

        temporary, path = self._write_mutated_task(mutate)
        self.addCleanup(temporary.cleanup)
        changed = load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)
        self.assertNotEqual(changed.definition_hash, baseline.definition_hash)
        assert changed.authorization_intent is not None
        self.assertIs(
            changed.authorization_intent.consequences.confidentiality,
            ImpactLevel.HIGH,
        )

    def test_rejects_malformed_authorization_intent(self) -> None:
        def mutate(task):
            task["authorization_intent"]["action"]["verb"] = "launch"

        temporary, path = self._write_mutated_task(mutate)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ConfigurationError, "authorization_intent"):
            load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)

    def test_rejects_unimplemented_distinct_idle_timeout(self) -> None:
        def mutate(task):
            task["time_limits"]["idle_seconds"] = 599

        temporary, path = self._write_mutated_task(mutate)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ConfigurationError, "idle timeout"):
            load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)

    def test_rejects_unimplemented_retry_or_repair_semantics(self) -> None:
        mutations = (
            ("max_attempts", 2),
            ("max_repairs_per_attempt", 1),
            ("retry_backoff_seconds", 30),
        )
        for field_name, value in mutations:
            with self.subTest(field_name=field_name):
                def mutate(task, name=field_name, selected=value):
                    task["attempt_limits"][name] = selected

                temporary, path = self._write_mutated_task(mutate)
                self.addCleanup(temporary.cleanup)
                with self.assertRaisesRegex(ConfigurationError, "not implemented"):
                    load_task_contract(path, definition_schema_path=TASK_SCHEMA_PATH)


if __name__ == "__main__":
    unittest.main()
