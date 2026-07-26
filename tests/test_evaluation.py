from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from agentops.context import LocalContextIndex, build_context_pack, load_source_documents
from agentops.contracts import load_task_contract
from agentops.evaluation import evaluate_chief_of_staff, load_evaluation_expectations


ROOT = Path(__file__).resolve().parents[1]


class ChiefOfStaffEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.task = load_task_contract(ROOT / "tasks/chief-of-staff-lite.json")
        with LocalContextIndex() as index:
            index.ingest_many(load_source_documents(ROOT / "fixtures/chief_of_staff/sources.json"))
            cls.pack = build_context_pack(
                index,
                cls.task.context_selection,
                task_id=cls.task.task_id,
                task_version=cls.task.version,
                prompt_version=cls.task.prompt_version,
            )
        cls.output = json.loads((ROOT / "fixtures/chief_of_staff/valid-output.json").read_text())
        cls.output["metadata"]["snapshot_hash"] = cls.pack.snapshot_hash
        cls.expectations = load_evaluation_expectations(ROOT / "fixtures/chief_of_staff/expectations.json")

    def test_valid_fixture_passes_transparent_metric_vector(self) -> None:
        result = evaluate_chief_of_staff(self.output, self.task.output_schema, self.pack, self.expectations)
        self.assertTrue(result.accepted, result.to_mapping())
        self.assertEqual(
            [metric.criterion_id for metric in result.metrics],
            ["schema_valid", "snapshot_match", "grounded", "complete", "prioritized", "actionable", "safe", "uncertainty_handled"],
        )

    def test_invalid_schema_fails_closed(self) -> None:
        output = copy.deepcopy(self.output)
        output["unexpected"] = "not allowed"
        result = evaluate_chief_of_staff(output, self.task.output_schema, self.pack, self.expectations)
        self.assertFalse(result.accepted)
        self.assertFalse(result.metric("schema_valid").passed)
        self.assertIn("not evaluated", result.metric("grounded").details[0])

    def test_unknown_source_reference_fails_grounding(self) -> None:
        output = copy.deepcopy(self.output)
        output["priorities"][0]["source_refs"] = ["unknown-source"]
        output["source_references"].append({"source_id": "unknown-source", "used_for": ["launch_brief"]})
        result = evaluate_chief_of_staff(output, self.task.output_schema, self.pack, self.expectations)
        self.assertTrue(result.metric("schema_valid").passed)
        self.assertFalse(result.metric("grounded").passed)
        self.assertIn("unknown", " ".join(result.metric("grounded").details))

    def test_snapshot_mismatch_is_reported(self) -> None:
        output = copy.deepcopy(self.output)
        output["metadata"]["snapshot_hash"] = "sha256:" + "0" * 64
        result = evaluate_chief_of_staff(output, self.task.output_schema, self.pack, self.expectations)
        self.assertFalse(result.metric("snapshot_match").passed)

    def test_forbidden_action_claim_fails_safety(self) -> None:
        output = copy.deepcopy(self.output)
        output["executive_summary"] += " Message sent."
        result = evaluate_chief_of_staff(output, self.task.output_schema, self.pack, self.expectations)
        self.assertTrue(result.metric("schema_valid").passed)
        self.assertFalse(result.metric("safe").passed)

    def test_missing_seeded_evidence_fails_completeness(self) -> None:
        expectations = copy.deepcopy(self.expectations)
        expectations["required_source_ids"].append("not-in-output")
        result = evaluate_chief_of_staff(self.output, self.task.output_schema, self.pack, expectations)
        self.assertFalse(result.metric("complete").passed)


if __name__ == "__main__":
    unittest.main()
