import asyncio
from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from ordomata.authorization import canonical_digest
from ordomata.authorization_inspection import inspect_authorization_shadows
from ordomata.execution_selection import build_execution_selection
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
)
from ordomata.orchestrator import prepare_chief_of_staff, run_chief_of_staff
from ordomata.routing import (
    RuntimeProfileState,
    TaskRoutingFeatures,
    load_execution_profiles,
)
from ordomata.shadow_authorization import task_authorization_intent_digest


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SELECTION_EVENT_TYPE = "task_execution_selection"


class ExecutionSelectionInspectionTests(unittest.TestCase):
    def _project(self, temporary: str) -> Path:
        root = Path(temporary)
        for name in ("tasks", "schemas", "fixtures", "profiles"):
            shutil.copytree(REPOSITORY_ROOT / name, root / name)
        return root

    def _completed_run(self, root: Path, run_id: str) -> Path:
        asyncio.run(run_chief_of_staff(root, run_id=run_id))
        return root / ".ordomata" / "state.sqlite3"

    @staticmethod
    def _restore_update_trigger(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TRIGGER run_events_no_update
            BEFORE UPDATE ON run_events BEGIN
                SELECT RAISE(ABORT, 'run events are append-only');
            END
            """
        )

    @staticmethod
    def _restore_delete_trigger(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TRIGGER run_events_no_delete
            BEFORE DELETE ON run_events BEGIN
                SELECT RAISE(ABORT, 'run events are append-only');
            END
            """
        )

    def test_valid_selection_is_inspected_without_raw_candidate_projection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            database = self._completed_run(root, "selection-inspection-clean")

            report = inspect_authorization_shadows(database)

            self.assertTrue(report.clean, report.to_mapping())
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            self.assertNotIn("mock.deterministic.local-draft", projection)
            self.assertNotIn(str(root), projection)

    def test_routed_multi_candidate_ranking_recomputes_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._project(temporary)
            prepared = prepare_chief_of_staff(root)
            profile_path = root / "profiles" / "default.json"
            profile_document = json.loads(profile_path.read_text(encoding="utf-8"))
            configured_mock = next(
                item
                for item in profile_document["profiles"]
                if item["runner_id"] == "mock"
            )
            profile_document["profiles"] = [
                item
                for item in profile_document["profiles"]
                if item["runner_id"] != "mock"
            ] + [
                {**configured_mock, "profile_id": "mock.selection-b"},
                {**configured_mock, "profile_id": "mock.selection-z"},
            ]
            profile_path.write_text(
                json.dumps(profile_document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            profiles = tuple(
                profile
                for profile in load_execution_profiles(profile_path)
                if profile.profile_id
                in {"mock.selection-b", "mock.selection-z"}
            )
            candidates = tuple(
                RuntimeProfileState(
                    profile=profile,
                    billing_assessment=BillingRouteAssessment(
                        runner_id="mock",
                        route=BillingRoute.MOCK,
                        confidence=AssessmentConfidence.HIGH,
                    ),
                    available=True,
                )
                for profile in profiles
            )
            task = TaskRoutingFeatures(
                task_kind="chief_of_staff",
                permission_class=prepared.contract.permission_class,
                required_capabilities=frozenset(
                    {
                        "isolated_workspace",
                        "local_draft",
                        "structured_output",
                    }
                ),
                allowed_roles=frozenset({"test"}),
                allowed_billing_routes=frozenset({BillingRoute.MOCK}),
                context_bytes=prepared.context_pack.raw_bytes,
                risk=1,
            )
            run_id = "selection-inspection-routed"
            selection = build_execution_selection(
                run_id=run_id,
                selection_mode="routed",
                task=task,
                candidates=reversed(candidates),
                task_definition_digest=prepared.contract.definition_hash,
                context_digest=prepared.context_pack.snapshot_hash,
                authorization_intent_digest=task_authorization_intent_digest(
                    prepared.contract
                ),
                evaluated_at=1_700_000_000.0,
            )
            asyncio.run(
                run_chief_of_staff(
                    root,
                    run_id=run_id,
                    profile_id="mock.selection-b",
                    prepared_task=prepared,
                    execution_selection=selection,
                )
            )

            database = root / ".ordomata" / "state.sqlite3"
            report = inspect_authorization_shadows(database, run_id=run_id)
            self.assertTrue(report.clean, report.to_mapping())
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            self.assertNotIn("mock.selection-b", projection)
            self.assertNotIn("mock.selection-z", projection)

            with closing(sqlite3.connect(database)) as connection:
                connection.execute("DROP TRIGGER run_events_no_update")
                row = connection.execute(
                    """
                    SELECT sequence, payload_json FROM run_events
                    WHERE run_id = ? AND event_type = ?
                    """,
                    (run_id, SELECTION_EVENT_TYPE),
                ).fetchone()
                assert row is not None
                sequence, payload_json = row
                payload = json.loads(payload_json)
                candidates_payload = payload["selection"]["candidates"]
                candidates_payload.reverse()
                for order, candidate in enumerate(candidates_payload):
                    candidate["candidate_order"] = order
                payload["selection"]["candidate_set_digest"] = canonical_digest(
                    candidates_payload
                )
                payload["selection_digest"] = canonical_digest(
                    payload["selection"]
                )
                connection.execute(
                    """
                    UPDATE run_events
                    SET event_id = ?, payload_json = ?
                    WHERE sequence = ?
                    """,
                    (
                        payload["selection_digest"],
                        json.dumps(payload, sort_keys=True),
                        sequence,
                    ),
                )
                self._restore_update_trigger(connection)
                connection.commit()

            tampered = inspect_authorization_shadows(database, run_id=run_id)
            self.assertIn(
                "execution_selection_candidate_order_invalid",
                tampered.runs[0].integrity_issues,
            )
            self.assertNotIn(
                "execution_selection_ranking_mismatch",
                tampered.runs[0].integrity_issues,
            )
            tampered_projection = json.dumps(tampered.to_mapping(), sort_keys=True)
            self.assertNotIn("mock.selection-b", tampered_projection)
            self.assertNotIn("mock.selection-z", tampered_projection)

    def test_binding_v2_requires_exactly_one_selection(self) -> None:
        for case in ("missing", "duplicate"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"selection-{case}"
                database = self._completed_run(root, run_id)
                with closing(sqlite3.connect(database)) as connection:
                    if case == "missing":
                        connection.execute("DROP TRIGGER run_events_no_delete")
                        connection.execute(
                            "DELETE FROM run_events WHERE run_id = ? AND event_type = ?",
                            (run_id, SELECTION_EVENT_TYPE),
                        )
                        self._restore_delete_trigger(connection)
                    else:
                        row = connection.execute(
                            """
                            SELECT payload_json, occurred_at FROM run_events
                            WHERE run_id = ? AND event_type = ?
                            """,
                            (run_id, SELECTION_EVENT_TYPE),
                        ).fetchone()
                        assert row is not None
                        connection.execute(
                            """
                            INSERT INTO run_events (
                                event_id, run_id, event_type, status,
                                payload_json, occurred_at
                            ) VALUES (?, ?, ?, NULL, ?, ?)
                            """,
                            (
                                canonical_digest(
                                    {"duplicate_selection_for": run_id}
                                ),
                                run_id,
                                SELECTION_EVENT_TYPE,
                                row[0],
                                row[1],
                            ),
                        )
                    connection.commit()

                report = inspect_authorization_shadows(database, run_id=run_id)
                expected = (
                    "execution_selection_missing"
                    if case == "missing"
                    else "execution_selection_duplicate"
                )
                self.assertFalse(report.clean)
                self.assertIn(expected, report.runs[0].integrity_issues)

    def test_selection_digest_identifier_binding_and_order_are_checked(
        self,
    ) -> None:
        cases = (
            ("digest", "execution_selection_digest_mismatch"),
            ("event_id", "execution_selection_event_identifier_mismatch"),
            ("binding", "execution_selection_binding_mismatch"),
            ("validity", "execution_selection_payload_invalid"),
            ("late", "execution_selection_order_invalid"),
            ("private_payload", "execution_selection_payload_invalid"),
        )
        for case, expected in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"selection-integrity-{case}"
                database = self._completed_run(root, run_id)
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute("DROP TRIGGER run_events_no_update")
                    row = connection.execute(
                        """
                        SELECT sequence, payload_json FROM run_events
                        WHERE run_id = ? AND event_type = ?
                        """,
                        (run_id, SELECTION_EVENT_TYPE),
                    ).fetchone()
                    assert row is not None
                    sequence, payload_json = row
                    payload = json.loads(payload_json)
                    if case == "digest":
                        payload["selection_digest"] = canonical_digest(
                            {"tampered": case}
                        )
                        connection.execute(
                            "UPDATE run_events SET payload_json = ? WHERE sequence = ?",
                            (
                                json.dumps(payload, sort_keys=True),
                                sequence,
                            ),
                        )
                    elif case == "event_id":
                        connection.execute(
                            "UPDATE run_events SET event_id = ? WHERE sequence = ?",
                            (canonical_digest({"tampered": case}), sequence),
                        )
                    elif case == "binding":
                        payload["selection"]["run_ref"] = canonical_digest(
                            {"run_id": "different-run"}
                        )
                        payload["selection_digest"] = canonical_digest(
                            payload["selection"]
                        )
                        connection.execute(
                            """
                            UPDATE run_events
                            SET event_id = ?, payload_json = ?
                            WHERE sequence = ?
                            """,
                            (
                                payload["selection_digest"],
                                json.dumps(payload, sort_keys=True),
                                sequence,
                            ),
                        )
                    elif case == "validity":
                        payload["selection"]["required_valid_until"] = (
                            payload["selection"]["evaluated_at"] - 1.0
                        )
                        payload["selection_digest"] = canonical_digest(
                            payload["selection"]
                        )
                        connection.execute(
                            """
                            UPDATE run_events
                            SET event_id = ?, payload_json = ?
                            WHERE sequence = ?
                            """,
                            (
                                payload["selection_digest"],
                                json.dumps(payload, sort_keys=True),
                                sequence,
                            ),
                        )
                    elif case == "private_payload":
                        payload["selection"]["unexpected_private_field"] = (
                            "private-selection-payload-must-not-project"
                        )
                        connection.execute(
                            "UPDATE run_events SET payload_json = ? WHERE sequence = ?",
                            (
                                json.dumps(payload, sort_keys=True),
                                sequence,
                            ),
                        )
                    else:
                        last_sequence = connection.execute(
                            "SELECT MAX(sequence) FROM run_events"
                        ).fetchone()[0]
                        connection.execute(
                            "UPDATE run_events SET sequence = ? WHERE sequence = ?",
                            (last_sequence + 1, sequence),
                        )
                    self._restore_update_trigger(connection)
                    connection.commit()

                report = inspect_authorization_shadows(database, run_id=run_id)
                self.assertFalse(report.clean)
                self.assertIn(expected, report.runs[0].integrity_issues)
                if case == "private_payload":
                    self.assertNotIn(
                        "private-selection-payload-must-not-project",
                        json.dumps(report.to_mapping(), sort_keys=True),
                    )

    def test_candidate_policy_ranking_and_selected_links_are_recomputed(
        self,
    ) -> None:
        cases = (
            ("policy", "execution_selection_policy_digest_mismatch"),
            (
                "candidate_digest",
                "execution_selection_candidate_set_digest_mismatch",
            ),
            ("candidate_order", "execution_selection_candidate_order_invalid"),
            (
                "profile_ref",
                "execution_selection_profile_reference_mismatch",
            ),
            ("profile_id", "execution_selection_payload_invalid"),
            ("rank", "execution_selection_ranking_mismatch"),
            ("score", "execution_selection_score_vector_mismatch"),
            (
                "rejection_codes",
                "execution_selection_rejection_codes_mismatch",
            ),
            (
                "selected",
                "execution_selection_selected_candidate_mismatch",
            ),
        )
        for case, expected in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._project(temporary)
                run_id = f"selection-recompute-{case}"
                database = self._completed_run(root, run_id)
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute("DROP TRIGGER run_events_no_update")
                    row = connection.execute(
                        """
                        SELECT sequence, payload_json FROM run_events
                        WHERE run_id = ? AND event_type = ?
                        """,
                        (run_id, SELECTION_EVENT_TYPE),
                    ).fetchone()
                    assert row is not None
                    sequence, payload_json = row
                    payload = json.loads(payload_json)
                    selection = payload["selection"]
                    candidate = selection["candidates"][0]
                    if case == "policy":
                        selection["routing_policy_digest"] = canonical_digest(
                            {"policy": "different"}
                        )
                    elif case == "candidate_digest":
                        selection["candidate_set_digest"] = canonical_digest(
                            {"candidates": "different"}
                        )
                    elif case == "candidate_order":
                        candidate["candidate_order"] = 7
                        selection["candidate_set_digest"] = canonical_digest(
                            selection["candidates"]
                        )
                    elif case == "profile_ref":
                        candidate["profile_id"] = "mock.different-profile"
                        selection["candidate_set_digest"] = canonical_digest(
                            selection["candidates"]
                        )
                    elif case == "profile_id":
                        candidate["profile_id"] = "unsafe/profile/path"
                        selection["candidate_set_digest"] = canonical_digest(
                            selection["candidates"]
                        )
                    elif case == "score":
                        candidate["score_vector"][0] += 0.125
                        selection["candidate_set_digest"] = canonical_digest(
                            selection["candidates"]
                        )
                    elif case == "rank":
                        candidate["rank"] = 3
                        selection["candidate_set_digest"] = canonical_digest(
                            selection["candidates"]
                        )
                    elif case == "rejection_codes":
                        candidate["rejection_codes"] = [
                            "profile_unavailable"
                        ]
                        selection["candidate_set_digest"] = canonical_digest(
                            selection["candidates"]
                        )
                    else:
                        selection["selected"]["profile_ref"] = canonical_digest(
                            {"profile_id": "different-profile"}
                        )
                    payload["selection_digest"] = canonical_digest(selection)
                    connection.execute(
                        """
                        UPDATE run_events
                        SET event_id = ?, payload_json = ?
                        WHERE sequence = ?
                        """,
                        (
                            payload["selection_digest"],
                            json.dumps(payload, sort_keys=True),
                            sequence,
                        ),
                    )
                    self._restore_update_trigger(connection)
                    connection.commit()

                report = inspect_authorization_shadows(database, run_id=run_id)
                self.assertFalse(report.clean)
                self.assertIn(expected, report.runs[0].integrity_issues)


if __name__ == "__main__":
    unittest.main()
