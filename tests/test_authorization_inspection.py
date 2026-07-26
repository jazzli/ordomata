from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from agentops.authorization import canonical_digest
from agentops.authorization_inspection import (
    ADMISSION_SCOPE,
    DISPATCH_SCOPE,
    PUBLICATION_SCOPE,
    inspect_authorization_shadows,
)
from agentops.errors import ConfigurationError
from agentops.models import PermissionClass, RunStatus
from agentops.state import (
    ArtifactRecord,
    RecordNotFoundError,
    RunRecord,
    SQLiteStateStore,
)


_PRIVATE_MARKERS = (
    "private-profile-marker",
    "/private/worktree-marker",
    "private-source-marker",
    "private-reason-marker",
    "private-obligation-marker",
    "private-evidence-marker",
    "private-rule-marker",
)


class AuthorizationInspectionTests(unittest.TestCase):
    def _create_run(
        self,
        database: Path,
        *,
        run_id: str = "run-inspect",
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
    ) -> SQLiteStateStore:
        store = SQLiteStateStore(database, clock=lambda: 100.0)
        store.create_run(
            RunRecord(
                run_id=run_id,
                task_id="inspect-task",
                task_version="1.0.0",
                runner_id="mock",
                workspace="/private/worktree-marker",
                run_directory="/private/run-marker",
                context_digest="a" * 64,
                permission_class=permission_class,
                timeout_seconds=60,
                attempt=1,
                created_at=100.0,
            )
        )
        return store

    def _shadow_payload(
        self,
        scope: str,
        *,
        effect: str = "permit",
        legacy_executable: bool = True,
        reported_parity: bool | None = None,
        schema_version: int = 2,
    ) -> dict[str, object]:
        publication = scope == PUBLICATION_SCOPE
        subject = {
            "principal_id": "agent:test",
            "controller_id": "controller:test",
            "role": "implementer",
            "role_version": "1",
            "profile_id": "private-profile-marker",
            "runner_id": "mock",
            "session_id": "attempt:run-inspect",
        }
        action = {
            "descriptive_claims": [],
            "verb": "create",
            "operation": (
                "artifact.publish_local_candidate"
                if publication
                else "chief_of_staff.local_brief"
            ),
            "parameters_digest": canonical_digest({"parameters": "bounded"}),
            "intended_effect": (
                "create_isolated_local_candidate"
                if publication
                else "create_local_structured_brief"
            ),
            "tool_id": None,
        }
        resource = {
            "resource_type": (
                "local_candidate_artifact" if publication else "local_artifact"
            ),
            "identifier": canonical_digest(
                {
                    "action_scope": scope,
                    "resource_type": (
                        "local_candidate_artifact"
                        if publication
                        else "local_artifact"
                    ),
                    "run_id": "run-inspect",
                }
            ),
            "version": "v1",
            "owner": "operator:local",
            "trust_boundary": "isolated_run_workspace",
            "protected": False,
            "sensitivity": "low",
            "repository_id": canonical_digest({"repository": "test"}),
            "content_digest": canonical_digest({"content": "test"}),
        }
        environment = {
            "approval_grants": [],
            "evaluated_at": 110.0,
            "isolation_state": "verified",
            "network_state": "disabled",
            "billing_route": "mock",
            "capacity_state": "not_applicable",
            "paid_continuation_protection": "not_applicable",
            "circuit_state": "closed",
            "flow_state": {
                ADMISSION_SCOPE: "admission_proposed",
                DISPATCH_SCOPE: "runner_dispatch_proposed",
                PUBLICATION_SCOPE: "local_candidate_publication_proposed",
            }[scope],
        }
        consequences = {
            "availability": "low",
            "blast_radius": "single_resource",
            "confidentiality": "low",
            "destructive": False,
            "integrity": "low",
            "reach": "local",
            "reversible": True,
            "sensitivity": "low",
        }
        attributes = {
            "subject": subject,
            "action": action,
            "resource": resource,
            "environment": environment,
            "consequences": consequences,
        }
        evidence = [
            {
                "attribute": attribute,
                "authenticated": True,
                "evidence_id": f"private-evidence-marker:{attribute}",
                "expires_at": 200.0,
                "observed_at": 100.0,
                "source": "controller",
                "source_id": "private-source-marker",
                "value_digest": canonical_digest(value),
            }
            for attribute, value in attributes.items()
        ]
        request = {
            "action": action,
            "consequences": consequences,
            "environment": environment,
            "evidence": evidence,
            "request_id": f"{scope}:run-inspect",
            "resource": resource,
            "subject": subject,
        }
        request_digest = canonical_digest(request)
        obligation = {
            "kind": "audit_receipt",
            "value": "private-obligation-marker",
        }
        decision = {
            "derived_permission_class": 1,
            "effect": effect,
            "evidence_refs": ["private-evidence-marker"],
            "expires_at": 150.0,
            "issued_at": 110.0,
            "matched_rule_ids": ["private-rule-marker"],
            "obligations": [obligation],
            "policy_bundle_id": "private-policy-marker",
            "policy_digest": canonical_digest({"policy": "bounded"}),
            "policy_version": "1",
            "reason_codes": ["current_stage_permit"],
            "reason_details": ["private-reason-marker"],
            "request_digest": request_digest,
            "request_id": f"{scope}:run-inspect",
        }
        recomputed_parity = (effect == "permit") == legacy_executable
        payload: dict[str, object] = {
            "schema_version": schema_version,
            "mode": "shadow",
            "action_scope": scope,
            "request": request,
            "request_digest": request_digest,
            "decision": decision,
            "decision_digest": canonical_digest(decision),
            "policy_bundle_id": decision["policy_bundle_id"],
            "policy_version": decision["policy_version"],
            "policy_digest": decision["policy_digest"],
            "effect": effect,
            "reason_codes": decision["reason_codes"],
            "matched_rule_ids": decision["matched_rule_ids"],
            "evidence_refs": decision["evidence_refs"],
            "obligations": decision["obligations"],
            "derived_permission_class": 1,
            "requested_permission_class": 1,
            "legacy_executable": legacy_executable,
            "execution_parity": (
                recomputed_parity if reported_parity is None else reported_parity
            ),
            "authority_ceiling_parity": True,
        }
        if schema_version == 2:
            task_intent = {
                "action": {
                    "intended_effect": action["intended_effect"],
                    "operation": action["operation"],
                    "verb": action["verb"],
                },
                "consequences": consequences,
                "resource": {
                    "protected": resource["protected"],
                    "resource_type": resource["resource_type"],
                    "sensitivity": resource["sensitivity"],
                    "trust_boundary": resource["trust_boundary"],
                },
            }
            payload.update(
                {
                    "intent_source": (
                        "controller_boundary_projection"
                        if publication
                        else "task_contract"
                    ),
                    "intent_digest": canonical_digest(task_intent),
                    "task_authorization_intent": task_intent,
                }
            )
        else:
            payload.pop("requested_permission_class")
            payload.pop("authority_ceiling_parity")
        return payload

    def _resign_payload(self, payload: dict[str, object]) -> None:
        request = payload["request"]
        decision = payload["decision"]
        self.assertIsInstance(request, dict)
        self.assertIsInstance(decision, dict)
        assert isinstance(request, dict)
        assert isinstance(decision, dict)
        request_digest = canonical_digest(request)
        payload["request_digest"] = request_digest
        decision["request_digest"] = request_digest
        payload["decision_digest"] = canonical_digest(decision)

    def test_absent_database_is_clean_and_does_not_create_state_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_directory = Path(temporary) / ".agentops"
            database = state_directory / "state.sqlite3"

            report = inspect_authorization_shadows(database, now=300.0)

            self.assertTrue(report.clean)
            self.assertFalse(report.database_present)
            self.assertEqual(report.runs, ())
            self.assertFalse(state_directory.exists())

    def test_requested_missing_run_raises_without_echoing_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.close()

            with self.assertRaises(RecordNotFoundError) as caught:
                inspect_authorization_shadows(
                    database,
                    run_id="private-missing-run-marker",
                    now=300.0,
                )

            self.assertNotIn("private-missing-run-marker", str(caught.exception))

    def test_complete_history_is_clean_read_only_and_strictly_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE),
                occurred_at=110.0,
            )
            store.append_event(
                "run-inspect",
                "billing_assessment",
                {"route": "mock"},
                occurred_at=110.5,
            )
            store.append_event(
                "run-inspect",
                "status",
                {"phase": "runner_execution"},
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(DISPATCH_SCOPE),
                occurred_at=112.0,
            )
            store.append_event(
                "run-inspect",
                "execution_accounting",
                {"incremental_api_charge": "none"},
                occurred_at=112.5,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(PUBLICATION_SCOPE),
                occurred_at=113.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                {"phase": "complete"},
                status=RunStatus.SUCCEEDED,
                occurred_at=114.0,
            )
            store.append_artifact(
                ArtifactRecord(
                    artifact_id="artifact-inspect",
                    run_id="run-inspect",
                    kind="candidate",
                    path="/private/artifact-marker",
                    sha256="b" * 64,
                    media_type="application/json",
                    size_bytes=10,
                    created_at=115.0,
                )
            )
            store.close()
            before = database.read_bytes()
            before_names = sorted(path.name for path in database.parent.iterdir())
            original_connect = sqlite3.connect
            connect_calls: list[tuple[object, dict[str, object]]] = []

            def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                connect_calls.append((args[0], dict(kwargs)))
                return original_connect(*args, **kwargs)

            with patch(
                "agentops.authorization_inspection.sqlite3.connect",
                side_effect=recording_connect,
            ):
                report = inspect_authorization_shadows(database, now=300.0)

            self.assertTrue(report.clean)
            self.assertEqual(report.inspected_run_count, 1)
            self.assertEqual(report.inspected_event_count, 3)
            self.assertEqual(
                report.runs[0].observed_scopes,
                tuple(sorted((ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE))),
            )
            self.assertEqual(report.runs[0].missing_scopes, ())
            for event in report.runs[0].events:
                self.assertTrue(event.request_digest_valid)
                self.assertTrue(event.decision_digest_valid)
                self.assertTrue(event.recomputed_execution_parity)
                self.assertEqual(len(event.evidence), 5)
                self.assertTrue(event.evidence[0].fresh_at_evaluation)
                self.assertFalse(event.evidence[0].fresh_now)
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            for marker in _PRIVATE_MARKERS:
                self.assertNotIn(marker, projection)
            self.assertEqual(database.read_bytes(), before)
            self.assertEqual(
                sorted(path.name for path in database.parent.iterdir()),
                before_names,
            )
            self.assertEqual(len(connect_calls), 1)
            self.assertIn("?mode=ro", str(connect_calls[0][0]))
            self.assertTrue(connect_calls[0][1]["uri"])

    def test_live_wal_is_read_through_a_private_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            try:
                store.append_event(
                    "run-inspect",
                    "authorization_shadow_decision",
                    self._shadow_payload(ADMISSION_SCOPE),
                    occurred_at=110.0,
                )
                before_names = sorted(
                    path.name for path in database.parent.iterdir()
                )

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertTrue(report.clean)
                self.assertEqual(report.inspected_event_count, 1)
                self.assertEqual(
                    sorted(path.name for path in database.parent.iterdir()),
                    before_names,
                )
            finally:
                store.close()

    def test_schema_v1_history_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE, schema_version=1),
                occurred_at=110.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertTrue(report.clean)
            self.assertEqual(report.inspected_event_count, 1)
            self.assertEqual(report.runs[0].events[0].integrity_issues, ())

    def test_tampering_and_legacy_disagreement_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            payload = self._shadow_payload(
                ADMISSION_SCOPE,
                effect="deny",
                legacy_executable=True,
                reported_parity=True,
            )
            payload["request_digest"] = "sha256:" + ("0" * 64)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                payload,
                occurred_at=110.0,
            )
            store.close()

            report = inspect_authorization_shadows(
                database,
                mismatches_only=True,
                now=120.0,
            )

            self.assertFalse(report.clean)
            self.assertEqual(report.parity_mismatch_count, 1)
            self.assertEqual(len(report.runs), 1)
            event = report.runs[0].events[0]
            self.assertFalse(event.recomputed_execution_parity)
            self.assertFalse(event.request_digest_valid)
            self.assertIn("request_digest_mismatch", event.integrity_issues)
            self.assertIn("execution_parity_mismatch", event.integrity_issues)
            self.assertIn(
                "decision_request_digest_mismatch", event.integrity_issues
            )

    def test_v2_scope_intent_and_requested_class_tampering_are_detected(
        self,
    ) -> None:
        cases: list[tuple[str, tuple[str, ...]]] = []

        swapped_scope = self._shadow_payload(ADMISSION_SCOPE)
        swapped_scope["action_scope"] = DISPATCH_SCOPE
        cases.append(
            (
                json.dumps(swapped_scope),
                (
                    "boundary_flow_state_mismatch",
                    "boundary_request_identifier_mismatch",
                    "boundary_resource_identifier_mismatch",
                ),
            )
        )

        intent_tampered = self._shadow_payload(ADMISSION_SCOPE)
        intent = intent_tampered["task_authorization_intent"]
        self.assertIsInstance(intent, dict)
        assert isinstance(intent, dict)
        action = intent["action"]
        self.assertIsInstance(action, dict)
        assert isinstance(action, dict)
        action["operation"] = "artifact.different_operation"
        intent_tampered["intent_digest"] = canonical_digest(intent)
        cases.append(
            (
                json.dumps(intent_tampered),
                ("task_intent_request_projection_mismatch",),
            )
        )

        class_tampered = self._shadow_payload(ADMISSION_SCOPE)
        class_tampered["requested_permission_class"] = 0
        cases.append(
            (
                json.dumps(class_tampered),
                ("requested_permission_class_run_mismatch",),
            )
        )

        source_tampered = self._shadow_payload(PUBLICATION_SCOPE)
        source_tampered["intent_source"] = "task_contract"
        cases.append(
            (
                json.dumps(source_tampered),
                ("task_intent_source_invalid",),
            )
        )

        derived_tampered = self._shadow_payload(ADMISSION_SCOPE)
        request = derived_tampered["request"]
        intent = derived_tampered["task_authorization_intent"]
        self.assertIsInstance(request, dict)
        self.assertIsInstance(intent, dict)
        assert isinstance(request, dict)
        assert isinstance(intent, dict)
        request_consequences = request["consequences"]
        intent_consequences = intent["consequences"]
        evidence = request["evidence"]
        assert isinstance(request_consequences, dict)
        assert isinstance(intent_consequences, dict)
        assert isinstance(evidence, list)
        request_consequences["confidentiality"] = "high"
        intent_consequences["confidentiality"] = "high"
        derived_tampered["intent_digest"] = canonical_digest(intent)
        consequence_evidence = next(
            item
            for item in evidence
            if isinstance(item, dict) and item.get("attribute") == "consequences"
        )
        consequence_evidence["value_digest"] = canonical_digest(
            request_consequences
        )
        self._resign_payload(derived_tampered)
        cases.append(
            (
                json.dumps(derived_tampered),
                (
                    "authority_ceiling_parity_mismatch",
                    "derived_class_exceeds_run_authority",
                    "derived_permission_class_mismatch",
                ),
            )
        )

        for index, (encoded, expected_issues) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "state.sqlite3"
                store = self._create_run(database)
                store.append_event(
                    "run-inspect",
                    "authorization_shadow_decision",
                    json.loads(encoded),
                    occurred_at=110.0,
                )
                store.close()

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertFalse(report.clean)
                issues = report.runs[0].events[0].integrity_issues
                for expected in expected_issues:
                    self.assertIn(expected, issues)

    def test_legacy_executable_is_recomputed_from_the_run_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            payload = self._shadow_payload(
                ADMISSION_SCOPE,
                effect="deny",
                legacy_executable=False,
                reported_parity=True,
            )
            decision = payload["decision"]
            self.assertIsInstance(decision, dict)
            assert isinstance(decision, dict)
            decision["effect"] = "deny"
            self._resign_payload(payload)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                payload,
                occurred_at=110.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            event = report.runs[0].events[0]
            self.assertFalse(event.legacy_executable)
            self.assertTrue(event.recomputed_legacy_executable)
            self.assertFalse(event.recomputed_execution_parity)
            self.assertIn(
                "legacy_executable_run_mismatch", event.integrity_issues
            )
            self.assertIn("execution_parity_mismatch", event.integrity_issues)

    def test_evidence_must_be_authenticated_and_fresh_at_evaluation(self) -> None:
        def unauthenticated(payload: dict[str, object]) -> None:
            request = payload["request"]
            assert isinstance(request, dict)
            evidence = request["evidence"]
            assert isinstance(evidence, list)
            assert isinstance(evidence[0], dict)
            evidence[0]["authenticated"] = False

        def stale(payload: dict[str, object]) -> None:
            request = payload["request"]
            assert isinstance(request, dict)
            evidence = request["evidence"]
            assert isinstance(evidence, list)
            assert isinstance(evidence[0], dict)
            evidence[0]["expires_at"] = 105.0

        def future(payload: dict[str, object]) -> None:
            request = payload["request"]
            assert isinstance(request, dict)
            evidence = request["evidence"]
            assert isinstance(evidence, list)
            assert isinstance(evidence[0], dict)
            evidence[0]["observed_at"] = 115.0

        for mutator, expected_issue in (
            (unauthenticated, "evidence_unauthenticated"),
            (stale, "evidence_stale_at_evaluation"),
            (future, "evidence_from_future_at_evaluation"),
        ):
            with (
                self.subTest(expected_issue=expected_issue),
                tempfile.TemporaryDirectory() as temporary,
            ):
                database = Path(temporary) / "state.sqlite3"
                store = self._create_run(database)
                payload = self._shadow_payload(ADMISSION_SCOPE)
                mutator(payload)
                self._resign_payload(payload)
                store.append_event(
                    "run-inspect",
                    "authorization_shadow_decision",
                    payload,
                    occurred_at=110.0,
                )
                store.close()

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertFalse(report.clean)
                self.assertIn(
                    expected_issue,
                    report.runs[0].events[0].integrity_issues,
                )

    def test_expected_boundary_coverage_uses_status_and_artifact_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE),
                occurred_at=110.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.SUCCEEDED,
                occurred_at=112.0,
            )
            store.append_artifact(
                ArtifactRecord(
                    artifact_id="artifact-inspect",
                    run_id="run-inspect",
                    kind="candidate",
                    path="artifacts/candidate.json",
                    sha256="b" * 64,
                    media_type="application/json",
                    size_bytes=10,
                    created_at=113.0,
                )
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            self.assertEqual(report.coverage_gap_count, 2)
            self.assertEqual(
                report.runs[0].missing_scopes,
                (PUBLICATION_SCOPE, DISPATCH_SCOPE),
            )

    def test_boundary_order_is_checked_against_controller_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "billing_assessment",
                {"route": "mock"},
                occurred_at=109.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE),
                occurred_at=110.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-inspect",
                "runner_event_observed",
                {"ordinal": 1},
                occurred_at=112.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(DISPATCH_SCOPE),
                occurred_at=113.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(PUBLICATION_SCOPE),
                occurred_at=114.0,
            )
            store.append_event(
                "run-inspect",
                "execution_accounting",
                {"incremental_api_charge": "none"},
                occurred_at=115.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.SUCCEEDED,
                occurred_at=116.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            self.assertEqual(
                report.runs[0].integrity_issues,
                (
                    "admission_boundary_order_invalid",
                    "dispatch_boundary_order_invalid",
                    "publication_boundary_order_invalid",
                ),
            )

    def test_malformed_event_and_database_return_only_fixed_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.close()
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """
                    INSERT INTO run_events (
                        event_id, run_id, event_type, status, payload_json, occurred_at
                    ) VALUES (?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        "malformed-event",
                        "run-inspect",
                        "authorization_shadow_decision",
                        '{"private-reason-marker":',
                        110.0,
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            report = inspect_authorization_shadows(database, now=120.0)
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            self.assertIn("payload_json_invalid", projection)
            self.assertNotIn("private-reason-marker", projection)

            malformed_database = Path(temporary) / "malformed.sqlite3"
            malformed_database.write_text("private-database-marker", encoding="utf-8")
            with self.assertRaises(ConfigurationError) as caught:
                inspect_authorization_shadows(malformed_database, now=120.0)
            self.assertNotIn("private-database-marker", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
