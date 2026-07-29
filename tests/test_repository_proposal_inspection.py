from __future__ import annotations

import asyncio
from contextlib import closing, contextmanager
from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
from ordomata.models import PermissionClass, RunStatus
from ordomata import repository_proposal as repository_proposal_module
from ordomata import (
    repository_proposal_inspection as repository_proposal_inspection_module,
)
from ordomata.repository_proposal import (
    REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
    REPOSITORY_PROPOSAL_RUNNER_ID,
    REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
    bind_repository_proposal_attempt,
)
from ordomata.repository_proposal_inspection import (
    RepositoryProposalInspectionReport,
    inspect_repository_proposal_evidence,
)
from ordomata.repository_registration import (
    RepositoryRegistration,
    validate_repository_registration,
)
from ordomata.state import (
    RecordNotFoundError,
    RunRecord,
    SQLiteStateStore,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FINDING_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_FINDING_CODES = frozenset(
    {
        "run_record_invalid",
        "runner_invalid",
        "permission_class_invalid",
        "history_cardinality_invalid",
        "created_event_invalid",
        "run_status_invalid",
        "unexpected_event",
        "event_limit_exceeded",
        "registration_selection_missing",
        "registration_selection_duplicate",
        "registration_selection_status_invalid",
        "registration_selection_payload_invalid",
        "registration_selection_event_identifier_mismatch",
        "repository_proposal_binding_missing",
        "repository_proposal_binding_duplicate",
        "repository_proposal_binding_status_invalid",
        "repository_proposal_binding_payload_invalid",
        "repository_proposal_binding_event_identifier_mismatch",
        "proposal_event_order_invalid",
        "durable_run_linkage_mismatch",
        "proposal_linkage_mismatch",
        "registration_component_linkage_mismatch",
        "disabled_semantics_mismatch",
    }
)
_FINDING_ORDER = (
    "run_record_invalid",
    "runner_invalid",
    "permission_class_invalid",
    "history_cardinality_invalid",
    "created_event_invalid",
    "run_status_invalid",
    "unexpected_event",
    "event_limit_exceeded",
    "registration_selection_missing",
    "registration_selection_duplicate",
    "registration_selection_status_invalid",
    "registration_selection_payload_invalid",
    "registration_selection_event_identifier_mismatch",
    "repository_proposal_binding_missing",
    "repository_proposal_binding_duplicate",
    "repository_proposal_binding_status_invalid",
    "repository_proposal_binding_payload_invalid",
    "repository_proposal_binding_event_identifier_mismatch",
    "proposal_event_order_invalid",
    "durable_run_linkage_mismatch",
    "proposal_linkage_mismatch",
    "registration_component_linkage_mismatch",
    "disabled_semantics_mismatch",
)
_FINDING_RANK = {code: index for index, code in enumerate(_FINDING_ORDER)}
_REPORT_MAPPING_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "inspection_scope",
        "inspection_mode",
        "validation_mode",
        "repair_performed",
        "dispatch_enabled",
        "authority_granted",
        "run_ref",
        "coverage",
        "truncated",
        "clean",
        "evidence_complete",
        "inspected_event_count",
        "permission_class",
        "current_status",
        "proposal_digest",
        "proposal_ref",
        "proposal_version_ref",
        "registration_digest",
        "registration_ref",
        "registration_version",
        "repository_ref",
        "registration_selection_digest",
        "repository_proposal_binding_digest",
        "selection_sequence",
        "binding_sequence",
        "finding_count",
        "findings",
    }
)
_PROPOSAL_DIGEST = canonical_digest(
    {"proposal": "private-proposal-content-inspection-marker"}
)
_PRIVATE_MARKERS = (
    "private-proposal-inspection-run-marker",
    "private-proposal-id-inspection-marker",
    "private-proposal-version-inspection-marker",
    "private-registration-id-inspection-marker",
    "private-repository-id-inspection-marker",
    "private-workspace-inspection-marker",
    "private-run-directory-inspection-marker",
    "private-path-inspection-marker",
    "private-command-inspection-marker",
    "private-test-command-inspection-marker",
    "private-repository-root-inspection-marker",
    "private-malformed-payload-inspection-marker",
    "private-sqlite-inspection-marker",
)


class RepositoryProposalInspectionTests(unittest.TestCase):
    @staticmethod
    def _repository(base: Path) -> Path:
        root = base / "private-repository-root-inspection-marker"
        root.mkdir()
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n",
            encoding="utf-8",
        )
        for name in ("source", "tests", "docs"):
            (root / name).mkdir()
        (root / "protected.txt").write_text(
            "controller-owned\n",
            encoding="utf-8",
        )
        return root

    @staticmethod
    def _registration_payload() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "repository_registration",
            "registration_id": "private-registration-id-inspection-marker",
            "registration_version": "1.0.0",
            "repository": {
                "repository_id": "private-repository-id-inspection-marker",
                "vcs": "git",
                "root": ".",
            },
            "verification_commands": {
                "format": [
                    {
                        "command_id": "private-command-inspection-marker",
                        "argv": ["python3", "-m", "compileall", "-q", "source"],
                        "cwd": ".",
                    }
                ],
                "lint": [],
                "type_check": [],
                "test": [
                    {
                        "command_id": "private-test-command-inspection-marker",
                        "argv": [
                            "python3",
                            "-m",
                            "unittest",
                            "discover",
                            "-s",
                            "tests",
                        ],
                        "cwd": ".",
                    }
                ],
                "build": [],
            },
            "path_policy": {
                "allowed_paths": ["docs", "source", "tests"],
                "protected_paths": [
                    "protected.txt",
                    ".ordomata",
                    ".git",
                    ".agentops",
                ],
            },
            "resource_limits": {
                "cpu_count": 2,
                "cpu_seconds": 300,
                "memory_bytes": 1_073_741_824,
                "process_count": 64,
                "workspace_bytes": 1_073_741_824,
                "output_bytes": 4_194_304,
                "artifact_count": 64,
                "artifact_bytes": 16_777_216,
                "wall_seconds": 600,
                "idle_seconds": 120,
            },
            "isolation_requirements": {
                "backend": "local_container",
                "network_mode": "disabled",
                "non_root": True,
                "read_only_base_repository": True,
                "read_only_root_filesystem": True,
                "explicit_mounts_only": True,
                "git_metadata_hidden": True,
                "credential_paths_denied": True,
                "control_sockets_denied": True,
                "fresh_cell_per_attempt": True,
            },
            "review_policy": {
                "output": "patch_only",
                "branch_creation": False,
                "commit": False,
                "push": False,
                "pull_request": False,
                "promotion": False,
            },
        }

    @classmethod
    def _registration(cls, root: Path) -> RepositoryRegistration:
        return validate_repository_registration(
            cls._registration_payload(),
            repository_root=root,
        )

    @staticmethod
    def _create_run(
        state: SQLiteStateStore,
        *,
        run_id: str = "private-proposal-inspection-run-marker",
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
    ) -> RunRecord:
        return state.create_run(
            RunRecord(
                run_id=run_id,
                task_id="private-proposal-id-inspection-marker",
                task_version="private-proposal-version-inspection-marker",
                runner_id=REPOSITORY_PROPOSAL_RUNNER_ID,
                workspace=(
                    "/synthetic-private-workspace-inspection-marker/" + run_id
                ),
                run_directory=(
                    "/synthetic-private-run-directory-inspection-marker/"
                    + run_id
                ),
                context_digest="sha256:" + "a" * 64,
                permission_class=permission_class,
                timeout_seconds=321,
                attempt=2,
                created_at=100.0,
            )
        )

    @classmethod
    def _create_complete(
        cls,
        base: Path,
        *,
        run_id: str = "private-proposal-inspection-run-marker",
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
        keep_open: bool = False,
    ) -> tuple[Path, Path, RunRecord, SQLiteStateStore | None]:
        root = cls._repository(base)
        database = base / "state.sqlite3"
        state = SQLiteStateStore(database, clock=lambda: 101.0)
        run = cls._create_run(
            state,
            run_id=run_id,
            permission_class=permission_class,
        )
        bind_repository_proposal_attempt(
            state,
            run_id=run.run_id,
            proposal_digest=_PROPOSAL_DIGEST,
            registration=cls._registration(root),
        )
        if keep_open:
            return database, root, run, state
        state.close()
        return database, root, run, None

    @staticmethod
    def _restore_trigger(
        connection: sqlite3.Connection,
        *,
        table: str,
        operation: str,
    ) -> None:
        messages = {
            ("run_events", "UPDATE"): "run events are append-only",
            ("run_events", "DELETE"): "run events are append-only",
            ("runs", "UPDATE"): "runs are append-only",
            ("runs", "DELETE"): "runs are append-only",
        }
        trigger_name = f"{table}_no_{operation.casefold()}"
        connection.execute(
            f"""
            CREATE TRIGGER {trigger_name}
            BEFORE {operation} ON {table} BEGIN
                SELECT RAISE(ABORT, '{messages[(table, operation)]}');
            END
            """
        )

    @classmethod
    @contextmanager
    def _tamper(
        cls,
        database: Path,
        *,
        event_update: bool = False,
        event_delete: bool = False,
        run_update: bool = False,
    ):
        with closing(sqlite3.connect(database)) as connection:
            removed: list[tuple[str, str]] = []
            for enabled, table, operation in (
                (event_update, "run_events", "UPDATE"),
                (event_delete, "run_events", "DELETE"),
                (run_update, "runs", "UPDATE"),
            ):
                if enabled:
                    connection.execute(
                        f"DROP TRIGGER {table}_no_{operation.casefold()}"
                    )
                    removed.append((table, operation))
            try:
                yield connection
            finally:
                for table, operation in removed:
                    cls._restore_trigger(
                        connection,
                        table=table,
                        operation=operation,
                    )
                connection.commit()

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        run_id: str,
        event_type: str,
    ) -> tuple[int, str, object]:
        row = connection.execute(
            """
            SELECT sequence, event_id, payload_json FROM run_events
            WHERE run_id = ? AND event_type = ?
            ORDER BY sequence LIMIT 1
            """,
            (run_id, event_type),
        ).fetchone()
        assert row is not None
        return int(row[0]), str(row[1]), row[2]

    @classmethod
    def _rewrite_payload(
        cls,
        database: Path,
        run_id: str,
        event_type: str,
        mutate,
        *,
        rehash: bool,
    ) -> None:
        with cls._tamper(database, event_update=True) as connection:
            sequence, event_id, payload_json = cls._event(
                connection,
                run_id,
                event_type,
            )
            payload = json.loads(str(payload_json))
            mutate(payload)
            if rehash:
                if event_type == REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE:
                    payload["selection_digest"] = canonical_digest(
                        payload["selection"]
                    )
                    event_id = payload["selection_digest"]
                else:
                    payload["binding_digest"] = canonical_digest(
                        payload["binding"]
                    )
                    event_id = payload["binding_digest"]
            connection.execute(
                """
                UPDATE run_events SET event_id = ?, payload_json = ?
                WHERE sequence = ?
                """,
                (
                    event_id,
                    json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                    sequence,
                ),
            )

    @staticmethod
    def _finding_codes(report) -> tuple[str, ...]:
        return tuple(finding.code for finding in report.findings)

    def _assert_fixed_report_shape(self, report) -> None:
        mapping = report.to_mapping()
        self.assertEqual(frozenset(mapping), _REPORT_MAPPING_KEYS)
        self.assertEqual(mapping["schema_version"], 1)
        self.assertEqual(mapping["kind"], "repository_proposal_inspection")
        self.assertEqual(mapping["inspection_scope"], "single_run")
        self.assertEqual(mapping["inspection_mode"], "read_only")
        self.assertEqual(mapping["validation_mode"], "read_only")
        self.assertFalse(mapping["repair_performed"])
        self.assertFalse(mapping["dispatch_enabled"])
        self.assertFalse(mapping["authority_granted"])
        self.assertEqual(mapping["finding_count"], len(report.findings))
        self.assertEqual(mapping["clean"], report.clean)
        self.assertEqual(
            mapping["evidence_complete"],
            report.coverage == "complete",
        )
        self.assertIn(report.coverage, {"complete", "incomplete", "invalid"})
        self.assertLessEqual(report.inspected_event_count, 4)
        self.assertEqual(
            tuple(item["code"] for item in mapping["findings"]),
            self._finding_codes(report),
        )
        for item in mapping["findings"]:
            self.assertEqual(set(item), {"code"})
            self.assertRegex(item["code"], _FINDING_CODE)
            self.assertIn(item["code"], _FINDING_CODES)
        codes = self._finding_codes(report)
        self.assertEqual(len(codes), len(set(codes)))
        self.assertLessEqual(len(codes), 24)
        self.assertEqual(
            tuple(_FINDING_RANK[code] for code in codes),
            tuple(sorted(_FINDING_RANK[code] for code in codes)),
        )

    def _assert_private_values_absent(self, value: object) -> None:
        projection = json.dumps(value, sort_keys=True, default=str)
        for marker in _PRIVATE_MARKERS:
            self.assertNotIn(marker, projection)

    def _assert_invalid(self, report) -> None:
        self._assert_fixed_report_shape(report)
        self.assertFalse(report.clean)
        self.assertEqual(report.coverage, "invalid")
        self.assertTrue(report.findings)
        self._assert_private_values_absent(report.to_mapping())

    def test_clean_class_zero_and_one_reports_are_complete_and_redacted(
        self,
    ) -> None:
        for permission_class in (
            PermissionClass.READ_ONLY,
            PermissionClass.LOCAL_DRAFT,
        ):
            with self.subTest(permission_class=permission_class), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(
                    base,
                    permission_class=permission_class,
                )

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )

                self._assert_fixed_report_shape(report)
                self.assertTrue(report.clean, report.to_mapping())
                self.assertEqual(report.coverage, "complete")
                self.assertFalse(report.truncated)
                self.assertEqual(report.inspected_event_count, 3)
                self.assertEqual(report.permission_class, int(permission_class))
                self.assertEqual(report.current_status, "created")
                self.assertEqual(
                    report.run_ref,
                    canonical_digest({"run_id": run.run_id}),
                )
                self.assertEqual(report.proposal_digest, _PROPOSAL_DIGEST)
                self.assertEqual(
                    report.proposal_ref,
                    canonical_digest({"proposal_id": run.task_id}),
                )
                self.assertEqual(
                    report.proposal_version_ref,
                    canonical_digest({"proposal_version": run.task_version}),
                )
                for value in (
                    report.registration_digest,
                    report.registration_ref,
                    report.repository_ref,
                    report.registration_selection_digest,
                    report.repository_proposal_binding_digest,
                ):
                    self.assertIsNotNone(value)
                    self.assertRegex(value, _DIGEST)
                self.assertEqual(report.registration_version, "1.0.0")
                self.assertEqual(report.selection_sequence, 2)
                self.assertEqual(report.binding_sequence, 3)
                self.assertEqual(report.findings, ())
                self._assert_private_values_absent(report.to_mapping())

    def test_complete_report_cannot_be_constructed_without_complete_evidence(
        self,
    ) -> None:
        with self.assertRaises(ValidationError):
            RepositoryProposalInspectionReport(
                run_ref=canonical_digest({"run_id": "private-forged-report"}),
                coverage="complete",
                truncated=False,
                inspected_event_count=0,
                permission_class=None,
                current_status=None,
                proposal_digest=None,
                proposal_ref=None,
                proposal_version_ref=None,
                registration_digest=None,
                registration_ref=None,
                registration_version=None,
                repository_ref=None,
                registration_selection_digest=None,
                repository_proposal_binding_digest=None,
                selection_sequence=None,
                binding_sequence=None,
                findings=(),
            )

    def test_multibyte_run_identifier_keeps_valid_created_event_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_id = "😀" * 2_000
            database, _, _, _ = self._create_complete(
                Path(temporary),
                run_id=run_id,
            )
            report = inspect_repository_proposal_evidence(
                database,
                run_id=run_id,
            )
            self.assertTrue(report.clean, report.to_mapping())
            self.assertNotIn(run_id, json.dumps(report.to_mapping()))

    def test_exact_recoverable_prefixes_are_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database = base / "created-only.sqlite3"
            with SQLiteStateStore(database) as state:
                run = self._create_run(state)
            created = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_fixed_report_shape(created)
            self.assertFalse(created.clean)
            self.assertEqual(created.coverage, "incomplete")
            self.assertFalse(created.truncated)
            self.assertEqual(created.inspected_event_count, 1)
            self.assertEqual(created.current_status, "created")
            self.assertIsNone(created.selection_sequence)
            self.assertIsNone(created.binding_sequence)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with self._tamper(database, event_delete=True) as connection:
                connection.execute(
                    "DELETE FROM run_events WHERE run_id = ? AND event_type = ?",
                    (run.run_id, REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE),
                )

            selection_only = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_fixed_report_shape(selection_only)
            self.assertFalse(selection_only.clean)
            self.assertEqual(selection_only.coverage, "incomplete")
            self.assertFalse(selection_only.truncated)
            self.assertEqual(selection_only.inspected_event_count, 2)
            self.assertEqual(selection_only.selection_sequence, 2)
            self.assertIsNone(selection_only.binding_sequence)
            self.assertEqual(
                selection_only.registration_selection_digest,
                self._read_payload(
                    database,
                    run.run_id,
                    REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                )["selection_digest"],
            )

    def test_created_prefix_over_predecessor_id_limit_is_not_recoverable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_id = "r" * 4_056
            database = Path(temporary) / "state.sqlite3"
            with SQLiteStateStore(database) as state:
                state.create_run(
                    RunRecord(
                        run_id=run_id,
                        task_id="proposal",
                        task_version="version",
                        runner_id=REPOSITORY_PROPOSAL_RUNNER_ID,
                        workspace="workspace",
                        run_directory="run-directory",
                        context_digest="sha256:" + "a" * 64,
                        permission_class=PermissionClass.LOCAL_DRAFT,
                        timeout_seconds=60,
                        attempt=1,
                        created_at=100.0,
                    )
                )
            report = inspect_repository_proposal_evidence(
                database,
                run_id=run_id,
            )
            self._assert_invalid(report)
            self.assertIn("created_event_invalid", self._finding_codes(report))

    @classmethod
    def _read_payload(
        cls,
        database: Path,
        run_id: str,
        event_type: str,
    ) -> dict[str, object]:
        with closing(sqlite3.connect(database)) as connection:
            _, _, payload_json = cls._event(connection, run_id, event_type)
        decoded = json.loads(str(payload_json))
        assert isinstance(decoded, dict)
        return decoded

    def test_missing_selection_with_binding_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with self._tamper(database, event_delete=True) as connection:
                connection.execute(
                    "DELETE FROM run_events WHERE run_id = ? AND event_type = ?",
                    (run.run_id, REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE),
                )

            report = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(report)
            self.assertEqual(report.inspected_event_count, 2)

    def test_duplicate_target_events_are_invalid(self) -> None:
        for event_type in (
            REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
        ):
            with self.subTest(event_type=event_type), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)
                with closing(sqlite3.connect(database)) as connection:
                    row = connection.execute(
                        """
                        SELECT payload_json, occurred_at FROM run_events
                        WHERE run_id = ? AND event_type = ?
                        """,
                        (run.run_id, event_type),
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
                                {"duplicate": event_type, "run": run.run_id}
                            ),
                            run.run_id,
                            event_type,
                            row[0],
                            row[1],
                        ),
                    )
                    connection.commit()

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self._assert_invalid(report)
                self.assertEqual(report.inspected_event_count, 4)
                self.assertFalse(report.truncated)

    def test_reordered_events_and_status_bearing_evidence_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with self._tamper(database, event_update=True) as connection:
                selection = self._event(
                    connection,
                    run.run_id,
                    REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                )
                binding = self._event(
                    connection,
                    run.run_id,
                    REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                )
                temporary_selection_id = canonical_digest(
                    {"temporary_selection": run.run_id}
                )
                connection.execute(
                    "UPDATE run_events SET event_id = ? WHERE sequence = ?",
                    (temporary_selection_id, selection[0]),
                )
                connection.execute(
                    """
                    UPDATE run_events
                    SET event_type = ?, event_id = ?, payload_json = ?
                    WHERE sequence = ?
                    """,
                    (
                        REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                        selection[1],
                        selection[2],
                        binding[0],
                    ),
                )
                connection.execute(
                    """
                    UPDATE run_events
                    SET event_type = ?, event_id = ?, payload_json = ?
                    WHERE sequence = ?
                    """,
                    (
                        REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                        binding[1],
                        binding[2],
                        selection[0],
                    ),
                )

            reordered = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(reordered)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with self._tamper(database, event_update=True) as connection:
                connection.execute(
                    """
                    UPDATE run_events SET status = 'created'
                    WHERE run_id = ? AND event_type = ?
                    """,
                    (run.run_id, REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE),
                )
            status_bearing = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(status_bearing)

    def test_extra_events_are_invalid_and_event_count_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with SQLiteStateStore(database) as state:
                state.append_event(
                    run.run_id,
                    "private-extra-inspection-event",
                    {},
                    event_id=canonical_digest({"extra": 1, "run": run.run_id}),
                )
            four = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(four)
            self.assertFalse(four.truncated)
            self.assertEqual(four.inspected_event_count, 4)

            with SQLiteStateStore(database) as state:
                for index in range(2, 8):
                    state.append_event(
                        run.run_id,
                        f"private-extra-inspection-event-{index}",
                        {},
                        event_id=canonical_digest(
                            {"extra": index, "run": run.run_id}
                        ),
                    )
            many = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(many)
            self.assertTrue(many.truncated)
            self.assertEqual(many.inspected_event_count, 4)

    def test_event_limit_detection_reads_only_a_five_row_index_window(
        self,
    ) -> None:
        class Result:
            @staticmethod
            def fetchall():
                return tuple({"sequence": index} for index in range(1, 6))

        class Connection:
            def __init__(self) -> None:
                self.calls: list[tuple[str, tuple[object, ...]]] = []

            def execute(self, sql, parameters):
                self.calls.append((sql, parameters))
                return Result()

        connection = Connection()
        events, truncated = (
            repository_proposal_inspection_module._read_event_window(
                connection,
                run_id="private-bounded-window-run-marker",
                database_encoding="utf-8",
            )
        )
        self.assertTrue(truncated)
        self.assertEqual(events, ())
        self.assertEqual(len(connection.calls), 1)
        sql, parameters = connection.calls[0]
        normalized = " ".join(sql.split()).upper()
        self.assertIn("INDEXED BY RUN_EVENTS_RUN_SEQUENCE", normalized)
        self.assertIn("LIMIT ?", normalized)
        self.assertNotIn("COUNT(", normalized)
        self.assertNotIn("SUM(", normalized)
        self.assertEqual(parameters, ("private-bounded-window-run-marker", 5))

    def test_later_status_transition_is_invalid_but_safely_projected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with SQLiteStateStore(database) as state:
                state.append_event(
                    run.run_id,
                    "status",
                    {},
                    status=RunStatus.FAILED,
                )

            report = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(report)
            self.assertIsNone(report.current_status)
            self.assertEqual(report.inspected_event_count, 4)

    def test_initial_created_event_metadata_is_strictly_validated(self) -> None:
        cases: tuple[tuple[str, object], ...] = (
            ("empty", ""),
            ("blob", sqlite3.Binary(b"private-created-event-inspection-marker")),
            ("oversized", "x" * 4_138),
            ("wrong_format", "innocuous-but-not-original"),
            ("non_v4_uuid", "__run_bound_non_v4_uuid__"),
        )
        for case, event_id in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)
                if event_id == "__run_bound_non_v4_uuid__":
                    event_id = f"{run.run_id}:created:{'0' * 32}"
                with self._tamper(database, event_update=True) as connection:
                    connection.execute(
                        """
                        UPDATE run_events SET event_id = ?
                        WHERE run_id = ? AND event_type = 'status'
                        """,
                        (event_id, run.run_id),
                    )

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self._assert_invalid(report)
                self.assertIn("created_event_invalid", self._finding_codes(report))

    def test_event_ids_and_all_digest_layers_are_recomputed(self) -> None:
        cases = (
            ("selection_event_id", REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE),
            ("binding_event_id", REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE),
            ("selection_digest", REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE),
            ("binding_digest", REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE),
            (
                "registration_evidence_digest",
                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
            ),
        )
        for case, event_type in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)
                if case.endswith("event_id"):
                    with self._tamper(database, event_update=True) as connection:
                        connection.execute(
                            """
                            UPDATE run_events SET event_id = ?
                            WHERE run_id = ? AND event_type = ?
                            """,
                            (
                                canonical_digest(
                                    {"wrong_event_id": case, "run": run.run_id}
                                ),
                                run.run_id,
                                event_type,
                            ),
                        )
                elif case == "selection_digest":
                    self._rewrite_payload(
                        database,
                        run.run_id,
                        event_type,
                        lambda payload: payload.__setitem__(
                            "selection_digest", "sha256:" + "0" * 64
                        ),
                        rehash=False,
                    )
                elif case == "binding_digest":
                    self._rewrite_payload(
                        database,
                        run.run_id,
                        event_type,
                        lambda payload: payload.__setitem__(
                            "binding_digest", "sha256:" + "0" * 64
                        ),
                        rehash=False,
                    )
                else:
                    def mutate(payload):
                        payload["selection"][
                            "selected_registration_evidence_digest"
                        ] = "sha256:" + "0" * 64

                    self._rewrite_payload(
                        database,
                        run.run_id,
                        event_type,
                        mutate,
                        rehash=True,
                    )

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self._assert_invalid(report)

    def test_coherently_rehashed_disabled_and_proposal_semantics_fail(self) -> None:
        cases = (
            (
                "selection_mode",
                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                lambda payload: payload["selection"].__setitem__(
                    "selection_mode", "agent_owned"
                ),
            ),
            (
                "selected_dispatch",
                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                lambda payload: payload["selection"][
                    "selected_registration"
                ].__setitem__("dispatch_enabled", True),
            ),
            (
                "selected_authority",
                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                lambda payload: payload["selection"][
                    "selected_registration"
                ].__setitem__("authority_granted", True),
            ),
            (
                "binding_validation",
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                lambda payload: payload["binding"].__setitem__(
                    "validation_mode", "execute"
                ),
            ),
            (
                "binding_dispatch",
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                lambda payload: payload["binding"].__setitem__(
                    "dispatch_enabled", True
                ),
            ),
            (
                "binding_authority",
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                lambda payload: payload["binding"].__setitem__(
                    "authority_granted", True
                ),
            ),
            (
                "proposal_link",
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                lambda payload: payload["binding"].__setitem__(
                    "proposal_digest", "sha256:" + "9" * 64
                ),
            ),
        )
        for case, event_type, mutate in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)

                if case.startswith("selected_"):
                    original_mutate = mutate

                    def mutate_selected(payload):
                        original_mutate(payload)
                        selected = payload["selection"]["selected_registration"]
                        payload["selection"][
                            "selected_registration_evidence_digest"
                        ] = canonical_digest(selected)

                    selected_mutate = mutate_selected
                else:
                    selected_mutate = mutate
                self._rewrite_payload(
                    database,
                    run.run_id,
                    event_type,
                    selected_mutate,
                    rehash=True,
                )

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self._assert_invalid(report)

    def test_every_durable_run_field_is_replayed_after_coherent_rehash(self) -> None:
        mutations = {
            "run_ref": "sha256:" + "1" * 64,
            "proposal_ref": "sha256:" + "2" * 64,
            "proposal_version_ref": "sha256:" + "3" * 64,
            "runner_ref": "sha256:" + "4" * 64,
            "workspace_ref": "sha256:" + "5" * 64,
            "run_directory_ref": "sha256:" + "6" * 64,
            "created_at_ref": "sha256:" + "7" * 64,
            "context_digest": "sha256:" + "8" * 64,
            "timeout_seconds": 322,
            "attempt": 3,
            "permission_class": 0,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)

                self._rewrite_payload(
                    database,
                    run.run_id,
                    REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                    lambda payload, field=field, replacement=replacement: payload[
                        "binding"
                    ].__setitem__(field, replacement),
                    rehash=True,
                )

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self._assert_invalid(report)

    def test_every_registration_component_link_is_replayed(self) -> None:
        fields = (
            "filesystem_identity_ref",
            "isolation_requirements_digest",
            "path_policy_digest",
            "registration_digest",
            "registration_evidence_digest",
            "registration_ref",
            "registration_selection_digest",
            "repository_ref",
            "resource_limits_digest",
            "review_policy_digest",
            "verification_commands_digest",
        )
        for field in fields:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)
                self._rewrite_payload(
                    database,
                    run.run_id,
                    REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                    lambda payload, field=field: payload["binding"].__setitem__(
                        field,
                        "sha256:" + "e" * 64,
                    ),
                    rehash=True,
                )

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self._assert_invalid(report)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            self._rewrite_payload(
                database,
                run.run_id,
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                lambda payload: payload["binding"].__setitem__(
                    "registration_version", "1.0.1"
                ),
                rehash=True,
            )
            self._assert_invalid(
                inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
            )

    def test_wrong_runner_is_inspected_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with self._tamper(database, run_update=True) as connection:
                connection.execute(
                    "UPDATE runs SET runner_id = ? WHERE run_id = ?",
                    ("private-wrong-runner-inspection-marker", run.run_id),
                )

            report = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(report)
            self.assertNotIn(
                "private-wrong-runner-inspection-marker",
                json.dumps(report.to_mapping(), sort_keys=True),
            )

    def test_invalid_durable_permission_class_is_value_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with self._tamper(database, run_update=True) as connection:
                connection.execute("PRAGMA ignore_check_constraints = ON")
                connection.execute(
                    "UPDATE runs SET permission_class = 2 WHERE run_id = ?",
                    (run.run_id,),
                )

            report = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self._assert_invalid(report)
            self.assertIsNone(report.permission_class)
            self.assertIn("run_record_invalid", self._finding_codes(report))
            self.assertIn("permission_class_invalid", self._finding_codes(report))

    def test_malformed_and_oversized_payloads_are_bounded_and_redacted(self) -> None:
        deeply_nested = '{"value":' * 66 + "null" + "}" * 66
        too_many_nodes = json.dumps(
            {"values": [0] * 10_001},
            separators=(",", ":"),
        )
        payloads: tuple[object, ...] = (
            '{"private-malformed-payload-inspection-marker":',
            "[]",
            '{"schema_version":1,"schema_version":1}',
            '{"value":NaN}',
            deeply_nested,
            too_many_nodes,
            json.dumps(
                {"private-malformed-payload-inspection-marker": "x"},
                separators=(",", ":"),
            ),
            json.dumps(
                {"oversized": "private-malformed-payload-inspection-marker" * 8_000},
                separators=(",", ":"),
            ),
            sqlite3.Binary(b"\xffprivate-malformed-payload-inspection-marker"),
        )
        for index, payload_json in enumerate(payloads):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)
                with self._tamper(database, event_update=True) as connection:
                    connection.execute(
                        """
                        UPDATE run_events SET payload_json = ?
                        WHERE run_id = ? AND event_type = ?
                        """,
                        (
                            payload_json,
                            run.run_id,
                            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                        ),
                    )

                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self._assert_invalid(report)
                self.assertIsNone(report.repository_proposal_binding_digest)

    def test_oversized_payload_is_rejected_before_json_parse_or_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            oversized_marker = "private-malformed-payload-inspection-marker" * 8_000
            oversized_json = json.dumps(
                {"oversized": oversized_marker},
                separators=(",", ":"),
            )
            with self._tamper(database, event_update=True) as connection:
                connection.execute(
                    """
                    UPDATE run_events SET payload_json = ?
                    WHERE run_id = ? AND event_type = ?
                    """,
                    (
                        oversized_json,
                        run.run_id,
                        REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                    ),
                )

            original_loads = json.loads

            def guarded_loads(value, *args, **kwargs):
                if isinstance(value, str) and "private-malformed" in value:
                    raise AssertionError("oversized payload reached JSON parser")
                return original_loads(value, *args, **kwargs)

            with patch.object(
                repository_proposal_inspection_module.json,
                "loads",
                side_effect=guarded_loads,
            ):
                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
            self._assert_invalid(report)

    def test_oversized_text_is_rejected_from_blob_metadata_before_read(
        self,
    ) -> None:
        class Blob:
            def __init__(self) -> None:
                self.closed = False

            def __len__(self) -> int:
                return 10_000_000

            def read(self):
                raise AssertionError("oversized blob content was read")

            def close(self) -> None:
                self.closed = True

        class Connection:
            def __init__(self, blob: Blob) -> None:
                self.blob = blob

            def blobopen(self, *args, **kwargs):
                return self.blob

        blob = Blob()
        value = repository_proposal_inspection_module._read_bounded_text_column(
            Connection(blob),
            table="run_events",
            column="payload_json",
            row_id=1,
            storage_type="text",
            characters=128,
            bytes_=128,
            database_encoding="utf-8",
        )
        self.assertIsNone(value)
        self.assertTrue(blob.closed)

    def test_exact_shapes_scalar_types_and_canonical_json_are_required(self) -> None:
        def extra_key(payload):
            payload["binding"]["private-extra-key-inspection-marker"] = True

        def boolean_attempt(payload):
            payload["binding"]["attempt"] = True

        def uppercase_digest(payload):
            payload["binding"]["context_digest"] = "sha256:" + "A" * 64

        for case, mutate in (
            ("extra_key", extra_key),
            ("boolean_attempt", boolean_attempt),
            ("uppercase_digest", uppercase_digest),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database, _, run, _ = self._create_complete(base)
                self._rewrite_payload(
                    database,
                    run.run_id,
                    REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                    mutate,
                    rehash=True,
                )
                self._assert_invalid(
                    inspect_repository_proposal_evidence(
                        database,
                        run_id=run.run_id,
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with self._tamper(database, event_update=True) as connection:
                sequence, event_id, payload_json = self._event(
                    connection,
                    run.run_id,
                    REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                )
                parsed = json.loads(str(payload_json))
                noncanonical = json.dumps(parsed, indent=2, sort_keys=False)
                connection.execute(
                    "UPDATE run_events SET payload_json = ? WHERE sequence = ?",
                    (noncanonical, sequence),
                )
            self._assert_invalid(
                inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
            )

    def test_missing_database_and_run_are_fixed_not_found_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            missing = base / "missing" / "state.sqlite3"
            with self.assertRaises(RecordNotFoundError) as caught:
                inspect_repository_proposal_evidence(
                    missing,
                    run_id="private-missing-run-inspection-marker",
                )
            self.assertFalse(missing.parent.exists())
            self.assertNotIn(
                "private-missing-run-inspection-marker",
                str(caught.exception),
            )
            self.assertNotIn(str(missing), str(caught.exception))

            database, _, _, _ = self._create_complete(base)
            with self.assertRaises(RecordNotFoundError) as caught:
                inspect_repository_proposal_evidence(
                    database,
                    run_id="private-missing-run-inspection-marker",
                )
            self.assertNotIn(
                "private-missing-run-inspection-marker",
                str(caught.exception),
            )

    def test_bad_run_identifiers_fail_validation_without_echo(self) -> None:
        for run_id in (None, "", "x" * 4_097, "private\x00run"):
            with self.subTest(run_id_type=type(run_id).__name__), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "missing.sqlite3"
                with self.assertRaises(ValidationError) as caught:
                    inspect_repository_proposal_evidence(
                        database,
                        run_id=run_id,
                    )
                self.assertNotIn("private", str(caught.exception))
                self.assertFalse(database.exists())

    def test_bad_paths_schema_and_sqlite_are_fixed_configuration_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory = base / "private-path-inspection-marker"
            directory.mkdir()
            corrupt = base / "corrupt.sqlite3"
            corrupt.write_bytes(b"private-sqlite-inspection-marker")
            target = base / "target.sqlite3"
            target.write_bytes(b"private-sqlite-inspection-marker")
            symlink = base / "symlink.sqlite3"
            symlink.symlink_to(target)
            for path in (directory, corrupt, symlink):
                with self.subTest(kind=path.name), self.assertRaises(
                    ConfigurationError
                ) as caught:
                    inspect_repository_proposal_evidence(
                        path,
                        run_id="private-proposal-inspection-run-marker",
                    )
                self.assertNotIn(str(path), str(caught.exception))
                self.assertNotIn(
                    "private-sqlite-inspection-marker",
                    str(caught.exception),
                )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("DROP TRIGGER run_events_no_update")
                connection.commit()
            with self.assertRaises(ConfigurationError):
                inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
            with closing(sqlite3.connect(database)) as connection:
                self.assertIsNone(
                    connection.execute(
                        """
                        SELECT 1 FROM sqlite_master
                        WHERE type = 'trigger' AND name = 'run_events_no_update'
                        """
                    ).fetchone()
                )

    @staticmethod
    def _schema_snapshot(database: Path) -> tuple[object, ...]:
        with closing(sqlite3.connect(database)) as connection:
            objects = tuple(
                connection.execute(
                    """
                    SELECT type, name, tbl_name, sql FROM sqlite_master
                    WHERE sql IS NOT NULL ORDER BY type, name
                    """
                ).fetchall()
            )
            migrations = tuple(
                connection.execute(
                    """
                    SELECT version, name, script_sha256, applied_at
                    FROM state_schema_migrations ORDER BY version
                    """
                ).fetchall()
            )
        return objects, migrations

    def test_inspection_is_query_only_and_creates_no_source_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, root, run, _ = self._create_complete(base)
            before_bytes = database.read_bytes()
            before_schema = self._schema_snapshot(database)
            before_names = tuple(sorted(path.name for path in base.iterdir()))
            before_repository = tuple(
                sorted(
                    (
                        path.relative_to(root).as_posix(),
                        path.stat().st_size,
                    )
                    for path in root.rglob("*")
                )
            )
            original_connect = sqlite3.connect
            connections: list[tuple[object, dict[str, object]]] = []

            def recording_connect(*args, **kwargs):
                connections.append((args[0], dict(kwargs)))
                return original_connect(*args, **kwargs)

            with (
                patch.object(
                    repository_proposal_inspection_module.sqlite3,
                    "connect",
                    side_effect=recording_connect,
                ),
                patch.object(
                    SQLiteStateStore,
                    "__init__",
                    side_effect=AssertionError("state store must not be opened"),
                ),
            ):
                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )

            self.assertTrue(report.clean, report.to_mapping())
            self.assertEqual(database.read_bytes(), before_bytes)
            self.assertEqual(self._schema_snapshot(database), before_schema)
            self.assertEqual(
                tuple(sorted(path.name for path in base.iterdir())),
                before_names,
            )
            self.assertEqual(
                tuple(
                    sorted(
                        (
                            path.relative_to(root).as_posix(),
                            path.stat().st_size,
                        )
                        for path in root.rglob("*")
                    )
                ),
                before_repository,
            )
            self.assertEqual(len(connections), 1)
            self.assertIn("?mode=ro", str(connections[0][0]))
            self.assertIn("&immutable=1", str(connections[0][0]))
            self.assertNotIn(database.as_uri(), str(connections[0][0]))
            self.assertTrue(connections[0][1].get("uri"))

    def test_live_wal_is_read_via_private_snapshot_without_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, state = self._create_complete(base, keep_open=True)
            assert state is not None
            try:
                before_names = tuple(sorted(path.name for path in base.iterdir()))
                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self.assertTrue(report.clean, report.to_mapping())
                self.assertEqual(
                    tuple(sorted(path.name for path in base.iterdir())),
                    before_names,
                )
            finally:
                state.close()

    def test_quiescent_rollback_journal_database_is_portably_inspected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            database = base / "state.sqlite3"
            state = SQLiteStateStore(
                database,
                clock=lambda: 101.0,
                _configure_journal_mode=False,
            )
            run = self._create_run(state)
            bind_repository_proposal_attempt(
                state,
                run_id=run.run_id,
                proposal_digest=_PROPOSAL_DIGEST,
                registration=self._registration(root),
            )
            state.close()
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(
                    connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "delete",
                )

            before = tuple(sorted(path.name for path in base.iterdir()))
            report = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            self.assertTrue(report.clean, report.to_mapping())
            self.assertEqual(
                tuple(sorted(path.name for path in base.iterdir())),
                before,
            )

    def test_utf16_databases_are_portably_inspected(self) -> None:
        for requested_encoding, expected_encoding in (
            ("UTF-16le", "UTF-16le"),
            ("UTF-16be", "UTF-16be"),
        ):
            with self.subTest(
                encoding=requested_encoding
            ), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                database = base / "state.sqlite3"
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(
                        f"PRAGMA encoding = '{requested_encoding}'"
                    )
                    connection.execute("CREATE TABLE freeze_encoding (id)")
                    connection.execute("DROP TABLE freeze_encoding")
                state = SQLiteStateStore(
                    database,
                    clock=lambda: 101.0,
                    _configure_journal_mode=False,
                )
                run = self._create_run(
                    state,
                    run_id="private-提案-😀-inspection-run-marker",
                )
                bind_repository_proposal_attempt(
                    state,
                    run_id=run.run_id,
                    proposal_digest=_PROPOSAL_DIGEST,
                    registration=self._registration(root),
                )
                state.close()
                with closing(sqlite3.connect(database)) as connection:
                    self.assertEqual(
                        connection.execute("PRAGMA encoding").fetchone()[0],
                        expected_encoding,
                    )

                before = {
                    path.name: path.read_bytes()
                    for path in base.iterdir()
                    if path.is_file()
                }
                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
                self.assertTrue(report.clean, report.to_mapping())
                self.assertEqual(
                    {
                        path.name: path.read_bytes()
                        for path in base.iterdir()
                        if path.is_file()
                    },
                    before,
                )

    def test_incoherent_or_hot_source_sidecars_fail_closed_unchanged(
        self,
    ) -> None:
        cases = (
            ("hot_journal", True, "-journal"),
            ("rollback_wal", False, "-wal"),
            ("rollback_shm", False, "-shm"),
            ("wal_orphan_shm", True, "-shm"),
        )
        for case, configure_wal, suffix in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                database = base / "state.sqlite3"
                state = SQLiteStateStore(
                    database,
                    _configure_journal_mode=configure_wal,
                )
                state.close()
                sidecar = Path(str(database) + suffix)
                sidecar.write_bytes(
                    b"private-incoherent-sidecar-inspection-marker"
                )
                before = {
                    path.name: path.read_bytes()
                    for path in base.iterdir()
                    if path.is_file()
                }
                with self.assertRaises(ConfigurationError) as caught:
                    inspect_repository_proposal_evidence(
                        database,
                        run_id="private-sidecar-run-inspection-marker",
                    )
                self.assertNotIn(str(database), str(caught.exception))
                self.assertNotIn(
                    "private-incoherent-sidecar-inspection-marker",
                    str(caught.exception),
                )
                self.assertEqual(
                    {
                        path.name: path.read_bytes()
                        for path in base.iterdir()
                        if path.is_file()
                    },
                    before,
                )

    def test_oversized_wal_snapshot_is_rejected_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database = base / "state.sqlite3"
            state = SQLiteStateStore(database)
            state.close()
            source_wal = Path(str(database) + "-wal")
            oversized_wal_bytes = (
                repository_proposal_inspection_module._MAX_STAGED_SNAPSHOT_BYTES
                - database.stat().st_size
                + 1
            )
            self.assertGreater(oversized_wal_bytes, 0)
            with source_wal.open("wb") as stream:
                stream.truncate(oversized_wal_bytes)
            before = (
                database.stat().st_size,
                source_wal.stat().st_size,
            )

            with patch.object(
                repository_proposal_inspection_module,
                "_copy_snapshot_file",
                side_effect=AssertionError("oversized snapshot reached copy"),
            ), self.assertRaises(ConfigurationError) as caught:
                inspect_repository_proposal_evidence(
                    database,
                    run_id="private-oversized-wal-inspection-marker",
                )

            self.assertEqual(
                str(caught.exception),
                (
                    "repository proposal inspection database is unreadable "
                    "or malformed"
                ),
            )
            self.assertEqual(
                (
                    database.stat().st_size,
                    source_wal.stat().st_size,
                ),
                before,
            )

    def test_oversized_quiescent_snapshot_is_rejected_before_copy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            with database.open("wb") as stream:
                stream.truncate(
                    repository_proposal_inspection_module._MAX_STAGED_SNAPSHOT_BYTES
                    + 1
                )
            before_size = database.stat().st_size

            with patch.object(
                repository_proposal_inspection_module,
                "_copy_snapshot_file",
                side_effect=AssertionError("oversized snapshot reached copy"),
            ), self.assertRaises(ConfigurationError) as caught:
                inspect_repository_proposal_evidence(
                    database,
                    run_id="private-oversized-main-inspection-marker",
                )

            self.assertEqual(
                str(caught.exception),
                (
                    "repository proposal inspection database is unreadable "
                    "or malformed"
                ),
            )
            self.assertEqual(database.stat().st_size, before_size)

    def test_quiescent_swap_before_header_uses_staged_identity(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO replacement is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            original_copy = (
                repository_proposal_inspection_module._copy_snapshot_file
            )
            original_header = (
                repository_proposal_inspection_module._sqlite_header_journal_mode
            )
            header_paths: list[Path] = []

            def swapping_copy(source, destination, *, expected_signature):
                result = original_copy(
                    source,
                    destination,
                    expected_signature=expected_signature,
                )
                if source == database:
                    database.unlink()
                    os.mkfifo(database)
                return result

            def recording_header(path):
                header_paths.append(path)
                return original_header(path)

            with (
                patch.object(
                    repository_proposal_inspection_module,
                    "_copy_snapshot_file",
                    side_effect=swapping_copy,
                ),
                patch.object(
                    repository_proposal_inspection_module,
                    "_sqlite_header_journal_mode",
                    side_effect=recording_header,
                ),
                self.assertRaises(ConfigurationError) as caught,
            ):
                inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )

            self.assertEqual(len(header_paths), 1)
            self.assertNotEqual(header_paths[0], database)
            self.assertEqual(
                str(caught.exception),
                (
                    "repository proposal inspection database changed during "
                    "inspection"
                ),
            )

    def test_quiescent_swap_before_connect_uses_staged_identity(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO replacement is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            original_inspect = (
                repository_proposal_inspection_module._inspect_snapshot
            )
            inspection_uris: list[str] = []

            def guarded_inspect(uri, *, run_id, run_ref):
                inspection_uris.append(str(uri))
                if str(uri).startswith(database.as_uri()):
                    raise AssertionError("SQLite reopened the source path")
                database.unlink()
                os.mkfifo(database)
                return original_inspect(
                    uri,
                    run_id=run_id,
                    run_ref=run_ref,
                )

            with (
                patch.object(
                    repository_proposal_inspection_module,
                    "_inspect_snapshot",
                    side_effect=guarded_inspect,
                ),
                self.assertRaises(ConfigurationError) as caught,
            ):
                inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )

            self.assertEqual(
                len(inspection_uris),
                1,
                str(caught.exception),
            )
            self.assertNotIn(database.as_uri(), inspection_uris[0])
            self.assertEqual(
                str(caught.exception),
                (
                    "repository proposal inspection database changed during "
                    "inspection"
                ),
            )

    def test_snapshot_copy_preserves_change_error_and_closes_both_streams(
        self,
    ) -> None:
        class SourceStream:
            def __init__(self) -> None:
                self.closed = False
                self.reads = iter((b"x", b"y"))

            @staticmethod
            def fileno() -> int:
                return 10

            def read(self, size: int) -> bytes:
                return next(self.reads)

            def close(self) -> None:
                self.closed = True

        class DestinationStream:
            def __init__(self) -> None:
                self.closed = False

            @staticmethod
            def write(value) -> int:
                return len(value)

            def close(self) -> None:
                self.closed = True
                raise OSError("private-snapshot-close-marker")

        class RegularMetadata:
            st_mode = repository_proposal_inspection_module.stat.S_IFREG

        expected_signature = (1, 2, 1, 3)
        source_stream = SourceStream()
        destination_stream = DestinationStream()
        with (
            patch.object(
                repository_proposal_inspection_module.os,
                "fstat",
                return_value=RegularMetadata(),
            ),
            patch.object(
                repository_proposal_inspection_module,
                "_metadata_signature",
                return_value=expected_signature,
            ),
            patch.object(
                repository_proposal_inspection_module.os,
                "open",
                side_effect=(10, 11),
            ),
            patch.object(
                repository_proposal_inspection_module.os,
                "fdopen",
                side_effect=(source_stream, destination_stream),
            ),
            self.assertRaises(ConfigurationError) as caught,
        ):
            repository_proposal_inspection_module._copy_snapshot_file(
                Path("private-unused-snapshot-source-marker"),
                Path("private-unused-snapshot-destination-marker"),
                expected_signature=expected_signature,
            )

        self.assertEqual(
            str(caught.exception),
            "repository proposal inspection database changed during inspection",
        )
        self.assertTrue(destination_stream.closed)
        self.assertTrue(source_stream.closed)

    def test_snapshot_source_open_is_nonblocking_and_rejects_special_file(
        self,
    ) -> None:
        class Metadata:
            st_mode = repository_proposal_inspection_module.stat.S_IFIFO

        expected_signature = (1, 2, 3, 4)
        with (
            patch.object(
                repository_proposal_inspection_module.os,
                "open",
                return_value=10,
            ) as open_call,
            patch.object(
                repository_proposal_inspection_module.os,
                "fstat",
                return_value=Metadata(),
            ),
            patch.object(
                repository_proposal_inspection_module,
                "_metadata_signature",
                return_value=expected_signature,
            ),
            patch.object(
                repository_proposal_inspection_module.os,
                "close",
            ) as close_call,
            self.assertRaises(ConfigurationError) as caught,
        ):
            repository_proposal_inspection_module._copy_snapshot_file(
                Path("private-special-snapshot-source-marker"),
                Path("private-special-snapshot-destination-marker"),
                expected_signature=expected_signature,
            )

        flags = open_call.call_args.args[1]
        nonblocking = getattr(
            repository_proposal_inspection_module.os,
            "O_NONBLOCK",
            0,
        )
        if nonblocking:
            self.assertTrue(flags & nonblocking)
        if hasattr(repository_proposal_inspection_module.os, "O_NOFOLLOW"):
            self.assertTrue(
                flags & repository_proposal_inspection_module.os.O_NOFOLLOW
            )
        close_call.assert_called_once_with(10)
        self.assertEqual(
            str(caught.exception),
            "repository proposal inspection database changed during inspection",
        )

    def test_snapshot_source_disappearance_is_a_change_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "private-snapshot-source-marker"
            destination = base / "private-snapshot-destination-marker"
            source.write_bytes(b"x")
            expected_signature = (
                repository_proposal_inspection_module._file_signature(
                    source,
                    required=True,
                )
            )
            assert expected_signature is not None
            source.unlink()

            with self.assertRaises(ConfigurationError) as caught:
                repository_proposal_inspection_module._copy_snapshot_file(
                    source,
                    destination,
                    expected_signature=expected_signature,
                )

            self.assertEqual(
                str(caught.exception),
                (
                    "repository proposal inspection database changed during "
                    "inspection"
                ),
            )
            self.assertFalse(destination.exists())

    def test_concurrent_wal_change_fails_without_returning_a_mixed_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, state = self._create_complete(base, keep_open=True)
            assert state is not None
            original_copy = (
                repository_proposal_inspection_module._copy_snapshot_file
            )
            copied = 0

            def changing_copy(source, destination, *, expected_signature):
                nonlocal copied
                result = original_copy(
                    source,
                    destination,
                    expected_signature=expected_signature,
                )
                copied += 1
                if copied == 1:
                    state.append_event(
                        run.run_id,
                        "private-concurrent-wal-inspection-marker",
                        {},
                        event_id=canonical_digest(
                            {"concurrent_wal": run.run_id}
                        ),
                    )
                return result

            try:
                with patch.object(
                    repository_proposal_inspection_module,
                    "_copy_snapshot_file",
                    side_effect=changing_copy,
                ), self.assertRaises(ConfigurationError) as caught:
                    inspect_repository_proposal_evidence(
                        database,
                        run_id=run.run_id,
                    )
                self.assertNotIn(run.run_id, str(caught.exception))
                self.assertNotIn(str(database), str(caught.exception))
            finally:
                state.close()

    def test_inspector_does_not_use_producer_validation_or_effect_paths(self) -> None:
        source = inspect.getsource(repository_proposal_inspection_module)
        self.assertNotIn(
            "validate_repository_registration_selection_payload",
            source,
        )
        self.assertNotIn(
            "validate_repository_proposal_attempt_binding_payload",
            source,
        )
        self.assertNotIn("bind_repository_proposal_attempt(", source)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with (
                patch.object(
                    repository_proposal_module,
                    "validate_repository_registration_selection_payload",
                    side_effect=AssertionError("producer selection validator"),
                ),
                patch.object(
                    repository_proposal_module,
                    "validate_repository_proposal_attempt_binding_payload",
                    side_effect=AssertionError("producer binding validator"),
                ),
                patch.object(
                    repository_proposal_module,
                    "bind_repository_proposal_attempt",
                    side_effect=AssertionError("producer binder"),
                ),
                patch.object(
                    SQLiteStateStore,
                    "__init__",
                    side_effect=AssertionError("state mutation path"),
                ),
                patch.object(subprocess, "run", side_effect=AssertionError("command")),
                patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
                patch.object(os, "system", side_effect=AssertionError("shell")),
                patch.object(
                    asyncio,
                    "create_subprocess_exec",
                    side_effect=AssertionError("async process"),
                ),
            ):
                report = inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
            self.assertTrue(report.clean, report.to_mapping())

    def test_sqlite_failures_are_fixed_and_do_not_expose_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, _, run, _ = self._create_complete(base)
            with patch.object(
                repository_proposal_inspection_module.sqlite3,
                "connect",
                side_effect=sqlite3.DatabaseError(
                    "private-sqlite-inspection-marker"
                ),
            ), self.assertRaises(ConfigurationError) as caught:
                inspect_repository_proposal_evidence(
                    database,
                    run_id=run.run_id,
                )
            self.assertNotIn(
                "private-sqlite-inspection-marker",
                str(caught.exception),
            )
            self.assertNotIn(str(database), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
