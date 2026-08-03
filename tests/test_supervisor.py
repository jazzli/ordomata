from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import itertools
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import ordomata.supervisor as supervisor_module
from ordomata.authorization import (
    AuthorizationEffect,
    ShadowAuthorizationEvaluator,
    canonical_digest,
)
from ordomata.errors import AuthorizationBlocked, ConfigurationError, ValidationError
from ordomata.models import PermissionClass
from ordomata.state import SQLiteStateStore
from ordomata.supervisor import (
    AdmissionConflictError,
    ClaimLostError,
    FlowSpec,
    FlowState,
    ForegroundSupervisor,
    SQLiteSupervisorStore,
    StaleReconciliationPlanError,
    StaleRevisionError,
    SupervisorError,
    SupervisorMode,
    inspect_pending_completions,
    inspect_reconciliation,
    inspect_supervisor_audit,
    inspect_supervisor_authorization,
    inspect_supervisor_status,
)


class SQLiteSupervisorStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "state.sqlite3"
        self.now = 100.0
        self.identifiers = itertools.count(1)
        self.store = self._open_store()

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _open_store(self) -> SQLiteSupervisorStore:
        return SQLiteSupervisorStore(
            self.database,
            clock=lambda: self.now,
            id_factory=lambda: f"test-id-{next(self.identifiers):016d}",
        )

    def _reopen_store(self) -> None:
        self.store.close()
        self.store = self._open_store()

    @staticmethod
    def _remove_v12_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            DROP TRIGGER supervisor_queued_timeout_reconciliation_authorization_observations_no_update;
            DROP TRIGGER supervisor_queued_timeout_reconciliation_authorization_observations_no_delete;
            DROP TRIGGER supervisor_queued_timeout_reconciliation_authorization_baseline_no_update;
            DROP TRIGGER supervisor_queued_timeout_reconciliation_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_queued_timeout_reconciliation_authorization_baseline_no_insert;
            DROP TABLE supervisor_queued_timeout_reconciliation_authorization_observations;
            DROP TABLE supervisor_queued_timeout_reconciliation_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 12;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @staticmethod
    def _remove_v11_schema(connection: sqlite3.Connection) -> None:
        SQLiteSupervisorStoreTests._remove_v12_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_pre_dispatch_reconciliation_authorization_observations_no_update;
            DROP TRIGGER supervisor_pre_dispatch_reconciliation_authorization_observations_no_delete;
            DROP TRIGGER supervisor_pre_dispatch_reconciliation_authorization_baseline_no_update;
            DROP TRIGGER supervisor_pre_dispatch_reconciliation_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_pre_dispatch_reconciliation_authorization_baseline_no_insert;
            DROP TABLE supervisor_pre_dispatch_reconciliation_authorization_observations;
            DROP TABLE supervisor_pre_dispatch_reconciliation_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 11;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @staticmethod
    def _remove_v10_schema(connection: sqlite3.Connection) -> None:
        SQLiteSupervisorStoreTests._remove_v11_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_attempt_completion_authorization_observations_no_update;
            DROP TRIGGER supervisor_attempt_completion_authorization_observations_no_delete;
            DROP TRIGGER supervisor_attempt_completion_authorization_baseline_no_update;
            DROP TRIGGER supervisor_attempt_completion_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_attempt_completion_authorization_baseline_no_insert;
            DROP TABLE supervisor_attempt_completion_authorization_observations;
            DROP TABLE supervisor_attempt_completion_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 10;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @staticmethod
    def _remove_v9_schema(connection: sqlite3.Connection) -> None:
        SQLiteSupervisorStoreTests._remove_v10_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_action_receipts_no_update;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_action_receipts_no_delete;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_decisions_no_update;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_decisions_no_delete;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_enforcement_baseline_no_update;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_enforcement_baseline_no_delete;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_enforcement_baseline_no_insert;
            DROP TABLE supervisor_pre_dispatch_intent_authorization_action_receipts;
            DROP TABLE supervisor_pre_dispatch_intent_authorization_decisions;
            DROP TABLE supervisor_pre_dispatch_intent_authorization_enforcement_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 9;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @staticmethod
    def _remove_v8_schema(connection: sqlite3.Connection) -> None:
        SQLiteSupervisorStoreTests._remove_v9_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_observations_no_update;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_observations_no_delete;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_baseline_no_update;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_pre_dispatch_intent_authorization_baseline_no_insert;
            DROP TABLE supervisor_pre_dispatch_intent_authorization_observations;
            DROP TABLE supervisor_pre_dispatch_intent_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 8;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @staticmethod
    def _remove_v7_schema(connection: sqlite3.Connection) -> None:
        SQLiteSupervisorStoreTests._remove_v8_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_attempt_claim_authorization_action_receipts_no_update;
            DROP TRIGGER supervisor_attempt_claim_authorization_action_receipts_no_delete;
            DROP TRIGGER supervisor_attempt_claim_authorization_decisions_no_update;
            DROP TRIGGER supervisor_attempt_claim_authorization_decisions_no_delete;
            DROP TRIGGER supervisor_attempt_claim_authorization_baseline_no_update;
            DROP TRIGGER supervisor_attempt_claim_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_attempt_claim_authorization_baseline_no_insert;
            DROP TABLE supervisor_attempt_claim_authorization_action_receipts;
            DROP TABLE supervisor_attempt_claim_authorization_decisions;
            DROP TABLE supervisor_attempt_claim_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 7;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @staticmethod
    def _remove_v6_schema(connection: sqlite3.Connection) -> None:
        SQLiteSupervisorStoreTests._remove_v7_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_flow_admission_authorization_action_receipts_no_update;
            DROP TRIGGER supervisor_flow_admission_authorization_action_receipts_no_delete;
            DROP TRIGGER supervisor_flow_admission_authorization_decisions_no_update;
            DROP TRIGGER supervisor_flow_admission_authorization_decisions_no_delete;
            DROP TRIGGER supervisor_flow_admission_authorization_baseline_no_update;
            DROP TRIGGER supervisor_flow_admission_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_flow_admission_authorization_baseline_no_insert;
            DROP TABLE supervisor_flow_admission_authorization_action_receipts;
            DROP TABLE supervisor_flow_admission_authorization_decisions;
            DROP TABLE supervisor_flow_admission_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 6;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @staticmethod
    def _remove_v5_schema(connection: sqlite3.Connection) -> None:
        SQLiteSupervisorStoreTests._remove_v6_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_control_authorization_action_receipts_no_update;
            DROP TRIGGER supervisor_control_authorization_action_receipts_no_delete;
            DROP TRIGGER supervisor_control_authorization_decisions_no_update;
            DROP TRIGGER supervisor_control_authorization_decisions_no_delete;
            DROP TRIGGER supervisor_control_authorization_baseline_no_update;
            DROP TRIGGER supervisor_control_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_control_authorization_baseline_no_insert;
            DROP TABLE supervisor_control_authorization_action_receipts;
            DROP TABLE supervisor_control_authorization_decisions;
            DROP TABLE supervisor_control_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 5;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    @classmethod
    def _remove_v4_schema(cls, connection: sqlite3.Connection) -> None:
        cls._remove_v5_schema(connection)
        connection.executescript(
            """
            DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_update;
            DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_delete;
            DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_update;
            DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_delete;
            DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_update;
            DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_delete;
            DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_insert;
            DROP TABLE supervisor_bookkeeping_authorization_observations;
            DROP TABLE supervisor_bookkeeping_authorization_sources;
            DROP TABLE supervisor_bookkeeping_authorization_baseline;
            DROP TRIGGER state_schema_migrations_no_delete;
            DELETE FROM state_schema_migrations WHERE version = 4;
            CREATE TRIGGER state_schema_migrations_no_delete
            BEFORE DELETE ON state_schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migrations are append-only');
            END;
            """
        )

    def _flow(self, flow_id: str = "flow-one", **changes: object) -> FlowSpec:
        values: dict[str, object] = {
            "flow_id": flow_id,
            "admission_key": f"admit:{flow_id}",
            "task_id": "repository-maintenance",
            "task_version": "v1",
            "task_definition_digest": "a" * 64,
            "context_digest": "b" * 64,
            "runner_id": "mock",
            "profile_id": "mock-maintainer",
            "permission_class": PermissionClass.LOCAL_DRAFT,
            "resource_keys": ("repo:test-project",),
            "available_at": 100.0,
            "deadline_at": 1_000.0,
            "mandatory_priority": 0,
            "blocker_priority": 0,
            "value_priority": 80,
            "evidence_priority": 70,
            "capacity_fit_priority": 90,
            "max_attempts": 2,
            "created_at": 100.0,
        }
        values.update(changes)
        return FlowSpec(**values)

    def _prepare_claim(self, spec: FlowSpec | None = None):
        selected = spec or self._flow()
        self.store.admit_flow(selected)
        control = self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        owner = "supervisor/instance-000000000001"
        self.assertTrue(
            self.store.acquire_foreground(owner, ttl_seconds=60.0, now=100.0)
        )
        return selected, control, owner

    def _start_and_claim(self, spec: FlowSpec | None = None):
        selected, control, owner = self._prepare_claim(spec)
        claim = self.store.try_claim_next(
            instance_owner=owner,
            expected_control_revision=control.revision,
            ttl_seconds=20.0,
            now=100.0,
        )
        self.assertIsNotNone(claim)
        assert claim is not None
        return claim

    def test_schema_migration_and_state_survive_reopen(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )

        self._reopen_store()

        self.assertEqual(self.store.get_flow(spec.flow_id), spec)
        self.assertEqual(self.store.current_control().mode, SupervisorMode.RUNNING)
        with closing(sqlite3.connect(self.database)) as connection:
            migrations = connection.execute(
                "SELECT version, name FROM state_schema_migrations ORDER BY version"
            ).fetchall()
            baseline_digest = connection.execute(
                "SELECT script_sha256 FROM state_schema_migrations WHERE version = 1"
            ).fetchone()[0]
        self.assertEqual(
            migrations,
            [
                (1, "baseline_state"),
                (2, "supervisor_control_plane"),
                (3, "supervisor_authorization_shadow"),
                (4, "supervisor_bookkeeping_authorization_shadow"),
                (5, "supervisor_control_authorization_enforcement"),
                (6, "supervisor_flow_admission_authorization_enforcement"),
                (7, "supervisor_attempt_claim_authorization_enforcement"),
                (8, "supervisor_pre_dispatch_intent_authorization_shadow"),
                (9, "supervisor_pre_dispatch_intent_authorization_enforcement"),
                (10, "supervisor_attempt_completion_authorization_shadow"),
                (11, "supervisor_pre_dispatch_reconciliation_authorization_shadow"),
                (12, "supervisor_queued_timeout_reconciliation_authorization_shadow"),
            ],
        )
        self.assertEqual(
            baseline_digest,
            "6076ff9c09a329bc60f1bdc79fd61d3251990219047005691eff8bbd9e9178e6",
        )

    def test_multi_version_migration_failure_rolls_back_every_version(self) -> None:
        database = Path(self.temporary.name) / "migration-rollback.sqlite3"
        baseline = SQLiteStateStore(database)
        baseline.close()
        original_execute = supervisor_module._execute_schema_script

        def fail_after_v3_schema(
            connection: sqlite3.Connection,
            script: str,
        ) -> None:
            original_execute(connection, script)
            if script == supervisor_module._SCHEMA_V3:
                raise RuntimeError("injected v3 migration failure")

        with patch(
            "ordomata.supervisor._execute_schema_script",
            side_effect=fail_after_v3_schema,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "injected v3 migration failure",
            ):
                SQLiteSupervisorStore(database)

        with closing(sqlite3.connect(database)) as connection:
            versions = connection.execute(
                "SELECT version FROM state_schema_migrations ORDER BY version"
            ).fetchall()
            supervisor_objects = connection.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name GLOB 'supervisor_*'
                """
            ).fetchall()
        self.assertEqual(versions, [(1,)])
        self.assertEqual(supervisor_objects, [])

    def test_v3_migration_baselines_preexisting_supervisor_history(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v4_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_authorization_observations_no_update;
                DROP TRIGGER supervisor_authorization_observations_no_delete;
                DROP TRIGGER supervisor_authorization_shadow_baseline_no_update;
                DROP TRIGGER supervisor_authorization_shadow_baseline_no_delete;
                DROP TRIGGER supervisor_authorization_shadow_baseline_no_insert;
                DROP TABLE supervisor_authorization_observations;
                DROP TABLE supervisor_authorization_shadow_baseline;
                DROP TRIGGER state_schema_migrations_no_delete;
                DELETE FROM state_schema_migrations WHERE version = 3;
                CREATE TRIGGER state_schema_migrations_no_delete
                BEFORE DELETE ON state_schema_migrations BEGIN
                    SELECT RAISE(ABORT, 'schema migrations are append-only');
                END;
                """
            )

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.observation_count, 0)
        self.assertEqual(audit.expected_observation_count, 0)
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT entity_type, entity_id
                FROM supervisor_authorization_shadow_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [("flow", spec.flow_id)])

    def test_v4_migration_baselines_preexisting_bookkeeping_history(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        control = self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        self.store.request_cancellation(
            spec.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )
        observations = self.store.list_bookkeeping_authorization_observations()
        cancellation_request_id = observations[-1].cancellation_request_id
        assert cancellation_request_id is not None
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v5_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_insert;
                DROP TABLE supervisor_bookkeeping_authorization_observations;
                DROP TABLE supervisor_bookkeeping_authorization_sources;
                DROP TABLE supervisor_bookkeeping_authorization_baseline;
                DROP TRIGGER state_schema_migrations_no_delete;
                DELETE FROM state_schema_migrations WHERE version = 4;
                CREATE TRIGGER state_schema_migrations_no_delete
                BEFORE DELETE ON state_schema_migrations BEGIN
                    SELECT RAISE(ABORT, 'schema migrations are append-only');
                END;
                """
            )

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.observation_count, 1)
        self.assertEqual(audit.expected_observation_count, 1)
        self.assertEqual(
            self.store.list_bookkeeping_authorization_observations(), ()
        )
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT entity_type, entity_id
                FROM supervisor_bookkeeping_authorization_baseline
                ORDER BY entity_type, entity_id
                """
            ).fetchall()
        self.assertEqual(
            baseline,
            [
                ("cancellation_request", cancellation_request_id),
                ("control_event", control.event_id),
            ],
        )

    def test_v4_migration_ignores_unowned_malformed_foreign_key(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v4_schema(connection)
            connection.executescript(
                """
                CREATE TABLE private_parent(identifier TEXT);
                CREATE TABLE private_child(
                    parent_id TEXT REFERENCES private_parent(identifier)
                );
                CREATE INDEX private_child_parent
                    ON private_child(parent_id);
                CREATE VIEW private_child_view AS
                    SELECT parent_id FROM private_child;
                CREATE TRIGGER private_child_noop
                AFTER INSERT ON private_child BEGIN
                    SELECT 1;
                END;
                INSERT INTO private_child(parent_id) VALUES ('private-value');
                """
            )

        self.store = self._open_store()

        with closing(sqlite3.connect(self.database)) as connection:
            version = connection.execute(
                "SELECT MAX(version) FROM state_schema_migrations"
            ).fetchone()[0]
            value = connection.execute(
                "SELECT parent_id FROM private_child"
            ).fetchone()[0]
        self.assertEqual(version, 12)
        self.assertEqual(value, "private-value")

    def test_missing_v3_schema_is_a_finding_even_without_flows(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v5_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_authorization_observations_no_update;
                DROP TRIGGER supervisor_authorization_observations_no_delete;
                DROP TRIGGER supervisor_authorization_shadow_baseline_no_update;
                DROP TRIGGER supervisor_authorization_shadow_baseline_no_delete;
                DROP TRIGGER supervisor_authorization_shadow_baseline_no_insert;
                DROP TABLE supervisor_authorization_observations;
                DROP TABLE supervisor_authorization_shadow_baseline;
                DROP TRIGGER state_schema_migrations_no_delete;
                DELETE FROM state_schema_migrations WHERE version = 3;
                CREATE TRIGGER state_schema_migrations_no_delete
                BEFORE DELETE ON state_schema_migrations BEGIN
                    SELECT RAISE(ABORT, 'schema migrations are append-only');
                END;
                """
            )

        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertEqual(audit.expected_observation_count, 0)
        self.assertIn(
            "authorization_schema_missing",
            {finding.code for finding in audit.findings},
        )

    def test_missing_v4_schema_is_a_finding_without_bookkeeping_events(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v5_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_insert;
                DROP TABLE supervisor_bookkeeping_authorization_observations;
                DROP TABLE supervisor_bookkeeping_authorization_sources;
                DROP TABLE supervisor_bookkeeping_authorization_baseline;
                DROP TRIGGER state_schema_migrations_no_delete;
                DELETE FROM state_schema_migrations WHERE version = 4;
                CREATE TRIGGER state_schema_migrations_no_delete
                BEFORE DELETE ON state_schema_migrations BEGIN
                    SELECT RAISE(ABORT, 'schema migrations are append-only');
                END;
                """
            )

        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertEqual(audit.expected_observation_count, 0)
        self.assertIn(
            "bookkeeping_authorization_schema_missing",
            {finding.code for finding in audit.findings},
        )

    def test_missing_core_supervisor_schema_cannot_audit_clean(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TABLE supervisor_flows")
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertFalse(audit.schema_present)
        self.assertEqual(audit.findings[0].code, "supervisor_schema_missing")

    def test_combined_audit_holds_one_read_transaction(self) -> None:
        self.store.admit_flow(self._flow())

        def assert_snapshot(connection, now):
            self.assertTrue(connection.in_transaction)
            return ()

        with patch(
            "ordomata.supervisor._audit_connection",
            side_effect=assert_snapshot,
        ):
            plan, authorization = inspect_supervisor_audit(
                self.database, now=100.0
            )

        self.assertEqual(plan.findings, ())
        self.assertTrue(authorization.clean)

    def test_reopen_fails_closed_when_an_invariant_trigger_is_missing(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TRIGGER supervisor_flow_revisions_no_update")
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError,
            "schema objects do not match",
        ):
            SQLiteSupervisorStore(self.database)

    def test_rejected_supervisor_schema_does_not_change_journal_mode(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
            self.assertEqual(mode, "delete")
            connection.execute(
                "DROP TRIGGER supervisor_flow_revisions_no_update"
            )
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError,
            "schema objects do not match",
        ):
            self._open_store()

        with closing(sqlite3.connect(self.database)) as connection:
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode, "delete")

    def test_audit_reports_missing_baseline_guard_without_repair(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TRIGGER runs_no_update")
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)

        self.assertFalse(audit.clean)
        self.assertFalse(audit.schema_present)
        self.assertIn(
            "baseline_schema_mismatch",
            {finding.code for finding in audit.findings},
        )
        with closing(sqlite3.connect(self.database)) as connection:
            trigger = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'runs_no_update'"
            ).fetchone()
        self.assertIsNone(trigger)

    def test_malformed_supervisor_columns_return_bounded_audit(self) -> None:
        self.store.admit_flow(self._flow())
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                ALTER TABLE supervisor_flows
                RENAME COLUMN task_id TO private_task_id
                """
            )
            connection.commit()

        authorization = inspect_supervisor_authorization(self.database)
        plan, combined = inspect_supervisor_audit(self.database, now=100.0)

        self.assertFalse(authorization.schema_present)
        self.assertEqual(
            {finding.code for finding in authorization.findings},
            {"authorization_schema_mismatch"},
        )
        self.assertEqual(plan.findings, ())
        self.assertEqual(combined, authorization)

    def test_malformed_migration_columns_return_bounded_audit(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                ALTER TABLE state_schema_migrations
                RENAME COLUMN name TO migration_name
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)

        self.assertFalse(audit.schema_present)
        self.assertIn(
            "migration_schema_mismatch",
            {finding.code for finding in audit.findings},
        )

    def test_supervisor_audit_reports_invalid_migration_timestamp(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "DROP TRIGGER state_schema_migrations_no_update"
            )
            connection.execute(
                """
                UPDATE state_schema_migrations
                SET applied_at = 'private-timestamp-marker'
                WHERE version = 2
                """
            )
            connection.execute(
                """
                CREATE TRIGGER state_schema_migrations_no_update
                BEFORE UPDATE ON state_schema_migrations BEGIN
                    SELECT RAISE(ABORT, 'schema migrations are append-only');
                END
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)

        self.assertIn(
            "migration_applied_at_invalid",
            {finding.code for finding in audit.findings},
        )

    def test_baseline_only_audit_reports_shared_guards_and_rogue_view(self) -> None:
        baseline_guard = Path(self.temporary.name) / "baseline-guard.sqlite3"
        store = SQLiteStateStore(baseline_guard)
        store.close()
        with closing(sqlite3.connect(baseline_guard)) as connection:
            connection.execute("DROP TRIGGER runs_no_update")
            connection.commit()
        self.assertIn(
            "baseline_schema_mismatch",
            {
                finding.code
                for finding in inspect_supervisor_authorization(
                    baseline_guard
                ).findings
            },
        )

        migration_guard = Path(self.temporary.name) / "migration-guard.sqlite3"
        store = SQLiteStateStore(migration_guard)
        store.close()
        with closing(sqlite3.connect(migration_guard)) as connection:
            connection.execute(
                "DROP TRIGGER state_schema_migrations_no_update"
            )
            connection.commit()
        self.assertIn(
            "migration_schema_mismatch",
            {
                finding.code
                for finding in inspect_supervisor_authorization(
                    migration_guard
                ).findings
            },
        )

        rogue_view = Path(self.temporary.name) / "rogue-view.sqlite3"
        store = SQLiteStateStore(rogue_view)
        store.close()
        with closing(sqlite3.connect(rogue_view)) as connection:
            connection.execute(
                "CREATE VIEW supervisor_private AS SELECT 1 AS value"
            )
            connection.commit()
        audit = inspect_supervisor_authorization(rogue_view)
        codes = {finding.code for finding in audit.findings}
        self.assertIn("supervisor_schema_missing", codes)
        self.assertIn("authorization_schema_mismatch", codes)

    def test_reopen_rejects_unexpected_trigger_on_supervisor_table(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                CREATE TRIGGER evil_control_side_effect
                AFTER INSERT ON supervisor_control_events BEGIN
                    DELETE FROM leases;
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "schema objects do not match",
        ):
            SQLiteSupervisorStore(self.database)

    def test_supervisor_schema_name_collision_is_rejected(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                CREATE TABLE supervisor_flow_revisions_no_update(
                    private_marker TEXT
                )
                """
            )
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError,
            "schema objects do not match",
        ):
            self._open_store()

        with closing(sqlite3.connect(self.database)) as connection:
            object_types = connection.execute(
                """
                SELECT type FROM sqlite_master
                WHERE name = 'supervisor_flow_revisions_no_update'
                ORDER BY type
                """
            ).fetchall()
        self.assertEqual(object_types, [("table",), ("trigger",)])

    def test_admission_is_idempotent_and_conflicting_replays_fail(self) -> None:
        spec = self._flow()
        admitted, created = self.store.admit_flow(spec)
        replayed, replay_created = self.store.admit_flow(spec)

        self.assertTrue(created)
        self.assertFalse(replay_created)
        self.assertEqual(admitted, replayed)
        self.assertEqual(len(self.store.list_flow_revisions(spec.flow_id)), 1)
        observations = self.store.list_authorization_observations(spec.flow_id)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].boundary, "flow_admission")
        self.assertEqual(observations[0].effect, "permit")
        self.assertEqual(
            observations[0].derived_permission_class,
            PermissionClass.LOCAL_DRAFT,
        )
        self.assertTrue(observations[0].legacy_executable)
        self.assertTrue(observations[0].execution_parity)
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.observation_count, 1)
        self.assertEqual(audit.expected_observation_count, 1)
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE supervisor_authorization_observations SET effect = 'deny'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frozen"):
                connection.execute(
                    """
                    INSERT INTO supervisor_authorization_shadow_baseline (
                        entity_type, entity_id
                    ) VALUES ('flow', 'forged-exemption')
                    """
                )
        with self.assertRaises(AdmissionConflictError):
            self.store.admit_flow(replace(spec, profile_id="different-profile"))
        with self.assertRaises(AdmissionConflictError):
            self.store.admit_flow(
                replace(spec, admission_key="admit:different-request")
            )
        self.assertEqual(len(self.store.list_flow_revisions(spec.flow_id)), 1)

    def test_shadow_failure_cannot_block_legacy_supervisor_admission(self) -> None:
        spec = self._flow()
        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("sensitive diagnostic"),
        ):
            admitted, created = self.store.admit_flow(spec)

        self.assertTrue(created)
        self.assertEqual(admitted, spec)
        self.assertEqual(self.store.get_flow(spec.flow_id), spec)
        self.assertEqual(self.store.list_authorization_observations(spec.flow_id), ())
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "observation_missing", {finding.code for finding in audit.findings}
        )

    def test_authorization_inspector_detects_tampering_and_missing_guards(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "DROP TRIGGER supervisor_authorization_observations_no_update"
            )
            connection.execute(
                """
                UPDATE supervisor_authorization_observations
                SET request_digest = ?
                """,
                ("sha256:" + "0" * 64,),
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("request_digest_mismatch", codes)
        self.assertFalse(audit.clean)

    def test_control_updates_require_current_revision_and_noop_does_not_grow(self) -> None:
        initial = self.store.current_control()
        self.assertEqual(initial.revision, 0)
        self.assertEqual(initial.mode, SupervisorMode.STOPPED)

        running = self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        with self.assertRaises(StaleRevisionError):
            self.store.update_control(
                expected_revision=0,
                mode=SupervisorMode.PAUSED,
                actor_id="operator/session-000000000001",
                reason_code="operator_paused",
                occurred_at=101.0,
            )
        paused = self.store.update_control(
            expected_revision=running.revision,
            mode=SupervisorMode.PAUSED,
            actor_id="operator/session-000000000001",
            reason_code="operator_paused",
            occurred_at=101.0,
        )
        replay = self.store.update_control(
            expected_revision=paused.revision,
            mode=SupervisorMode.PAUSED,
            actor_id="operator/session-000000000001",
            reason_code="operator_paused",
            occurred_at=102.0,
        )

        self.assertEqual(replay, paused)
        with closing(sqlite3.connect(self.database)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM supervisor_control_events"
            ).fetchone()[0]
        self.assertEqual(count, 2)
        observations = self.store.list_bookkeeping_authorization_observations()
        self.assertEqual(
            [observation.boundary for observation in observations],
            ["control_transition", "control_transition"],
        )
        self.assertEqual(
            [observation.control_event_id for observation in observations],
            [running.event_id, paused.event_id],
        )
        self.assertTrue(all(item.effect == "permit" for item in observations))
        self.assertTrue(all(item.execution_parity for item in observations))
        self.assertTrue(
            all(
                item.derived_permission_class is PermissionClass.LOCAL_DRAFT
                for item in observations
            )
        )
        payloads = json.dumps(
            [observation.payload for observation in observations], sort_keys=True
        )
        self.assertNotIn("operator/session-000000000001", payloads)
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.observation_count, 2)
        self.assertEqual(audit.expected_observation_count, 2)
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    """
                    UPDATE supervisor_bookkeeping_authorization_observations
                    SET effect = 'deny'
                    """
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frozen"):
                connection.execute(
                    """
                    INSERT INTO supervisor_bookkeeping_authorization_baseline (
                        entity_type, entity_id
                    ) VALUES ('control_event', 'forged-exemption')
                    """
                )

    def test_flow_admission_pep_persists_exact_decision_and_receipt(self) -> None:
        spec = self._flow(
            "flow-private-marker",
            admission_key="admit/private-marker",
        )
        admitted, created = self.store.admit_flow(spec)

        self.assertTrue(created)
        self.assertEqual(admitted, spec)
        with closing(sqlite3.connect(self.database)) as connection:
            decision = connection.execute(
                """
                SELECT flow_id, decision_event_id, request_digest, decision_digest,
                       payload_json
                FROM supervisor_flow_admission_authorization_decisions
                """
            ).fetchone()
            receipt = connection.execute(
                """
                SELECT flow_id, decision_event_id, receipt_digest, payload_json
                FROM supervisor_flow_admission_authorization_action_receipts
                """
            ).fetchone()
        self.assertIsNotNone(decision)
        self.assertIsNotNone(receipt)
        assert decision is not None
        assert receipt is not None
        self.assertEqual(decision[0], spec.flow_id)
        self.assertEqual(receipt[0], spec.flow_id)
        self.assertEqual(decision[1], decision[3])
        self.assertEqual(receipt[1], decision[1])
        serialized = json.dumps([decision[4], receipt[3]], sort_keys=True)
        self.assertNotIn("flow-private-marker", serialized)
        self.assertNotIn("admit/private-marker", serialized)
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.flow_admission_enforcement_record_count, 2)
        self.assertEqual(audit.expected_flow_admission_enforcement_record_count, 2)

    def test_flow_admission_pep_receipt_failure_rolls_back_admission(self) -> None:
        with patch.object(
            self.store,
            "_append_flow_admission_authorization_receipt",
            side_effect=RuntimeError("private receipt failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "private receipt failure"):
                self.store.admit_flow(self._flow())

        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_flows",
                    "supervisor_flow_revisions",
                    "supervisor_flow_admission_authorization_decisions",
                    "supervisor_flow_admission_authorization_action_receipts",
                )
            )
        self.assertEqual(counts, (0, 0, 0, 0))

    def test_flow_admission_pep_requires_exact_initial_revision(self) -> None:
        with patch.object(
            self.store,
            "_insert_flow_revision",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                SupervisorError,
                "revision persistence is uncertain",
            ):
                self.store.admit_flow(self._flow())

        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_flows",
                    "supervisor_flow_admission_authorization_decisions",
                    "supervisor_flow_admission_authorization_action_receipts",
                )
            )
        self.assertEqual(counts, (0, 0, 0))

    def test_flow_admission_pep_requires_exact_decision_and_receipt_readback(
        self,
    ) -> None:
        with patch.object(
            self.store,
            "_append_flow_admission_authorization_decision",
            return_value={},
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.admit_flow(self._flow())

        with patch.object(
            self.store,
            "_append_flow_admission_authorization_receipt",
            return_value={},
        ):
            with self.assertRaisesRegex(
                SupervisorError,
                "receipt persistence is uncertain",
            ):
                self.store.admit_flow(self._flow("flow-two"))

        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_flows",
                    "supervisor_flow_admission_authorization_decisions",
                    "supervisor_flow_admission_authorization_action_receipts",
                )
            )
        self.assertEqual(counts, (0, 0, 0))

    def test_flow_admission_pep_rebuild_rejects_a_replaced_first_pass(self) -> None:
        original = supervisor_module.evaluate_supervisor_flow_admission_authorization

        def forged_first_pass(*args, **kwargs):
            authorization = original(*args, **kwargs)
            forged_action = replace(
                authorization.request.action,
                parameters_digest=canonical_digest({"forged": True}),
            )
            return replace(
                authorization,
                request=replace(authorization.request, action=forged_action),
            )

        with patch(
            "ordomata.supervisor.evaluate_supervisor_flow_admission_authorization",
            side_effect=forged_first_pass,
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.admit_flow(self._flow())

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM supervisor_flows"
                ).fetchone()[0],
                0,
            )

    def test_flow_admission_pep_audit_detects_decision_and_receipt_tampering(
        self,
    ) -> None:
        self.store.admit_flow(self._flow())
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                DROP TRIGGER supervisor_flow_admission_authorization_decisions_no_update;
                DROP TRIGGER supervisor_flow_admission_authorization_action_receipts_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_flow_admission_authorization_decisions
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.execute(
                """
                UPDATE supervisor_flow_admission_authorization_action_receipts
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("flow_admission_authorization_decision_invalid", codes)
        self.assertIn("flow_admission_authorization_receipt_invalid", codes)

    def test_attempt_claim_pep_persists_exact_decision_and_receipt(self) -> None:
        claim = self._start_and_claim(
            self._flow("flow-private-marker", resource_keys=("repo:private",))
        )

        with closing(sqlite3.connect(self.database)) as connection:
            decision = connection.execute(
                """
                SELECT attempt_id, flow_id, decision_event_id, request_digest,
                       decision_digest, payload_json
                FROM supervisor_attempt_claim_authorization_decisions
                """
            ).fetchone()
            receipt = connection.execute(
                """
                SELECT attempt_id, flow_id, decision_event_id, receipt_digest,
                       payload_json
                FROM supervisor_attempt_claim_authorization_action_receipts
                """
            ).fetchone()
        self.assertIsNotNone(decision)
        self.assertIsNotNone(receipt)
        assert decision is not None
        assert receipt is not None
        self.assertEqual(decision[0], claim.attempt.attempt_id)
        self.assertEqual(decision[1], claim.flow.flow_id)
        self.assertEqual(receipt[0], claim.attempt.attempt_id)
        self.assertEqual(receipt[1], claim.flow.flow_id)
        self.assertEqual(decision[2], decision[4])
        self.assertEqual(receipt[2], decision[2])
        serialized = json.dumps([decision[5], receipt[4]], sort_keys=True)
        for private_value in (
            claim.flow.flow_id,
            claim.attempt.attempt_id,
            claim.attempt.run_id,
            "supervisor/instance-000000000001",
            "attempt/",
        ):
            self.assertNotIn(private_value, serialized)
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.attempt_claim_enforcement_record_count, 2)
        self.assertEqual(audit.expected_attempt_claim_enforcement_record_count, 2)

    def test_attempt_claim_pep_failures_roll_back_every_claim_effect(self) -> None:
        _, control, owner = self._prepare_claim()
        with patch.object(
            self.store,
            "_append_attempt_claim_authorization_receipt",
            side_effect=RuntimeError("private receipt failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "private receipt failure"):
                self.store.try_claim_next(
                    instance_owner=owner,
                    expected_control_revision=control.revision,
                    ttl_seconds=20.0,
                    now=100.0,
                )

        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_attempts",
                    "supervisor_attempt_events",
                    "supervisor_attempt_claim_authorization_decisions",
                    "supervisor_attempt_claim_authorization_action_receipts",
                )
            )
            revision_count = connection.execute(
                "SELECT COUNT(*) FROM supervisor_flow_revisions WHERE flow_id = 'flow-one'"
            ).fetchone()[0]
            claim_lease_count = connection.execute(
                "SELECT COUNT(*) FROM leases WHERE lease_key != 'supervisor:foreground'"
            ).fetchone()[0]
        self.assertEqual(counts, (0, 0, 0, 0))
        self.assertEqual(revision_count, 1)
        self.assertEqual(claim_lease_count, 0)

    def test_attempt_claim_pep_requires_exact_readback_and_effect_records(self) -> None:
        _, control, owner = self._prepare_claim()
        with patch.object(
            self.store,
            "_append_attempt_claim_authorization_decision",
            return_value={},
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.try_claim_next(
                    instance_owner=owner,
                    expected_control_revision=control.revision,
                    ttl_seconds=20.0,
                    now=100.0,
                )
        with patch.object(
            self.store,
            "_insert_attempt_event",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                SupervisorError,
                "effect persistence is uncertain",
            ):
                self.store.try_claim_next(
                    instance_owner=owner,
                    expected_control_revision=control.revision,
                    ttl_seconds=20.0,
                    now=100.0,
                )

        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_attempts",
                    "supervisor_attempt_events",
                    "supervisor_attempt_claim_authorization_decisions",
                    "supervisor_attempt_claim_authorization_action_receipts",
                )
            )
        self.assertEqual(counts, (0, 0, 0, 0))

    def test_attempt_claim_pep_rebuild_rejects_a_replaced_first_pass(self) -> None:
        _, control, owner = self._prepare_claim()
        original = supervisor_module.evaluate_supervisor_attempt_claim_authorization

        def forged_first_pass(*args, **kwargs):
            authorization = original(*args, **kwargs)
            forged_action = replace(
                authorization.request.action,
                parameters_digest=canonical_digest({"forged": True}),
            )
            return replace(
                authorization,
                request=replace(authorization.request, action=forged_action),
            )

        with patch(
            "ordomata.supervisor.evaluate_supervisor_attempt_claim_authorization",
            side_effect=forged_first_pass,
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.try_claim_next(
                    instance_owner=owner,
                    expected_control_revision=control.revision,
                    ttl_seconds=20.0,
                    now=100.0,
                )

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM supervisor_attempts"
                ).fetchone()[0],
                0,
            )

    def test_attempt_claim_pep_audit_detects_decision_and_receipt_tampering(
        self,
    ) -> None:
        self._start_and_claim()
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                DROP TRIGGER supervisor_attempt_claim_authorization_decisions_no_update;
                DROP TRIGGER supervisor_attempt_claim_authorization_action_receipts_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_attempt_claim_authorization_decisions
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.execute(
                """
                UPDATE supervisor_attempt_claim_authorization_action_receipts
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("attempt_claim_authorization_decision_invalid", codes)
        self.assertIn("attempt_claim_authorization_receipt_invalid", codes)

    def test_pre_dispatch_intent_pep_persists_exact_decision_and_receipt(
        self,
    ) -> None:
        claim = self._start_and_claim(
            self._flow(
                "flow-pre-dispatch-pep-private",
                resource_keys=("repo:private-pre-dispatch",),
            )
        )
        target = self.store.mark_attempt_dispatching(claim, now=101.0)

        with closing(sqlite3.connect(self.database)) as connection:
            decision = connection.execute(
                """
                SELECT target_attempt_event_id, source_attempt_event_id,
                       attempt_id, flow_id, decision_event_id, request_digest,
                       decision_digest, payload_json
                FROM supervisor_pre_dispatch_intent_authorization_decisions
                """
            ).fetchone()
            receipt = connection.execute(
                """
                SELECT target_attempt_event_id, attempt_id, flow_id,
                       decision_event_id, receipt_digest, payload_json
                FROM supervisor_pre_dispatch_intent_authorization_action_receipts
                """
            ).fetchone()
            source_attempt_event_id = connection.execute(
                """
                SELECT event_id
                FROM supervisor_attempt_events
                WHERE attempt_id = ? AND state = 'created'
                """,
                (claim.attempt.attempt_id,),
            ).fetchone()[0]
        self.assertIsNotNone(decision)
        self.assertIsNotNone(receipt)
        assert decision is not None
        assert receipt is not None
        self.assertEqual(decision[0], target.event_id)
        self.assertEqual(decision[2], claim.attempt.attempt_id)
        self.assertEqual(decision[3], claim.flow.flow_id)
        self.assertEqual(decision[4], decision[6])
        self.assertEqual(receipt[0], target.event_id)
        self.assertEqual(receipt[1], claim.attempt.attempt_id)
        self.assertEqual(receipt[2], claim.flow.flow_id)
        self.assertEqual(receipt[3], decision[4])
        serialized = json.dumps([decision[7], receipt[5]], sort_keys=True)
        for private_value in (
            claim.flow.flow_id,
            claim.attempt.attempt_id,
            claim.attempt.run_id,
            claim.attempt.lease_owner,
            claim.flow_revision.event_id,
            source_attempt_event_id,
            target.event_id,
            "repo:private-pre-dispatch",
        ):
            self.assertNotIn(private_value, serialized)
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_intent_enforcement_record_count, 2)
        self.assertEqual(
            audit.expected_pre_dispatch_intent_enforcement_record_count,
            2,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    """
                    UPDATE supervisor_pre_dispatch_intent_authorization_decisions
                    SET payload_json = '{"tampered":true}'
                    """
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frozen"):
                connection.execute(
                    """
                    INSERT INTO supervisor_pre_dispatch_intent_authorization_enforcement_baseline (
                        target_attempt_event_id
                    ) VALUES ('forged-exemption')
                    """
                )

    def test_pre_dispatch_intent_pep_failure_rolls_back_every_effect(self) -> None:
        claim = self._start_and_claim()
        with patch.object(
            self.store,
            "_append_pre_dispatch_intent_authorization_receipt",
            side_effect=RuntimeError("private receipt failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "private receipt failure"):
                self.store.mark_attempt_dispatching(claim, now=101.0)

        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_pre_dispatch_intent_authorization_decisions",
                    "supervisor_pre_dispatch_intent_authorization_action_receipts",
                    "supervisor_pre_dispatch_intent_authorization_observations",
                )
            )
            dispatch_count = connection.execute(
                """
                SELECT COUNT(*) FROM supervisor_attempt_events
                WHERE attempt_id = ? AND state = 'dispatching'
                """,
                (claim.attempt.attempt_id,),
            ).fetchone()[0]
        self.assertEqual(counts, (0, 0, 0))
        self.assertEqual(dispatch_count, 0)

    def test_pre_dispatch_intent_pep_requires_exact_records_and_effect(self) -> None:
        claim = self._start_and_claim()
        with patch.object(
            self.store,
            "_append_pre_dispatch_intent_authorization_decision",
            return_value={},
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.mark_attempt_dispatching(claim, now=101.0)
        with patch.object(self.store, "_insert_attempt_event", return_value=None):
            with self.assertRaisesRegex(
                SupervisorError,
                "effect persistence is uncertain",
            ):
                self.store.mark_attempt_dispatching(claim, now=101.0)

        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_pre_dispatch_intent_authorization_decisions",
                    "supervisor_pre_dispatch_intent_authorization_action_receipts",
                    "supervisor_pre_dispatch_intent_authorization_observations",
                )
            )
            dispatch_count = connection.execute(
                """
                SELECT COUNT(*) FROM supervisor_attempt_events
                WHERE attempt_id = ? AND state = 'dispatching'
                """,
                (claim.attempt.attempt_id,),
            ).fetchone()[0]
        self.assertEqual(counts, (0, 0, 0))
        self.assertEqual(dispatch_count, 0)

    def test_pre_dispatch_intent_pep_rebuild_rejects_replaced_first_pass(
        self,
    ) -> None:
        claim = self._start_and_claim()
        original = supervisor_module.evaluate_supervisor_pre_dispatch_intent_authorization

        def forged_first_pass(*args: object, **kwargs: object) -> object:
            authorization = original(*args, **kwargs)
            forged_action = replace(
                authorization.request.action,
                parameters_digest=canonical_digest({"forged": True}),
            )
            return replace(
                authorization,
                request=replace(authorization.request, action=forged_action),
            )

        with patch(
            "ordomata.supervisor.evaluate_supervisor_pre_dispatch_intent_authorization",
            side_effect=forged_first_pass,
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.mark_attempt_dispatching(claim, now=101.0)

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM supervisor_attempt_events
                    WHERE attempt_id = ? AND state = 'dispatching'
                    """,
                    (claim.attempt.attempt_id,),
                ).fetchone()[0],
                0,
            )

    def test_pre_dispatch_intent_pep_audit_detects_tampering(self) -> None:
        claim = self._start_and_claim()
        self.store.mark_attempt_dispatching(claim, now=101.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                DROP TRIGGER supervisor_pre_dispatch_intent_authorization_decisions_no_update;
                DROP TRIGGER supervisor_pre_dispatch_intent_authorization_action_receipts_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_pre_dispatch_intent_authorization_decisions
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.execute(
                """
                UPDATE supervisor_pre_dispatch_intent_authorization_action_receipts
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("pre_dispatch_intent_enforcement_decision_invalid", codes)
        self.assertIn("pre_dispatch_intent_enforcement_receipt_invalid", codes)

    def test_v9_migration_baselines_existing_pre_dispatch_intents(self) -> None:
        legacy = self._start_and_claim()
        legacy_target = self.store.mark_attempt_dispatching(legacy, now=101.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v9_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_intent_enforcement_record_count, 0)
        self.assertEqual(
            audit.expected_pre_dispatch_intent_enforcement_record_count,
            0,
        )
        current = self._flow(
            "flow-pre-dispatch-enforcement-current",
            resource_keys=("repo:current-pre-dispatch",),
        )
        self.store.admit_flow(current)
        current_claim = self.store.try_claim_next(
            instance_owner="supervisor/instance-000000000001",
            expected_control_revision=1,
            ttl_seconds=20.0,
            now=101.0,
        )
        self.assertIsNotNone(current_claim)
        assert current_claim is not None
        self.store.mark_attempt_dispatching(current_claim, now=102.0)
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT target_attempt_event_id
                FROM supervisor_pre_dispatch_intent_authorization_enforcement_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(legacy_target.event_id,)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_intent_enforcement_record_count, 2)
        self.assertEqual(
            audit.expected_pre_dispatch_intent_enforcement_record_count,
            2,
        )

    def test_malformed_pre_v9_dispatch_intent_history_is_rejected_before_baseline(
        self,
    ) -> None:
        claim = self._start_and_claim()
        self.store.mark_attempt_dispatching(claim, now=101.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v9_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_attempt_events_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_attempt_events
                SET reason_code = 'forged_dispatch_intent'
                WHERE attempt_id = ? AND state = 'dispatching'
                """,
                (claim.attempt.attempt_id,),
            )
            connection.executescript(
                """
                CREATE TRIGGER supervisor_attempt_events_no_update
                BEFORE UPDATE ON supervisor_attempt_events BEGIN
                    SELECT RAISE(ABORT, 'supervisor attempt events are append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v9 supervisor pre-dispatch intent history is invalid",
        ):
            self._open_store()

    def test_v10_migration_baselines_existing_attempt_completions(self) -> None:
        legacy = self._start_and_claim()
        _, legacy_outbox = self.store.complete_attempt(
            legacy,
            expected_flow_revision=legacy.flow_revision.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="legacy_completion",
            now=101.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v10_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.attempt_completion_observation_count, 0)
        self.assertEqual(
            audit.expected_attempt_completion_observation_count,
            0,
        )
        current = self._flow(
            "flow-completion-current",
            resource_keys=("repo:current-completion",),
        )
        self.store.admit_flow(current)
        current_claim = self.store.try_claim_next(
            instance_owner="supervisor/instance-000000000001",
            expected_control_revision=1,
            ttl_seconds=20.0,
            now=102.0,
        )
        self.assertIsNotNone(current_claim)
        assert current_claim is not None
        self.store.complete_attempt(
            current_claim,
            expected_flow_revision=current_claim.flow_revision.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="current_completion",
            now=103.0,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT outbox_id
                FROM supervisor_attempt_completion_authorization_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(legacy_outbox.outbox_id,)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.attempt_completion_observation_count, 1)
        self.assertEqual(
            audit.expected_attempt_completion_observation_count,
            1,
        )

    def test_malformed_pre_v10_completion_history_is_rejected_before_baseline(
        self,
    ) -> None:
        claim = self._start_and_claim()
        _, outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=claim.flow_revision.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="checks_passed",
            now=101.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v10_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_completion_outbox_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_completion_outbox
                SET envelope_json = '{"forged":true}'
                WHERE outbox_id = ?
                """,
                (outbox.outbox_id,),
            )
            connection.executescript(
                """
                CREATE TRIGGER supervisor_completion_outbox_no_update
                BEFORE UPDATE ON supervisor_completion_outbox BEGIN
                    SELECT RAISE(ABORT, 'supervisor completion outbox is append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v10 supervisor attempt completion history is invalid",
        ):
            self._open_store()

    def test_v11_migration_baselines_existing_pre_dispatch_reconciliations(
        self,
    ) -> None:
        legacy = self._start_and_claim()
        legacy_plan = self.store.reconciliation_plan(now=121.0)
        self.store.apply_reconciliation(
            plan_digest=legacy_plan.plan_digest,
            now=121.0,
        )
        legacy_outbox = self.store.list_pending_completions()[0]
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v11_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_reconciliation_observation_count, 0)
        self.assertEqual(
            audit.expected_pre_dispatch_reconciliation_observation_count,
            0,
        )
        current = self._flow(
            "flow-reconciliation-current",
            resource_keys=("repo:current-reconciliation",),
        )
        self.store.admit_flow(current)
        current_claim = self.store.try_claim_next(
            instance_owner="supervisor/instance-000000000001",
            expected_control_revision=1,
            ttl_seconds=20.0,
            now=122.0,
        )
        self.assertIsNotNone(current_claim)
        assert current_claim is not None
        current_plan = self.store.reconciliation_plan(now=143.0)
        self.store.apply_reconciliation(
            plan_digest=current_plan.plan_digest,
            now=143.0,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT outbox_id
                FROM supervisor_pre_dispatch_reconciliation_authorization_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(legacy_outbox.outbox_id,)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_reconciliation_observation_count, 1)
        self.assertEqual(
            audit.expected_pre_dispatch_reconciliation_observation_count,
            1,
        )

    def test_malformed_pre_v11_reconciliation_history_is_rejected_before_baseline(
        self,
    ) -> None:
        claim = self._start_and_claim()
        plan = self.store.reconciliation_plan(now=121.0)
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=121.0)
        outbox = self.store.list_pending_completions()[0]
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v11_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_completion_outbox_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_completion_outbox
                SET envelope_json = '{"forged":true}'
                WHERE outbox_id = ?
                """,
                (outbox.outbox_id,),
            )
            connection.executescript(
                """
                CREATE TRIGGER supervisor_completion_outbox_no_update
                BEFORE UPDATE ON supervisor_completion_outbox BEGIN
                    SELECT RAISE(ABORT, 'supervisor completion outbox is append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v11 supervisor pre-dispatch reconciliation history is invalid",
        ):
            self._open_store()

    def test_v12_migration_baselines_existing_queued_timeout_reconciliations(
        self,
    ) -> None:
        legacy = self._flow(
            "flow-queued-timeout-legacy",
            deadline_at=110.0,
            resource_keys=("repo:queued-timeout-legacy",),
        )
        self.store.admit_flow(legacy)
        legacy_plan = self.store.reconciliation_plan(now=111.0)
        self.store.apply_reconciliation(
            plan_digest=legacy_plan.plan_digest,
            now=111.0,
        )
        legacy_outbox = self.store.list_pending_completions()[0]
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v12_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.queued_timeout_reconciliation_observation_count, 0)
        self.assertEqual(
            audit.expected_queued_timeout_reconciliation_observation_count,
            0,
        )
        current = self._flow(
            "flow-queued-timeout-current",
            deadline_at=130.0,
            resource_keys=("repo:queued-timeout-current",),
        )
        self.store.admit_flow(current)
        current_plan = self.store.reconciliation_plan(now=131.0)
        self.store.apply_reconciliation(
            plan_digest=current_plan.plan_digest,
            now=131.0,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT outbox_id
                FROM supervisor_queued_timeout_reconciliation_authorization_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(legacy_outbox.outbox_id,)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.queued_timeout_reconciliation_observation_count, 1)
        self.assertEqual(
            audit.expected_queued_timeout_reconciliation_observation_count,
            1,
        )

    def test_malformed_pre_v12_queued_timeout_history_is_rejected_before_baseline(
        self,
    ) -> None:
        spec = self._flow(deadline_at=110.0)
        self.store.admit_flow(spec)
        plan = self.store.reconciliation_plan(now=111.0)
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=111.0)
        outbox = self.store.list_pending_completions()[0]
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v12_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_completion_outbox_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_completion_outbox
                SET envelope_json = '{"forged":true}'
                WHERE outbox_id = ?
                """,
                (outbox.outbox_id,),
            )
            connection.executescript(
                """
                CREATE TRIGGER supervisor_completion_outbox_no_update
                BEFORE UPDATE ON supervisor_completion_outbox BEGIN
                    SELECT RAISE(ABORT, 'supervisor completion outbox is append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v12 supervisor queued-timeout reconciliation history is invalid",
        ):
            self._open_store()

    def test_pre_dispatch_intent_shadow_persists_redacted_parity(self) -> None:
        claim = self._start_and_claim(
            self._flow(
                "flow-pre-dispatch-private",
                resource_keys=("repo:private-project",),
            )
        )

        self.assertEqual(
            self.store.renew_claim(claim, ttl_seconds=20.0, now=101.0),
            121.0,
        )
        target = self.store.mark_attempt_dispatching(claim, now=102.0)

        observations = self.store.list_pre_dispatch_intent_authorization_observations(
            claim.attempt.attempt_id
        )
        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation.flow_id, claim.flow.flow_id)
        self.assertEqual(observation.attempt_id, claim.attempt.attempt_id)
        self.assertEqual(observation.source_flow_revision, claim.flow_revision.revision)
        self.assertEqual(observation.target_attempt_event_id, target.event_id)
        self.assertEqual(observation.effect, "permit")
        self.assertEqual(
            observation.derived_permission_class,
            PermissionClass.LOCAL_DRAFT,
        )
        self.assertTrue(observation.legacy_executable)
        self.assertTrue(observation.execution_parity)
        serialized = json.dumps(observation.payload, sort_keys=True)
        for private_value in (
            claim.flow.flow_id,
            claim.attempt.attempt_id,
            claim.attempt.run_id,
            claim.attempt.lease_owner,
            "repo:private-project",
            target.event_id,
        ):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(
            observation.payload["action_scope"],
            "supervisor_local_attempt_pre_dispatch_intent_only",
        )
        self.assertEqual(
            observation.payload["pre_dispatch_intent"]["target"]["attempt_state"],
            "dispatching",
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_intent_observation_count, 1)
        self.assertEqual(audit.expected_pre_dispatch_intent_observation_count, 1)
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    """
                    UPDATE supervisor_pre_dispatch_intent_authorization_observations
                    SET effect = 'deny'
                    """
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frozen"):
                connection.execute(
                    """
                    INSERT INTO supervisor_pre_dispatch_intent_authorization_baseline (
                        attempt_event_id
                    ) VALUES ('forged-exemption')
                    """
                )

    def test_pre_dispatch_shadow_failure_cannot_block_local_intent(self) -> None:
        claim = self._start_and_claim()

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("private shadow failure"),
        ):
            target = self.store.mark_attempt_dispatching(claim, now=101.0)

        self.assertEqual(target.state, supervisor_module.AttemptState.DISPATCHING)
        self.assertEqual(
            self.store.list_pre_dispatch_intent_authorization_observations(),
            (),
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "pre_dispatch_intent_authorization_observation_missing",
            {finding.code for finding in audit.findings},
        )

    def test_pre_dispatch_shadow_audit_replays_the_builtin_evaluator(self) -> None:
        claim = self._start_and_claim()
        original = supervisor_module.ShadowAuthorizationEvaluator.evaluate

        def forged_first_pass(request, policy):
            return replace(
                original(supervisor_module.ShadowAuthorizationEvaluator(), request, policy),
                effect=AuthorizationEffect.DENY,
            )

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=forged_first_pass,
        ):
            target = self.store.mark_attempt_dispatching(claim, now=101.0)

        self.assertEqual(target.state, supervisor_module.AttemptState.DISPATCHING)
        observation = self.store.list_pre_dispatch_intent_authorization_observations()[0]
        self.assertEqual(observation.effect, "deny")
        self.assertFalse(observation.execution_parity)
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "pre_dispatch_intent_authorization_observation_invalid",
            {finding.code for finding in audit.findings},
        )

    def test_pre_dispatch_shadow_audit_detects_tampering(self) -> None:
        claim = self._start_and_claim()
        self.store.mark_attempt_dispatching(claim, now=101.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                DROP TRIGGER supervisor_pre_dispatch_intent_authorization_observations_no_update
                """
            )
            connection.execute(
                """
                UPDATE supervisor_pre_dispatch_intent_authorization_observations
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("pre_dispatch_intent_authorization_observation_invalid", codes)

    def test_attempt_completion_shadow_persists_redacted_parity(self) -> None:
        claim = self._start_and_claim(
            self._flow(
                "flow-completion-private",
                resource_keys=("repo:private-completion",),
            )
        )
        source_attempt = self.store.mark_attempt_dispatching(claim, now=101.0)
        completed, outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=claim.flow_revision.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="checks_passed",
            now=102.0,
        )

        observations = self.store.list_attempt_completion_authorization_observations(
            claim.attempt.attempt_id
        )
        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation.flow_id, claim.flow.flow_id)
        self.assertEqual(observation.attempt_id, claim.attempt.attempt_id)
        self.assertEqual(observation.source_flow_revision, claim.flow_revision.revision)
        self.assertEqual(observation.source_attempt_event_id, source_attempt.event_id)
        self.assertEqual(observation.target_flow_event_id, completed.event_id)
        self.assertEqual(observation.outbox_id, outbox.outbox_id)
        self.assertEqual(observation.effect, "permit")
        self.assertEqual(
            observation.derived_permission_class,
            PermissionClass.LOCAL_DRAFT,
        )
        self.assertTrue(observation.legacy_executable)
        self.assertTrue(observation.execution_parity)
        serialized = json.dumps(observation.payload, sort_keys=True)
        for private_value in (
            claim.flow.flow_id,
            claim.attempt.attempt_id,
            claim.attempt.run_id,
            claim.attempt.lease_owner,
            claim.flow_revision.event_id,
            source_attempt.event_id,
            completed.event_id,
            outbox.outbox_id,
            "repo:private-completion",
        ):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(
            observation.payload["action_scope"],
            "supervisor_local_attempt_completion_only",
        )
        self.assertEqual(
            observation.payload["attempt_completion"]["target"]["flow_state"],
            "succeeded",
        )
        self.assertEqual(
            observation.payload["attempt_completion"]["completion"]["state"],
            "succeeded",
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.attempt_completion_observation_count, 1)
        self.assertEqual(
            audit.expected_attempt_completion_observation_count,
            1,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    """
                    UPDATE supervisor_attempt_completion_authorization_observations
                    SET effect = 'deny'
                    """
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frozen"):
                connection.execute(
                    """
                    INSERT INTO supervisor_attempt_completion_authorization_baseline (
                        outbox_id
                    ) VALUES ('forged-exemption')
                    """
                )

    def test_attempt_completion_shadow_failure_cannot_block_local_completion(
        self,
    ) -> None:
        claim = self._start_and_claim()

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("private shadow failure"),
        ):
            completed, outbox = self.store.complete_attempt(
                claim,
                expected_flow_revision=claim.flow_revision.revision,
                outcome=FlowState.SUCCEEDED,
                reason_code="checks_passed",
                now=101.0,
            )

        self.assertEqual(completed.state, FlowState.SUCCEEDED)
        self.assertEqual(self.store.list_pending_completions(), (outbox,))
        self.assertEqual(
            self.store.list_attempt_completion_authorization_observations(),
            (),
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "attempt_completion_authorization_observation_missing",
            {finding.code for finding in audit.findings},
        )

    def test_attempt_completion_shadow_binds_selected_cancellation_outcome(
        self,
    ) -> None:
        claim = self._start_and_claim()
        cancellation = self.store.request_cancellation(
            claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )
        completed, outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=cancellation.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="worker_finished_after_cancel",
            now=102.0,
        )

        self.assertEqual(completed.state, FlowState.CANCELLED)
        self.assertEqual(outbox.envelope["state"], "cancelled")
        observation = self.store.list_attempt_completion_authorization_observations()[0]
        completion = observation.payload["attempt_completion"]
        self.assertTrue(completion["source"]["cancellation_requested"])
        self.assertEqual(completion["target"]["flow_state"], "cancelled")
        self.assertEqual(completion["completion"]["state"], "cancelled")
        self.assertNotIn("requested_outcome", completion)
        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertNotIn("attempt_completion_authorization_source_invalid", codes)
        self.assertNotIn("attempt_completion_authorization_observation_invalid", codes)

    def test_attempt_completion_shadow_audit_replays_builtin_evaluator(self) -> None:
        claim = self._start_and_claim()
        original = supervisor_module.ShadowAuthorizationEvaluator.evaluate

        def forged_first_pass(request, policy):
            return replace(
                original(
                    supervisor_module.ShadowAuthorizationEvaluator(),
                    request,
                    policy,
                ),
                effect=AuthorizationEffect.DENY,
            )

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=forged_first_pass,
        ):
            completed, _ = self.store.complete_attempt(
                claim,
                expected_flow_revision=claim.flow_revision.revision,
                outcome=FlowState.SUCCEEDED,
                reason_code="checks_passed",
                now=101.0,
            )

        self.assertEqual(completed.state, FlowState.SUCCEEDED)
        observation = self.store.list_attempt_completion_authorization_observations()[0]
        self.assertEqual(observation.effect, "deny")
        self.assertFalse(observation.execution_parity)
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "attempt_completion_authorization_observation_invalid",
            {finding.code for finding in audit.findings},
        )

    def test_attempt_completion_shadow_audit_detects_tampering(self) -> None:
        claim = self._start_and_claim()
        self.store.complete_attempt(
            claim,
            expected_flow_revision=claim.flow_revision.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="checks_passed",
            now=101.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                DROP TRIGGER supervisor_attempt_completion_authorization_observations_no_update
                """
            )
            connection.execute(
                """
                UPDATE supervisor_attempt_completion_authorization_observations
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("attempt_completion_authorization_observation_invalid", codes)

    def test_pre_dispatch_reconciliation_shadow_persists_redacted_parity(
        self,
    ) -> None:
        claim = self._start_and_claim(
            self._flow(
                "flow-reconciliation-private",
                resource_keys=("repo:private-reconciliation",),
            )
        )
        plan = self.store.reconciliation_plan(now=121.0)
        self.assertEqual(plan.actionable_count, 1)
        self.assertEqual(plan.findings[0].action, "mark_lost_pre_dispatch")
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=121.0)
        completed = self.store.current_flow_revision(claim.flow.flow_id)
        outbox = self.store.list_pending_completions()[0]

        observations = (
            self.store.list_pre_dispatch_reconciliation_authorization_observations(
                claim.attempt.attempt_id
            )
        )
        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation.flow_id, claim.flow.flow_id)
        self.assertEqual(observation.attempt_id, claim.attempt.attempt_id)
        self.assertEqual(observation.source_flow_revision, claim.flow_revision.revision)
        self.assertEqual(observation.target_flow_event_id, completed.event_id)
        self.assertEqual(observation.outbox_id, outbox.outbox_id)
        self.assertEqual(
            observation.reconciliation_action,
            "mark_lost_pre_dispatch",
        )
        self.assertEqual(observation.effect, "permit")
        self.assertEqual(
            observation.derived_permission_class,
            PermissionClass.LOCAL_DRAFT,
        )
        self.assertTrue(observation.legacy_executable)
        self.assertTrue(observation.execution_parity)
        serialized = json.dumps(observation.payload, sort_keys=True)
        for private_value in (
            claim.flow.flow_id,
            claim.attempt.attempt_id,
            claim.attempt.run_id,
            claim.attempt.lease_owner,
            claim.flow_revision.event_id,
            completed.event_id,
            outbox.outbox_id,
            "repo:private-reconciliation",
        ):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(
            observation.payload["action_scope"],
            "supervisor_local_pre_dispatch_reconciliation_only",
        )
        reconciliation = observation.payload["pre_dispatch_reconciliation"]
        self.assertEqual(reconciliation["target"]["flow_state"], "lost")
        self.assertEqual(
            reconciliation["completion"]["state"],
            "lost",
        )
        self.assertEqual(
            reconciliation["reconciliation"]["action"],
            "mark_lost_pre_dispatch",
        )
        self.assertIn(
            "owned_expired",
            {
                lease["lease_state"]
                for lease in reconciliation["source"]["lease_snapshot"]
            },
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_reconciliation_observation_count, 1)
        self.assertEqual(
            audit.expected_pre_dispatch_reconciliation_observation_count,
            1,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    """
                    UPDATE supervisor_pre_dispatch_reconciliation_authorization_observations
                    SET effect = 'deny'
                    """
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frozen"):
                connection.execute(
                    """
                    INSERT INTO supervisor_pre_dispatch_reconciliation_authorization_baseline (
                        outbox_id
                    ) VALUES ('forged-exemption')
                    """
                )

    def test_pre_dispatch_reconciliation_shadow_failure_cannot_block_repair(
        self,
    ) -> None:
        claim = self._start_and_claim()
        plan = self.store.reconciliation_plan(now=121.0)

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("private shadow failure"),
        ):
            applied = self.store.apply_reconciliation(
                plan_digest=plan.plan_digest,
                now=121.0,
            )

        self.assertEqual(applied, plan.findings)
        self.assertEqual(
            self.store.current_flow_revision(claim.flow.flow_id).state,
            FlowState.LOST,
        )
        self.assertEqual(len(self.store.list_pending_completions()), 1)
        self.assertEqual(
            self.store.list_pre_dispatch_reconciliation_authorization_observations(),
            (),
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "pre_dispatch_reconciliation_authorization_observation_missing",
            {finding.code for finding in audit.findings},
        )

    def test_pre_dispatch_reconciliation_shadow_binds_cancelled_repair(
        self,
    ) -> None:
        claim = self._start_and_claim()
        self.store.request_cancellation(
            claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )
        plan = self.store.reconciliation_plan(now=121.0)
        self.assertEqual(
            plan.findings[0].action,
            "finalize_cancelled_pre_dispatch",
        )
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=121.0)

        completed = self.store.current_flow_revision(claim.flow.flow_id)
        self.assertEqual(completed.state, FlowState.CANCELLED)
        observation = (
            self.store.list_pre_dispatch_reconciliation_authorization_observations()
        )[0]
        self.assertEqual(
            observation.reconciliation_action,
            "finalize_cancelled_pre_dispatch",
        )
        reconciliation = observation.payload["pre_dispatch_reconciliation"]
        self.assertTrue(reconciliation["source"]["cancellation_requested"])
        self.assertEqual(reconciliation["target"]["flow_state"], "cancelled")
        self.assertEqual(
            reconciliation["reconciliation"]["action"],
            "finalize_cancelled_pre_dispatch",
        )
        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertNotIn(
            "pre_dispatch_reconciliation_authorization_source_invalid",
            codes,
        )
        self.assertNotIn(
            "pre_dispatch_reconciliation_authorization_observation_invalid",
            codes,
        )

    def test_pre_dispatch_reconciliation_shadow_audit_replays_builtin_evaluator(
        self,
    ) -> None:
        claim = self._start_and_claim()
        plan = self.store.reconciliation_plan(now=121.0)
        original = supervisor_module.ShadowAuthorizationEvaluator.evaluate

        def forged_first_pass(request, policy):
            return replace(
                original(
                    supervisor_module.ShadowAuthorizationEvaluator(),
                    request,
                    policy,
                ),
                effect=AuthorizationEffect.DENY,
            )

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=forged_first_pass,
        ):
            self.store.apply_reconciliation(
                plan_digest=plan.plan_digest,
                now=121.0,
            )

        observation = (
            self.store.list_pre_dispatch_reconciliation_authorization_observations()
        )[0]
        self.assertEqual(observation.effect, "deny")
        self.assertFalse(observation.execution_parity)
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "pre_dispatch_reconciliation_authorization_observation_invalid",
            {finding.code for finding in audit.findings},
        )

    def test_pre_dispatch_reconciliation_shadow_audit_detects_tampering(
        self,
    ) -> None:
        claim = self._start_and_claim()
        plan = self.store.reconciliation_plan(now=121.0)
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=121.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                DROP TRIGGER supervisor_pre_dispatch_reconciliation_authorization_observations_no_update
                """
            )
            connection.execute(
                """
                UPDATE supervisor_pre_dispatch_reconciliation_authorization_observations
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn(
            "pre_dispatch_reconciliation_authorization_observation_invalid",
            codes,
        )

    def test_queued_timeout_reconciliation_shadow_persists_redacted_parity(
        self,
    ) -> None:
        spec = self._flow(
            "flow-queued-timeout-private",
            deadline_at=110.0,
            resource_keys=("repo:private-queued-timeout",),
        )
        self.store.admit_flow(spec)
        source = self.store.current_flow_revision(spec.flow_id)
        plan = self.store.reconciliation_plan(now=111.0)
        self.assertEqual(plan.actionable_count, 1)
        self.assertEqual(plan.findings[0].action, "mark_queued_timed_out")
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=111.0)
        completed = self.store.current_flow_revision(spec.flow_id)
        outbox = self.store.list_pending_completions()[0]

        observations = (
            self.store.list_queued_timeout_reconciliation_authorization_observations(
                spec.flow_id
            )
        )
        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation.flow_id, spec.flow_id)
        self.assertEqual(observation.source_flow_revision, source.revision)
        self.assertEqual(observation.source_flow_event_id, source.event_id)
        self.assertEqual(observation.target_flow_event_id, completed.event_id)
        self.assertEqual(observation.outbox_id, outbox.outbox_id)
        self.assertEqual(
            observation.reconciliation_action,
            "mark_queued_timed_out",
        )
        self.assertEqual(observation.effect, "permit")
        self.assertEqual(
            observation.derived_permission_class,
            PermissionClass.LOCAL_DRAFT,
        )
        self.assertTrue(observation.legacy_executable)
        self.assertTrue(observation.execution_parity)
        serialized = json.dumps(observation.payload, sort_keys=True)
        for private_value in (
            spec.flow_id,
            source.event_id,
            completed.event_id,
            outbox.outbox_id,
            "repo:private-queued-timeout",
        ):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(
            observation.payload["action_scope"],
            "supervisor_local_queued_timeout_reconciliation_only",
        )
        reconciliation = observation.payload["queued_timeout_reconciliation"]
        self.assertEqual(reconciliation["source"]["flow_state"], "queued")
        self.assertEqual(reconciliation["target"]["flow_state"], "timed_out")
        self.assertEqual(reconciliation["completion"]["state"], "timed_out")
        self.assertTrue(reconciliation["completion"]["attempt_absent"])
        self.assertEqual(
            reconciliation["reconciliation"]["action"],
            "mark_queued_timed_out",
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.queued_timeout_reconciliation_observation_count, 1)
        self.assertEqual(
            audit.expected_queued_timeout_reconciliation_observation_count,
            1,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    """
                    UPDATE supervisor_queued_timeout_reconciliation_authorization_observations
                    SET effect = 'deny'
                    """
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frozen"):
                connection.execute(
                    """
                    INSERT INTO supervisor_queued_timeout_reconciliation_authorization_baseline (
                        outbox_id
                    ) VALUES ('forged-exemption')
                    """
                )

    def test_queued_timeout_reconciliation_shadow_failure_cannot_block_repair(
        self,
    ) -> None:
        spec = self._flow(deadline_at=110.0)
        self.store.admit_flow(spec)
        plan = self.store.reconciliation_plan(now=111.0)

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("private shadow failure"),
        ):
            applied = self.store.apply_reconciliation(
                plan_digest=plan.plan_digest,
                now=111.0,
            )

        self.assertEqual(applied, plan.findings)
        self.assertEqual(
            self.store.current_flow_revision(spec.flow_id).state,
            FlowState.TIMED_OUT,
        )
        self.assertEqual(len(self.store.list_pending_completions()), 1)
        self.assertEqual(
            self.store.list_queued_timeout_reconciliation_authorization_observations(),
            (),
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "queued_timeout_reconciliation_authorization_observation_missing",
            {finding.code for finding in audit.findings},
        )

    def test_queued_timeout_reconciliation_shadow_audit_replays_builtin_evaluator(
        self,
    ) -> None:
        spec = self._flow(deadline_at=110.0)
        self.store.admit_flow(spec)
        plan = self.store.reconciliation_plan(now=111.0)
        original = supervisor_module.ShadowAuthorizationEvaluator.evaluate

        def forged_first_pass(request, policy):
            return replace(
                original(
                    supervisor_module.ShadowAuthorizationEvaluator(),
                    request,
                    policy,
                ),
                effect=AuthorizationEffect.DENY,
            )

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=forged_first_pass,
        ):
            self.store.apply_reconciliation(
                plan_digest=plan.plan_digest,
                now=111.0,
            )

        observation = (
            self.store.list_queued_timeout_reconciliation_authorization_observations()
        )[0]
        self.assertEqual(observation.effect, "deny")
        self.assertFalse(observation.execution_parity)
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "queued_timeout_reconciliation_authorization_observation_invalid",
            {finding.code for finding in audit.findings},
        )

    def test_queued_timeout_reconciliation_shadow_audit_detects_tampering(
        self,
    ) -> None:
        spec = self._flow(deadline_at=110.0)
        self.store.admit_flow(spec)
        plan = self.store.reconciliation_plan(now=111.0)
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=111.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                DROP TRIGGER supervisor_queued_timeout_reconciliation_authorization_observations_no_update
                """
            )
            connection.execute(
                """
                UPDATE supervisor_queued_timeout_reconciliation_authorization_observations
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn(
            "queued_timeout_reconciliation_authorization_observation_invalid",
            codes,
        )

    def test_v8_migration_baselines_existing_pre_dispatch_intents(self) -> None:
        legacy = self._start_and_claim()
        legacy_target = self.store.mark_attempt_dispatching(legacy, now=101.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v8_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_intent_observation_count, 0)
        self.assertEqual(audit.expected_pre_dispatch_intent_observation_count, 0)
        current = self._flow(
            "flow-pre-dispatch-current",
            resource_keys=("repo:current-project",),
        )
        self.store.admit_flow(current)
        current_claim = self.store.try_claim_next(
            instance_owner="supervisor/instance-000000000001",
            expected_control_revision=1,
            ttl_seconds=20.0,
            now=101.0,
        )
        self.assertIsNotNone(current_claim)
        assert current_claim is not None
        self.store.mark_attempt_dispatching(current_claim, now=102.0)
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT attempt_event_id
                FROM supervisor_pre_dispatch_intent_authorization_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(legacy_target.event_id,)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())
        self.assertEqual(audit.pre_dispatch_intent_observation_count, 1)
        self.assertEqual(audit.expected_pre_dispatch_intent_observation_count, 1)

    def test_malformed_pre_v8_dispatch_intent_history_is_rejected_before_baseline(
        self,
    ) -> None:
        claim = self._start_and_claim()
        self.store.mark_attempt_dispatching(claim, now=101.0)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v8_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_attempt_events_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_attempt_events
                SET reason_code = 'forged_dispatch_intent'
                WHERE attempt_id = ? AND state = 'dispatching'
                """,
                (claim.attempt.attempt_id,),
            )
            connection.executescript(
                """
                CREATE TRIGGER supervisor_attempt_events_no_update
                BEFORE UPDATE ON supervisor_attempt_events BEGIN
                    SELECT RAISE(ABORT, 'supervisor attempt events are append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v8 supervisor pre-dispatch intent history is invalid",
        ):
            self._open_store()

    def test_v7_migration_baselines_existing_attempts_before_enforcement(self) -> None:
        legacy = self._start_and_claim()
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v7_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.attempt_claim_enforcement_record_count, 0)
        self.assertEqual(audit.expected_attempt_claim_enforcement_record_count, 0)
        current = self._flow(
            "flow-current",
            resource_keys=("repo:current-project",),
        )
        self.store.admit_flow(current)
        current_claim = self.store.try_claim_next(
            instance_owner="supervisor/instance-000000000001",
            expected_control_revision=1,
            ttl_seconds=20.0,
            now=100.0,
        )
        self.assertIsNotNone(current_claim)
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT attempt_id
                FROM supervisor_attempt_claim_authorization_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(legacy.attempt.attempt_id,)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.attempt_claim_enforcement_record_count, 2)
        self.assertEqual(audit.expected_attempt_claim_enforcement_record_count, 2)

    def test_malformed_pre_v7_attempt_history_is_rejected_before_baseline(self) -> None:
        claim = self._start_and_claim()
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v7_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_attempt_events_no_delete;
                """
            )
            connection.execute(
                "DELETE FROM supervisor_attempt_events WHERE attempt_id = ?",
                (claim.attempt.attempt_id,),
            )
            connection.executescript(
                """
                CREATE TRIGGER supervisor_attempt_events_no_delete
                BEFORE DELETE ON supervisor_attempt_events BEGIN
                    SELECT RAISE(ABORT, 'supervisor attempt events are append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v7 supervisor attempt history is invalid",
        ):
            self._open_store()

    def test_attempt_history_rejects_claims_beyond_the_flow_budget(self) -> None:
        claim = self._start_and_claim(self._flow(max_attempts=1))
        with closing(sqlite3.connect(self.database)) as connection:
            connection.row_factory = sqlite3.Row
            revisions = connection.execute(
                """
                SELECT * FROM supervisor_flow_revisions
                WHERE flow_id = ? ORDER BY revision
                """,
                (claim.flow.flow_id,),
            ).fetchall()
            events = connection.execute(
                """
                SELECT * FROM supervisor_attempt_events
                WHERE attempt_id = ? ORDER BY revision
                """,
                (claim.attempt.attempt_id,),
            ).fetchall()

        with self.assertRaisesRegex(
            ValidationError,
            "attempt number exceeds its flow budget",
        ):
            supervisor_module._verify_attempt_claim_history(
                attempt=replace(claim.attempt, attempt_number=2),
                spec=claim.flow,
                revision_rows=revisions,
                event_rows=events,
            )

    def test_v6_migration_baselines_existing_flows_before_enforcement(self) -> None:
        legacy = self._flow("flow-legacy")
        self.store.admit_flow(legacy)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v6_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.flow_admission_enforcement_record_count, 0)
        self.assertEqual(audit.expected_flow_admission_enforcement_record_count, 0)
        current = self._flow("flow-current")
        self.store.admit_flow(current)
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT flow_id
                FROM supervisor_flow_admission_authorization_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(legacy.flow_id,)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.flow_admission_enforcement_record_count, 2)
        self.assertEqual(audit.expected_flow_admission_enforcement_record_count, 2)

    def test_malformed_pre_v6_flow_history_is_rejected_before_baseline(self) -> None:
        self.store.admit_flow(self._flow())
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v6_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_flow_revisions_no_delete;
                DELETE FROM supervisor_flow_revisions WHERE flow_id = 'flow-one';
                CREATE TRIGGER supervisor_flow_revisions_no_delete
                BEFORE DELETE ON supervisor_flow_revisions BEGIN
                    SELECT RAISE(ABORT, 'supervisor flow revisions are append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v6 supervisor flow history is invalid",
        ):
            self._open_store()

    def test_control_pep_persists_exact_decisions_and_receipts(self) -> None:
        running = self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/private-control-session",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        paused = self.store.update_control(
            expected_revision=running.revision,
            mode=SupervisorMode.PAUSED,
            actor_id="operator/private-control-session",
            reason_code="operator_paused",
            occurred_at=101.0,
        )

        with closing(sqlite3.connect(self.database)) as connection:
            decisions = connection.execute(
                """
                SELECT control_event_id, decision_event_id, request_digest,
                       decision_digest, payload_json
                FROM supervisor_control_authorization_decisions
                ORDER BY sequence
                """
            ).fetchall()
            receipts = connection.execute(
                """
                SELECT control_event_id, decision_event_id, receipt_digest,
                       payload_json
                FROM supervisor_control_authorization_action_receipts
                ORDER BY sequence
                """
            ).fetchall()
        self.assertEqual(
            [row[0] for row in decisions],
            [running.event_id, paused.event_id],
        )
        self.assertEqual(
            [row[0] for row in receipts],
            [running.event_id, paused.event_id],
        )
        self.assertTrue(
            all(row[1] == row[3] for row in decisions)
        )
        self.assertTrue(
            all(row[1] == decision[1] for row, decision in zip(receipts, decisions))
        )
        serialized = json.dumps(
            [*(tuple(row) for row in decisions), *(tuple(row) for row in receipts)],
            sort_keys=True,
        )
        self.assertNotIn("operator/private-control-session", serialized)
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.control_enforcement_record_count, 4)
        self.assertEqual(audit.expected_control_enforcement_record_count, 4)

    def test_control_pep_receipt_failure_rolls_back_the_control_change(self) -> None:
        with patch.object(
            self.store,
            "_append_control_authorization_receipt",
            side_effect=RuntimeError("private receipt failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "private receipt failure"):
                self.store.update_control(
                    expected_revision=0,
                    mode=SupervisorMode.RUNNING,
                    actor_id="operator/session-000000000001",
                    reason_code="operator_started",
                    occurred_at=100.0,
                )

        self.assertEqual(self.store.current_control().revision, 0)
        with closing(sqlite3.connect(self.database)) as connection:
            control_count = connection.execute(
                "SELECT COUNT(*) FROM supervisor_control_events"
            ).fetchone()[0]
            decision_count = connection.execute(
                """
                SELECT COUNT(*) FROM supervisor_control_authorization_decisions
                """
            ).fetchone()[0]
            receipt_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM supervisor_control_authorization_action_receipts
                """
            ).fetchone()[0]
        self.assertEqual((control_count, decision_count, receipt_count), (0, 0, 0))

    def test_control_pep_requires_exact_receipt_readback(self) -> None:
        with patch.object(
            self.store,
            "_append_control_authorization_receipt",
            return_value={},
        ):
            with self.assertRaisesRegex(
                SupervisorError,
                "receipt persistence is uncertain",
            ):
                self.store.update_control(
                    expected_revision=0,
                    mode=SupervisorMode.RUNNING,
                    actor_id="operator/session-000000000001",
                    reason_code="operator_started",
                    occurred_at=100.0,
                )

        self.assertEqual(self.store.current_control().revision, 0)
        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_control_events",
                    "supervisor_control_authorization_decisions",
                    "supervisor_control_authorization_action_receipts",
                )
            )
        self.assertEqual(counts, (0, 0, 0))

    def test_control_pep_requires_exact_decision_readback(self) -> None:
        with patch.object(
            self.store,
            "_append_control_authorization_decision",
            return_value={},
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.update_control(
                    expected_revision=0,
                    mode=SupervisorMode.RUNNING,
                    actor_id="operator/session-000000000001",
                    reason_code="operator_started",
                    occurred_at=100.0,
                )

        self.assertEqual(self.store.current_control().revision, 0)
        with closing(sqlite3.connect(self.database)) as connection:
            counts = tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "supervisor_control_events",
                    "supervisor_control_authorization_decisions",
                    "supervisor_control_authorization_action_receipts",
                )
            )
        self.assertEqual(counts, (0, 0, 0))

    def test_control_pep_rebuild_rejects_a_replaced_first_pass(self) -> None:
        original = supervisor_module.evaluate_supervisor_control_authorization

        def forged_first_pass(*args, **kwargs):
            authorization = original(*args, **kwargs)
            forged_action = replace(
                authorization.request.action,
                parameters_digest=canonical_digest({"forged": True}),
            )
            return replace(
                authorization,
                request=replace(authorization.request, action=forged_action),
            )

        with patch(
            "ordomata.supervisor.evaluate_supervisor_control_authorization",
            side_effect=forged_first_pass,
        ):
            with self.assertRaises(AuthorizationBlocked):
                self.store.update_control(
                    expected_revision=0,
                    mode=SupervisorMode.RUNNING,
                    actor_id="operator/session-000000000001",
                    reason_code="operator_started",
                    occurred_at=100.0,
                )

        self.assertEqual(self.store.current_control().revision, 0)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM supervisor_control_events"
                ).fetchone()[0],
                0,
            )

    def test_control_pep_audit_detects_decision_and_receipt_tampering(self) -> None:
        self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                DROP TRIGGER supervisor_control_authorization_decisions_no_update;
                DROP TRIGGER supervisor_control_authorization_action_receipts_no_update;
                """
            )
            connection.execute(
                """
                UPDATE supervisor_control_authorization_decisions
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.execute(
                """
                UPDATE supervisor_control_authorization_action_receipts
                SET payload_json = '{"tampered":true}'
                """
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertFalse(audit.clean)
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("control_authorization_decision_invalid", codes)
        self.assertIn("control_authorization_receipt_invalid", codes)

    def test_v5_migration_baselines_existing_controls_before_enforcement(self) -> None:
        running = self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v5_schema(connection)

        self.store = self._open_store()
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.control_enforcement_record_count, 0)
        self.assertEqual(audit.expected_control_enforcement_record_count, 0)
        paused = self.store.update_control(
            expected_revision=running.revision,
            mode=SupervisorMode.PAUSED,
            actor_id="operator/session-000000000001",
            reason_code="operator_paused",
            occurred_at=101.0,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            baseline = connection.execute(
                """
                SELECT control_event_id
                FROM supervisor_control_authorization_baseline
                """
            ).fetchall()
        self.assertEqual(baseline, [(running.event_id,)])
        self.assertNotEqual(paused.event_id, running.event_id)
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean)
        self.assertEqual(audit.control_enforcement_record_count, 2)
        self.assertEqual(audit.expected_control_enforcement_record_count, 2)

    def test_bookkeeping_shadow_failure_cannot_block_control_or_cancellation(self) -> None:
        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("sensitive diagnostic"),
        ):
            control = self.store.update_control(
                expected_revision=0,
                mode=SupervisorMode.RUNNING,
                actor_id="operator/session-000000000001",
                reason_code="operator_started",
                occurred_at=100.0,
            )

        spec = self._flow()
        self.store.admit_flow(spec)
        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("sensitive diagnostic"),
        ):
            cancelled = self.store.request_cancellation(
                spec.flow_id,
                requested_by="operator/session-000000000001",
                reason_code="operator_cancelled",
                now=101.0,
            )

        self.assertEqual(control.revision, 1)
        self.assertEqual(cancelled.state, FlowState.CANCELLED)
        self.assertEqual(
            self.store.list_bookkeeping_authorization_observations(), ()
        )
        with closing(sqlite3.connect(self.database)) as connection:
            cancellation_count = connection.execute(
                "SELECT COUNT(*) FROM supervisor_cancellation_requests"
            ).fetchone()[0]
        self.assertEqual(cancellation_count, 1)
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertEqual(audit.observation_count, 1)
        self.assertEqual(audit.expected_observation_count, 3)
        self.assertEqual(
            sum(
                finding.code == "bookkeeping_observation_missing"
                for finding in audit.findings
            ),
            2,
        )

    def test_bookkeeping_authorization_inspector_detects_tampering(self) -> None:
        self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                DROP TRIGGER
                supervisor_bookkeeping_authorization_observations_no_update
                """
            )
            connection.execute(
                """
                UPDATE supervisor_bookkeeping_authorization_observations
                SET request_digest = ?
                """,
                ("sha256:" + "0" * 64,),
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        codes = {finding.code for finding in audit.findings}
        self.assertIn("authorization_schema_mismatch", codes)
        self.assertIn("request_digest_mismatch", codes)
        self.assertFalse(audit.clean)

    def test_authorization_audit_verifies_source_append_only_guards(self) -> None:
        self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TRIGGER supervisor_control_events_no_update")
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertFalse(audit.schema_present)
        self.assertIn(
            "authorization_schema_mismatch",
            {finding.code for finding in audit.findings},
        )

    def test_authorization_audit_verifies_migration_ledger_guards(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TRIGGER state_schema_migrations_no_update")
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertFalse(audit.schema_present)
        self.assertIn(
            "migration_schema_mismatch",
            {finding.code for finding in audit.findings},
        )

    def test_authorization_audit_rejects_future_migration_versions(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                INSERT INTO state_schema_migrations (
                    version, name, script_sha256, applied_at
                ) VALUES (13, 'future_unknown', ?, 100.0)
                """,
                ("0" * 64,),
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "migration_version_set_mismatch",
            {finding.code for finding in audit.findings},
        )

    def test_bookkeeping_audit_detects_duplicate_and_misordered_controls(self) -> None:
        running = self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        self.store.update_control(
            expected_revision=running.revision,
            mode=SupervisorMode.PAUSED,
            actor_id="operator/session-000000000001",
            reason_code="operator_paused",
            occurred_at=101.0,
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            first_payload = connection.execute(
                """
                SELECT payload_json
                FROM supervisor_bookkeeping_authorization_observations
                ORDER BY sequence LIMIT 1
                """
            ).fetchone()[0]
            connection.execute(
                """
                DROP TRIGGER
                supervisor_bookkeeping_authorization_observations_no_update
                """
            )
            connection.execute(
                """
                UPDATE supervisor_bookkeeping_authorization_observations
                SET payload_json = ? WHERE sequence = 2
                """,
                (first_payload,),
            )
            connection.commit()

        codes = {
            finding.code
            for finding in inspect_supervisor_authorization(self.database).findings
        }
        self.assertIn("bookkeeping_boundary_coverage_or_order_mismatch", codes)
        self.assertIn("bookkeeping_observation_duplicated", codes)
        self.assertIn("bookkeeping_observation_missing", codes)

    def test_higher_class_shadow_denial_is_retained_without_enabling_it(self) -> None:
        original_evaluate = ShadowAuthorizationEvaluator.evaluate

        def elevated_decision(request, policy):
            decision = original_evaluate(
                ShadowAuthorizationEvaluator(), request, policy
            )
            return replace(
                decision,
                effect=AuthorizationEffect.DENY,
                derived_permission_class=PermissionClass.EXTERNAL_CONSEQUENTIAL,
            )

        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=elevated_decision,
        ):
            control = self.store.update_control(
                expected_revision=0,
                mode=SupervisorMode.RUNNING,
                actor_id="operator/session-000000000001",
                reason_code="operator_started",
                occurred_at=100.0,
            )
            audit = inspect_supervisor_authorization(self.database)

        self.assertEqual(control.revision, 1)
        observations = self.store.list_bookkeeping_authorization_observations()
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].effect, "deny")
        self.assertEqual(
            observations[0].derived_permission_class,
            PermissionClass.EXTERNAL_CONSEQUENTIAL,
        )
        self.assertFalse(observations[0].execution_parity)
        self.assertFalse(inspect_supervisor_status(self.database).dispatch_enabled)
        self.assertFalse(audit.clean)
        self.assertIn(
            "legacy_authorization_parity_mismatch",
            {finding.code for finding in audit.findings},
        )

    def test_malformed_pre_v4_history_is_rejected_before_baseline(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v5_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_observations_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_sources_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_update;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_delete;
                DROP TRIGGER supervisor_bookkeeping_authorization_baseline_no_insert;
                DROP TABLE supervisor_bookkeeping_authorization_observations;
                DROP TABLE supervisor_bookkeeping_authorization_sources;
                DROP TABLE supervisor_bookkeeping_authorization_baseline;
                DROP TRIGGER state_schema_migrations_no_delete;
                DELETE FROM state_schema_migrations WHERE version = 4;
                CREATE TRIGGER state_schema_migrations_no_delete
                BEFORE DELETE ON state_schema_migrations BEGIN
                    SELECT RAISE(ABORT, 'schema migrations are append-only');
                END;
                DROP TRIGGER supervisor_flows_no_delete;
                DELETE FROM supervisor_flows WHERE flow_id = 'flow-one';
                CREATE TRIGGER supervisor_flows_no_delete
                BEFORE DELETE ON supervisor_flows BEGIN
                    SELECT RAISE(ABORT, 'supervisor flows are append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v4 supervisor bookkeeping history has invalid references",
        ):
            self._open_store()

    def test_pre_v4_cancellation_without_revision_history_is_rejected(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v4_schema(connection)
            connection.executescript(
                """
                INSERT INTO supervisor_cancellation_requests (
                    request_id, flow_id, reason_code, requested_by, requested_at
                ) VALUES (
                    'pre-v4-cancellation', 'flow-one', 'operator_cancelled',
                    'operator', 101.0
                );
                DROP TRIGGER supervisor_flow_revisions_no_delete;
                DELETE FROM supervisor_flow_revisions WHERE flow_id = 'flow-one';
                CREATE TRIGGER supervisor_flow_revisions_no_delete
                BEFORE DELETE ON supervisor_flow_revisions BEGIN
                    SELECT RAISE(ABORT, 'supervisor flow revisions are append-only');
                END;
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v4 supervisor bookkeeping history is invalid",
        ):
            self._open_store()

    def test_failed_pre_v4_schema_check_commits_no_v4_objects(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v4_schema(connection)
            connection.execute("DROP TRIGGER supervisor_control_events_no_update")
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v4 supervisor schema is invalid",
        ):
            self._open_store()

        with closing(sqlite3.connect(self.database)) as connection:
            version = connection.execute(
                "SELECT 1 FROM state_schema_migrations WHERE version = 4"
            ).fetchone()
            table = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table'
                AND name = 'supervisor_bookkeeping_authorization_observations'
                """
            ).fetchone()
        self.assertIsNone(version)
        self.assertIsNone(table)

    def test_pre_v4_cancellation_flag_cannot_ride_a_claim_transition(self) -> None:
        self._start_and_claim()
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            self._remove_v4_schema(connection)
            connection.executescript(
                """
                DROP TRIGGER supervisor_flow_revisions_no_update;
                UPDATE supervisor_flow_revisions
                SET cancellation_requested = 1
                WHERE flow_id = 'flow-one' AND revision = 2;
                CREATE TRIGGER supervisor_flow_revisions_no_update
                BEFORE UPDATE ON supervisor_flow_revisions BEGIN
                    SELECT RAISE(ABORT, 'supervisor flow revisions are append-only');
                END;
                INSERT INTO supervisor_cancellation_requests (
                    request_id, flow_id, reason_code, requested_by, requested_at
                ) VALUES (
                    'pre-v4-cancellation', 'flow-one', 'operator_cancelled',
                    'operator', 101.0
                );
                """
            )

        with self.assertRaisesRegex(
            ConfigurationError,
            "pre-v4 supervisor bookkeeping history is invalid",
        ):
            self._open_store()

    def test_malformed_sensitive_flow_reference_is_not_emitted_by_audit(self) -> None:
        sensitive_flow_id = "sk-secretmaterial123456789"
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                INSERT INTO supervisor_cancellation_requests (
                    request_id, flow_id, reason_code, requested_by, requested_at
                ) VALUES (?, ?, 'operator_cancelled', 'operator', 100.0)
                """,
                ("malformed-cancellation", sensitive_flow_id),
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        serialized = json.dumps(audit.to_mapping(), sort_keys=True)
        self.assertFalse(audit.clean)
        self.assertNotIn(sensitive_flow_id, serialized)
        self.assertIn("bookkeeping_target_missing", serialized)

    def test_sensitive_existing_flow_reference_is_hashed_in_missing_findings(self) -> None:
        self.store.admit_flow(self._flow())
        sensitive_flow_id = "sk-secretmaterial987654321"
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                INSERT INTO supervisor_flows (
                    flow_id, admission_key, request_digest, task_id, task_version,
                    task_definition_digest, context_digest, runner_id, profile_id,
                    permission_class, resource_keys_json, available_at, deadline_at,
                    attempt_timeout_seconds, mandatory_priority, blocker_priority,
                    value_priority, evidence_priority, capacity_fit_priority,
                    max_attempts, created_at
                )
                SELECT ?, 'malformed-sensitive-admission', request_digest,
                    task_id, task_version, task_definition_digest, context_digest,
                    runner_id, profile_id, permission_class, resource_keys_json,
                    available_at, deadline_at, attempt_timeout_seconds,
                    mandatory_priority, blocker_priority, value_priority,
                    evidence_priority, capacity_fit_priority, max_attempts, created_at
                FROM supervisor_flows WHERE flow_id = 'flow-one'
                """,
                (sensitive_flow_id,),
            )
            connection.execute(
                """
                INSERT INTO supervisor_flow_revisions (
                    event_id, flow_id, revision, state, cancellation_requested,
                    active_attempt_id, reason_code, occurred_at
                ) VALUES ('malformed-flow-event', ?, 1, 'queued', 0, NULL,
                    'admitted', 100.0)
                """,
                (sensitive_flow_id,),
            )
            connection.execute(
                """
                INSERT INTO supervisor_cancellation_requests (
                    request_id, flow_id, reason_code, requested_by, requested_at
                ) VALUES ('malformed-cancellation', ?, 'operator_cancelled',
                    'operator', 101.0)
                """,
                (sensitive_flow_id,),
            )
            connection.execute(
                """
                INSERT INTO supervisor_bookkeeping_authorization_sources (
                    cancellation_request_id, flow_id, source_flow_revision
                ) VALUES ('malformed-cancellation', ?, 1)
                """,
                (sensitive_flow_id,),
            )
            connection.commit()

        audit = inspect_supervisor_authorization(self.database)
        serialized = json.dumps(audit.to_mapping(), sort_keys=True)
        self.assertFalse(audit.clean)
        self.assertNotIn(sensitive_flow_id, serialized)
        self.assertIn("bookkeeping_observation_missing", serialized)

    def test_claim_cancellation_completion_and_outbox_are_sticky(self) -> None:
        claim = self._start_and_claim()
        observations = self.store.list_authorization_observations(claim.flow.flow_id)
        self.assertEqual(
            [observation.boundary for observation in observations],
            ["flow_admission", "attempt_claim"],
        )
        self.assertTrue(all(item.effect == "permit" for item in observations))
        self.assertTrue(all(item.execution_parity for item in observations))
        dispatch = self.store.mark_attempt_dispatching(claim, now=101.0)
        self.assertEqual(dispatch.state.value, "dispatching")

        cancellation = self.store.request_cancellation(
            claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=102.0,
        )
        self.assertEqual(cancellation.state, FlowState.RUNNING)
        self.assertTrue(cancellation.cancellation_requested)
        with self.assertRaises(ClaimLostError):
            self.store.renew_claim(claim, ttl_seconds=20.0, now=103.0)

        completed, outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=cancellation.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="worker_finished_after_cancel",
            now=103.0,
        )
        self.assertEqual(completed.state, FlowState.CANCELLED)
        self.assertTrue(completed.cancellation_requested)
        self.assertEqual(outbox.envelope["state"], "cancelled")
        self.assertEqual(self.store.list_pending_completions(), (outbox,))
        self.assertEqual(inspect_pending_completions(self.database), (outbox,))

        replayed_revision, replayed_outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=cancellation.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="worker_finished_after_cancel",
            now=104.0,
        )
        self.assertEqual(replayed_revision, completed)
        self.assertEqual(replayed_outbox, outbox)

        receipt = self.store.acknowledge_completion(
            outbox.outbox_id,
            consumer_id="controller/local-consumer",
            result_digest="c" * 64,
            delivery_id="delivery-one",
            now=105.0,
        )
        replayed_receipt = self.store.acknowledge_completion(
            outbox.outbox_id,
            consumer_id="controller/local-consumer",
            result_digest="c" * 64,
            delivery_id="delivery-replay",
            now=106.0,
        )
        self.assertEqual(replayed_receipt, receipt)
        self.assertEqual(receipt.idempotency_key, outbox.idempotency_key)
        self.assertEqual(self.store.list_pending_completions(), ())

    def test_forged_claim_fields_cannot_bypass_durable_fencing(self) -> None:
        claim = self._start_and_claim()
        forged = replace(
            claim,
            attempt=replace(
                claim.attempt,
                lease_keys=(),
                lease_owner="attempt/forged-000000000001",
            ),
        )

        with self.assertRaises(ClaimLostError):
            self.store.mark_attempt_dispatching(forged, now=101.0)
        with self.assertRaises(ClaimLostError):
            self.store.renew_claim(forged, ttl_seconds=20.0, now=101.0)
        with self.assertRaises(ClaimLostError):
            self.store.complete_attempt(
                forged,
                expected_flow_revision=claim.flow_revision.revision,
                outcome=FlowState.SUCCEEDED,
                reason_code="checks_passed",
                now=101.0,
            )

    def test_completion_replay_returns_its_historical_source_revision(self) -> None:
        claim = self._start_and_claim()
        waiting, waiting_outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=claim.flow_revision.revision,
            outcome=FlowState.WAITING,
            reason_code="prerequisite_waiting",
            now=101.0,
        )
        cancelled = self.store.request_cancellation(
            claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=102.0,
        )
        self.assertEqual(cancelled.state, FlowState.CANCELLED)

        replayed, replayed_outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=claim.flow_revision.revision,
            outcome=FlowState.WAITING,
            reason_code="prerequisite_waiting",
            now=103.0,
        )

        self.assertEqual(replayed, waiting)
        self.assertEqual(replayed_outbox, waiting_outbox)
        self.assertNotEqual(replayed.revision, cancelled.revision)

    def test_pre_dispatch_cancellation_finishes_without_a_worker(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)

        cancelled = self.store.request_cancellation(
            spec.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )
        replayed = self.store.request_cancellation(
            spec.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=102.0,
        )

        self.assertEqual(cancelled.state, FlowState.CANCELLED)
        self.assertEqual(replayed, cancelled)
        pending = self.store.list_pending_completions()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].envelope["state"], "cancelled")
        observations = self.store.list_bookkeeping_authorization_observations()
        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation.boundary, "flow_cancellation")
        self.assertEqual(observation.flow_id, spec.flow_id)
        self.assertIsNotNone(observation.cancellation_request_id)
        self.assertEqual(observation.effect, "deny")
        self.assertEqual(
            observation.derived_permission_class,
            PermissionClass.EXTERNAL_CONSEQUENTIAL,
        )
        self.assertFalse(observation.execution_parity)
        self.assertNotIn(
            "operator/session-000000000001",
            json.dumps(observation.payload, sort_keys=True),
        )
        request = observation.payload["request"]
        self.assertEqual(request["environment"]["flow_state"], "queued")
        self.assertEqual(
            request["action"]["intended_effect"],
            "record_and_apply_local_flow_cancellation",
        )
        self.assertNotEqual(request["resource"]["version"], spec.request_digest)
        with closing(sqlite3.connect(self.database)) as connection:
            source = connection.execute(
                """
                SELECT cancellation_request_id, flow_id, source_flow_revision
                FROM supervisor_bookkeeping_authorization_sources
                """
            ).fetchone()
        self.assertEqual(
            source,
            (observation.cancellation_request_id, spec.flow_id, 1),
        )
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertIn(
            "legacy_authorization_parity_mismatch",
            {finding.code for finding in audit.findings},
        )
        self.assertEqual(audit.observation_count, 2)
        self.assertEqual(audit.expected_observation_count, 2)

    def test_cancellation_replay_after_later_revision_returns_current_head(self) -> None:
        claim = self._start_and_claim()
        cancellation = self.store.request_cancellation(
            claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )
        completed, _ = self.store.complete_attempt(
            claim,
            expected_flow_revision=cancellation.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="worker_finished_after_cancel",
            now=102.0,
        )

        replayed = self.store.request_cancellation(
            claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )

        self.assertEqual(completed.state, FlowState.CANCELLED)
        self.assertEqual(replayed, completed)
        observations = [
            observation
            for observation in self.store.list_bookkeeping_authorization_observations()
            if observation.boundary == "flow_cancellation"
        ]
        self.assertEqual(len(observations), 1)

    def test_running_and_final_cancellations_bind_exact_source_revisions(self) -> None:
        running_claim = self._start_and_claim(self._flow("flow-running"))
        running_cancelled = self.store.request_cancellation(
            running_claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )
        self.store.complete_attempt(
            running_claim,
            expected_flow_revision=running_cancelled.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="worker_finished_after_cancel",
            now=102.0,
        )

        final_spec = self._flow(
            "flow-final", resource_keys=("repo:final-project",)
        )
        self.store.admit_flow(final_spec)
        owner = "supervisor/instance-000000000001"
        final_claim = self.store.try_claim_next(
            instance_owner=owner,
            expected_control_revision=1,
            ttl_seconds=20.0,
            now=103.0,
        )
        self.assertIsNotNone(final_claim)
        assert final_claim is not None
        final_revision, _ = self.store.complete_attempt(
            final_claim,
            expected_flow_revision=final_claim.flow_revision.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="checks_passed",
            now=104.0,
        )
        after_cancellation = self.store.request_cancellation(
            final_spec.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=105.0,
        )

        self.assertEqual(after_cancellation, final_revision)
        cancellations = [
            observation
            for observation in self.store.list_bookkeeping_authorization_observations()
            if observation.boundary == "flow_cancellation"
        ]
        self.assertEqual(len(cancellations), 2)
        self.assertEqual(
            [
                item.payload["request"]["environment"]["flow_state"]
                for item in cancellations
            ],
            ["running", "succeeded"],
        )
        with closing(sqlite3.connect(self.database)) as connection:
            sources = connection.execute(
                """
                SELECT flow_id, source_flow_revision
                FROM supervisor_bookkeeping_authorization_sources
                ORDER BY flow_id
                """
            ).fetchall()
        self.assertEqual(sources, [("flow-final", 3), ("flow-running", 2)])
        audit = inspect_supervisor_authorization(self.database)
        self.assertFalse(audit.clean)
        self.assertEqual(
            sum(
                finding.code == "legacy_authorization_parity_mismatch"
                for finding in audit.findings
            ),
            2,
        )

    def test_expired_pre_dispatch_claim_requires_digest_bound_reconciliation(self) -> None:
        claim = self._start_and_claim()

        plan = self.store.reconciliation_plan(now=121.0)
        inspected = inspect_reconciliation(self.database, now=121.0)
        self.assertEqual(inspected, plan)
        self.assertEqual(plan.actionable_count, 1)
        self.assertEqual(plan.findings[0].kind, "expired_pre_dispatch_claim")
        self.assertEqual(plan.findings[0].action, "mark_lost_pre_dispatch")

        applied = self.store.apply_reconciliation(
            plan_digest=plan.plan_digest,
            now=121.0,
        )
        self.assertEqual(applied, plan.findings)
        current = self.store.current_flow_revision(claim.flow.flow_id)
        self.assertEqual(current.state, FlowState.LOST)
        self.assertIsNone(current.active_attempt_id)
        self.assertEqual(len(self.store.list_pending_completions()), 1)

        with self.assertRaises(StaleReconciliationPlanError):
            self.store.apply_reconciliation(
                plan_digest=plan.plan_digest,
                now=121.0,
            )

    def test_queued_deadline_is_reconciled_to_timed_out(self) -> None:
        spec = self._flow(deadline_at=110.0)
        self.store.admit_flow(spec)

        plan = self.store.reconciliation_plan(now=111.0)
        self.assertEqual(plan.actionable_count, 1)
        self.assertEqual(plan.findings[0].action, "mark_queued_timed_out")
        self.store.apply_reconciliation(
            plan_digest=plan.plan_digest,
            now=111.0,
        )

        current = self.store.current_flow_revision(spec.flow_id)
        self.assertEqual(current.state, FlowState.TIMED_OUT)
        self.assertEqual(
            self.store.list_pending_completions()[0].idempotency_key,
            f"flow:{spec.flow_id}:revision:{current.revision}",
        )

    def test_repaired_completion_outbox_preserves_terminal_attempt_link(
        self,
    ) -> None:
        claim = self._start_and_claim()
        with patch(
            "ordomata.supervisor.ShadowAuthorizationEvaluator.evaluate",
            side_effect=RuntimeError("private shadow failure"),
        ):
            completed, outbox = self.store.complete_attempt(
                claim,
                expected_flow_revision=claim.flow_revision.revision,
                outcome=FlowState.SUCCEEDED,
                reason_code="checks_passed",
                now=101.0,
            )
        self.assertEqual(completed.state, FlowState.SUCCEEDED)
        self.assertEqual(outbox.attempt_id, claim.attempt.attempt_id)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                DROP TRIGGER supervisor_completion_outbox_no_delete;
                """
            )
            connection.execute(
                """
                DELETE FROM supervisor_completion_outbox
                WHERE outbox_id = ?
                """,
                (outbox.outbox_id,),
            )
            connection.executescript(
                """
                CREATE TRIGGER supervisor_completion_outbox_no_delete
                BEFORE DELETE ON supervisor_completion_outbox BEGIN
                    SELECT RAISE(ABORT, 'supervisor completion outbox is append-only');
                END;
                """
            )
            connection.commit()
        self.store = self._open_store()

        plan = self.store.reconciliation_plan(now=102.0)
        self.assertEqual(plan.actionable_count, 1)
        self.assertEqual(plan.findings[0].action, "repair_completion_outbox")
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=102.0)

        repaired = self.store.list_pending_completions()
        self.assertEqual(len(repaired), 1)
        self.assertEqual(repaired[0].attempt_id, claim.attempt.attempt_id)
        self.assertEqual(repaired[0].envelope["attempt_id"], claim.attempt.attempt_id)

    def test_reconciliation_releases_orphan_attempt_leases_without_changing_completion(
        self,
    ) -> None:
        claim = self._start_and_claim()
        completed, outbox = self.store.complete_attempt(
            claim,
            expected_flow_revision=claim.flow_revision.revision,
            outcome=FlowState.SUCCEEDED,
            reason_code="checks_passed",
            now=101.0,
        )
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executemany(
                """
                INSERT INTO leases (
                    lease_key, owner_id, acquired_at, renewed_at, expires_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (key, claim.attempt.lease_owner, 100.0, 101.0, 122.0)
                    for key in claim.attempt.lease_keys
                ],
            )
            connection.commit()

        plan = self.store.reconciliation_plan(now=102.0)
        self.assertEqual(
            [finding.action for finding in plan.findings if finding.action],
            ["release_orphan_attempt_leases"],
        )
        self.store.apply_reconciliation(plan_digest=plan.plan_digest, now=102.0)

        with closing(sqlite3.connect(self.database)) as connection:
            leftovers = connection.execute(
                """
                SELECT lease_key FROM leases
                WHERE owner_id = ? ORDER BY lease_key
                """,
                (claim.attempt.lease_owner,),
            ).fetchall()
        self.assertEqual(leftovers, [])
        self.assertEqual(
            self.store.current_flow_revision(claim.flow.flow_id),
            completed,
        )
        self.assertEqual(self.store.list_pending_completions(), (outbox,))
        audit = inspect_supervisor_authorization(self.database)
        self.assertTrue(audit.clean, audit.to_mapping())

    def test_read_only_inspection_of_absent_database_creates_nothing(self) -> None:
        absent = Path(self.temporary.name) / "absent.sqlite3"

        status = inspect_supervisor_status(absent, now=100.0)
        plan = inspect_reconciliation(absent, now=100.0)
        authorization = inspect_supervisor_authorization(absent)
        pending = inspect_pending_completions(absent)

        self.assertFalse(status.database_present)
        self.assertFalse(status.schema_present)
        self.assertEqual(status.mode, SupervisorMode.STOPPED)
        self.assertFalse(status.dispatch_enabled)
        self.assertFalse(plan.database_present)
        self.assertEqual(plan.findings, ())
        self.assertTrue(authorization.clean)
        self.assertFalse(authorization.database_present)
        self.assertEqual(pending, ())
        self.assertFalse(absent.exists())

    def test_read_only_inspection_creates_no_wal_or_shared_memory_sidecars(self) -> None:
        self.store.admit_flow(self._flow())
        self.store.close()
        before = {path.name: path.stat().st_mtime_ns for path in self.database.parent.iterdir()}

        self.assertTrue(inspect_supervisor_status(self.database, now=100.0).schema_present)
        self.assertEqual(inspect_reconciliation(self.database, now=100.0).findings, ())
        self.assertTrue(inspect_supervisor_authorization(self.database).clean)
        self.assertEqual(inspect_pending_completions(self.database), ())

        after = {path.name: path.stat().st_mtime_ns for path in self.database.parent.iterdir()}
        self.assertEqual(after, before)
        self._reopen_store()

    def test_live_read_only_inspection_sees_uncheckpointed_wal_frames(self) -> None:
        with closing(sqlite3.connect(self.database)) as pinned_reader:
            pinned_reader.execute("BEGIN")
            self.assertEqual(
                pinned_reader.execute(
                    "SELECT COUNT(*) FROM supervisor_flows"
                ).fetchone()[0],
                0,
            )
            self.store.admit_flow(self._flow())

            status = inspect_supervisor_status(self.database, now=100.0)
            self.assertEqual(status.flow_counts, {"queued": 1})
            pinned_reader.rollback()

    def test_immutable_inspection_rejects_concurrent_wal_creation(self) -> None:
        self.store.admit_flow(self._flow())
        self.store.close()
        original_audit = supervisor_module._audit_connection

        def mutate_after_snapshot(connection, now):
            with closing(sqlite3.connect(self.database)) as writer:
                writer.execute(
                    "CREATE TABLE private_concurrent_marker(value TEXT)"
                )
                writer.commit()
            return original_audit(connection, now)

        with patch(
            "ordomata.supervisor._audit_connection",
            side_effect=mutate_after_snapshot,
        ):
            with self.assertRaisesRegex(
                ConfigurationError,
                "changed during inspection",
            ):
                inspect_reconciliation(self.database, now=100.0)

    def test_two_connections_cannot_claim_the_same_flow(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        control = self.store.update_control(
            expected_revision=0,
            mode=SupervisorMode.RUNNING,
            actor_id="operator/session-000000000001",
            reason_code="operator_started",
            occurred_at=100.0,
        )
        owner = "supervisor/instance-000000000001"
        self.assertTrue(
            self.store.acquire_foreground(owner, ttl_seconds=60.0, now=100.0)
        )
        second = self._open_store()
        try:
            first_claim = self.store.try_claim_next(
                instance_owner=owner,
                expected_control_revision=control.revision,
                ttl_seconds=20.0,
                now=100.0,
            )
            second_claim = second.try_claim_next(
                instance_owner=owner,
                expected_control_revision=control.revision,
                ttl_seconds=20.0,
                now=100.0,
            )
        finally:
            second.close()

        self.assertIsNotNone(first_claim)
        self.assertIsNone(second_claim)
        self.assertEqual(
            self.store.current_flow_revision(spec.flow_id).state,
            FlowState.RUNNING,
        )

    def test_cancellation_winning_before_dispatch_blocks_dispatch_marker(self) -> None:
        claim = self._start_and_claim()
        self.store.request_cancellation(
            claim.flow.flow_id,
            requested_by="operator/session-000000000001",
            reason_code="operator_cancelled",
            now=101.0,
        )

        with self.assertRaises(ClaimLostError):
            self.store.mark_attempt_dispatching(claim, now=102.0)

    def test_repeated_idle_ticks_do_not_append_durable_state(self) -> None:
        owner = "supervisor/instance-000000000001"
        supervisor = ForegroundSupervisor(
            self.store,
            instance_owner=owner,
            clock=lambda: self.now,
            lease_ttl_seconds=30.0,
        )
        first = supervisor.tick()
        self.assertFalse(first["dispatch_enabled"])
        self.assertFalse(first["claimed"])
        self.assertEqual(
            first["dispatch_blockers"],
            [
                "runtime_abac_enforcement_not_implemented",
                "repository_worker_containment_not_proven",
            ],
        )

        tables = (
            "state_schema_migrations",
            "supervisor_control_events",
            "supervisor_flows",
            "supervisor_flow_revisions",
            "supervisor_attempts",
            "supervisor_attempt_events",
            "supervisor_completion_outbox",
            "supervisor_completion_delivery_events",
            "supervisor_completion_receipts",
            "leases",
        )

        def row_counts() -> tuple[int, ...]:
            with closing(sqlite3.connect(self.database)) as connection:
                return tuple(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in tables
                )

        before = row_counts()
        for _ in range(100):
            self.assertEqual(supervisor.tick(), first)
        self.assertEqual(row_counts(), before)
        supervisor.close()


if __name__ == "__main__":
    unittest.main()
