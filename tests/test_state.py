from __future__ import annotations

from contextlib import closing, contextmanager
import sqlite3
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from ordomata.errors import BillingRouteBlocked, ConfigurationError, ValidationError
from ordomata.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    CapacityState,
    CircuitBreakerState,
    PermissionClass,
    RunStatus,
)
from ordomata.state import (
    ArtifactRecord,
    InvalidStateTransition,
    RunRecord,
    SQLiteStateStore,
    SQLiteBillingCircuitGuard,
    SecretPersistenceError,
    StateStoreError,
)


class SQLiteStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "state.sqlite3"
        self.store = SQLiteStateStore(self.database, clock=lambda: 100.0)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _run(self, run_id: str = "run-1") -> RunRecord:
        record = RunRecord(
            run_id=run_id,
            task_id="lint",
            task_version="v1",
            runner_id="mock",
            workspace="/worktree",
            run_directory="/runs/run-1",
            context_digest="a" * 64,
            permission_class=PermissionClass.LOCAL_DRAFT,
            timeout_seconds=60,
            attempt=1,
            created_at=100.0,
        )
        return self.store.create_run(record)

    def test_run_lifecycle_is_an_append_only_event_stream(self) -> None:
        self._run()
        self.assertEqual(self.store.current_status("run-1"), RunStatus.CREATED)
        self.store.append_event(
            "run-1", "status", {"check_count": 3}, status=RunStatus.RUNNING, occurred_at=101
        )
        self.store.append_event(
            "run-1", "status", {"checks_passed": 3}, status=RunStatus.SUCCEEDED, occurred_at=102
        )
        self.assertEqual(self.store.current_status("run-1"), RunStatus.SUCCEEDED)
        events = self.store.list_events("run-1")
        self.assertEqual([event.status for event in events], [RunStatus.CREATED, RunStatus.RUNNING, RunStatus.SUCCEEDED])
        self.assertEqual(events[1].payload, {"check_count": 3})
        with self.assertRaises(InvalidStateTransition):
            self.store.append_event("run-1", "status", status=RunStatus.RUNNING)

    def test_database_triggers_reject_update_and_delete(self) -> None:
        self._run()
        self.store.append_artifact(
            ArtifactRecord(
                artifact_id="artifact-1",
                run_id="run-1",
                kind="diff",
                path="artifacts/diff.patch",
                sha256="b" * 64,
                media_type="text/x-diff",
                size_bytes=12,
                created_at=101,
            )
        )
        connection = sqlite3.connect(self.database)
        try:
            for statement in (
                "UPDATE runs SET task_id = 'other' WHERE run_id = 'run-1'",
                "DELETE FROM run_events WHERE run_id = 'run-1'",
                "UPDATE run_artifacts SET kind = 'other' WHERE artifact_id = 'artifact-1'",
            ):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    connection.execute(statement)
        finally:
            connection.rollback()
            connection.close()

    def test_new_database_records_frozen_baseline_migration(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                """
                SELECT version, name, script_sha256
                FROM state_schema_migrations
                """
            ).fetchone()
            triggers = {
                item[0]
                for item in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'trigger'
                      AND tbl_name = 'state_schema_migrations'
                    """
                ).fetchall()
            }

        self.assertEqual(
            row,
            (
                1,
                "baseline_state",
                "6076ff9c09a329bc60f1bdc79fd61d3251990219047005691eff8bbd9e9178e6",
            ),
        )
        self.assertEqual(
            triggers,
            {
                "state_schema_migrations_no_update",
                "state_schema_migrations_no_delete",
            },
        )

    def test_fresh_schema_failure_rolls_back_partial_ddl(self) -> None:
        database = Path(self.temporary.name) / "rollback.sqlite3"

        def fail_after_one_statement(
            connection: sqlite3.Connection, _: str
        ) -> None:
            connection.execute("CREATE TABLE partial_schema(value TEXT)")
            raise RuntimeError("injected schema failure")

        with patch(
            "ordomata.state._execute_schema_script",
            side_effect=fail_after_one_statement,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected schema failure"):
                SQLiteStateStore(database)

        with closing(sqlite3.connect(database)) as connection:
            objects = connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE name NOT GLOB 'sqlite_*'
                """
            ).fetchall()
        self.assertEqual(objects, [])

    def test_exact_legacy_baseline_is_adopted_transactionally(self) -> None:
        self._run()
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TABLE state_schema_migrations")
            connection.commit()

        self.store = SQLiteStateStore(self.database, clock=lambda: 101.0)

        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                "SELECT version, name, applied_at FROM state_schema_migrations"
            ).fetchone()
            run_count = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            event_count = connection.execute(
                "SELECT COUNT(*) FROM run_events"
            ).fetchone()[0]
        self.assertEqual(row, (1, "baseline_state", 101.0))
        self.assertEqual((run_count, event_count), (1, 1))

    def test_legacy_adoption_failure_rolls_back_and_preserves_history(self) -> None:
        database = Path(self.temporary.name) / "adoption-rollback.sqlite3"
        store = SQLiteStateStore(database, clock=lambda: 100.0)
        record = RunRecord(
            run_id="legacy-run",
            task_id="lint",
            task_version="v1",
            runner_id="mock",
            workspace="/worktree",
            run_directory="/runs/legacy-run",
            context_digest="a" * 64,
            permission_class=PermissionClass.LOCAL_DRAFT,
            timeout_seconds=60,
            attempt=1,
            created_at=100.0,
        )
        store.create_run(record)
        store.close()
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("DROP TABLE state_schema_migrations")
            connection.commit()

        def fail_after_ledger_table(
            connection: sqlite3.Connection,
            _: str,
        ) -> None:
            connection.execute(
                """
                CREATE TABLE state_schema_migrations(
                    version INTEGER PRIMARY KEY
                )
                """
            )
            raise RuntimeError("injected adoption failure")

        with patch(
            "ordomata.state._execute_schema_script",
            side_effect=fail_after_ledger_table,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "injected adoption failure",
            ):
                SQLiteStateStore(database)

        with closing(sqlite3.connect(database)) as connection:
            ledger_objects = connection.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name GLOB 'state_schema_migrations*'
                """
            ).fetchall()
            run_count = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            event_count = connection.execute(
                "SELECT COUNT(*) FROM run_events"
            ).fetchone()[0]
        self.assertEqual(ledger_objects, [])
        self.assertEqual((run_count, event_count), (1, 1))

    def test_legacy_baseline_with_unknown_view_is_not_adopted(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TABLE state_schema_migrations")
            connection.execute("CREATE VIEW private_view AS SELECT 1 AS value")
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError, "unrecognized schema objects"
        ):
            SQLiteStateStore(self.database)

        with closing(sqlite3.connect(self.database)) as connection:
            ledger = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'state_schema_migrations'"
            ).fetchone()
            view = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'private_view'"
            ).fetchone()
        self.assertIsNone(ledger)
        self.assertIsNotNone(view)

    def test_schema_name_collision_cannot_hide_an_unknown_object(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TABLE state_schema_migrations")
            connection.execute(
                "CREATE TABLE runs_no_update(private_marker TEXT)"
            )
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError, "schema objects do not match"
        ):
            SQLiteStateStore(self.database)

        with closing(sqlite3.connect(self.database)) as connection:
            object_types = connection.execute(
                """
                SELECT type FROM sqlite_master
                WHERE name = 'runs_no_update' ORDER BY type
                """
            ).fetchall()
            ledger = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'state_schema_migrations'"
            ).fetchone()
        self.assertEqual(object_types, [("table",), ("trigger",)])
        self.assertIsNone(ledger)

    def test_migration_guard_name_collision_is_rejected(self) -> None:
        database = Path(self.temporary.name) / "migration-collision.sqlite3"
        store = SQLiteStateStore(database)
        store.close()
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """
                CREATE TABLE state_schema_migrations_no_update(
                    private_marker TEXT
                )
                """
            )
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError, "ledger schema is invalid"
        ):
            SQLiteStateStore(database)

    def test_missing_baseline_trigger_fails_without_repair(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TRIGGER runs_no_update")
            connection.commit()

        with self.assertRaisesRegex(ConfigurationError, "schema objects do not match"):
            SQLiteStateStore(self.database)

        with closing(sqlite3.connect(self.database)) as connection:
            trigger = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'runs_no_update'"
            ).fetchone()
        self.assertIsNone(trigger)

    def test_missing_migration_trigger_fails_without_repair(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "DROP TRIGGER state_schema_migrations_no_update"
            )
            connection.commit()

        with self.assertRaisesRegex(ConfigurationError, "ledger schema is invalid"):
            SQLiteStateStore(self.database)

        with closing(sqlite3.connect(self.database)) as connection:
            trigger = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE name = 'state_schema_migrations_no_update'
                """
            ).fetchone()
        self.assertIsNone(trigger)

    def test_gapped_and_future_migration_ledgers_fail_closed(self) -> None:
        cases = (
            (
                3,
                "supervisor_authorization_shadow",
                "b014646a473c24b8f705017a844dfa56c0ae8671c8f99560f952d3822df89640",
            ),
            (5, "future_schema", "f" * 64),
        )
        self.store.close()
        for index, (version, name, digest) in enumerate(cases):
            database = Path(self.temporary.name) / f"invalid-{index}.sqlite3"
            store = SQLiteStateStore(database, clock=lambda: 100.0)
            store.close()
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    INSERT INTO state_schema_migrations (
                        version, name, script_sha256, applied_at
                    ) VALUES (?, ?, ?, 101.0)
                    """,
                    (version, name, digest),
                )
                connection.commit()

            with self.subTest(version=version):
                with self.assertRaisesRegex(
                    ConfigurationError, "migration ledger is invalid"
                ):
                    SQLiteStateStore(database)

    def test_migration_version_and_required_tables_must_agree(self) -> None:
        from ordomata.supervisor import SQLiteSupervisorStore

        missing_current = Path(self.temporary.name) / "missing-current.sqlite3"
        supervisor = SQLiteSupervisorStore(missing_current)
        supervisor.close()
        with closing(sqlite3.connect(missing_current)) as connection:
            connection.execute(
                "DROP TABLE supervisor_bookkeeping_authorization_observations"
            )
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError,
            "does not match installed schema",
        ):
            SQLiteStateStore(missing_current)

        premature = Path(self.temporary.name) / "premature.sqlite3"
        store = SQLiteStateStore(premature)
        store.close()
        with closing(sqlite3.connect(premature)) as connection:
            connection.execute(
                "CREATE TABLE supervisor_control_events(private_marker TEXT)"
            )
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError,
            "does not match installed schema",
        ):
            SQLiteStateStore(premature)

    def test_wrong_frozen_migration_identity_is_not_repaired(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                DROP TRIGGER state_schema_migrations_no_update;
                UPDATE state_schema_migrations
                SET script_sha256 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
                WHERE version = 1;
                CREATE TRIGGER state_schema_migrations_no_update
                BEFORE UPDATE ON state_schema_migrations BEGIN
                    SELECT RAISE(ABORT, 'schema migrations are append-only');
                END;
                """
            )

        with self.assertRaisesRegex(ConfigurationError, "migration ledger is invalid"):
            SQLiteStateStore(self.database)

        with closing(sqlite3.connect(self.database)) as connection:
            digest = connection.execute(
                "SELECT script_sha256 FROM state_schema_migrations WHERE version = 1"
            ).fetchone()[0]
        self.assertEqual(digest, "f" * 64)

    def test_invalid_migration_timestamps_fail_without_repair(self) -> None:
        self.store.close()
        for index, applied_at in enumerate(("private-marker", float("inf"))):
            database = Path(self.temporary.name) / f"timestamp-{index}.sqlite3"
            store = SQLiteStateStore(database)
            store.close()
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "DROP TRIGGER state_schema_migrations_no_update"
                )
                connection.execute(
                    "UPDATE state_schema_migrations SET applied_at = ?",
                    (applied_at,),
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

            with self.subTest(applied_at=applied_at):
                with self.assertRaisesRegex(
                    ConfigurationError, "migration ledger is invalid"
                ):
                    SQLiteStateStore(database)

            with closing(sqlite3.connect(database)) as connection:
                persisted = connection.execute(
                    "SELECT applied_at FROM state_schema_migrations"
                ).fetchone()[0]
            self.assertEqual(persisted, applied_at)

    def test_view_only_database_is_not_mistaken_for_empty_state(self) -> None:
        database = Path(self.temporary.name) / "view-only.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE VIEW private_view AS SELECT 1 AS value")
            connection.commit()

        with self.assertRaises(ConfigurationError):
            SQLiteStateStore(database)

        with closing(sqlite3.connect(database)) as connection:
            objects = connection.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name NOT GLOB 'sqlite_*'
                ORDER BY type, name
                """
            ).fetchall()
        self.assertEqual(objects, [("view", "private_view")])

    def test_public_status_event_type_remains_reopen_compatible(self) -> None:
        self._run()
        self.store.append_event(
            "run-1",
            "runner_started",
            status=RunStatus.RUNNING,
            occurred_at=101.0,
        )
        self.store.close()

        self.store = SQLiteStateStore(self.database)

        self.assertEqual(self.store.current_status("run-1"), RunStatus.RUNNING)

    def test_foreign_key_and_terminal_history_corruption_fail_closed(self) -> None:
        self.store.close()
        foreign_key_database = Path(self.temporary.name) / "orphan.sqlite3"
        store = SQLiteStateStore(foreign_key_database)
        store.close()
        with closing(sqlite3.connect(foreign_key_database)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                """
                INSERT INTO run_events (
                    event_id, run_id, event_type, status, payload_json, occurred_at
                ) VALUES ('orphan-event', 'missing-run', 'status', 'created', '{}', 1.0)
                """
            )
            connection.commit()
        with self.assertRaisesRegex(ConfigurationError, "history is invalid"):
            SQLiteStateStore(foreign_key_database)

        terminal_database = Path(self.temporary.name) / "terminal.sqlite3"
        store = SQLiteStateStore(terminal_database, clock=lambda: 1.0)
        record = RunRecord(
            run_id="terminal-run",
            task_id="lint",
            task_version="v1",
            runner_id="mock",
            workspace="/worktree",
            run_directory="/runs/terminal-run",
            context_digest="a" * 64,
            permission_class=PermissionClass.LOCAL_DRAFT,
            timeout_seconds=60,
            attempt=1,
            created_at=1.0,
        )
        store.create_run(record)
        store.append_event(
            record.run_id, "status", status=RunStatus.RUNNING, occurred_at=2.0
        )
        store.append_event(
            record.run_id, "status", status=RunStatus.SUCCEEDED, occurred_at=3.0
        )
        store.close()
        with closing(sqlite3.connect(terminal_database)) as connection:
            connection.execute(
                """
                INSERT INTO run_events (
                    event_id, run_id, event_type, status, payload_json, occurred_at
                ) VALUES (
                    'invalid-restart', 'terminal-run', 'status', 'running', '{}', 4.0
                )
                """
            )
            connection.commit()
        with self.assertRaisesRegex(ConfigurationError, "history is invalid"):
            SQLiteStateStore(terminal_database)

    def test_unowned_malformed_foreign_key_does_not_block_baseline_open(self) -> None:
        database = Path(self.temporary.name) / "extension.sqlite3"
        store = SQLiteStateStore(database)
        store.close()
        with closing(sqlite3.connect(database)) as connection:
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

        reopened = SQLiteStateStore(database)
        reopened.close()
        with closing(sqlite3.connect(database)) as connection:
            value = connection.execute(
                "SELECT parent_id FROM private_child"
            ).fetchone()[0]
        self.assertEqual(value, "private-value")

    def test_nonprefixed_trigger_on_baseline_table_is_rejected(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """
                CREATE TRIGGER private_run_side_effect
                AFTER INSERT ON runs BEGIN
                    SELECT 1;
                END
                """
            )
            connection.commit()

        with self.assertRaisesRegex(
            ConfigurationError,
            "schema objects do not match",
        ):
            SQLiteStateStore(self.database)

    def test_current_supervisor_schema_is_accepted_by_baseline_store(self) -> None:
        from ordomata.supervisor import SQLiteSupervisorStore

        database = Path(self.temporary.name) / "supervisor.sqlite3"
        supervisor = SQLiteSupervisorStore(database, clock=lambda: 100.0)
        supervisor.close()

        store = SQLiteStateStore(database)
        store.close()

    def test_secret_like_event_payload_is_never_inserted(self) -> None:
        self._run()
        with self.assertRaises(SecretPersistenceError):
            self.store.append_event("run-1", "diagnostic", {"api_key": "not-recorded"})
        with self.assertRaises(SecretPersistenceError):
            self.store.append_event(
                "run-1", "diagnostic", {"message": "Authorization: Bearer abcdefghijklmnop"}
            )
        with self.assertRaises(SecretPersistenceError):
            self.store.append_event(
                "run-1", "diagnostic", {"token": "opaque-credential-value"}
            )
        self.assertEqual(len(self.store.list_events("run-1")), 1)

    def test_leases_are_mutable_and_expire(self) -> None:
        first = self.store.try_acquire_lease("repo:one", "worker-a", 10, now=100)
        self.assertIsNotNone(first)
        self.assertIsNone(self.store.try_acquire_lease("repo:one", "worker-b", 10, now=105))
        renewed = self.store.try_acquire_lease("repo:one", "worker-a", 20, now=106)
        self.assertEqual(renewed.expires_at, 126)
        replacement = self.store.try_acquire_lease("repo:one", "worker-b", 5, now=127)
        self.assertEqual(replacement.owner_id, "worker-b")
        self.assertTrue(self.store.release_lease("repo:one", "worker-b"))

    def test_billing_dispatch_reservation_is_atomic_across_connections(self) -> None:
        fingerprint = "a" * 64
        assessment = BillingRouteAssessment(
            runner_id="codex",
            route=BillingRoute.SUBSCRIPTION_INCLUDED,
            confidence=AssessmentConfidence.HIGH,
            account_identity_fingerprint=fingerprint,
        )
        first_guard = SQLiteBillingCircuitGuard(
            self.store, profile_id="codex-review"
        )
        second_store = SQLiteStateStore(
            self.database, clock=lambda: 100.0, timeout_seconds=0.1
        )
        try:
            second_guard = SQLiteBillingCircuitGuard(
                second_store, profile_id="codex-review"
            )
            first = first_guard.reserve_dispatch(
                assessment, owner_id="run-one", ttl_seconds=60
            )
            self.assertIsNotNone(first)
            self.assertIsNone(
                second_guard.reserve_dispatch(
                    assessment, owner_id="run-two", ttl_seconds=60
                )
            )

            assert first is not None
            first_guard.complete_dispatch(
                first,
                run_id="run-one",
                capacity_state=CapacityState.AVAILABLE,
                capacity_reason_code="post_run_capacity_available",
                circuit_breaker_required=False,
                broad_scope_required=False,
                reason_code="post_run_billing_evidence_unknown",
            )
            second = second_guard.reserve_dispatch(
                assessment, owner_id="run-two", ttl_seconds=60
            )
            self.assertIsNotNone(second)
            assert second is not None
            second_guard.complete_dispatch(
                second,
                run_id="run-two",
                capacity_state=CapacityState.AVAILABLE,
                capacity_reason_code="post_run_capacity_available",
                circuit_breaker_required=False,
                broad_scope_required=False,
                reason_code="post_run_billing_evidence_unknown",
            )
        finally:
            second_store.close()

    def test_billing_breaker_is_opened_before_reservation_release(self) -> None:
        fingerprint = "b" * 64
        assessment = BillingRouteAssessment(
            runner_id="claude",
            route=BillingRoute.SUBSCRIPTION_INCLUDED,
            confidence=AssessmentConfidence.HIGH,
            account_identity_fingerprint=fingerprint,
        )
        guard = SQLiteBillingCircuitGuard(self.store, profile_id="claude-review")
        reservation = guard.reserve_dispatch(
            assessment, owner_id="run-paid", ttl_seconds=60
        )
        self.assertIsNotNone(reservation)
        assert reservation is not None
        guard.complete_dispatch(
            reservation,
            run_id="run-paid",
            capacity_state=CapacityState.AVAILABLE,
            capacity_reason_code="post_run_capacity_available",
            circuit_breaker_required=True,
            broad_scope_required=False,
            reason_code="post_run_paid_route_possible",
        )

        account_global = self.store.current_billing_circuit(
            runner_id="claude",
            account_identity_fingerprint=fingerprint,
            profile_id=None,
        )
        self.assertIsNotNone(account_global)
        assert account_global is not None
        self.assertEqual(account_global.state, CircuitBreakerState.OPEN)
        with self.assertRaisesRegex(BillingRouteBlocked, "durable billing circuit"):
            guard.reserve_dispatch(
                assessment, owner_id="run-after-paid", ttl_seconds=60
            )

    def test_safe_completion_releases_billing_reservation_after_error(self) -> None:
        fingerprint = "d" * 64
        reservation = self.store.try_reserve_billing_dispatch(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            owner_id="billing/error-fixture",
            ttl_seconds=60,
            reservation_id="reservation-error-fixture",
        )
        self.assertIsNotNone(reservation)
        assert reservation is not None
        # A deterministic pre-launch failure has no unknown provider outcome,
        # so completion releases without opening a breaker.
        self.store.complete_billing_dispatch(
            reservation,
            run_id="run-error",
            capacity_state=CapacityState.AVAILABLE,
            capacity_reason_code="prelaunch_capacity_available",
            circuit_breaker_required=False,
            broad_scope_required=False,
            reason_code="post_run_billing_evidence_unknown",
        )
        for lease_key in reservation.lease_keys:
            self.assertIsNone(self.store.get_lease(lease_key))

    def test_completion_rechecks_expiry_after_acquiring_write_lock(self) -> None:
        clock = [100.0]
        self.store.close()
        self.store = SQLiteStateStore(self.database, clock=lambda: clock[0])
        fingerprint = "e" * 64
        reservation = self.store.try_reserve_billing_dispatch(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            owner_id="billing/lock-delay-fixture",
            ttl_seconds=5,
            reservation_id="reservation-lock-delay-fixture",
        )
        self.assertIsNotNone(reservation)
        assert reservation is not None
        real_transaction = self.store._transaction

        @contextmanager
        def delayed_transaction():
            with real_transaction() as connection:
                clock[0] = 106.0
                yield connection

        with (
            patch.object(self.store, "_transaction", delayed_transaction),
            self.assertRaisesRegex(
                StateStoreError,
                "billing dispatch reservation was lost",
            ),
        ):
            self.store.complete_billing_dispatch(
                reservation,
                run_id="run-lock-delay",
                capacity_state=CapacityState.AVAILABLE,
                capacity_reason_code="post_run_capacity_available",
                circuit_breaker_required=False,
                broad_scope_required=False,
                reason_code="post_run_billing_evidence_unknown",
            )

        broad_capacity = self.store.latest_billing_capacity_event(
            runner_id="codex",
            account_identity_fingerprint=None,
            profile_id=None,
        )
        self.assertIsNotNone(broad_capacity)
        assert broad_capacity is not None
        self.assertEqual(broad_capacity.capacity_state, CapacityState.UNKNOWN)
        self.assertEqual(
            broad_capacity.reason_code,
            "billing_dispatch_reservation_lost",
        )
        self.assertEqual(broad_capacity.occurred_at, 106.0)
        broad_circuit = self.store.current_billing_circuit(
            runner_id="codex",
            account_identity_fingerprint=None,
            profile_id=None,
        )
        self.assertIsNotNone(broad_circuit)
        assert broad_circuit is not None
        self.assertEqual(broad_circuit.state, CircuitBreakerState.OPEN)
        self.assertEqual(
            broad_circuit.reason_code,
            "billing_dispatch_reservation_lost",
        )
        for lease_key in reservation.lease_keys:
            self.assertIsNone(self.store.get_lease(lease_key))

    def test_expired_billing_reservation_opens_broad_breaker(self) -> None:
        fingerprint = "f" * 64
        reservation = self.store.try_reserve_billing_dispatch(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            owner_id="billing/crashed-fixture",
            ttl_seconds=5,
            now=100,
            reservation_id="reservation-crashed-fixture",
        )
        self.assertIsNotNone(reservation)
        with self.assertRaisesRegex(BillingRouteBlocked, "expired billing reservation"):
            self.store.try_reserve_billing_dispatch(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                profile_id="codex-review",
                owner_id="billing/next-fixture",
                ttl_seconds=60,
                now=106,
                reservation_id="reservation-next-fixture",
            )
        broad = self.store.current_billing_circuit(
            runner_id="codex",
            account_identity_fingerprint=None,
            profile_id=None,
        )
        self.assertIsNotNone(broad)
        assert broad is not None
        self.assertEqual(broad.state, CircuitBreakerState.OPEN)
        self.assertEqual(
            broad.reason_code, "billing_dispatch_reservation_expired"
        )

    def test_capacity_block_survives_restart_and_requires_newer_observation(self) -> None:
        fingerprint = "1" * 64
        self.store.append_billing_capacity_event(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            capacity_state=CapacityState.LIMIT_REACHED,
            reason_code="included_capacity_exhausted",
            occurred_at=90,
        )
        self.store.close()
        self.store = SQLiteStateStore(self.database, clock=lambda: 100.0)
        guard = SQLiteBillingCircuitGuard(self.store, profile_id="codex-review")

        stale = BillingRouteAssessment(
            runner_id="codex",
            route=BillingRoute.SUBSCRIPTION_INCLUDED,
            confidence=AssessmentConfidence.HIGH,
            capacity_state=CapacityState.AVAILABLE,
            capacity_observed_at=90,
            account_identity_fingerprint=fingerprint,
        )
        with self.assertRaisesRegex(BillingRouteBlocked, "durable capacity state"):
            guard.reserve_dispatch(stale, owner_id="stale-run", ttl_seconds=60)

        current = BillingRouteAssessment(
            runner_id="codex",
            route=BillingRoute.SUBSCRIPTION_INCLUDED,
            confidence=AssessmentConfidence.HIGH,
            capacity_state=CapacityState.AVAILABLE,
            capacity_observed_at=91,
            account_identity_fingerprint=fingerprint,
        )
        reservation = guard.reserve_dispatch(
            current, owner_id="reverified-run", ttl_seconds=60
        )
        self.assertIsNotNone(reservation)
        recovered = self.store.latest_billing_capacity_event(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
        )
        self.assertIsNotNone(recovered)
        assert recovered is not None and reservation is not None
        self.assertEqual(recovered.capacity_state, CapacityState.AVAILABLE)
        self.assertEqual(recovered.reason_code, "preflight_capacity_reverified")
        guard.complete_dispatch(
            reservation,
            run_id="reverified-run",
            capacity_state=CapacityState.AVAILABLE,
            capacity_reason_code="post_run_capacity_available",
            circuit_breaker_required=False,
            broad_scope_required=False,
            reason_code="post_run_billing_evidence_unknown",
        )

        self.store.close()
        self.store = SQLiteStateStore(self.database, clock=lambda: 101.0)
        restarted = SQLiteBillingCircuitGuard(
            self.store, profile_id="codex-review"
        ).reserve_dispatch(
            BillingRouteAssessment(
                runner_id="codex",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                capacity_state=CapacityState.AVAILABLE,
                capacity_observed_at=101,
                account_identity_fingerprint=fingerprint,
            ),
            owner_id="after-restart",
            ttl_seconds=60,
        )
        self.assertIsNotNone(restarted)

    def test_assert_closed_rejects_stale_durable_capacity(self) -> None:
        fingerprint = "5" * 64
        blocked = self.store.append_billing_capacity_event(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            capacity_state=CapacityState.COOLDOWN,
            reason_code="post_run_capacity_cooldown",
            occurred_at=90,
        )
        guard = SQLiteBillingCircuitGuard(self.store, profile_id="codex-review")
        with self.assertRaisesRegex(BillingRouteBlocked, "durable capacity state"):
            guard.assert_closed(
                BillingRouteAssessment(
                    runner_id="codex",
                    route=BillingRoute.SUBSCRIPTION_INCLUDED,
                    confidence=AssessmentConfidence.HIGH,
                    capacity_state=CapacityState.AVAILABLE,
                    capacity_observed_at=90,
                    account_identity_fingerprint=fingerprint,
                )
            )
        self.assertEqual(
            self.store.latest_billing_capacity_event(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                profile_id="codex-review",
            ),
            blocked,
        )

    def test_assert_closed_allows_fresh_post_reset_without_appending(self) -> None:
        fingerprint = "6" * 64
        blocked = self.store.append_billing_capacity_event(
            runner_id="claude",
            account_identity_fingerprint=None,
            profile_id="claude-review",
            capacity_state=CapacityState.BLOCKED_UNTIL_RESET,
            reason_code="included_capacity_exhausted",
            reset_at=120,
            occurred_at=90,
        )
        self.store.close()
        self.store = SQLiteStateStore(self.database, clock=lambda: 121.0)
        guard = SQLiteBillingCircuitGuard(self.store, profile_id="claude-review")
        guard.assert_closed(
            BillingRouteAssessment(
                runner_id="claude",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                capacity_state=CapacityState.AVAILABLE,
                capacity_observed_at=121,
                account_identity_fingerprint=fingerprint,
            )
        )
        self.assertEqual(
            self.store.latest_billing_capacity_event(
                runner_id="claude",
                account_identity_fingerprint=None,
                profile_id="claude-review",
            ),
            blocked,
        )

    def test_future_reset_blocks_until_strictly_newer_real_observation(self) -> None:
        fingerprint = "2" * 64
        self.store.append_billing_capacity_event(
            runner_id="claude",
            account_identity_fingerprint=fingerprint,
            profile_id="claude-review",
            capacity_state=CapacityState.BLOCKED_UNTIL_RESET,
            reason_code="included_capacity_exhausted",
            reset_at=120,
            occurred_at=90,
        )
        guard = SQLiteBillingCircuitGuard(self.store, profile_id="claude-review")
        for observed_at in (99, 120, 121):
            assessment = BillingRouteAssessment(
                runner_id="claude",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                capacity_state=CapacityState.AVAILABLE,
                capacity_observed_at=observed_at,
                account_identity_fingerprint=fingerprint,
            )
            with self.assertRaisesRegex(
                BillingRouteBlocked, "durable capacity state"
            ):
                guard.reserve_dispatch(
                    assessment,
                    owner_id=f"before-reset-{observed_at}",
                    ttl_seconds=60,
                )

        self.store.close()
        self.store = SQLiteStateStore(self.database, clock=lambda: 121.0)
        reservation = SQLiteBillingCircuitGuard(
            self.store, profile_id="claude-review"
        ).reserve_dispatch(
            BillingRouteAssessment(
                runner_id="claude",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                capacity_state=CapacityState.AVAILABLE,
                capacity_observed_at=121,
                account_identity_fingerprint=fingerprint,
            ),
            owner_id="after-reset",
            ttl_seconds=60,
        )
        self.assertIsNotNone(reservation)

    def test_capacity_reverification_covers_all_applicable_scopes(self) -> None:
        fingerprint = "3" * 64
        profile_id = "codex-review"
        scoped_states = (
            (None, None, CapacityState.LIMIT_REACHED, 80),
            (None, profile_id, CapacityState.BLOCKED_UNTIL_RESET, 81),
            (fingerprint, None, CapacityState.COOLDOWN, 82),
            (fingerprint, profile_id, CapacityState.UNKNOWN, 83),
        )
        for scoped_fingerprint, scoped_profile, capacity_state, occurred_at in scoped_states:
            self.store.append_billing_capacity_event(
                runner_id="codex",
                account_identity_fingerprint=scoped_fingerprint,
                profile_id=scoped_profile,
                capacity_state=capacity_state,
                reason_code="durable_capacity_fixture",
                reset_at=85 if capacity_state is CapacityState.BLOCKED_UNTIL_RESET else None,
                occurred_at=occurred_at,
            )

        guard = SQLiteBillingCircuitGuard(self.store, profile_id=profile_id)
        reservation = guard.reserve_dispatch(
            BillingRouteAssessment(
                runner_id="codex",
                route=BillingRoute.SUBSCRIPTION_INCLUDED,
                confidence=AssessmentConfidence.HIGH,
                capacity_state=CapacityState.AVAILABLE,
                capacity_observed_at=90,
                account_identity_fingerprint=fingerprint,
            ),
            owner_id="all-scopes-reverified",
            ttl_seconds=60,
        )
        self.assertIsNotNone(reservation)
        for scoped_fingerprint, scoped_profile, _state, _occurred_at in scoped_states:
            latest = self.store.latest_billing_capacity_event(
                runner_id="codex",
                account_identity_fingerprint=scoped_fingerprint,
                profile_id=scoped_profile,
            )
            self.assertIsNotNone(latest)
            assert latest is not None
            self.assertEqual(latest.capacity_state, CapacityState.AVAILABLE)
            self.assertEqual(latest.reason_code, "preflight_capacity_reverified")

    def test_completion_records_capacity_before_releasing_dispatch(self) -> None:
        fingerprint = "4" * 64
        guard = SQLiteBillingCircuitGuard(self.store, profile_id="codex-review")
        assessment = BillingRouteAssessment(
            runner_id="codex",
            route=BillingRoute.SUBSCRIPTION_INCLUDED,
            confidence=AssessmentConfidence.HIGH,
            capacity_state=CapacityState.AVAILABLE,
            capacity_observed_at=100,
            account_identity_fingerprint=fingerprint,
        )
        reservation = guard.reserve_dispatch(
            assessment, owner_id="capacity-consuming-run", ttl_seconds=60
        )
        self.assertIsNotNone(reservation)
        assert reservation is not None
        guard.complete_dispatch(
            reservation,
            run_id="capacity-consuming-run",
            capacity_state=CapacityState.LIMIT_REACHED,
            capacity_reason_code="included_capacity_exhausted",
            circuit_breaker_required=False,
            broad_scope_required=False,
            reason_code="post_run_billing_evidence_unknown",
        )
        for lease_key in reservation.lease_keys:
            self.assertIsNone(self.store.get_lease(lease_key))
        with self.assertRaisesRegex(BillingRouteBlocked, "durable capacity state"):
            guard.reserve_dispatch(
                assessment, owner_id="immediate-next-run", ttl_seconds=60
            )

    def test_schedule_slot_and_resource_claim_are_atomic(self) -> None:
        first = self.store.try_claim_schedule_slot(
            claim_id="claim-1",
            schedule_id="daily-lint",
            slot_id="0",
            scheduled_for=100,
            claimed_at=100,
            deadline_at=130,
            owner_id="worker/claim-1",
            lease_keys=("repo:one", "runner:mock"),
        )
        self.assertIsNotNone(first)
        duplicate = self.store.try_claim_schedule_slot(
            claim_id="claim-2",
            schedule_id="daily-lint",
            slot_id="0",
            scheduled_for=100,
            claimed_at=101,
            deadline_at=131,
            owner_id="worker/claim-2",
            lease_keys=("repo:one",),
        )
        self.assertIsNone(duplicate)
        busy = self.store.try_claim_schedule_slot(
            claim_id="claim-3",
            schedule_id="typecheck",
            slot_id="0",
            scheduled_for=100,
            claimed_at=101,
            deadline_at=131,
            owner_id="worker/claim-3",
            lease_keys=("repo:one",),
        )
        self.assertIsNone(busy)
        self.assertEqual(len(self.store.list_schedule_claims()), 1)

    def test_billing_capacity_and_circuit_state_are_append_only(self) -> None:
        fingerprint = "c" * 64
        first = self.store.append_billing_capacity_event(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            capacity_state=CapacityState.AVAILABLE,
            reason_code="preflight_capacity_available",
            occurred_at=100,
        )
        blocked = self.store.append_billing_capacity_event(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            capacity_state=CapacityState.BLOCKED_UNTIL_RESET,
            reason_code="included_capacity_exhausted",
            reset_at=200,
            occurred_at=101,
        )
        self.assertLess(first.sequence, blocked.sequence)
        self.assertEqual(
            self.store.latest_billing_capacity_event(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                profile_id="codex-review",
            ),
            blocked,
        )

        opened = self.store.append_billing_circuit_event(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            state=CircuitBreakerState.OPEN,
            reason_code="post_run_billing_evidence_unknown",
            occurred_at=102,
        )
        self.assertEqual(
            self.store.current_billing_circuit(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                profile_id="codex-review",
            ),
            opened,
        )
        guard = SQLiteBillingCircuitGuard(self.store, profile_id="codex-review")
        with self.assertRaisesRegex(BillingRouteBlocked, "durable billing circuit"):
            guard.assert_closed(
                BillingRouteAssessment(
                    runner_id="codex",
                    route=BillingRoute.SUBSCRIPTION_INCLUDED,
                    confidence=AssessmentConfidence.HIGH,
                    account_identity_fingerprint=fingerprint,
                )
            )
        closed = self.store.append_billing_circuit_event(
            runner_id="codex",
            account_identity_fingerprint=fingerprint,
            profile_id="codex-review",
            state=CircuitBreakerState.CLOSED,
            reason_code="operator_verified_billing_safe",
            occurred_at=103,
        )
        self.assertEqual(
            self.store.current_billing_circuit(
                runner_id="codex",
                account_identity_fingerprint=fingerprint,
                profile_id="codex-review",
            ),
            closed,
        )
        with self.assertRaisesRegex(BillingRouteBlocked, "durable capacity state"):
            guard.assert_closed(
                BillingRouteAssessment(
                    runner_id="codex",
                    route=BillingRoute.SUBSCRIPTION_INCLUDED,
                    confidence=AssessmentConfidence.HIGH,
                    account_identity_fingerprint=fingerprint,
                )
            )

        self.store.append_billing_circuit_event(
            runner_id="codex",
            profile_id="codex-review",
            state=CircuitBreakerState.OPEN,
            reason_code="post_run_billing_evidence_unknown",
            occurred_at=104,
        )
        with self.assertRaisesRegex(BillingRouteBlocked, "durable billing circuit"):
            guard.assert_closed(
                BillingRouteAssessment(
                    runner_id="codex",
                    route=BillingRoute.SUBSCRIPTION_INCLUDED,
                    confidence=AssessmentConfidence.HIGH,
                    account_identity_fingerprint="d" * 64,
                )
            )

        connection = sqlite3.connect(self.database)
        try:
            for statement in (
                "DELETE FROM billing_capacity_events",
                "UPDATE billing_circuit_events SET state = 'open'",
            ):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    connection.execute(statement)
                connection.rollback()
        finally:
            connection.close()

    def test_billing_state_rejects_raw_identity_and_unbounded_reason(self) -> None:
        with self.assertRaisesRegex(ValidationError, "fingerprint"):
            self.store.append_billing_circuit_event(
                runner_id="claude",
                account_identity_fingerprint="operator@example.invalid",
                state=CircuitBreakerState.OPEN,
                reason_code="post_run_billing_evidence_unknown",
            )
        with self.assertRaisesRegex(ValidationError, "reason_code"):
            self.store.append_billing_capacity_event(
                runner_id="claude",
                capacity_state=CapacityState.UNKNOWN,
                reason_code="raw diagnostic: $12.34",
            )


if __name__ == "__main__":
    unittest.main()
