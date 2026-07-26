from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import itertools
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ordomata.errors import ConfigurationError
from ordomata.models import PermissionClass
from ordomata.supervisor import (
    AdmissionConflictError,
    ClaimLostError,
    FlowSpec,
    FlowState,
    ForegroundSupervisor,
    SQLiteSupervisorStore,
    StaleReconciliationPlanError,
    StaleRevisionError,
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

    def _start_and_claim(self, spec: FlowSpec | None = None):
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
            ],
        )
        self.assertEqual(
            baseline_digest,
            "6076ff9c09a329bc60f1bdc79fd61d3251990219047005691eff8bbd9e9178e6",
        )

    def test_v3_migration_baselines_preexisting_supervisor_history(self) -> None:
        spec = self._flow()
        self.store.admit_flow(spec)
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
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

    def test_missing_v3_schema_is_a_finding_even_without_flows(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
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
        self.assertEqual(audit.findings[0].code, "authorization_schema_missing")

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
