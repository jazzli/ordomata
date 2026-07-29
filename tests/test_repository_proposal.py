from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest, canonical_json
from ordomata.errors import ConfigurationError, ValidationError
from ordomata.models import PermissionClass, RunStatus
from ordomata.repository_proposal import (
    REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
    REPOSITORY_PROPOSAL_RUNNER_ID,
    REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
    RepositoryRegistrationSelection,
    bind_repository_proposal_attempt as _bind_repository_proposal_attempt,
    validate_repository_proposal_attempt_binding_payload,
    validate_repository_registration_selection_payload,
)
from ordomata.repository_registration import (
    RepositoryRegistration,
    validate_repository_registration,
)
from ordomata.state import RunRecord, SQLiteStateStore


SELECTION_KEYS = {
    "kind",
    "proposal_digest",
    "run_ref",
    "selection_mode",
    "selected_registration",
    "selected_registration_evidence_digest",
}
REGISTRATION_EVIDENCE_KEYS = {
    "authority_granted",
    "dispatch_enabled",
    "filesystem_identity_ref",
    "isolation_requirements_digest",
    "kind",
    "path_policy_digest",
    "registration_digest",
    "registration_ref",
    "registration_version",
    "repository_ref",
    "resource_limits_digest",
    "review_policy_digest",
    "schema_version",
    "validation_mode",
    "verification_commands_digest",
}
BINDING_KEYS = {
    "attempt",
    "authority_granted",
    "context_digest",
    "created_at_ref",
    "dispatch_enabled",
    "filesystem_identity_ref",
    "isolation_requirements_digest",
    "kind",
    "path_policy_digest",
    "permission_class",
    "proposal_digest",
    "proposal_ref",
    "proposal_version_ref",
    "registration_digest",
    "registration_evidence_digest",
    "registration_ref",
    "registration_selection_digest",
    "registration_version",
    "repository_ref",
    "resource_limits_digest",
    "review_policy_digest",
    "run_directory_ref",
    "run_ref",
    "runner_ref",
    "timeout_seconds",
    "validation_mode",
    "verification_commands_digest",
    "workspace_ref",
}

DEFAULT_PROPOSAL_DIGEST = canonical_digest(
    {"proposal": "private-proposal-content-marker"}
)


def bind_repository_proposal_attempt(
    state: SQLiteStateStore,
    *,
    run_id: str,
    registration: RepositoryRegistration,
    proposal_digest: str = DEFAULT_PROPOSAL_DIGEST,
):
    """Keep individual tests concise while always binding proposal content."""

    return _bind_repository_proposal_attempt(
        state,
        run_id=run_id,
        registration=registration,
        proposal_digest=proposal_digest,
    )


class RepositoryProposalTests(unittest.TestCase):
    @staticmethod
    def _repository(base: Path) -> Path:
        root = base / "private-repository-root-marker"
        root.mkdir()
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n",
            encoding="utf-8",
        )
        for name in (
            "private-source-path-marker",
            "private-test-path-marker",
            "private-docs-path-marker",
        ):
            (root / name).mkdir()
        (root / "private-protected-path-marker.txt").write_text(
            "controller-owned\n",
            encoding="utf-8",
        )
        return root

    @staticmethod
    def _registration_payload() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "repository_registration",
            "registration_id": "private-registration-id-marker",
            "registration_version": "1.0.0",
            "repository": {
                "repository_id": "private-repository-id-marker",
                "vcs": "git",
                "root": ".",
            },
            "verification_commands": {
                "format": [
                    {
                        "command_id": "private-format-command-marker",
                        "argv": [
                            "python3",
                            "-m",
                            "compileall",
                            "-q",
                            "private-source-path-marker",
                        ],
                        "cwd": ".",
                    }
                ],
                "lint": [],
                "type_check": [],
                "test": [
                    {
                        "command_id": "private-test-command-marker",
                        "argv": [
                            "python3",
                            "-m",
                            "unittest",
                            "discover",
                            "-s",
                            "private-test-path-marker",
                        ],
                        "cwd": ".",
                    }
                ],
                "build": [],
            },
            "path_policy": {
                "allowed_paths": [
                    "private-test-path-marker",
                    "private-source-path-marker",
                    "private-docs-path-marker",
                ],
                "protected_paths": [
                    "private-protected-path-marker.txt",
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
    def _registration(
        cls,
        root: Path,
        *,
        payload: dict[str, object] | None = None,
    ) -> RepositoryRegistration:
        return validate_repository_registration(
            cls._registration_payload() if payload is None else payload,
            repository_root=root,
        )

    @staticmethod
    def _create_run(
        state: SQLiteStateStore,
        *,
        run_id: str = "private-proposal-run-marker",
        runner_id: str = REPOSITORY_PROPOSAL_RUNNER_ID,
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
        context_digest: str = "sha256:" + "a" * 64,
        timeout_seconds: int = 321,
        attempt: int = 1,
    ) -> RunRecord:
        record = RunRecord(
            run_id=run_id,
            task_id="private-proposal-id-marker",
            task_version="private-proposal-version-marker",
            runner_id=runner_id,
            workspace=f"/synthetic-workspace-private-marker/{run_id}",
            run_directory=f"/synthetic-run-directory-private-marker/{run_id}",
            context_digest=context_digest,
            permission_class=permission_class,
            timeout_seconds=timeout_seconds,
            attempt=attempt,
            created_at=100.0,
        )
        return state.create_run(record)

    @staticmethod
    def _proposal_events(state: SQLiteStateStore, run_id: str):
        events = state.list_events(run_id)
        selection = tuple(
            event
            for event in events
            if event.event_type == REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE
        )
        binding = tuple(
            event
            for event in events
            if event.event_type
            == REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE
        )
        return events, selection, binding

    @staticmethod
    def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
        entries: list[tuple[object, ...]] = []
        for directory, directory_names, file_names in os.walk(
            root,
            followlinks=False,
        ):
            parent = Path(directory)
            for name in sorted((*directory_names, *file_names)):
                path = parent / name
                relative = path.relative_to(root).as_posix()
                metadata = path.lstat()
                mode = stat.S_IMODE(metadata.st_mode)
                if path.is_symlink():
                    entries.append(
                        (relative, "symlink", mode, os.readlink(path))
                    )
                elif path.is_dir():
                    entries.append((relative, "directory", mode))
                else:
                    entries.append(
                        (
                            relative,
                            "file",
                            mode,
                            hashlib.sha256(path.read_bytes()).hexdigest(),
                        )
                    )
        return tuple(sorted(entries))

    @staticmethod
    def _schema_snapshot(database: Path) -> tuple[object, ...]:
        with closing(sqlite3.connect(database)) as connection:
            objects = tuple(
                connection.execute(
                    """
                    SELECT type, name, tbl_name, sql FROM sqlite_master
                    WHERE sql IS NOT NULL
                    ORDER BY type, name
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

    def test_happy_path_has_strict_digest_only_shapes_and_stays_created(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            database = base / "state.sqlite3"
            with SQLiteStateStore(database, clock=lambda: 101.0) as state:
                run = self._create_run(state)

                result = bind_repository_proposal_attempt(
                    state,
                    run_id=run.run_id,
                    registration=registration,
                )

                events, selections, bindings = self._proposal_events(
                    state,
                    run.run_id,
                )
                self.assertEqual(len(events), 3)
                self.assertEqual(len(selections), 1)
                self.assertEqual(len(bindings), 1)
                self.assertEqual(
                    [event.event_type for event in events],
                    [
                        "status",
                        REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                        REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                    ],
                )
                self.assertEqual(
                    [event.status for event in events],
                    [RunStatus.CREATED, None, None],
                )
                self.assertEqual(state.current_status(run.run_id), RunStatus.CREATED)

                selection_payload = selections[0].payload
                selection = selection_payload["selection"]
                selected = selection["selected_registration"]
                self.assertEqual(set(selection_payload), {
                    "schema_version", "selection", "selection_digest"
                })
                self.assertEqual(set(selection), SELECTION_KEYS)
                self.assertEqual(set(selected), REGISTRATION_EVIDENCE_KEYS)
                self.assertEqual(selected, registration.to_evidence())
                self.assertEqual(selection["selection_mode"], "controller_owned")
                self.assertEqual(
                    selection["proposal_digest"],
                    DEFAULT_PROPOSAL_DIGEST,
                )
                self.assertEqual(
                    selection["selected_registration_evidence_digest"],
                    canonical_digest(selected),
                )
                self.assertEqual(
                    selection_payload["selection_digest"],
                    canonical_digest(selection),
                )
                self.assertEqual(
                    selections[0].event_id,
                    selection_payload["selection_digest"],
                )

                binding_payload = bindings[0].payload
                binding = binding_payload["binding"]
                self.assertEqual(set(binding_payload), {
                    "schema_version", "binding", "binding_digest"
                })
                self.assertEqual(set(binding), BINDING_KEYS)
                self.assertEqual(
                    binding_payload["binding_digest"],
                    canonical_digest(binding),
                )
                self.assertEqual(
                    bindings[0].event_id,
                    binding_payload["binding_digest"],
                )
                self.assertEqual(
                    binding["registration_selection_digest"],
                    selection_payload["selection_digest"],
                )
                self.assertEqual(
                    binding["registration_evidence_digest"],
                    selection["selected_registration_evidence_digest"],
                )
                self.assertEqual(
                    binding["proposal_digest"],
                    DEFAULT_PROPOSAL_DIGEST,
                )
                for key in REGISTRATION_EVIDENCE_KEYS - {
                    "authority_granted",
                    "dispatch_enabled",
                    "kind",
                    "schema_version",
                    "validation_mode",
                }:
                    if key != "registration_version":
                        self.assertEqual(binding[key], selected[key])
                self.assertFalse(binding["dispatch_enabled"])
                self.assertFalse(binding["authority_granted"])
                self.assertEqual(binding["validation_mode"], "read_only")
                self.assertEqual(result.selection_sequence, selections[0].sequence)
                self.assertEqual(result.binding_sequence, bindings[0].sequence)
                self.assertFalse(result.to_evidence()["dispatch_enabled"])
                self.assertFalse(result.to_evidence()["authority_granted"])
                self.assertEqual(
                    result.to_evidence()["run_status_at_readback"],
                    RunStatus.CREATED.value,
                )
                self.assertNotIn("run_status", result.to_evidence())

                serialized = json.dumps(
                    [selection_payload, binding_payload, result.to_evidence()],
                    sort_keys=True,
                )
                for private_value in (
                    str(root),
                    run.run_id,
                    run.task_id,
                    run.task_version,
                    run.workspace,
                    run.run_directory,
                    "private-registration-id-marker",
                    "private-repository-id-marker",
                    "private-source-path-marker",
                    "private-test-path-marker",
                    "private-docs-path-marker",
                    "private-protected-path-marker.txt",
                    "private-format-command-marker",
                    "private-test-command-marker",
                ):
                    self.assertNotIn(private_value, serialized)

    def test_class_zero_and_one_bind_exact_durable_run_metadata(self) -> None:
        for index, permission_class in enumerate(
            (PermissionClass.READ_ONLY, PermissionClass.LOCAL_DRAFT),
            start=1,
        ):
            with (
                self.subTest(permission_class=permission_class),
                tempfile.TemporaryDirectory() as temporary,
            ):
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                with SQLiteStateStore(base / "state.sqlite3") as state:
                    run = self._create_run(
                        state,
                        run_id=f"private-class-{index}-run-marker",
                        permission_class=permission_class,
                        context_digest="b" * 64,
                        timeout_seconds=200 + index,
                        attempt=index,
                    )
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )
                    _, _, bindings = self._proposal_events(state, run.run_id)
                    binding = bindings[0].payload["binding"]

                    self.assertEqual(binding["permission_class"], int(permission_class))
                    self.assertEqual(binding["timeout_seconds"], run.timeout_seconds)
                    self.assertEqual(binding["attempt"], run.attempt)
                    self.assertEqual(binding["context_digest"], "sha256:" + "b" * 64)
                    self.assertEqual(
                        binding["run_ref"],
                        canonical_digest({"run_id": run.run_id}),
                    )
                    self.assertEqual(
                        binding["created_at_ref"],
                        canonical_digest({"created_at": run.created_at}),
                    )
                    self.assertEqual(
                        binding["proposal_ref"],
                        canonical_digest({"proposal_id": run.task_id}),
                    )
                    self.assertEqual(
                        binding["proposal_digest"],
                        DEFAULT_PROPOSAL_DIGEST,
                    )
                    self.assertEqual(
                        binding["proposal_version_ref"],
                        canonical_digest({"proposal_version": run.task_version}),
                    )
                    self.assertEqual(
                        binding["runner_ref"],
                        canonical_digest({"runner_id": run.runner_id}),
                    )
                    self.assertEqual(
                        binding["workspace_ref"],
                        canonical_digest({"workspace": run.workspace}),
                    )
                    self.assertEqual(
                        binding["run_directory_ref"],
                        canonical_digest({"run_directory": run.run_directory}),
                    )

    def test_same_registration_across_runs_has_run_bound_event_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            with SQLiteStateStore(base / "state.sqlite3") as state:
                results = []
                for run_id in ("private-first-run-marker", "private-second-run-marker"):
                    self._create_run(state, run_id=run_id)
                    results.append(
                        bind_repository_proposal_attempt(
                            state,
                            run_id=run_id,
                            registration=registration,
                        )
                    )

                self.assertNotEqual(results[0].run_ref, results[1].run_ref)
                self.assertNotEqual(
                    results[0].registration_selection_digest,
                    results[1].registration_selection_digest,
                )
                self.assertNotEqual(
                    results[0].repository_proposal_binding_digest,
                    results[1].repository_proposal_binding_digest,
                )
                self.assertEqual(
                    results[0].registration_digest,
                    results[1].registration_digest,
                )

    def test_exact_retry_and_reopen_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            database = base / "state.sqlite3"
            run_id = "private-idempotent-run-marker"
            with SQLiteStateStore(database) as state:
                self._create_run(state, run_id=run_id)
                first = bind_repository_proposal_attempt(
                    state,
                    run_id=run_id,
                    registration=registration,
                )
                first_events = state.list_events(run_id)
                repeated = bind_repository_proposal_attempt(
                    state,
                    run_id=run_id,
                    registration=registration,
                )
                self.assertEqual(first, repeated)
                self.assertEqual(first_events, state.list_events(run_id))

            with SQLiteStateStore(database) as reopened:
                after_restart = bind_repository_proposal_attempt(
                    reopened,
                    run_id=run_id,
                    registration=registration,
                )
                self.assertEqual(first, after_restart)
                self.assertEqual(len(reopened.list_events(run_id)), 3)

    def test_conflicting_registration_replay_fails_without_new_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            first = self._registration(root)
            changed_payload = deepcopy(self._registration_payload())
            changed_payload["registration_version"] = "1.0.1"
            changed_limits = changed_payload["resource_limits"]
            assert isinstance(changed_limits, dict)
            changed_limits["cpu_count"] = 3
            conflicting = self._registration(root, payload=changed_payload)
            with SQLiteStateStore(base / "state.sqlite3") as state:
                run = self._create_run(state)
                bind_repository_proposal_attempt(
                    state,
                    run_id=run.run_id,
                    registration=first,
                )
                original = state.list_events(run.run_id)

                with self.assertRaises(ValidationError):
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=conflicting,
                    )

                self.assertEqual(state.list_events(run.run_id), original)

                with self.assertRaises(ValidationError):
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=first,
                        proposal_digest=canonical_digest(
                            {"proposal": "changed-private-proposal-content"}
                        ),
                    )

                self.assertEqual(state.list_events(run.run_id), original)

    def test_selection_only_recovery_cannot_change_proposal_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            with SQLiteStateStore(base / "state.sqlite3") as state:
                run = self._create_run(state)
                original_append = SQLiteStateStore.append_event_once

                def fail_binding(
                    store,
                    observed_run_id,
                    event_type,
                    *args,
                    **kwargs,
                ):
                    if (
                        event_type
                        == REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE
                    ):
                        raise RuntimeError("private-precommit-failure-marker")
                    return original_append(
                        store,
                        observed_run_id,
                        event_type,
                        *args,
                        **kwargs,
                    )

                with patch.object(
                    SQLiteStateStore,
                    "append_event_once",
                    new=fail_binding,
                ):
                    with self.assertRaises(ConfigurationError):
                        bind_repository_proposal_attempt(
                            state,
                            run_id=run.run_id,
                            registration=registration,
                        )

                partial = state.list_events(run.run_id)
                self.assertEqual(len(partial), 2)
                changed_proposal_digest = canonical_digest(
                    {"proposal": "changed-after-selection-private-marker"}
                )
                with self.assertRaises(ValidationError):
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                        proposal_digest=changed_proposal_digest,
                    )
                self.assertEqual(state.list_events(run.run_id), partial)

                result = bind_repository_proposal_attempt(
                    state,
                    run_id=run.run_id,
                    registration=registration,
                )
                self.assertEqual(result.proposal_digest, DEFAULT_PROPOSAL_DIGEST)
                self.assertEqual(len(state.list_events(run.run_id)), 3)

    def test_duplicate_unexpected_and_out_of_order_histories_fail_closed(self) -> None:
        cases = ("unexpected", "binding_without_selection", "duplicate", "reordered")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                database = base / "state.sqlite3"
                with SQLiteStateStore(database) as state:
                    run = self._create_run(state, run_id=f"private-{case}-run-marker")
                    if case == "unexpected":
                        state.append_event(
                            run.run_id,
                            "private_unexpected_event_marker",
                            {"ordinal": 1},
                        )
                    elif case == "binding_without_selection":
                        state.append_event(
                            run.run_id,
                            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                            {"inert": True},
                            event_id=canonical_digest({"case": case}),
                        )
                    else:
                        bind_repository_proposal_attempt(
                            state,
                            run_id=run.run_id,
                            registration=registration,
                        )
                        if case == "duplicate":
                            state.append_event(
                                run.run_id,
                                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                                {"duplicate": True},
                                event_id=canonical_digest({"case": case}),
                            )

                if case == "reordered":
                    with closing(sqlite3.connect(database)) as connection:
                        connection.execute("DROP TRIGGER run_events_no_update")
                        rows = connection.execute(
                            """
                            SELECT event_type, sequence FROM run_events
                            WHERE run_id = ? AND event_type IN (?, ?)
                            """,
                            (
                                run.run_id,
                                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                            ),
                        ).fetchall()
                        sequences = {event_type: sequence for event_type, sequence in rows}
                        selection_sequence = sequences[
                            REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE
                        ]
                        binding_sequence = sequences[
                            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE
                        ]
                        connection.execute(
                            "UPDATE run_events SET sequence = -1 WHERE sequence = ?",
                            (selection_sequence,),
                        )
                        connection.execute(
                            "UPDATE run_events SET sequence = ? WHERE sequence = ?",
                            (selection_sequence, binding_sequence),
                        )
                        connection.execute(
                            "UPDATE run_events SET sequence = ? WHERE sequence = -1",
                            (binding_sequence,),
                        )
                        self._restore_update_trigger(connection)
                        connection.commit()

                with SQLiteStateStore(database) as state:
                    before = state.list_events(run.run_id)
                    with self.assertRaises(ValidationError):
                        bind_repository_proposal_attempt(
                            state,
                            run_id=run.run_id,
                            registration=registration,
                        )
                    self.assertEqual(state.list_events(run.run_id), before)
                    self.assertEqual(state.current_status(run.run_id), RunStatus.CREATED)

    def test_disabled_runner_created_status_and_context_digest_are_required(self) -> None:
        cases = (
            "runner",
            "running",
            "terminal",
            "digest",
            "proposal_digest",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                with SQLiteStateStore(base / "state.sqlite3") as state:
                    run = self._create_run(
                        state,
                        run_id=f"private-invalid-{case}-run-marker",
                        runner_id=(
                            "mock"
                            if case == "runner"
                            else REPOSITORY_PROPOSAL_RUNNER_ID
                        ),
                        context_digest=("not-a-digest" if case == "digest" else "c" * 64),
                    )
                    if case == "running":
                        state.append_event(
                            run.run_id,
                            "status",
                            {},
                            status=RunStatus.RUNNING,
                        )
                    elif case == "terminal":
                        state.append_event(
                            run.run_id,
                            "status",
                            {},
                            status=RunStatus.FAILED,
                        )

                    with self.assertRaises(ValidationError):
                        bind_repository_proposal_attempt(
                            state,
                            run_id=run.run_id,
                            registration=registration,
                            proposal_digest=(
                                "d" * 64
                                if case == "proposal_digest"
                                else DEFAULT_PROPOSAL_DIGEST
                            ),
                        )
                    _, selections, bindings = self._proposal_events(state, run.run_id)
                    self.assertEqual(selections, ())
                    self.assertEqual(bindings, ())

                with SQLiteStateStore(base / "state.sqlite3") as reopened:
                    with self.assertRaises(ValidationError):
                        bind_repository_proposal_attempt(
                            reopened,
                            run_id="private-missing-run-marker",
                            registration=registration,
                        )

    def test_status_bearing_proposal_event_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            database = base / "state.sqlite3"
            with SQLiteStateStore(database) as state:
                run = self._create_run(state)
                bind_repository_proposal_attempt(
                    state,
                    run_id=run.run_id,
                    registration=registration,
                )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute("DROP TRIGGER run_events_no_update")
                    connection.execute(
                        """
                        UPDATE run_events SET status = 'created'
                        WHERE run_id = ? AND event_type = ?
                        """,
                        (run.run_id, REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE),
                    )
                    self._restore_update_trigger(connection)
                    connection.commit()
                before = state.list_events(run.run_id)
                with self.assertRaises(ValidationError):
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )
                self.assertEqual(state.list_events(run.run_id), before)

    def test_forged_and_stale_registration_snapshots_are_revalidated(self) -> None:
        for case in ("forged", "stale"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                if case == "forged":
                    registration = replace(
                        registration,
                        review_policy=replace(
                            registration.review_policy,
                            push=True,
                        ),
                    )
                else:
                    (root / ".git").rename(root / ".git-private-stale-marker")
                with SQLiteStateStore(base / "state.sqlite3") as state:
                    run = self._create_run(state, run_id=f"private-{case}-run-marker")
                    with self.assertRaises(ValidationError):
                        bind_repository_proposal_attempt(
                            state,
                            run_id=run.run_id,
                            registration=registration,
                        )
                    self.assertEqual(len(state.list_events(run.run_id)), 1)

    def test_forged_nested_registration_values_cannot_invoke_hooks(self) -> None:
        invoked: list[str] = []

        class HostileTuple(tuple):
            def __iter__(self):
                invoked.append("iter")
                raise AssertionError("caller-defined iteration must not run")

        class HostilePathLike:
            def __fspath__(self):
                invoked.append("fspath")
                raise AssertionError("caller-defined path conversion must not run")

        for case in ("command_argv", "allowed_paths", "canonical_root"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                if case == "command_argv":
                    command = registration.verification_commands.test[0]
                    forged_command = replace(
                        command,
                        argv=HostileTuple(command.argv),
                    )
                    registration = replace(
                        registration,
                        verification_commands=replace(
                            registration.verification_commands,
                            test=(forged_command,),
                        ),
                    )
                elif case == "allowed_paths":
                    registration = replace(
                        registration,
                        path_policy=replace(
                            registration.path_policy,
                            allowed_paths=HostileTuple(
                                registration.path_policy.allowed_paths
                            ),
                        ),
                    )
                else:
                    registration = replace(
                        registration,
                        repository=replace(
                            registration.repository,
                            canonical_root=HostilePathLike(),
                        ),
                    )

                with SQLiteStateStore(base / "state.sqlite3") as state:
                    run = self._create_run(
                        state,
                        run_id=f"private-hook-{case}-run-marker",
                    )
                    with self.assertRaisesRegex(
                        ValidationError,
                        "repository proposal evidence is invalid",
                    ):
                        bind_repository_proposal_attempt(
                            state,
                            run_id=run.run_id,
                            registration=registration,
                        )
                    self.assertEqual(len(state.list_events(run.run_id)), 1)
        self.assertEqual(invoked, [])

    def test_registration_evidence_schema_version_rejects_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            with SQLiteStateStore(base / "state.sqlite3") as state:
                run = self._create_run(state)
                bind_repository_proposal_attempt(
                    state,
                    run_id=run.run_id,
                    registration=registration,
                )
                _, selections, bindings = self._proposal_events(
                    state,
                    run.run_id,
                )

            forged = deepcopy(selections[0].payload)
            selection = forged["selection"]
            selected = selection["selected_registration"]
            selected["schema_version"] = True
            selection["selected_registration_evidence_digest"] = (
                canonical_digest(selected)
            )
            forged["selection_digest"] = canonical_digest(selection)

            with self.assertRaisesRegex(
                ValidationError,
                "repository proposal evidence is invalid",
            ):
                validate_repository_registration_selection_payload(forged)

            forged_selection = RepositoryRegistrationSelection(
                canonical_json(selection),
                forged["selection_digest"],
            )
            with self.assertRaisesRegex(
                ValidationError,
                "repository proposal evidence is invalid",
            ):
                validate_repository_proposal_attempt_binding_payload(
                    bindings[0].payload,
                    selection=forged_selection,
                )

    def test_oversized_binding_payloads_fail_before_replay_or_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            database = base / "state.sqlite3"
            with SQLiteStateStore(database) as state:
                run = self._create_run(state)
                bind_repository_proposal_attempt(
                    state,
                    run_id=run.run_id,
                    registration=registration,
                )
                _, selections, bindings = self._proposal_events(
                    state,
                    run.run_id,
                )
                selection = validate_repository_registration_selection_payload(
                    selections[0].payload
                )
                oversized = deepcopy(bindings[0].payload)
                oversized["binding"]["workspace_ref"] = "a" * 131_073
                with self.assertRaisesRegex(
                    ValidationError,
                    "repository proposal evidence is invalid",
                ):
                    validate_repository_proposal_attempt_binding_payload(
                        oversized,
                        selection=selection,
                    )

                oversized_json = json.dumps(
                    {"oversized": "a" * 131_073},
                    separators=(",", ":"),
                    sort_keys=True,
                )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute("DROP TRIGGER run_events_no_update")
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
                    self._restore_update_trigger(connection)
                    connection.commit()

                with self.assertRaisesRegex(
                    ValidationError,
                    "repository proposal evidence is invalid",
                ):
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )

    def test_public_registration_projection_hook_cannot_control_selection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            expected = registration.to_evidence()
            poisoned = {
                **expected,
                "authority_granted": True,
                "dispatch_enabled": True,
                "registration_digest": "private-poisoned-projection-marker",
            }
            with SQLiteStateStore(base / "state.sqlite3") as state:
                run = self._create_run(state)
                with patch.object(
                    RepositoryRegistration,
                    "to_evidence",
                    return_value=poisoned,
                ):
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )
                _, selections, _ = self._proposal_events(state, run.run_id)
                selected = selections[0].payload["selection"][
                    "selected_registration"
                ]
                self.assertEqual(selected, expected)
                self.assertFalse(selected["authority_granted"])
                self.assertFalse(selected["dispatch_enabled"])
                self.assertNotIn(
                    "private-poisoned-projection-marker",
                    selections[0].payload_json,
                )

    def test_forged_selection_json_fails_with_fixed_public_validation_error(
        self,
    ) -> None:
        private_marker = "private-forged-selection-json-marker"
        cases = {
            "array": "[]",
            "null": "null",
            "malformed": "{",
            "scalar": json.dumps(private_marker),
            "non_string": 7,
            "deep": "[" * 2_000 + "0" + "]" * 2_000,
            "oversized": '{"x":"' + "a" * 131_073 + '"}',
        }
        for case, raw in cases.items():
            with self.subTest(case=case):
                selection = RepositoryRegistrationSelection(
                    raw,  # type: ignore[arg-type]
                    canonical_digest({"private_fixture": private_marker}),
                )
                with self.assertRaises(ValidationError) as caught:
                    validate_repository_proposal_attempt_binding_payload(
                        {},
                        selection=selection,
                    )
                self.assertEqual(
                    str(caught.exception),
                    "repository proposal evidence is invalid",
                )
                self.assertNotIn(private_marker, str(caught.exception))

    def test_created_status_is_rechecked_atomically_at_each_append(self) -> None:
        for target in (
            REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                with SQLiteStateStore(base / "state.sqlite3") as state:
                    run = self._create_run(
                        state,
                        run_id=f"private-status-race-{target}",
                    )
                    original = SQLiteStateStore.append_event_once
                    injected = False

                    def transition_before_append(
                        store,
                        observed_run_id,
                        event_type,
                        *args,
                        **kwargs,
                    ):
                        nonlocal injected
                        if event_type == target and not injected:
                            injected = True
                            store.append_event(
                                observed_run_id,
                                "status",
                                {},
                                status=RunStatus.RUNNING,
                                event_id=canonical_digest(
                                    {
                                        "run_id": observed_run_id,
                                        "status_race_target": target,
                                    }
                                ),
                            )
                        return original(
                            store,
                            observed_run_id,
                            event_type,
                            *args,
                            **kwargs,
                        )

                    with patch.object(
                        SQLiteStateStore,
                        "append_event_once",
                        new=transition_before_append,
                    ):
                        with self.assertRaises(ConfigurationError):
                            bind_repository_proposal_attempt(
                                state,
                                run_id=run.run_id,
                                registration=registration,
                            )

                    self.assertTrue(injected)
                    _, selections, bindings = self._proposal_events(state, run.run_id)
                    self.assertEqual(
                        len(selections),
                        int(
                            target
                            == REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE
                        ),
                    )
                    self.assertEqual(bindings, ())
                    self.assertEqual(state.current_status(run.run_id), RunStatus.RUNNING)

    def test_exact_predecessor_history_is_checked_at_each_append(self) -> None:
        for target in (
            REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                with SQLiteStateStore(base / "state.sqlite3") as state:
                    run = self._create_run(
                        state,
                        run_id=f"private-history-race-{target}",
                    )
                    original = SQLiteStateStore.append_event_once
                    injected = False

                    def append_unexpected_before_target(
                        store,
                        observed_run_id,
                        event_type,
                        *args,
                        **kwargs,
                    ):
                        nonlocal injected
                        if event_type == target and not injected:
                            injected = True
                            store.append_event(
                                observed_run_id,
                                "private_unexpected_statusless_event",
                                {},
                                event_id=canonical_digest(
                                    {
                                        "run_id": observed_run_id,
                                        "history_race_target": target,
                                    }
                                ),
                            )
                        return original(
                            store,
                            observed_run_id,
                            event_type,
                            *args,
                            **kwargs,
                        )

                    with patch.object(
                        SQLiteStateStore,
                        "append_event_once",
                        new=append_unexpected_before_target,
                    ):
                        with self.assertRaises(ConfigurationError):
                            bind_repository_proposal_attempt(
                                state,
                                run_id=run.run_id,
                                registration=registration,
                            )

                    self.assertTrue(injected)
                    events, selections, bindings = self._proposal_events(
                        state,
                        run.run_id,
                    )
                    self.assertEqual(
                        len(selections),
                        int(
                            target
                            == REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE
                        ),
                    )
                    self.assertEqual(bindings, ())
                    self.assertEqual(
                        events[-1].event_type,
                        "private_unexpected_statusless_event",
                    )
                    self.assertEqual(
                        state.current_status(run.run_id),
                        RunStatus.CREATED,
                    )

    def test_precommit_failures_and_commit_then_raise_are_reconciled_exactly(
        self,
    ) -> None:
        for target in (
            REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
        ):
            for commit_first in (False, True):
                with (
                    self.subTest(target=target, commit_first=commit_first),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    base = Path(temporary)
                    root = self._repository(base)
                    registration = self._registration(root)
                    database = base / "state.sqlite3"
                    with SQLiteStateStore(database) as state:
                        run = self._create_run(
                            state,
                            run_id=f"private-failure-{int(commit_first)}-{target}",
                        )
                        original = SQLiteStateStore.append_event_once
                        injected = False

                        def injected_append(store, observed_run_id, event_type, *args, **kwargs):
                            nonlocal injected
                            if event_type == target and not injected:
                                injected = True
                                if commit_first:
                                    original(
                                        store,
                                        observed_run_id,
                                        event_type,
                                        *args,
                                        **kwargs,
                                    )
                                raise OSError("private injected persistence marker")
                            return original(
                                store,
                                observed_run_id,
                                event_type,
                                *args,
                                **kwargs,
                            )

                        with patch.object(
                            SQLiteStateStore,
                            "append_event_once",
                            new=injected_append,
                        ):
                            if commit_first:
                                result = bind_repository_proposal_attempt(
                                    state,
                                    run_id=run.run_id,
                                    registration=registration,
                                )
                                self.assertEqual(
                                    result.run_ref,
                                    canonical_digest({"run_id": run.run_id}),
                                )
                            else:
                                with self.assertRaises(ConfigurationError):
                                    bind_repository_proposal_attempt(
                                        state,
                                        run_id=run.run_id,
                                        registration=registration,
                                    )
                        self.assertTrue(injected)
                        events, selections, bindings = self._proposal_events(state, run.run_id)
                        if commit_first:
                            self.assertEqual((len(selections), len(bindings)), (1, 1))
                        elif target == REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE:
                            self.assertEqual((len(selections), len(bindings)), (0, 0))
                        else:
                            self.assertEqual((len(selections), len(bindings)), (1, 0))
                        self.assertEqual(state.current_status(run.run_id), RunStatus.CREATED)
                        persisted = "\n".join(event.payload_json for event in events)
                        self.assertNotIn("private injected persistence marker", persisted)

                        if not commit_first:
                            recovered = bind_repository_proposal_attempt(
                                state,
                                run_id=run.run_id,
                                registration=registration,
                            )
                            self.assertEqual(
                                recovered.run_ref,
                                canonical_digest({"run_id": run.run_id}),
                            )
                            self.assertEqual(len(state.list_events(run.run_id)), 3)

    def test_commit_failure_before_durability_rolls_back_and_never_reconciles(
        self,
    ) -> None:
        class CommitFailureConnection:
            def __init__(self, connection):
                self.connection = connection
                self.fail_next_commit = False

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def commit(self):
                if self.fail_next_commit:
                    self.fail_next_commit = False
                    raise sqlite3.OperationalError(
                        "private commit-before-durability marker"
                    )
                return self.connection.commit()

        for target in (
            REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                database = base / "state.sqlite3"
                with SQLiteStateStore(database) as state:
                    run = self._create_run(
                        state,
                        run_id=f"private-commit-failure-{target}",
                    )
                    proxy = CommitFailureConnection(state._connection)
                    state._connection = proxy
                    original = SQLiteStateStore.append_event_once
                    injected = False

                    def fail_target_commit(
                        store,
                        observed_run_id,
                        event_type,
                        *args,
                        **kwargs,
                    ):
                        nonlocal injected
                        if event_type == target and not injected:
                            injected = True
                            proxy.fail_next_commit = True
                        return original(
                            store,
                            observed_run_id,
                            event_type,
                            *args,
                            **kwargs,
                        )

                    with patch.object(
                        SQLiteStateStore,
                        "append_event_once",
                        new=fail_target_commit,
                    ):
                        with self.assertRaisesRegex(
                            ConfigurationError,
                            "repository proposal evidence persistence is uncertain",
                        ):
                            bind_repository_proposal_attempt(
                                state,
                                run_id=run.run_id,
                                registration=registration,
                            )

                    self.assertTrue(injected)
                    self.assertFalse(state._connection.in_transaction)
                    with closing(sqlite3.connect(database)) as independent:
                        persisted_types = tuple(
                            row[0]
                            for row in independent.execute(
                                """
                                SELECT event_type FROM run_events
                                WHERE run_id = ? ORDER BY sequence
                                """,
                                (run.run_id,),
                            ).fetchall()
                        )
                    self.assertNotIn(target, persisted_types)
                    self.assertEqual(
                        persisted_types,
                        (
                            ("status",)
                            if target
                            == REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE
                            else (
                                "status",
                                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                            )
                        ),
                    )

                    recovered = bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )
                    self.assertEqual(recovered.proposal_digest, DEFAULT_PROPOSAL_DIGEST)
                    self.assertEqual(len(state.get_run_snapshot(run.run_id).events), 3)

    def test_binding_uses_only_consistent_run_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            with SQLiteStateStore(base / "state.sqlite3") as state:
                run = self._create_run(state)
                with (
                    patch.object(
                        SQLiteStateStore,
                        "get_run",
                        side_effect=AssertionError("legacy split run read"),
                    ),
                    patch.object(
                        SQLiteStateStore,
                        "list_events",
                        side_effect=AssertionError("legacy split event read"),
                    ),
                    patch.object(
                        SQLiteStateStore,
                        "current_status",
                        side_effect=AssertionError("legacy split status read"),
                    ),
                ):
                    result = bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )
                snapshot = state.get_run_snapshot(run.run_id)
                self.assertEqual(result.to_evidence()["run_status_at_readback"], "created")
                self.assertEqual(len(snapshot.events), 3)
                self.assertEqual(snapshot.current_status, RunStatus.CREATED)

    def test_run_snapshot_is_consistent_during_concurrent_append(self) -> None:
        class CallbackCursor:
            def __init__(self, cursor, callback):
                self.cursor = cursor
                self.callback = callback

            def __getattr__(self, name):
                return getattr(self.cursor, name)

            def fetchone(self):
                row = self.cursor.fetchone()
                self.callback()
                return row

        class InterleavingConnection:
            def __init__(self, connection, callback):
                self.connection = connection
                self.callback = callback

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def execute(self, statement, parameters=()):
                cursor = self.connection.execute(statement, parameters)
                normalized = " ".join(statement.split())
                if normalized.startswith("SELECT * FROM runs WHERE run_id"):
                    return CallbackCursor(cursor, self.callback)
                return cursor

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database = base / "state.sqlite3"
            with (
                SQLiteStateStore(database) as reader,
                SQLiteStateStore(database) as writer,
            ):
                run = self._create_run(reader)
                appended = False

                def append_after_run_read() -> None:
                    nonlocal appended
                    if appended:
                        return
                    appended = True
                    writer.append_event(
                        run.run_id,
                        "private_concurrent_snapshot_event",
                        {},
                        event_id=canonical_digest(
                            {"snapshot_race_run_id": run.run_id}
                        ),
                    )

                reader._connection = InterleavingConnection(
                    reader._connection,
                    append_after_run_read,
                )
                snapshot = reader.get_run_snapshot(run.run_id)

                self.assertTrue(appended)
                self.assertEqual(
                    tuple(event.event_type for event in snapshot.events),
                    ("status",),
                )
                self.assertEqual(snapshot.current_status, RunStatus.CREATED)
                self.assertEqual(
                    tuple(event.event_type for event in reader.list_events(run.run_id)),
                    ("status", "private_concurrent_snapshot_event"),
                )

    def test_committed_baseexception_is_preserved_and_later_reconciled(self) -> None:
        for target in (
            REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
            REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                registration = self._registration(root)
                with SQLiteStateStore(base / "state.sqlite3") as state:
                    run = self._create_run(
                        state,
                        run_id=f"private-baseexception-{target}",
                    )
                    original = SQLiteStateStore.append_event_once
                    injected = False

                    def interrupt_after_commit(store, observed_run_id, event_type, *args, **kwargs):
                        nonlocal injected
                        result = original(
                            store,
                            observed_run_id,
                            event_type,
                            *args,
                            **kwargs,
                        )
                        if event_type == target and not injected:
                            injected = True
                            raise KeyboardInterrupt("private interruption marker")
                        return result

                    with patch.object(
                        SQLiteStateStore,
                        "append_event_once",
                        new=interrupt_after_commit,
                    ):
                        with self.assertRaises(KeyboardInterrupt):
                            bind_repository_proposal_attempt(
                                state,
                                run_id=run.run_id,
                                registration=registration,
                            )

                    _, selections, bindings = self._proposal_events(state, run.run_id)
                    self.assertEqual(len(selections), 1)
                    self.assertEqual(
                        len(bindings),
                        int(target == REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE),
                    )
                    recovered = bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )
                    self.assertEqual(recovered.run_ref, canonical_digest({"run_id": run.run_id}))
                    self.assertEqual(len(state.list_events(run.run_id)), 3)

    def test_concurrent_exact_and_conflicting_calls_preserve_single_pair(self) -> None:
        for conflicting in (False, True):
            with self.subTest(conflicting=conflicting), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self._repository(base)
                first_registration = self._registration(root)
                second_payload = deepcopy(self._registration_payload())
                second_payload["registration_version"] = "1.0.1"
                second_registration = self._registration(root, payload=second_payload)
                database = base / "state.sqlite3"
                run_id = f"private-concurrent-{int(conflicting)}-run-marker"
                with SQLiteStateStore(database) as initial:
                    self._create_run(initial, run_id=run_id)

                stores = (SQLiteStateStore(database), SQLiteStateStore(database))
                barrier = threading.Barrier(2)
                registrations = (
                    first_registration,
                    second_registration if conflicting else first_registration,
                )

                def invoke(index: int):
                    barrier.wait(timeout=5)
                    try:
                        return (
                            "ok",
                            bind_repository_proposal_attempt(
                                stores[index],
                                run_id=run_id,
                                registration=registrations[index],
                            ),
                        )
                    except Exception as error:
                        return ("error", error)

                try:
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        outcomes = tuple(executor.map(invoke, (0, 1)))
                finally:
                    for store in stores:
                        store.close()

                with SQLiteStateStore(database) as state:
                    events, selections, bindings = self._proposal_events(state, run_id)
                    self.assertEqual(len(events), 3)
                    self.assertEqual(len(selections), 1)
                    self.assertEqual(len(bindings), 1)
                    self.assertEqual(state.current_status(run_id), RunStatus.CREATED)
                if conflicting:
                    self.assertEqual([outcome[0] for outcome in outcomes].count("ok"), 1)
                    self.assertEqual([outcome[0] for outcome in outcomes].count("error"), 1)
                    error = next(value for kind, value in outcomes if kind == "error")
                    self.assertIsInstance(error, (ConfigurationError, ValidationError))
                else:
                    self.assertEqual([outcome[0] for outcome in outcomes], ["ok", "ok"])
                    self.assertEqual(outcomes[0][1], outcomes[1][1])

    def test_events_are_append_only_and_binding_has_no_schema_or_repo_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._repository(base)
            registration = self._registration(root)
            database = base / "state.sqlite3"
            with SQLiteStateStore(database) as state:
                run = self._create_run(state)
                schema_before = self._schema_snapshot(database)
                tree_before = self._tree_snapshot(root)
                with (
                    patch.object(
                        subprocess,
                        "run",
                        side_effect=AssertionError("must not run a process"),
                    ) as run_process,
                    patch.object(
                        subprocess,
                        "Popen",
                        side_effect=AssertionError("must not start a process"),
                    ) as popen_process,
                    patch.object(
                        os,
                        "system",
                        side_effect=AssertionError("must not invoke a shell"),
                    ) as shell_process,
                ):
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        registration=registration,
                    )
                run_process.assert_not_called()
                popen_process.assert_not_called()
                shell_process.assert_not_called()
                self.assertEqual(self._tree_snapshot(root), tree_before)
                self.assertEqual(self._schema_snapshot(database), schema_before)
                self.assertEqual(state.current_status(run.run_id), RunStatus.CREATED)

            with closing(sqlite3.connect(database)) as connection:
                for statement in (
                    """
                    UPDATE run_events SET event_type = 'changed'
                    WHERE event_type = 'repository_registration_selection'
                    """,
                    """
                    DELETE FROM run_events
                    WHERE event_type = 'repository_proposal_attempt_binding'
                    """,
                ):
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                        connection.execute(statement)
                    connection.rollback()


if __name__ == "__main__":
    unittest.main()
