from __future__ import annotations

from contextlib import closing
from dataclasses import FrozenInstanceError, replace
import inspect
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

from ordomata import (
    repository_proposal_admission as repository_proposal_admission_module,
)
from ordomata.authorization import (
    AuthorizationEffect,
    canonical_digest,
)
from ordomata.errors import ConfigurationError, ValidationError
from ordomata.models import PermissionClass
from ordomata.repository_proposal import (
    REPOSITORY_PROPOSAL_RUNNER_ID,
    bind_repository_proposal_attempt,
)
from ordomata.repository_proposal_admission import (
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION,
    REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION,
    REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE,
    REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION,
    REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE,
    RepositoryProposalAdmissionShadow,
    evaluate_repository_proposal_admission_shadow,
)
from ordomata.repository_proposal_inspection import (
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


_RESULT_MAPPING_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "mode",
        "action_scope",
        "decision_authoritative",
        "enforcement_enabled",
        "authority_granted",
        "admission_performed",
        "action_performed",
        "action_receipt_created",
        "evidence_persisted",
        "repair_performed",
        "dispatch_enabled",
        "route_selected",
        "billing_assessed",
        "obligations_enforced",
        "run_ref",
        "inspection",
        "inspection_digest",
        "requested_permission_class",
        "evaluation_status",
        "request",
        "request_digest",
        "policy",
        "policy_digest",
        "decision",
        "decision_digest",
        "effect",
        "derived_permission_class",
        "decision_current_at_evaluation",
        "permission_class_matches",
        "obligations_exact",
        "shadow_eligible",
        "block_reason_codes",
        "evaluated_at",
    }
)
_NO_EFFECT_KEYS = (
    "decision_authoritative",
    "enforcement_enabled",
    "authority_granted",
    "admission_performed",
    "action_performed",
    "action_receipt_created",
    "evidence_persisted",
    "repair_performed",
    "dispatch_enabled",
    "route_selected",
    "billing_assessed",
    "obligations_enforced",
)
_PROPOSAL_DIGEST = canonical_digest(
    {"proposal": "private-proposal-admission-content-marker"}
)
_PRIVATE_MARKERS = (
    "private-proposal-admission-run-marker",
    "private-proposal-admission-second-run-marker",
    "private-proposal-admission-id-marker",
    "private-proposal-admission-version-marker",
    "private-registration-admission-id-marker",
    "private-repository-admission-id-marker",
    "private-repository-admission-root-marker",
    "private-workspace-admission-marker",
    "private-run-directory-admission-marker",
    "private-command-admission-marker",
    "private-test-command-admission-marker",
    "private-evaluator-failure-marker",
    "private-evaluator-forgery-marker",
    "private-missing-admission-marker",
    "private-corrupt-admission-marker",
)


class RepositoryProposalAdmissionShadowTests(unittest.TestCase):
    @staticmethod
    def _repository(base: Path) -> Path:
        root = base / "private-repository-admission-root-marker"
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
            "registration_id": "private-registration-admission-id-marker",
            "registration_version": "1.0.0",
            "repository": {
                "repository_id": "private-repository-admission-id-marker",
                "vcs": "git",
                "root": ".",
            },
            "verification_commands": {
                "format": [
                    {
                        "command_id": "private-command-admission-marker",
                        "argv": [
                            "python3",
                            "-m",
                            "compileall",
                            "-q",
                            "source",
                        ],
                        "cwd": ".",
                    }
                ],
                "lint": [],
                "type_check": [],
                "test": [
                    {
                        "command_id": "private-test-command-admission-marker",
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
        run_id: str = "private-proposal-admission-run-marker",
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
    ) -> RunRecord:
        return state.create_run(
            RunRecord(
                run_id=run_id,
                task_id="private-proposal-admission-id-marker",
                task_version="private-proposal-admission-version-marker",
                runner_id=REPOSITORY_PROPOSAL_RUNNER_ID,
                workspace=(
                    "/synthetic-private-workspace-admission-marker/"
                    + run_id
                ),
                run_directory=(
                    "/synthetic-private-run-directory-admission-marker/"
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
    def _create_created_only(
        cls,
        base: Path,
        *,
        run_id: str = "private-proposal-admission-run-marker",
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
    ) -> tuple[Path, Path, RunRecord]:
        root = cls._repository(base)
        database = base / "state.sqlite3"
        with SQLiteStateStore(database, clock=lambda: 101.0) as state:
            run = cls._create_run(
                state,
                run_id=run_id,
                permission_class=permission_class,
            )
        return database, root, run

    @classmethod
    def _create_complete(
        cls,
        base: Path,
        *,
        run_id: str = "private-proposal-admission-run-marker",
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
    ) -> tuple[Path, Path, RunRecord]:
        database, root, run = cls._create_created_only(
            base,
            run_id=run_id,
            permission_class=permission_class,
        )
        with SQLiteStateStore(database, clock=lambda: 102.0) as state:
            bind_repository_proposal_attempt(
                state,
                run_id=run.run_id,
                proposal_digest=_PROPOSAL_DIGEST,
                registration=cls._registration(root),
            )
        return database, root, run

    @staticmethod
    def _schema_snapshot(database: Path) -> tuple[object, ...]:
        with closing(sqlite3.connect(database)) as connection:
            objects = tuple(
                connection.execute(
                    """
                    SELECT type, name, tbl_name, sql
                    FROM sqlite_master
                    ORDER BY type, name
                    """
                ).fetchall()
            )
            runs = tuple(
                connection.execute(
                    """
                    SELECT
                        run_id, task_id, task_version, runner_id,
                        workspace, run_directory, context_digest,
                        permission_class, timeout_seconds, attempt, created_at
                    FROM runs ORDER BY run_id
                    """
                ).fetchall()
            )
            events = tuple(
                connection.execute(
                    """
                    SELECT run_id, sequence, event_type, event_id, payload_json
                    FROM run_events ORDER BY run_id, sequence
                    """
                ).fetchall()
            )
        return objects, runs, events

    def _assert_private_values_absent(self, value: object) -> None:
        projection = json.dumps(value, sort_keys=True, default=str)
        for marker in _PRIVATE_MARKERS:
            self.assertNotIn(marker, projection)

    def _assert_no_effect(self, mapping: dict[str, object]) -> None:
        for key in _NO_EFFECT_KEYS:
            self.assertIs(mapping[key], False, key)

    def _assert_fixed_mapping(
        self,
        result: RepositoryProposalAdmissionShadow,
    ) -> dict[str, object]:
        mapping = result.to_mapping()
        self.assertEqual(frozenset(mapping), _RESULT_MAPPING_KEYS)
        self.assertEqual(
            mapping["schema_version"],
            REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION,
        )
        self.assertEqual(
            mapping["kind"],
            REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND,
        )
        self.assertEqual(mapping["mode"], "shadow")
        self.assertEqual(
            mapping["action_scope"],
            REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE,
        )
        self._assert_no_effect(mapping)
        self.assertEqual(
            canonical_digest(mapping["inspection"]),
            mapping["inspection_digest"],
        )
        self._assert_private_values_absent(mapping)
        return mapping

    def test_clean_class_zero_and_one_have_exact_fixed_shadow_projections(
        self,
    ) -> None:
        cases = (
            (
                PermissionClass.READ_ONLY,
                "read",
                REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION,
                REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE,
                "read_only",
            ),
            (
                PermissionClass.LOCAL_DRAFT,
                "create",
                REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION,
                REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE,
                "isolated_local_only",
            ),
        )
        for (
            permission_class,
            verb,
            operation,
            resource_type,
            class_obligation,
        ) in cases:
            with (
                self.subTest(permission_class=permission_class),
                tempfile.TemporaryDirectory() as temporary,
            ):
                database, _, run = self._create_complete(
                    Path(temporary),
                    permission_class=permission_class,
                )

                result = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=run.run_id,
                    evaluated_at=200.0,
                )
                mapping = self._assert_fixed_mapping(result)

                expected_run_ref = canonical_digest({"run_id": run.run_id})
                self.assertEqual(result.run_ref, expected_run_ref)
                self.assertEqual(mapping["run_ref"], expected_run_ref)
                self.assertEqual(mapping["evaluation_status"], "evaluated")
                self.assertEqual(
                    mapping["requested_permission_class"],
                    int(permission_class),
                )
                self.assertEqual(
                    mapping["derived_permission_class"],
                    int(permission_class),
                )
                self.assertEqual(mapping["effect"], "permit")
                self.assertTrue(mapping["decision_current_at_evaluation"])
                self.assertTrue(mapping["permission_class_matches"])
                self.assertTrue(mapping["obligations_exact"])
                self.assertTrue(mapping["shadow_eligible"])
                self.assertEqual(mapping["block_reason_codes"], [])

                request = mapping["request"]
                policy = mapping["policy"]
                decision = mapping["decision"]
                self.assertIsInstance(request, dict)
                self.assertIsInstance(policy, dict)
                self.assertIsInstance(decision, dict)
                assert isinstance(request, dict)
                assert isinstance(policy, dict)
                assert isinstance(decision, dict)
                self.assertEqual(
                    canonical_digest(request),
                    mapping["request_digest"],
                )
                self.assertEqual(
                    canonical_digest(policy),
                    mapping["policy_digest"],
                )
                self.assertEqual(
                    canonical_digest(decision),
                    mapping["decision_digest"],
                )
                self.assertEqual(request["action"]["verb"], verb)
                self.assertEqual(request["action"]["operation"], operation)
                self.assertEqual(
                    request["resource"]["resource_type"],
                    resource_type,
                )
                self.assertEqual(
                    request["resource"]["content_digest"],
                    mapping["inspection_digest"],
                )
                self.assertEqual(
                    request["resource"]["repository_id"],
                    mapping["inspection"]["repository_ref"],
                )
                self.assertEqual(
                    request["subject"],
                    {
                        "controller_id": "ordomata:local-controller",
                        "principal_id": (
                            "controller:repository-proposal-admission-shadow"
                        ),
                        "profile_id": "profile:not-applicable-local-non-ai",
                        "role": "controller",
                        "role_version": "1",
                        "runner_id": "repository-proposal-disabled",
                        "session_id": f"repository-proposal:{expected_run_ref}",
                    },
                )
                self.assertEqual(
                    request["environment"]["billing_route"],
                    "local_non_ai",
                )
                self.assertEqual(
                    request["environment"]["capacity_state"],
                    "not_applicable",
                )
                self.assertEqual(
                    request["environment"]["network_state"],
                    "disabled",
                )
                self.assertEqual(
                    request["environment"][
                        "paid_continuation_protection"
                    ],
                    "not_applicable",
                )
                self.assertEqual(
                    tuple(
                        (
                            evidence["attribute"],
                            evidence["source"],
                            evidence["authenticated"],
                        )
                        for evidence in request["evidence"]
                    ),
                    (
                        ("action", "controller", True),
                        ("consequences", "controller", True),
                        ("environment", "controller", True),
                        ("resource", "local_registry", True),
                        ("subject", "controller", True),
                    ),
                )

                self.assertEqual(
                    policy["bundle_id"],
                    (
                        f"{REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID}."
                        f"class-{int(permission_class)}"
                    ),
                )
                self.assertEqual(
                    policy["version"],
                    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION,
                )
                self.assertEqual(
                    policy["enabled_classes"],
                    [int(permission_class)],
                )
                self.assertEqual(policy["allowed_roles"], ["controller"])
                self.assertEqual(policy["allowed_verbs"], [verb])
                self.assertEqual(
                    policy["allowed_operations"],
                    [operation],
                )
                self.assertEqual(
                    policy["allowed_resource_types"],
                    [resource_type],
                )
                self.assertEqual(
                    policy["allowed_network_states"],
                    ["disabled"],
                )
                self.assertEqual(
                    policy["allowed_billing_routes"],
                    ["local_non_ai"],
                )
                self.assertEqual(
                    decision["policy_bundle_id"],
                    policy["bundle_id"],
                )
                self.assertEqual(
                    decision["request_digest"],
                    mapping["request_digest"],
                )
                self.assertEqual(decision["effect"], "permit")
                self.assertEqual(
                    decision["derived_permission_class"],
                    int(permission_class),
                )
                self.assertEqual(
                    decision["obligations"],
                    [
                        {
                            "kind": "audit_receipt",
                            "value": "append_after_action",
                        },
                        {
                            "kind": class_obligation,
                            "value": "required",
                        },
                    ],
                )
                self.assertEqual(decision["issued_at"], 200.0)
                self.assertEqual(decision["expires_at"], 230.0)

                mapping["inspection"]["coverage"] = "forged"
                mapping["block_reason_codes"].append("forged")
                self.assertEqual(
                    result.to_mapping()["inspection"]["coverage"],
                    "complete",
                )
                self.assertEqual(
                    result.to_mapping()["block_reason_codes"],
                    [],
                )

    def test_incomplete_inspection_skips_authorization_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, _, run = self._create_created_only(Path(temporary))

            with patch.object(
                repository_proposal_admission_module,
                "ShadowAuthorizationEvaluator",
                side_effect=AssertionError(
                    "authorization evaluator must not be called"
                ),
            ) as evaluator:
                result = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=run.run_id,
                    evaluated_at=200.0,
                )

            evaluator.assert_not_called()
            mapping = self._assert_fixed_mapping(result)
            self.assertEqual(result.effect, AuthorizationEffect.INDETERMINATE)
            self.assertEqual(mapping["effect"], "indeterminate")
            self.assertEqual(mapping["evaluation_status"], "not_evaluated")
            self.assertEqual(
                mapping["block_reason_codes"],
                ["inspection_not_clean_complete"],
            )
            self.assertFalse(mapping["inspection"]["clean"])
            self.assertEqual(mapping["inspection"]["coverage"], "incomplete")
            self.assertIsNone(mapping["request"])
            self.assertIsNone(mapping["request_digest"])
            self.assertIsNone(mapping["policy"])
            self.assertIsNone(mapping["policy_digest"])
            self.assertIsNone(mapping["decision"])
            self.assertIsNone(mapping["decision_digest"])
            self.assertFalse(mapping["shadow_eligible"])

    def test_public_api_freshly_reinspects_and_accepts_no_report_or_policy(
        self,
    ) -> None:
        signature = inspect.signature(
            evaluate_repository_proposal_admission_shadow
        )
        self.assertEqual(
            tuple(signature.parameters),
            ("database_path", "run_id", "evaluated_at"),
        )
        self.assertEqual(
            signature.parameters["run_id"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            signature.parameters["evaluated_at"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        for forbidden in (
            "inspection",
            "report",
            "policy",
            "request",
            "evaluator",
            "permission_class",
        ):
            self.assertNotIn(forbidden, signature.parameters)

        with tempfile.TemporaryDirectory() as temporary:
            database, root, run = self._create_created_only(Path(temporary))
            public_inspector = (
                repository_proposal_admission_module
                .inspect_repository_proposal_evidence
            )
            with patch.object(
                repository_proposal_admission_module,
                "inspect_repository_proposal_evidence",
                side_effect=AssertionError(
                    "mutable public inspector alias must not be trusted"
                ),
            ) as substituted:
                first = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=run.run_id,
                    evaluated_at=200.0,
                )
                with SQLiteStateStore(
                    database,
                    clock=lambda: 201.0,
                ) as state:
                    bind_repository_proposal_attempt(
                        state,
                        run_id=run.run_id,
                        proposal_digest=_PROPOSAL_DIGEST,
                        registration=self._registration(root),
                    )
                second = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=run.run_id,
                    evaluated_at=202.0,
                )

            substituted.assert_not_called()
            self.assertIs(
                public_inspector,
                inspect_repository_proposal_evidence,
            )
            self.assertEqual(first.evaluation_status, "not_evaluated")
            self.assertEqual(second.evaluation_status, "evaluated")
            self.assertFalse(first.inspection.clean)
            self.assertTrue(second.inspection.clean)
            self.assertNotEqual(
                first.inspection_digest,
                second.inspection_digest,
            )
            self.assertTrue(second.shadow_eligible)

    def test_cross_run_inspection_mismatch_fails_before_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, _, run = self._create_complete(Path(temporary))
            inspection = inspect_repository_proposal_evidence(
                database,
                run_id=run.run_id,
            )
            other_run_id = "private-proposal-admission-second-run-marker"

            with (
                patch.object(
                    repository_proposal_admission_module,
                    "_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE",
                    return_value=inspection,
                ),
                patch.object(
                    repository_proposal_admission_module,
                    "ShadowAuthorizationEvaluator",
                    side_effect=AssertionError(
                        "mismatched inspection must not be evaluated"
                    ),
                ) as evaluator,
            ):
                result = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=other_run_id,
                    evaluated_at=200.0,
                )

            evaluator.assert_not_called()
            mapping = self._assert_fixed_mapping(result)
            self.assertEqual(
                mapping["run_ref"],
                canonical_digest({"run_id": other_run_id}),
            )
            self.assertNotEqual(
                mapping["run_ref"],
                mapping["inspection"]["run_ref"],
            )
            self.assertEqual(mapping["evaluation_status"], "failed")
            self.assertEqual(
                mapping["block_reason_codes"],
                ["inspection_run_binding_mismatch"],
            )
            self.assertEqual(mapping["effect"], "indeterminate")
            self.assertIsNone(mapping["request"])
            self.assertIsNone(mapping["policy"])
            self.assertIsNone(mapping["decision"])

    def test_evaluator_substitution_and_failures_are_inert_and_sanitized(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, _, run = self._create_complete(Path(temporary))
            baseline = evaluate_repository_proposal_admission_shadow(
                database,
                run_id=run.run_id,
                evaluated_at=200.0,
            )
            assert baseline.decision is not None
            forged = replace(
                baseline.decision,
                reason_details=(
                    "private-evaluator-forgery-marker",
                ),
            )

            class SubstitutedEvaluator:
                def evaluate(self, request, policy):
                    return forged

            with patch.object(
                repository_proposal_admission_module,
                "ShadowAuthorizationEvaluator",
                SubstitutedEvaluator,
            ):
                mismatch = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=run.run_id,
                    evaluated_at=200.0,
                )

            mismatch_mapping = self._assert_fixed_mapping(mismatch)
            self.assertEqual(mismatch.evaluation_status, "failed")
            self.assertEqual(
                mismatch.block_reason_codes,
                ("authorization_replay_mismatch",),
            )
            self.assertEqual(mismatch.effect, AuthorizationEffect.INDETERMINATE)
            self.assertIsNone(mismatch.request)
            self.assertIsNone(mismatch.policy)
            self.assertIsNone(mismatch.decision)
            self.assertNotIn(
                "private-evaluator-forgery-marker",
                json.dumps(mismatch_mapping, sort_keys=True),
            )

            with patch.object(
                repository_proposal_admission_module,
                "ShadowAuthorizationEvaluator",
                side_effect=RuntimeError(
                    "private-evaluator-failure-marker"
                ),
            ):
                failed = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=run.run_id,
                    evaluated_at=200.0,
                )

            failed_mapping = self._assert_fixed_mapping(failed)
            self.assertEqual(failed.evaluation_status, "failed")
            self.assertEqual(
                failed.block_reason_codes,
                ("authorization_evaluation_failed",),
            )
            self.assertEqual(failed.effect, AuthorizationEffect.INDETERMINATE)
            self.assertIsNone(failed.request)
            self.assertIsNone(failed.policy)
            self.assertIsNone(failed.decision)
            self.assertNotIn(
                "private-evaluator-failure-marker",
                json.dumps(failed_mapping, sort_keys=True),
            )

    def test_invalid_time_and_inspection_fail_with_fixed_messages(self) -> None:
        invalid_times = (
            None,
            True,
            "200",
            -1,
            float("nan"),
            float("inf"),
            -float("inf"),
            10**10_000,
        )
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "private-missing-admission-marker"
            for evaluated_at in invalid_times:
                with (
                    self.subTest(evaluated_at=type(evaluated_at).__name__),
                    patch.object(
                        repository_proposal_admission_module,
                        "_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE",
                        side_effect=AssertionError(
                            "invalid time must fail before inspection"
                        ),
                    ) as inspector,
                    self.assertRaises(ValidationError) as caught,
                ):
                    evaluate_repository_proposal_admission_shadow(
                        database,
                        run_id="private-proposal-admission-run-marker",
                        evaluated_at=evaluated_at,
                    )
                inspector.assert_not_called()
                self.assertEqual(
                    str(caught.exception),
                    "repository proposal admission shadow request is invalid",
                )
            self.assertFalse(database.exists())

        for invalid_inspection in (None, {}, object()):
            with (
                self.subTest(type=type(invalid_inspection).__name__),
                patch.object(
                    repository_proposal_admission_module,
                    "_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE",
                    return_value=invalid_inspection,
                ),
                self.assertRaises(ValidationError) as caught,
            ):
                evaluate_repository_proposal_admission_shadow(
                    "private-corrupt-admission-marker",
                    run_id="private-proposal-admission-run-marker",
                    evaluated_at=200.0,
                )
            self.assertEqual(
                str(caught.exception),
                (
                    "repository proposal admission shadow inspection "
                    "result is invalid"
                ),
            )
            self.assertNotIn(
                "private-corrupt-admission-marker",
                str(caught.exception),
            )

    def test_inspection_errors_remain_fixed_and_do_not_create_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            missing = (
                base
                / "private-missing-admission-marker"
                / "state.sqlite3"
            )
            with self.assertRaises(RecordNotFoundError) as caught:
                evaluate_repository_proposal_admission_shadow(
                    missing,
                    run_id="private-missing-admission-marker",
                    evaluated_at=200.0,
                )
            self.assertEqual(
                str(caught.exception),
                "requested repository proposal run was not found",
            )
            self.assertFalse(missing.parent.exists())

            corrupt = base / "private-corrupt-admission-marker.sqlite3"
            corrupt.write_bytes(b"private-corrupt-admission-marker")
            with self.assertRaises(ConfigurationError) as caught:
                evaluate_repository_proposal_admission_shadow(
                    corrupt,
                    run_id="private-proposal-admission-run-marker",
                    evaluated_at=200.0,
                )
            self.assertEqual(
                str(caught.exception),
                (
                    "repository proposal inspection database is unreadable "
                    "or malformed"
                ),
            )
            self.assertNotIn(str(corrupt), str(caught.exception))
            self.assertNotIn(
                "private-corrupt-admission-marker",
                str(caught.exception),
            )

    def test_result_rejects_normal_construction_and_detects_low_level_tamper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, _, run = self._create_complete(Path(temporary))
            result = evaluate_repository_proposal_admission_shadow(
                database,
                run_id=run.run_id,
                evaluated_at=200.0,
            )

        with self.assertRaises(FrozenInstanceError):
            result.evaluation_status = "failed"  # type: ignore[misc]
        with self.assertRaises(TypeError) as caught:
            replace(result, inspection_digest="sha256:" + "f" * 64)
        self.assertEqual(
            str(caught.exception),
            "repository proposal admission shadows are factory-created",
        )
        with self.assertRaises(TypeError) as caught:
            result.__setstate__((None,))
        self.assertEqual(
            str(caught.exception),
            "repository proposal admission shadows are factory-created",
        )
        object.__setattr__(
            result,
            "inspection_digest",
            "sha256:" + "f" * 64,
        )
        self.assertFalse(result.shadow_eligible)
        with self.assertRaises(TypeError) as caught:
            RepositoryProposalAdmissionShadow(
                run_ref=result.run_ref,
                inspection=result.inspection,
                inspection_digest=result.inspection_digest,
                evaluated_at=result.evaluated_at,
                requested_permission_class=result.requested_permission_class,
                evaluation_status="invented",
                request=None,
                policy=None,
                decision=None,
                block_reason_codes=(),
            )
        self.assertEqual(
            str(caught.exception),
            "repository proposal admission shadows are factory-created",
        )

    def test_evaluation_is_query_only_and_exposes_no_effect_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            database, root, run = self._create_complete(base)
            before_bytes = database.read_bytes()
            before_schema = self._schema_snapshot(database)
            before_paths = tuple(
                sorted(
                    (
                        path.relative_to(base).as_posix(),
                        path.stat().st_size,
                    )
                    for path in base.rglob("*")
                )
            )
            before_repository = tuple(
                sorted(
                    (
                        path.relative_to(root).as_posix(),
                        path.stat().st_size,
                    )
                    for path in root.rglob("*")
                )
            )

            with (
                patch.object(
                    SQLiteStateStore,
                    "__init__",
                    side_effect=AssertionError(
                        "admission shadow must not open mutable state"
                    ),
                ),
                patch.object(
                    subprocess,
                    "Popen",
                    side_effect=AssertionError(
                        "admission shadow must not spawn a process"
                    ),
                ),
                patch.object(
                    subprocess,
                    "run",
                    side_effect=AssertionError(
                        "admission shadow must not run a command"
                    ),
                ),
                patch.object(
                    socket,
                    "create_connection",
                    side_effect=AssertionError(
                        "admission shadow must not use a network"
                    ),
                ),
                patch.object(
                    urllib.request,
                    "urlopen",
                    side_effect=AssertionError(
                        "admission shadow must not use a network"
                    ),
                ),
            ):
                result = evaluate_repository_proposal_admission_shadow(
                    database,
                    run_id=run.run_id,
                    evaluated_at=200.0,
                )

            mapping = self._assert_fixed_mapping(result)
            self.assertTrue(mapping["shadow_eligible"])
            self.assertEqual(database.read_bytes(), before_bytes)
            self.assertEqual(self._schema_snapshot(database), before_schema)
            self.assertEqual(
                tuple(
                    sorted(
                        (
                            path.relative_to(base).as_posix(),
                            path.stat().st_size,
                        )
                        for path in base.rglob("*")
                    )
                ),
                before_paths,
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

        self.assertEqual(
            set(repository_proposal_admission_module.__all__),
            {
                "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE",
                "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND",
                "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID",
                "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION",
                "REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION",
                "REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION",
                "REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE",
                "REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION",
                "REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE",
                "RepositoryProposalAdmissionShadow",
                "evaluate_repository_proposal_admission_shadow",
            },
        )
        for forbidden in (
            "admit",
            "authorize",
            "dispatch",
            "enforce",
            "execute",
            "persist",
            "promote",
            "receipt",
            "repair",
            "route",
        ):
            self.assertFalse(
                any(
                    forbidden in name.casefold()
                    for name in repository_proposal_admission_module.__all__
                    if name
                    not in {
                        "RepositoryProposalAdmissionShadow",
                        "evaluate_repository_proposal_admission_shadow",
                    }
                ),
                forbidden,
            )


if __name__ == "__main__":
    unittest.main()
