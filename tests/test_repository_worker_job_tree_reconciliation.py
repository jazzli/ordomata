from __future__ import annotations

import ast
from contextlib import ExitStack
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ordomata.repository_worker_job_tree_reconciliation as reconciliation_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
from ordomata.repository_registration import (
    BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
    REPOSITORY_REGISTRATION_EVIDENCE_KIND,
)
from ordomata.repository_worker_job_tree import (
    RepositoryWorkerJobTreeSourceFile,
    derive_repository_worker_job_tree_contract,
)
from ordomata.repository_worker_job_tree_materialization import (
    RepositoryWorkerJobTreeMaterializationLease,
    materialize_repository_worker_job_tree,
)
from ordomata.repository_worker_job_tree_reconciliation import (
    RECONCILIATION_SCOPE,
    REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND,
    REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND,
    REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_KIND,
    REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION,
    RepositoryWorkerJobTreeCandidateBundle,
    RepositoryWorkerJobTreePatchOperation,
    derive_repository_worker_job_tree_reconciliation,
)
from ordomata.repository_worker_job_tree_snapshot import (
    capture_repository_worker_job_tree_source_snapshot,
)


_PRIVATE_MARKER = "private-reconciliation-source-marker"
_CANDIDATE_MARKER = "private-reconciliation-candidate-marker"


def _ref(label: str) -> str:
    return canonical_digest({"fixture": label})


def _path_policy() -> dict[str, object]:
    return {
        "allowed_paths": ["docs", "source", "tests"],
        "generated_paths": ["source/generated"],
        "protected_paths": [
            ".agentops",
            ".git",
            ".ordomata",
            "source/protected",
        ],
        "vendor_paths": ["vendor"],
    }


def _resource_limits() -> dict[str, int]:
    return {
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
    }


def _registration_evidence(
    *,
    path_policy: dict[str, object],
    resource_limits: dict[str, int],
) -> dict[str, object]:
    return {
        "authority_granted": False,
        "baseline_attestation_source": (
            BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE
        ),
        "baseline_authenticity_verified": False,
        "baseline_command_results_digest": _ref("baseline"),
        "baseline_freshness_verified": False,
        "baseline_result_count": 2,
        "dispatch_enabled": False,
        "executable_toolchain_attestation_source": (
            EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE
        ),
        "executable_toolchain_authenticity_verified": False,
        "executable_toolchain_content_verified": False,
        "executable_toolchain_execution_correspondence_verified": False,
        "executable_toolchain_freshness_verified": False,
        "executable_toolchain_identities_digest": _ref("identities"),
        "executable_toolchain_identity_count": 2,
        "executable_toolchain_resolution_verified": False,
        "filesystem_identity_ref": _ref("filesystem"),
        "isolation_requirements_digest": _ref("isolation"),
        "kind": REPOSITORY_REGISTRATION_EVIDENCE_KIND,
        "path_policy_digest": canonical_digest(path_policy),
        "registration_digest": _ref("registration"),
        "registration_ref": _ref("registration-id"),
        "registration_version": "4.0.0",
        "repository_ref": _ref("repository"),
        "resource_limits_digest": canonical_digest(resource_limits),
        "review_policy_digest": _ref("review-policy"),
        "schema_version": 4,
        "toolchain_completeness_verified": False,
        "validation_mode": "read_only",
        "verification_commands_digest": _ref("commands"),
    }


class RepositoryWorkerJobTreeReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.source_root = self.root / "source-root"
        self.job_root = self.root / "job-root"
        self.source_root.mkdir(mode=0o700)
        self.job_root.mkdir(mode=0o700)
        self.source_root.chmod(0o700)
        self.job_root.chmod(0o700)
        self.path_policy = _path_policy()
        self.resource_limits = _resource_limits()
        self._write("docs/guide.md", b"documentation\n")
        self._write("source/main.py", b"print('safe')\n", executable=True)
        self._write("tests/test_main.py", _PRIVATE_MARKER.encode("utf-8"))
        self.snapshot = capture_repository_worker_job_tree_source_snapshot(
            self.source_root,
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
        )
        self.contract = derive_repository_worker_job_tree_contract(
            _registration_evidence(
                path_policy=self.path_policy,
                resource_limits=self.resource_limits,
            ),
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
            source_bundle=self.snapshot.source_bundle,
        )
        self.lease = RepositoryWorkerJobTreeMaterializationLease(self.job_root)
        self.receipt = materialize_repository_worker_job_tree(
            self.snapshot,
            contract=self.contract,
            lease=self.lease,
        )

    def tearDown(self) -> None:
        self.lease.close()
        self.temporary_directory.cleanup()

    def _write(
        self,
        relative_path: str,
        content: bytes,
        *,
        executable: bool = False,
    ) -> None:
        path = self.source_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o700 if executable else 0o600)

    def _candidate(self) -> RepositoryWorkerJobTreeCandidateBundle:
        return RepositoryWorkerJobTreeCandidateBundle(
            files=(
                RepositoryWorkerJobTreeSourceFile(
                    "docs/guide.md",
                    b"updated documentation\n",
                ),
                RepositoryWorkerJobTreeSourceFile(
                    "source/main.py",
                    b"print('safe')\n",
                    executable=False,
                ),
                RepositoryWorkerJobTreeSourceFile(
                    "tests/new.py",
                    _CANDIDATE_MARKER.encode("utf-8"),
                ),
            )
        )

    def _reconcile(
        self,
        candidate: RepositoryWorkerJobTreeCandidateBundle | None = None,
    ):
        return derive_repository_worker_job_tree_reconciliation(
            self.snapshot,
            contract=self.contract,
            materialization_receipt=self.receipt,
            candidate_bundle=self._candidate() if candidate is None else candidate,
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
        )

    def test_reconciliation_is_private_digest_only_and_classifies_operations(
        self,
    ) -> None:
        before_tree = {
            str(path.relative_to(self.job_root)): path.read_bytes()
            for path in sorted(self.job_root.rglob("*"))
            if path.is_file()
        }

        reconciliation = self._reconcile()
        mapping = reconciliation.to_mapping()

        self.assertEqual(
            mapping["kind"], REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_KIND
        )
        self.assertEqual(
            mapping["schema_version"],
            REPOSITORY_WORKER_JOB_TREE_RECONCILIATION_SCHEMA_VERSION,
        )
        self.assertEqual(mapping["reconciliation_scope"], RECONCILIATION_SCOPE)
        self.assertEqual(mapping["source_file_count"], 3)
        self.assertEqual(mapping["candidate_file_count"], 3)
        self.assertEqual(mapping["added_file_count"], 1)
        self.assertEqual(mapping["modified_file_count"], 2)
        self.assertEqual(mapping["deleted_file_count"], 1)
        self.assertEqual(
            [operation.operation for operation in reconciliation.operations],
            ["modified", "modified", "added", "deleted"],
        )
        self.assertEqual(
            [operation.relative_path for operation in reconciliation.operations],
            [
                "docs/guide.md",
                "source/main.py",
                "tests/new.py",
                "tests/test_main.py",
            ],
        )
        for name in (
            "authority_granted",
            "candidate_filesystem_captured",
            "dispatch_enabled",
            "patch_application_implemented",
            "worker_execution_permitted",
        ):
            self.assertFalse(mapping[name])
        self.assertTrue(mapping["patch_reconciliation_implemented"])
        rendered = json.dumps(mapping, sort_keys=True)
        for private_value in (
            _PRIVATE_MARKER,
            _CANDIDATE_MARKER,
            "docs/guide.md",
            "source/main.py",
            str(self.job_root),
        ):
            self.assertNotIn(private_value, rendered)
        self.assertEqual(
            {
                str(path.relative_to(self.job_root)): path.read_bytes()
                for path in sorted(self.job_root.rglob("*"))
                if path.is_file()
            },
            before_tree,
        )
        self.assertEqual(self.lease.state, "active")

    def test_identical_and_empty_candidate_bundles_have_exact_operations(self) -> None:
        identical = RepositoryWorkerJobTreeCandidateBundle(
            files=tuple(
                RepositoryWorkerJobTreeSourceFile(
                    item.relative_path,
                    item.content,
                    executable=item.executable,
                )
                for item in self.snapshot.source_bundle.files
            )
        )

        unchanged = self._reconcile(identical)
        self.assertEqual(unchanged.operations, ())
        self.assertEqual(unchanged.to_mapping()["added_file_count"], 0)
        self.assertEqual(unchanged.to_mapping()["modified_file_count"], 0)
        self.assertEqual(unchanged.to_mapping()["deleted_file_count"], 0)

        all_deleted = self._reconcile(
            RepositoryWorkerJobTreeCandidateBundle(files=())
        )
        self.assertEqual(
            [operation.operation for operation in all_deleted.operations],
            ["deleted", "deleted", "deleted"],
        )
        self.assertEqual(all_deleted.to_mapping()["candidate_file_count"], 0)
        self.assertEqual(all_deleted.to_mapping()["deleted_file_count"], 3)

    def test_candidate_policy_and_contract_drift_fail_closed(self) -> None:
        generated_candidate = RepositoryWorkerJobTreeCandidateBundle(
            files=(
                RepositoryWorkerJobTreeSourceFile(
                    "source/generated/derived.py",
                    b"derived",
                ),
            )
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree reconciliation is invalid$",
        ):
            self._reconcile(generated_candidate)

        object.__setattr__(
            self.contract,
            "source_bundle_digest",
            _ref("different-source"),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree reconciliation is invalid$",
        ):
            self._reconcile()

    def test_materialization_receipt_schema_drift_fails_closed(self) -> None:
        object.__setattr__(self.receipt, "schema_version", True)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree reconciliation is invalid$",
        ):
            self._reconcile()

    def test_reconciliation_revalidates_its_retained_policy(self) -> None:
        reconciliation = self._reconcile()
        restricted_policy = _path_policy()
        restricted_policy["allowed_paths"] = ["docs"]
        object.__setattr__(reconciliation, "path_policy", restricted_policy)
        object.__setattr__(
            reconciliation,
            "path_policy_digest",
            canonical_digest(restricted_policy),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree reconciliation is invalid$",
        ):
            reconciliation.to_mapping()

    def test_patch_operation_and_reconciliation_shape_tampering_fail_closed(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree patch operation is invalid$",
        ):
            RepositoryWorkerJobTreePatchOperation(
                kind=REPOSITORY_WORKER_JOB_TREE_PATCH_OPERATION_KIND,
                operation="added",
                relative_path="source/new.py",
                before_content=b"unexpected",
                before_executable=None,
                after_content=b"new",
                after_executable=False,
            )

        reconciliation = self._reconcile()
        object.__setattr__(reconciliation, "added_file_count", 0)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree reconciliation is invalid$",
        ):
            reconciliation.to_mapping()

    def test_reconciliation_captures_its_complete_pure_proof_graph(self) -> None:
        candidate = self._candidate()
        helper_names = (
            "_candidate_bundle_digest",
            "_content_digest",
            "_derive_operations",
            "_detached_candidate_bundle",
            "_is_digest",
            "_materialization_receipt_projection",
            "_operation_projection",
            "_path_policy_snapshot",
            "_reconciliation_projection",
            "_resource_limits_snapshot",
            "_source_bundle_digest",
            "_validate_candidate_policy",
            "_validate_source_policy",
            "_validated_inputs",
        )
        with ExitStack() as stack:
            for name in helper_names:
                stack.enter_context(
                    patch.object(
                        reconciliation_module,
                        name,
                        side_effect=AssertionError("public helper must not run"),
                    )
                )
            reconciliation = self._reconcile(candidate)
            mapping = reconciliation.to_mapping()
            self.assertEqual(
                reconciliation.operations[0].to_canonical()["operation"],
                "modified",
            )
            self.assertEqual(mapping["added_file_count"], 1)
        self.assertEqual(reconciliation.added_file_count, 1)

        object.__setattr__(candidate, "files", ())
        self.assertEqual(reconciliation.candidate_file_count, 3)

    def test_candidate_bundle_projection_is_bounded_and_private(self) -> None:
        candidate = self._candidate()
        self.assertEqual(
            candidate.candidate_bundle_digest,
            reconciliation_module._candidate_bundle_digest(candidate),
        )
        self.assertEqual(
            REPOSITORY_WORKER_JOB_TREE_CANDIDATE_BUNDLE_KIND,
            "repository_worker_no_git_job_tree_candidate_bundle",
        )
        object.__setattr__(candidate, "files", ("not-a-file",))
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate bundle is invalid$",
        ):
            _ = candidate.candidate_file_count

    def test_module_has_no_filesystem_process_or_network_runtime_imports(self) -> None:
        tree = ast.parse(inspect.getsource(reconciliation_module))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertFalse(
            imported
            & {
                "asyncio",
                "os",
                "pathlib",
                "socket",
                "sqlite3",
                "subprocess",
                "tempfile",
                "urllib",
            }
        )


if __name__ == "__main__":
    unittest.main()
