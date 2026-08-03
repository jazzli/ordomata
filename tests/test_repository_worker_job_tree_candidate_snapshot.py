from __future__ import annotations

import ast
from contextlib import ExitStack
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import ordomata.repository_worker_job_tree_candidate_snapshot as candidate_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
from ordomata.repository_registration import (
    BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
    REPOSITORY_REGISTRATION_EVIDENCE_KIND,
)
from ordomata.repository_worker_job_tree import (
    derive_repository_worker_job_tree_contract,
)
from ordomata.repository_worker_job_tree_candidate_snapshot import (
    CANDIDATE_SNAPSHOT_SCOPE,
    REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND,
    REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION,
    capture_repository_worker_job_tree_candidate_snapshot,
)
from ordomata.repository_worker_job_tree_materialization import (
    RepositoryWorkerJobTreeMaterializationLease,
    materialize_repository_worker_job_tree,
)
from ordomata.repository_worker_job_tree_reconciliation import (
    derive_repository_worker_job_tree_reconciliation,
)
from ordomata.repository_worker_job_tree_snapshot import (
    capture_repository_worker_job_tree_source_snapshot,
)


_PRIVATE_MARKER = "private-candidate-snapshot-source-marker"
_CANDIDATE_MARKER = "private-candidate-snapshot-candidate-marker"


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


class RepositoryWorkerJobTreeCandidateSnapshotTests(unittest.TestCase):
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
        self._write_source("docs/guide.md", b"documentation\n")
        self._write_source("source/main.py", b"print('safe')\n", executable=True)
        self._write_source("tests/test_main.py", _PRIVATE_MARKER.encode("utf-8"))
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

    def _write_source(
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

    def _write_candidate(
        self,
        relative_path: str,
        content: bytes,
        *,
        executable: bool = False,
    ) -> Path:
        path = self.job_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o700 if executable else 0o600)
        return path

    def _capture(self):
        return capture_repository_worker_job_tree_candidate_snapshot(
            self.snapshot,
            contract=self.contract,
            materialization_receipt=self.receipt,
            lease=self.lease,
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
        )

    @staticmethod
    def _tree(root: Path) -> dict[str, tuple[bytes, int]]:
        return {
            str(path.relative_to(root)): (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
            for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def test_capture_is_private_digest_only_and_reconciliation_compatible(self) -> None:
        self._write_candidate("docs/guide.md", b"updated documentation\n")
        (self.job_root / "source" / "main.py").chmod(0o600)
        (self.job_root / "tests" / "test_main.py").unlink()
        self._write_candidate(
            "tests/new.py",
            _CANDIDATE_MARKER.encode("utf-8"),
        )
        before_tree = self._tree(self.job_root)

        candidate_snapshot = self._capture()
        mapping = candidate_snapshot.to_mapping()
        reconciliation = derive_repository_worker_job_tree_reconciliation(
            self.snapshot,
            contract=self.contract,
            materialization_receipt=self.receipt,
            candidate_bundle=candidate_snapshot.candidate_bundle,
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
        )

        self.assertEqual(
            mapping["kind"], REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_KIND
        )
        self.assertEqual(
            mapping["schema_version"],
            REPOSITORY_WORKER_JOB_TREE_CANDIDATE_SNAPSHOT_SCHEMA_VERSION,
        )
        self.assertEqual(mapping["candidate_snapshot_scope"], CANDIDATE_SNAPSHOT_SCOPE)
        self.assertEqual(mapping["source_file_count"], 3)
        self.assertEqual(mapping["candidate_file_count"], 3)
        self.assertEqual(mapping["candidate_directory_count"], 3)
        for name in (
            "authority_granted",
            "candidate_capture_authority_granted",
            "candidate_origin_proven",
            "dispatch_enabled",
            "patch_application_implemented",
            "patch_reconciliation_implemented",
            "worker_execution_permitted",
        ):
            self.assertFalse(mapping[name])
        self.assertTrue(mapping["candidate_filesystem_captured"])
        self.assertTrue(mapping["stable_double_capture_verified"])
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
            [file.relative_path for file in candidate_snapshot.candidate_bundle.files],
            ["docs/guide.md", "source/main.py", "tests/new.py"],
        )
        self.assertEqual(
            candidate_snapshot.candidate_bundle_digest,
            candidate_snapshot.candidate_bundle.candidate_bundle_digest,
        )
        self.assertEqual(reconciliation.added_file_count, 1)
        self.assertEqual(reconciliation.modified_file_count, 2)
        self.assertEqual(reconciliation.deleted_file_count, 1)
        self.assertEqual(self._tree(self.job_root), before_tree)
        self.assertEqual(self.lease.state, "active")

    def test_empty_candidate_represents_all_file_deletions(self) -> None:
        for path in sorted(self.job_root.rglob("*")):
            if path.is_file():
                path.unlink()

        candidate_snapshot = self._capture()

        self.assertEqual(candidate_snapshot.candidate_bundle.files, ())
        self.assertEqual(candidate_snapshot.candidate_file_count, 0)
        self.assertEqual(candidate_snapshot.candidate_directory_count, 3)

    def test_repeated_capture_reuses_the_held_root_without_cursor_drift(self) -> None:
        first = self._capture()
        second = self._capture()

        self.assertEqual(first.candidate_tree_digest, second.candidate_tree_digest)
        self.assertEqual(first.candidate_file_count, 3)
        self.assertEqual(second.candidate_file_count, 3)

    def test_unsafe_candidate_entries_and_mode_drift_fail_closed(self) -> None:
        generated_directory = self.job_root / "source" / "generated"
        generated_directory.mkdir(mode=0o700)
        generated_directory.chmod(0o700)
        self._write_candidate("source/generated/output.py", b"generated")
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            self._capture()

        (generated_directory / "output.py").unlink()
        generated_directory.rmdir()
        (self.job_root / "docs" / "guide.md").chmod(0o644)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            self._capture()

    def test_symlink_hardlink_and_unrepresentable_empty_directory_fail_closed(
        self,
    ) -> None:
        os.symlink("guide.md", self.job_root / "docs" / "linked.md")
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            self._capture()
        (self.job_root / "docs" / "linked.md").unlink()

        os.link(
            self.job_root / "docs" / "guide.md",
            self.job_root / "docs" / "hard-linked.md",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            self._capture()
        (self.job_root / "docs" / "hard-linked.md").unlink()

        empty_directory = self.job_root / "source" / "unrepresented"
        empty_directory.mkdir(mode=0o700)
        empty_directory.chmod(0o700)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            self._capture()

    def test_replaced_root_and_lineage_drift_fail_closed(self) -> None:
        replacement = self.root / "replacement-root"
        replacement.mkdir(mode=0o700)
        replacement.chmod(0o700)
        displaced = self.root / "displaced-job-root"
        self.job_root.rename(displaced)
        replacement.rename(self.job_root)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            self._capture()

    def test_closed_lease_and_retained_snapshot_tampering_fail_closed(self) -> None:
        candidate_snapshot = self._capture()
        object.__setattr__(candidate_snapshot, "candidate_file_count", 0)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            candidate_snapshot.to_mapping()

        self.lease.close()
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            self._capture()

    def test_retained_policy_and_receipt_drift_fail_closed(self) -> None:
        candidate_snapshot = self._capture()
        restricted_policy = _path_policy()
        restricted_policy["allowed_paths"] = ["docs"]
        object.__setattr__(candidate_snapshot, "path_policy", restricted_policy)
        object.__setattr__(
            candidate_snapshot,
            "path_policy_digest",
            canonical_digest(restricted_policy),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            candidate_snapshot.to_mapping()

        candidate_snapshot = self._capture()
        object.__setattr__(self.receipt, "schema_version", True)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree candidate snapshot is invalid$",
        ):
            candidate_snapshot.to_mapping()

    def test_capture_freezes_its_complete_proof_graph(self) -> None:
        helper_names = (
            "_candidate_bundle_digest",
            "_candidate_snapshot_projection",
            "_candidate_tree_digest",
            "_capture_candidate_tree",
            "_close_descriptor",
            "_content_digest",
            "_descriptor_support_is_available",
            "_directory_entry_names",
            "_directory_flags",
            "_directory_paths_for_files",
            "_entry_metadata",
            "_held_root_matches",
            "_is_at_or_below",
            "_is_canonical_relative_path",
            "_is_digest",
            "_lease_root_descriptor",
            "_materialization_receipt_projection",
            "_metadata_signature",
            "_open_absolute_directory",
            "_open_directory_at",
            "_path_policy_snapshot",
            "_path_ref",
            "_read_candidate_file",
            "_read_exact",
            "_regular_read_flags",
            "_resource_limits_snapshot",
            "_root_identity",
            "_root_path_matches",
            "_source_bundle_digest",
            "_validate_candidate_bundle_policy",
            "_validate_candidate_relative_path",
            "_validate_directory_paths",
            "_validate_source_bundle_policy",
            "_validated_inputs",
            "_validated_lineage",
        )
        with ExitStack() as stack:
            for name in helper_names:
                stack.enter_context(
                    patch.object(
                        candidate_module,
                        name,
                        side_effect=AssertionError("public helper must not run"),
                    )
                )
            candidate_snapshot = self._capture()
            self.assertEqual(
                candidate_snapshot.to_mapping()["candidate_file_count"],
                3,
            )

    def test_module_has_no_process_network_or_git_runtime_imports(self) -> None:
        tree = ast.parse(inspect.getsource(candidate_module))
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
                "socket",
                "sqlite3",
                "subprocess",
                "urllib",
            }
        )

    def test_capture_uses_no_mutating_runtime_api(self) -> None:
        tree = ast.parse(inspect.getsource(candidate_module))
        os_calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        }
        self.assertFalse(
            os_calls
            & {
                "chmod",
                "fchmod",
                "fsync",
                "link",
                "mkdir",
                "remove",
                "rename",
                "replace",
                "rmdir",
                "symlink",
                "unlink",
                "write",
            }
        )


if __name__ == "__main__":
    unittest.main()
