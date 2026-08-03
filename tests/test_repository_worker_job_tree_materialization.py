from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import ordomata.repository_worker_job_tree_materialization as materialization_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
from ordomata.repository_registration import (
    BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
    REPOSITORY_REGISTRATION_EVIDENCE_KIND,
)
from ordomata.repository_worker_job_tree import (
    derive_repository_worker_job_tree_contract,
)
from ordomata.repository_worker_job_tree_materialization import (
    MATERIALIZATION_SCOPE,
    REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND,
    REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION,
    RepositoryWorkerJobTreeMaterializationLease,
    materialize_repository_worker_job_tree,
)
from ordomata.repository_worker_job_tree_snapshot import (
    capture_repository_worker_job_tree_source_snapshot,
)


_PRIVATE_MARKER = "private-materialized-source-marker"


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


class RepositoryWorkerJobTreeMaterializationTests(unittest.TestCase):
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

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write(
        self,
        relative_path: str,
        content: bytes,
        *,
        executable: bool = False,
    ) -> Path:
        path = self.source_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o700 if executable else 0o600)
        return path

    @staticmethod
    def _tree(root: Path) -> dict[str, bytes]:
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def _materialize(self, root: Path | None = None):
        lease = RepositoryWorkerJobTreeMaterializationLease(
            self.job_root if root is None else root
        )
        receipt = materialize_repository_worker_job_tree(
            self.snapshot,
            contract=self.contract,
            lease=lease,
        )
        return lease, receipt

    def test_materializes_only_detached_allowed_source_with_digest_only_evidence(
        self,
    ) -> None:
        source_before = self._tree(self.source_root)
        self._write("source/main.py", b"print('changed after snapshot')\n")

        lease, receipt = self._materialize()
        mapping = receipt.to_mapping()

        self.assertEqual(
            mapping["kind"], REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_KIND
        )
        self.assertEqual(
            mapping["schema_version"],
            REPOSITORY_WORKER_JOB_TREE_MATERIALIZATION_SCHEMA_VERSION,
        )
        self.assertEqual(mapping["materialization_scope"], MATERIALIZATION_SCOPE)
        self.assertEqual(mapping["source_file_count"], 3)
        self.assertEqual(
            mapping["source_total_bytes"],
            sum(len(content) for content in source_before.values()),
        )
        self.assertEqual(
            mapping["source_snapshot_digest"], self.snapshot.snapshot_digest
        )
        self.assertEqual(
            mapping["job_tree_contract_digest"], self.contract.contract_digest
        )
        for name in (
            "authority_granted",
            "dispatch_enabled",
            "materialization_authority_granted",
            "patch_reconciliation_implemented",
            "worker_execution_permitted",
        ):
            self.assertFalse(mapping[name])
        self.assertTrue(mapping["git_metadata_prohibited"])
        self.assertTrue(mapping["job_tree_materialized"])
        rendered = json.dumps(mapping, sort_keys=True)
        self.assertNotIn(_PRIVATE_MARKER, rendered)
        self.assertNotIn("docs/guide.md", rendered)
        self.assertNotIn(str(self.source_root), rendered)
        self.assertNotIn(str(self.job_root), rendered)

        self.assertEqual(self._tree(self.job_root), source_before)
        self.assertEqual(
            (self.job_root / "source" / "main.py").read_bytes(),
            b"print('safe')\n",
        )
        self.assertFalse((self.job_root / ".git").exists())
        self.assertEqual(
            stat.S_IMODE((self.job_root / "docs").stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE((self.job_root / "docs" / "guide.md").stat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE((self.job_root / "source" / "main.py").stat().st_mode),
            0o700,
        )
        self.assertEqual(lease.state, "active")
        self.assertIs(lease.receipt, receipt)

        lease.close()
        self.assertEqual(lease.state, "closed")
        self.assertEqual(self._tree(self.job_root), source_before)

    def test_mismatched_contract_never_touches_target_root(self) -> None:
        object.__setattr__(
            self.contract,
            "source_bundle_digest",
            _ref("different-source-bundle"),
        )
        lease = RepositoryWorkerJobTreeMaterializationLease(self.job_root)

        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree materialization is invalid$",
        ):
            materialize_repository_worker_job_tree(
                self.snapshot,
                contract=self.contract,
                lease=lease,
            )

        self.assertEqual(list(self.job_root.iterdir()), [])
        self.assertEqual(lease.state, "new")

    def test_target_root_guards_reject_aliases_mode_and_existing_content(self) -> None:
        cases: list[tuple[str, Path]] = []

        nonempty_root = self.root / "nonempty-root"
        nonempty_root.mkdir(mode=0o700)
        nonempty_root.chmod(0o700)
        (nonempty_root / "existing.txt").write_bytes(b"preserve")
        cases.append(("nonempty", nonempty_root))

        wrong_mode_root = self.root / "wrong-mode-root"
        wrong_mode_root.mkdir(mode=0o755)
        wrong_mode_root.chmod(0o755)
        cases.append(("mode", wrong_mode_root))

        alias_root = self.root / "job-root-alias"
        os.symlink(self.job_root, alias_root)
        cases.append(("alias", alias_root))

        cases.append(("source", self.source_root))

        for name, root in cases:
            with self.subTest(name=name):
                lease = RepositoryWorkerJobTreeMaterializationLease(root)
                with self.assertRaisesRegex(
                    ValidationError,
                    "^repository worker job tree materialization is invalid$",
                ) as raised:
                    materialize_repository_worker_job_tree(
                        self.snapshot,
                        contract=self.contract,
                        lease=lease,
                    )
                self.assertNotIn(str(root), str(raised.exception))
                self.assertEqual(lease.state, "new")

        self.assertEqual((nonempty_root / "existing.txt").read_bytes(), b"preserve")
        self.assertEqual(list(self.job_root.iterdir()), [])

    def test_target_root_cannot_alias_or_nest_inside_captured_source_root(self) -> None:
        nested_root = self.source_root / "private-job-root"
        nested_root.mkdir(mode=0o700)
        nested_root.chmod(0o700)
        lease = RepositoryWorkerJobTreeMaterializationLease(nested_root)

        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree materialization is invalid$",
        ):
            materialize_repository_worker_job_tree(
                self.snapshot,
                contract=self.contract,
                lease=lease,
            )
        self.assertEqual(list(nested_root.iterdir()), [])

        archived_source_root = self.root / "archived-source-root"
        self.source_root.rename(archived_source_root)
        self.source_root.mkdir(mode=0o700)
        self.source_root.chmod(0o700)
        replacement_lease = RepositoryWorkerJobTreeMaterializationLease(
            self.source_root
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree materialization is invalid$",
        ):
            materialize_repository_worker_job_tree(
                self.snapshot,
                contract=self.contract,
                lease=replacement_lease,
            )

        self.assertEqual(
            list((archived_source_root / "private-job-root").iterdir()),
            [],
        )
        self.assertEqual(list(self.source_root.iterdir()), [])

    def test_materializes_nested_and_root_level_entries_through_root_descriptor(
        self,
    ) -> None:
        nested_source_root = self.root / "nested-source-root"
        nested_job_root = self.root / "nested-job-root"
        nested_source_root.mkdir(mode=0o700)
        nested_job_root.mkdir(mode=0o700)
        nested_source_root.chmod(0o700)
        nested_job_root.chmod(0o700)
        (nested_source_root / "README.md").write_bytes(b"root-level\n")
        nested_source = nested_source_root / "source" / "nested" / "deeper"
        nested_source.mkdir(parents=True)
        (nested_source / "tool.py").write_bytes(b"print('nested')\n")
        (nested_source_root / "README.md").chmod(0o600)
        (nested_source / "tool.py").chmod(0o700)
        policy = {
            "allowed_paths": ["README.md", "source"],
            "generated_paths": ["source/generated"],
            "protected_paths": [".agentops", ".git", ".ordomata"],
            "vendor_paths": [],
        }
        snapshot = capture_repository_worker_job_tree_source_snapshot(
            nested_source_root,
            path_policy=policy,
            resource_limits=self.resource_limits,
        )
        contract = derive_repository_worker_job_tree_contract(
            _registration_evidence(
                path_policy=policy,
                resource_limits=self.resource_limits,
            ),
            path_policy=policy,
            resource_limits=self.resource_limits,
            source_bundle=snapshot.source_bundle,
        )
        lease = RepositoryWorkerJobTreeMaterializationLease(nested_job_root)

        materialize_repository_worker_job_tree(
            snapshot,
            contract=contract,
            lease=lease,
        )

        self.assertEqual(
            self._tree(nested_job_root),
            {
                "README.md": b"root-level\n",
                "source/nested/deeper/tool.py": b"print('nested')\n",
            },
        )
        self.assertEqual(
            stat.S_IMODE((nested_job_root / "README.md").stat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE(
                (nested_job_root / "source" / "nested" / "deeper").stat().st_mode
            ),
            0o700,
        )
        lease.close()

    def test_failed_write_rolls_back_known_entries_and_preserves_source(self) -> None:
        source_before = self._tree(self.source_root)
        lease = RepositoryWorkerJobTreeMaterializationLease(self.job_root)

        with patch.object(
            materialization_module.os,
            "write",
            side_effect=OSError("injected write failure"),
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^repository worker job tree materialization is invalid$",
            ):
                materialize_repository_worker_job_tree(
                    self.snapshot,
                    contract=self.contract,
                    lease=lease,
                )

        self.assertEqual(list(self.job_root.iterdir()), [])
        self.assertEqual(self._tree(self.source_root), source_before)
        self.assertEqual(lease.state, "new")

    def test_interruption_during_write_rolls_back_before_reraising(self) -> None:
        lease = RepositoryWorkerJobTreeMaterializationLease(self.job_root)

        with patch.object(
            materialization_module.os,
            "write",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                materialize_repository_worker_job_tree(
                    self.snapshot,
                    contract=self.contract,
                    lease=lease,
                )

        self.assertEqual(list(self.job_root.iterdir()), [])
        self.assertEqual(lease.state, "new")

    def test_descriptor_close_failure_never_reports_clean_materialization(
        self,
    ) -> None:
        original_close = materialization_module._close_descriptor

        def close_but_report_failure(descriptor: int | None) -> bool:
            original_close(descriptor)
            return False

        with patch.object(
            materialization_module,
            "_close_descriptor",
            side_effect=close_but_report_failure,
        ):
            self.assertFalse(
                materialization_module._root_path_matches(
                    self.job_root,
                    materialization_module._root_identity(
                        self.job_root.stat()
                    ),
                )
            )

        def close_regular_file_but_report_failure(
            descriptor: int | None,
        ) -> bool:
            is_regular_file = False
            if descriptor is not None:
                try:
                    is_regular_file = stat.S_ISREG(
                        os.fstat(descriptor).st_mode
                    )
                except OSError:
                    pass
            closed = original_close(descriptor)
            return False if is_regular_file else closed

        lease = RepositoryWorkerJobTreeMaterializationLease(self.job_root)
        with patch.object(
            materialization_module,
            "_close_descriptor",
            side_effect=close_regular_file_but_report_failure,
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^repository worker job tree materialization is invalid$",
            ):
                materialize_repository_worker_job_tree(
                    self.snapshot,
                    contract=self.contract,
                    lease=lease,
                )

        self.assertEqual(list(self.job_root.iterdir()), [])
        self.assertEqual(lease.state, "new")

    def test_unknown_post_write_entry_is_never_deleted_or_reported_clean(self) -> None:
        original_verify = materialization_module._verify_materialized_tree
        calls = 0

        def inject_protected_entry(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            original_verify(*args, **kwargs)
            if calls == 1:
                (self.job_root / ".git").mkdir()

        lease = RepositoryWorkerJobTreeMaterializationLease(self.job_root)
        with patch.object(
            materialization_module,
            "_verify_materialized_tree",
            side_effect=inject_protected_entry,
        ):
            with self.assertRaisesRegex(
                ConfigurationError,
                "^repository worker job tree materialization cleanup is uncertain$",
            ):
                materialize_repository_worker_job_tree(
                    self.snapshot,
                    contract=self.contract,
                    lease=lease,
                )

        self.assertEqual(calls, 2)
        self.assertEqual(
            sorted(path.name for path in self.job_root.iterdir()),
            [".git"],
        )
        self.assertEqual(lease.state, "cleanup_unverifiable")

    def test_replaced_target_root_fails_closed_and_cleans_only_held_root(self) -> None:
        previous_root = self.root / "previous-job-root"
        original_verify = materialization_module._verify_materialized_tree

        def replace_after_verify(*args: object, **kwargs: object) -> None:
            original_verify(*args, **kwargs)
            self.job_root.rename(previous_root)
            self.job_root.mkdir(mode=0o700)
            self.job_root.chmod(0o700)

        lease = RepositoryWorkerJobTreeMaterializationLease(self.job_root)
        with patch.object(
            materialization_module,
            "_verify_materialized_tree",
            side_effect=replace_after_verify,
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^repository worker job tree materialization is invalid$",
            ):
                materialize_repository_worker_job_tree(
                    self.snapshot,
                    contract=self.contract,
                    lease=lease,
                )

        self.assertEqual(list(self.job_root.iterdir()), [])
        self.assertEqual(list(previous_root.iterdir()), [])
        self.assertEqual(lease.state, "new")

    def test_lease_is_one_shot_and_receipt_shape_is_rechecked(self) -> None:
        lease, receipt = self._materialize()
        object.__setattr__(receipt, "source_file_count", 0)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree materialization is invalid$",
        ):
            receipt.to_mapping()

        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree materialization is invalid$",
        ):
            materialize_repository_worker_job_tree(
                self.snapshot,
                contract=self.contract,
                lease=lease,
            )
        lease.close()

    def test_module_has_no_process_network_or_git_runtime_imports(self) -> None:
        tree = ast.parse(inspect.getsource(materialization_module))
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
                "tempfile",
                "urllib",
            }
        )


if __name__ == "__main__":
    unittest.main()
