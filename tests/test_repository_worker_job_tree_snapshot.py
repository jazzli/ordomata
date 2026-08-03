from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ordomata.repository_worker_job_tree_snapshot as snapshot_module
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
from ordomata.repository_worker_job_tree_snapshot import (
    REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND,
    REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION,
    capture_repository_worker_job_tree_source_snapshot,
)


_PRIVATE_MARKER = "private-source-snapshot-marker"


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


class RepositoryWorkerJobTreeSourceSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name) / "source-root"
        self.root.mkdir()
        self.path_policy = _path_policy()
        self.resource_limits = _resource_limits()
        self._write("docs/guide.md", b"documentation\n")
        self._write("source/main.py", b"print('safe')\n", executable=True)
        self._write("tests/test_main.py", _PRIVATE_MARKER.encode("utf-8"))

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write(
        self,
        relative_path: str,
        content: bytes,
        *,
        executable: bool = False,
    ) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        if executable:
            path.chmod(0o700)
        return path

    def _tree_bytes(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def _capture(self):
        return capture_repository_worker_job_tree_source_snapshot(
            self.root,
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
        )

    def test_capture_is_detached_digest_only_and_contract_bindable(self) -> None:
        before = self._tree_bytes()

        snapshot = self._capture()
        mapping = snapshot.to_mapping()

        self.assertEqual(
            mapping["kind"], REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_KIND
        )
        self.assertEqual(
            mapping["schema_version"],
            REPOSITORY_WORKER_JOB_TREE_SOURCE_SNAPSHOT_SCHEMA_VERSION,
        )
        self.assertEqual(mapping["source_file_count"], 3)
        self.assertEqual(mapping["source_total_bytes"], sum(map(len, before.values())))
        self.assertTrue(mapping["source_snapshot_captured"])
        for name in (
            "authority_granted",
            "dispatch_enabled",
            "materialization_implemented",
            "source_snapshot_registration_bound",
            "worker_execution_permitted",
        ):
            self.assertFalse(mapping[name])
        rendered = json.dumps(mapping, sort_keys=True)
        self.assertNotIn(_PRIVATE_MARKER, rendered)
        self.assertNotIn("source/main.py", rendered)
        self.assertNotIn(str(self.root), rendered)
        self.assertEqual(self._tree_bytes(), before)
        self.assertEqual(
            [item.relative_path for item in snapshot.source_bundle.files],
            ["docs/guide.md", "source/main.py", "tests/test_main.py"],
        )
        self.assertTrue(snapshot.source_bundle.files[1].executable)

        contract = derive_repository_worker_job_tree_contract(
            _registration_evidence(
                path_policy=self.path_policy,
                resource_limits=self.resource_limits,
            ),
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
            source_bundle=snapshot.source_bundle,
        )
        self.assertEqual(
            contract.source_bundle_digest,
            snapshot.source_bundle_digest,
        )

    def test_exclusions_are_not_captured_but_allowed_content_is(self) -> None:
        self._write("source/generated/derived.py", b"generated")
        self._write("source/protected/private.txt", b"protected")
        self._write("vendor/library.txt", b"vendor")

        snapshot = self._capture()

        self.assertEqual(
            [item.relative_path for item in snapshot.source_bundle.files],
            ["docs/guide.md", "source/main.py", "tests/test_main.py"],
        )

    def test_unsafe_missing_and_symlinked_inputs_fail_closed(self) -> None:
        cases: list[tuple[str, str]] = []

        credential_path = self._write("source/.env.example", b"not-a-secret")
        cases.append(("credential-shaped", str(credential_path)))
        for name, marker in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    ValidationError,
                    "^repository worker job tree source snapshot is invalid$",
                ) as raised:
                    self._capture()
                self.assertNotIn(marker, str(raised.exception))
        credential_path.unlink()

        target = self._write("outside.txt", b"outside")
        os.symlink(target, self.root / "source" / "linked.txt")
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree source snapshot is invalid$",
        ):
            self._capture()
        (self.root / "source" / "linked.txt").unlink()

        (self.root / "tests").rename(self.root / "missing-tests")
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree source snapshot is invalid$",
        ):
            self._capture()

    def test_root_alias_hardlinks_and_oversized_files_fail_before_read(self) -> None:
        root_alias = Path(self.temporary_directory.name) / "source-root-alias"
        os.symlink(self.root, root_alias)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree source snapshot is invalid$",
        ):
            capture_repository_worker_job_tree_source_snapshot(
                root_alias,
                path_policy=self.path_policy,
                resource_limits=self.resource_limits,
            )
        root_alias.unlink()

        os.link(self.root / "source" / "main.py", self.root / "source" / "copy.py")
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree source snapshot is invalid$",
        ):
            self._capture()
        (self.root / "source" / "copy.py").unlink()

        oversized_root = Path(self.temporary_directory.name) / "oversized-root"
        (oversized_root / "source").mkdir(parents=True)
        oversized_file = oversized_root / "source" / "large.py"
        with oversized_file.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        source_only_policy = {
            "allowed_paths": ["source"],
            "generated_paths": [],
            "protected_paths": [".agentops", ".git", ".ordomata"],
            "vendor_paths": [],
        }
        with patch.object(
            snapshot_module.os,
            "read",
            side_effect=AssertionError("oversized file must not be read"),
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^repository worker job tree source snapshot is invalid$",
            ):
                capture_repository_worker_job_tree_source_snapshot(
                    oversized_root,
                    path_policy=source_only_policy,
                    resource_limits=self.resource_limits,
                )

    def test_directory_node_budget_fails_before_content_reads(self) -> None:
        for index in range(4):
            self._write(f"source/extra-{index}.py", b"x")
        policy = {
            "allowed_paths": ["source"],
            "generated_paths": [],
            "protected_paths": [".agentops", ".git", ".ordomata"],
            "vendor_paths": [],
        }

        with (
            patch.object(snapshot_module, "_MAX_SOURCE_NODES", 4),
            patch.object(
                snapshot_module.os,
                "read",
                side_effect=AssertionError("over-budget directory must not read"),
            ),
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^repository worker job tree source snapshot is invalid$",
            ):
                capture_repository_worker_job_tree_source_snapshot(
                    self.root,
                    path_policy=policy,
                    resource_limits=self.resource_limits,
                )

    def test_direct_file_root_uses_its_immediate_parent_descriptor(self) -> None:
        policy = _path_policy()
        policy["allowed_paths"] = ["source/main.py"]
        policy["generated_paths"] = []
        policy["vendor_paths"] = []

        snapshot = capture_repository_worker_job_tree_source_snapshot(
            self.root,
            path_policy=policy,
            resource_limits=self.resource_limits,
        )

        self.assertEqual(
            [item.relative_path for item in snapshot.source_bundle.files],
            ["source/main.py"],
        )

    def test_capacity_and_source_drift_fail_closed(self) -> None:
        capacity_root = Path(self.temporary_directory.name) / "capacity-root"
        capacity_root.mkdir()
        capacity_source = capacity_root / "source"
        capacity_source.mkdir()
        exact = capacity_source / "exact.py"
        exact.write_bytes(b"x" * (1024 * 1024))
        policy = {
            "allowed_paths": ["source"],
            "generated_paths": [],
            "protected_paths": [".agentops", ".git", ".ordomata"],
            "vendor_paths": [],
        }
        limits = _resource_limits()
        limits["workspace_bytes"] = 1024 * 1024
        limits["output_bytes"] = 1024 * 1024
        limits["artifact_bytes"] = 1024 * 1024
        snapshot = capture_repository_worker_job_tree_source_snapshot(
            capacity_root,
            path_policy=policy,
            resource_limits=limits,
        )
        self.assertEqual(snapshot.source_total_bytes, 1024 * 1024)

        exact.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree source snapshot is invalid$",
        ):
            capture_repository_worker_job_tree_source_snapshot(
                capacity_root,
                path_policy=policy,
                resource_limits=limits,
            )

        source_only_policy = dict(policy)
        source_only_policy["allowed_paths"] = ["source"]
        source_only_limits = _resource_limits()
        main = self.root / "source" / "main.py"
        original_reader = snapshot_module._read_exact_file

        def mutate_after_read(descriptor: int, expected_size: int) -> bytes:
            content = original_reader(descriptor, expected_size)
            if os.fstat(descriptor).st_ino == main.stat().st_ino:
                main.write_bytes(b"print('swap')\n")
            return content

        with patch.object(
            snapshot_module,
            "_read_exact_file",
            side_effect=mutate_after_read,
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^repository worker job tree source snapshot is invalid$",
            ):
                capture_repository_worker_job_tree_source_snapshot(
                    self.root,
                    path_policy=source_only_policy,
                    resource_limits=source_only_limits,
                )

    def test_nested_allowed_directory_replacement_is_rejected(self) -> None:
        nested_root = Path(self.temporary_directory.name) / "nested-root"
        source_directory = nested_root / "container" / "source"
        source_directory.mkdir(parents=True)
        (source_directory / "main.py").write_bytes(b"print('safe')\n")
        policy = {
            "allowed_paths": ["container/source"],
            "generated_paths": [],
            "protected_paths": [".agentops", ".git", ".ordomata"],
            "vendor_paths": [],
        }
        original_capture = snapshot_module._capture_directory

        def replace_after_capture(
            descriptor: int,
            **kwargs: object,
        ) -> int:
            remaining = original_capture(descriptor, **kwargs)
            if kwargs["relative_path"] == "container/source":
                source_directory.rename(nested_root / "container" / "original")
                source_directory.mkdir()
                (source_directory / "main.py").write_bytes(b"print('swap')\n")
            return remaining

        with patch.object(
            snapshot_module,
            "_capture_directory",
            side_effect=replace_after_capture,
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^repository worker job tree source snapshot is invalid$",
            ):
                capture_repository_worker_job_tree_source_snapshot(
                    nested_root,
                    path_policy=policy,
                    resource_limits=self.resource_limits,
                )

    def test_capture_uses_no_mutating_runtime_api(self) -> None:
        with (
            patch.object(snapshot_module.os, "mkdir", side_effect=AssertionError),
            patch.object(snapshot_module.os, "replace", side_effect=AssertionError),
            patch.object(snapshot_module.os, "unlink", side_effect=AssertionError),
            patch.object(snapshot_module.os, "write", side_effect=AssertionError),
        ):
            snapshot = self._capture()
        self.assertEqual(snapshot.source_file_count, 3)

    def test_snapshot_rechecks_shape_and_captures_input_validators(self) -> None:
        snapshot = self._capture()
        object.__setattr__(snapshot, "source_file_count", 0)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree source snapshot is invalid$",
        ):
            snapshot.to_mapping()

        with patch.object(
            snapshot_module,
            "_path_policy_snapshot",
            side_effect=AssertionError("public helper must not run"),
        ):
            captured = self._capture()
        self.assertEqual(captured.source_file_count, 3)

        private_root_snapshot = self._capture()
        object.__setattr__(
            private_root_snapshot,
            "source_root_components",
            ("unexpected-root",),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree source snapshot is invalid$",
        ):
            private_root_snapshot.to_mapping()

    def test_module_has_no_process_or_network_runtime_imports(self) -> None:
        tree = ast.parse(inspect.getsource(snapshot_module))
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
