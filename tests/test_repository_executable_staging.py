from __future__ import annotations

import asyncio
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pickle
import shutil
from types import SimpleNamespace
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
import ordomata.artifact_filesystem as artifact_filesystem_module
import ordomata.repository_executable_staging as staging_module
import ordomata.state as state_module
from ordomata.repository_executable_resolution import (
    MEASUREMENT_SOURCE,
    RESOLUTION_SCOPE,
    RepositoryExecutableResolutionReceipt,
    resolve_repository_executables,
)
from ordomata.repository_executable_staging import (
    REPOSITORY_EXECUTABLE_STAGE_BINDING_KIND,
    REPOSITORY_EXECUTABLE_STAGE_CLEANUP_KIND,
    REPOSITORY_EXECUTABLE_STAGED_FILE_KIND,
    REPOSITORY_EXECUTABLE_STAGING_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_STAGING_KIND,
    REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION,
    STAGING_SCOPE,
    STAGING_SOURCE,
    RepositoryExecutableStageBinding,
    RepositoryExecutableStageCleanupReceipt,
    RepositoryExecutableStagedFile,
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    cleanup_repository_executable_stage,
    stage_repository_executable_bytes,
)
from ordomata.repository_registration import (
    RepositoryRegistration,
    validate_repository_registration,
)


FIXED_STAGING_ERROR = "repository executable staging is invalid"
FIXED_CLEANUP_ERROR = (
    "repository executable staging cleanup is uncertain"
)
FIXED_COPY_ERROR = "repository executable staging lease cannot be copied"

STAGED_FILE_KEYS = {
    "content_bytes",
    "content_digest",
    "kind",
    "source_filesystem_identity_ref",
    "source_metadata_digest",
    "staged_file_ref",
    "staged_filesystem_identity_ref",
    "staged_metadata_digest",
}
STAGE_BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "declared_executable_ref",
    "kind",
    "resolved_executable_ref",
    "staged_file_ref",
}
STAGING_RECEIPT_KEYS = {
    "action_resolution_receipt_digest",
    "baseline_command_results_digest",
    "bindings",
    "executable_toolchain_identities_digest",
    "expected_resolution_receipt_digest",
    "kind",
    "measurement_source",
    "post_stage_resolution_receipt_digest",
    "registration_digest",
    "repository_ref",
    "resolution_context_digest",
    "resolution_scope",
    "schema_version",
    "staged_files",
    "staging_context_digest",
    "staging_scope",
    "staging_source",
    "total_staged_bytes",
    "unique_file_count",
    "verification_commands_digest",
}
STAGING_EVIDENCE_KEYS = {
    "acl_privacy_verified",
    "action_boundary_remeasurement_complete",
    "action_receipt_issued",
    "atomic_snapshot_verified",
    "authority_granted",
    "authorization_verified",
    "baseline_execution_correspondence_verified",
    "billing_eligible",
    "capacity_eligible",
    "circuit_eligible",
    "configuration_coverage_verified",
    "controller_write_descriptors_closed",
    "crash_cleanup_verified",
    "current_lease_activity_verified",
    "current_source_freshness_verified",
    "current_staged_namespace_presence_verified",
    "dependency_environment_coverage_verified",
    "dispatch_enabled",
    "durable_control_plane_persistence_enabled",
    "dynamic_loader_identity_verified",
    "effect_class",
    "effective_invocability_verified",
    "environment_coverage_verified",
    "executable_authenticity_verified",
    "executable_provenance_verified",
    "execution_enabled",
    "expected_resolution_authenticity_verified",
    "expected_resolution_correspondence_verified",
    "external_writable_descriptor_absence_verified",
    "filesystem_immutability_verified",
    "fork_descriptor_inheritance_excluded",
    "future_execution_correspondence_verified",
    "interpreter_identity_verified",
    "kind",
    "launcher_identity_verified",
    "lease_scoped_filesystem_stage_established",
    "lease_process_binding_established",
    "live_execution_eligible",
    "measurement_source",
    "module_identity_verified",
    "mount_alias_exclusion_verified",
    "package_identity_verified",
    "plugin_identity_verified",
    "post_stage_resolution_correspondence_verified",
    "proposal_lineage_extended",
    "read_only_descriptor_lease_established",
    "receipt_authenticity_verified",
    "receipt_digest",
    "registration_digest",
    "repository_ref",
    "resolution_context_digest",
    "resolution_scope",
    "route_eligible",
    "same_user_tamper_resistance_verified",
    "schema_version",
    "secure_erasure_verified",
    "shared_library_identity_verified",
    "shebang_identity_verified",
    "staged_byte_correspondence_verified",
    "staged_file_count",
    "staged_readback_complete",
    "staging_root_metadata_restored",
    "staging_scope",
    "staging_source",
    "toolchain_completeness_verified",
    "total_staged_bytes",
    "validation_mode",
}
CLEANUP_RECEIPT_KEYS = {
    "descriptor_release_complete",
    "kind",
    "outcome",
    "owned_namespace_absence_verified",
    "schema_version",
    "secure_erasure_verified",
    "staging_receipt_digest",
    "staging_root_identity_verified",
    "staging_root_metadata_restored",
}


@unittest.skipUnless(os.name == "posix", "the v1 staging backend is POSIX-only")
class RepositoryExecutableStagingTests(unittest.TestCase):
    @staticmethod
    def _write_executable(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o755)

    @classmethod
    def _workspace(
        cls,
        temporary: str,
    ) -> tuple[Path, Path, Path, Path, Path]:
        base = Path(temporary).resolve(strict=True)
        root = base / "private-staging-repository-marker"
        outside = base / "private-staging-outside-marker"
        search_one = base / "private-staging-search-one-marker"
        search_two = base / "private-staging-search-two-marker"
        staging_root = base / "private-staging-root-marker"
        for directory in (root, outside, search_one, search_two, staging_root):
            directory.mkdir()
        staging_root.chmod(0o700)
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
        cls._write_executable(
            search_one / "private-bare-tool-marker",
            b"first-controller-tool\n",
        )
        cls._write_executable(
            search_two / "private-bare-tool-marker",
            b"second-controller-tool\n",
        )
        cls._write_executable(
            root
            / "private-source-path-marker"
            / "private-relative-tool-marker",
            b"repository-relative-tool\n",
        )
        (outside / "sentinel.txt").write_text(
            "outside-unchanged\n",
            encoding="utf-8",
        )
        return root, outside, search_one, search_two, staging_root

    @staticmethod
    def _payload() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "repository_registration",
            "registration_id": "private-staging-registration-marker",
            "registration_version": "1.0.0",
            "repository": {
                "repository_id": "private-staging-repository-id-marker",
                "vcs": "git",
                "root": ".",
            },
            "verification_commands": {
                "format": [
                    {
                        "command_id": "private-bare-command-marker",
                        "argv": ["private-bare-tool-marker", "--check"],
                        "cwd": ".",
                    }
                ],
                "lint": [],
                "type_check": [],
                "test": [
                    {
                        "command_id": "private-relative-command-marker",
                        "argv": [
                            "private-source-path-marker/"
                            "private-relative-tool-marker",
                            "--test",
                        ],
                        "cwd": ".",
                    }
                ],
                "build": [],
            },
            "path_policy": {
                "allowed_paths": [
                    "private-docs-path-marker",
                    "private-source-path-marker",
                    "private-test-path-marker",
                ],
                "protected_paths": [
                    ".agentops",
                    ".git",
                    ".ordomata",
                    "private-protected-path-marker.txt",
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

    @staticmethod
    def _command_digest(kind: str, command: dict[str, object]) -> str:
        return canonical_digest(
            {
                "command": {
                    "argv": list(command["argv"]),
                    "command_id": command["command_id"],
                    "cwd": command["cwd"],
                    "kind": kind,
                },
                "kind": "repository_verification_command",
                "schema_version": 1,
            }
        )

    @classmethod
    def _baseline(cls, payload: dict[str, object]) -> dict[str, object]:
        results: list[dict[str, object]] = []
        ordinal = 0
        for kind in ("format", "lint", "type_check", "test", "build"):
            for command in payload["verification_commands"][kind]:
                started_at = 1_000 + ordinal * 2_000
                results.append(
                    {
                        "kind": kind,
                        "command_id": command["command_id"],
                        "command_digest": cls._command_digest(kind, command),
                        "started_at_unix_ms": started_at,
                        "completed_at_unix_ms": started_at + 1_000,
                        "termination": {"kind": "exited", "exit_code": 0},
                    }
                )
                ordinal += 1
        return {
            "kind": "repository_baseline_command_results",
            "attestation_source": "controller_supplied",
            "snapshot_digest": "sha256:" + "b" * 64,
            "results": results,
        }

    @classmethod
    def _identities(cls, payload: dict[str, object]) -> dict[str, object]:
        identities: list[dict[str, object]] = []
        for kind in ("format", "lint", "type_check", "test", "build"):
            for command in payload["verification_commands"][kind]:
                command_id = command["command_id"]
                identities.append(
                    {
                        "kind": kind,
                        "command_id": command_id,
                        "command_digest": cls._command_digest(kind, command),
                        "executable_identity_digest": canonical_digest(
                            {"opaque_executable_claim": f"{kind}:{command_id}"}
                        ),
                        "toolchain_identity_digest": canonical_digest(
                            {"opaque_toolchain_claim": f"{kind}:{command_id}"}
                        ),
                    }
                )
        return {
            "kind": "repository_executable_toolchain_identities",
            "attestation_source": "controller_supplied",
            "identities": identities,
        }

    @classmethod
    def _versioned_payload(cls, schema_version: int) -> dict[str, object]:
        payload = cls._payload()
        if schema_version >= 2:
            payload["schema_version"] = schema_version
            payload["path_policy"]["generated_paths"] = []
            payload["path_policy"]["vendor_paths"] = []
        if schema_version >= 3:
            payload["baseline_command_results"] = cls._baseline(payload)
        if schema_version >= 4:
            payload["executable_toolchain_identities"] = cls._identities(payload)
        return payload

    @classmethod
    def _registration(
        cls,
        root: Path,
        *,
        payload: dict[str, object] | None = None,
        schema_version: int = 4,
    ) -> RepositoryRegistration:
        return validate_repository_registration(
            payload or cls._versioned_payload(schema_version),
            repository_root=root,
        )

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
                    entries.append((relative, "symlink", mode, os.readlink(path)))
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

    def _assert_staging_invalid(
        self,
        registration: RepositoryRegistration,
        *,
        search_directories: object,
        expected_resolution: object,
        lease: object,
        private_marker: str = "private-staging-error-marker",
    ) -> ValidationError:
        with self.assertRaises(ValidationError) as caught:
            stage_repository_executable_bytes(
                registration,
                search_directories=search_directories,
                expected_resolution=expected_resolution,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    def _stage(
        self,
        registration: RepositoryRegistration,
        search_directories: tuple[Path, ...],
        staging_root: Path,
    ) -> tuple[
        RepositoryExecutableResolutionReceipt,
        RepositoryExecutableStageLease,
        RepositoryExecutableStagingReceipt,
    ]:
        expected = resolve_repository_executables(
            registration,
            search_directories=search_directories,
        )
        lease = RepositoryExecutableStageLease(staging_root)
        receipt = stage_repository_executable_bytes(
            registration,
            search_directories=search_directories,
            expected_resolution=expected,
            lease=lease,
        )
        return expected, lease, receipt

    def test_receipt_evidence_contract_correspondence_and_privacy(self) -> None:
        self.assertEqual(REPOSITORY_EXECUTABLE_STAGING_SCHEMA_VERSION, 1)
        self.assertEqual(
            REPOSITORY_EXECUTABLE_STAGING_KIND,
            "repository_executable_staging",
        )
        self.assertEqual(
            REPOSITORY_EXECUTABLE_STAGING_EVIDENCE_KIND,
            "repository_executable_staging_validation",
        )
        self.assertEqual(STAGING_SOURCE, "controller_copied")
        self.assertEqual(STAGING_SCOPE, "posix_unlinked_readonly_v1")

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected, lease, receipt = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                self.assertIsInstance(receipt, RepositoryExecutableStagingReceipt)
                self.assertIs(lease.receipt, receipt)
                self.assertEqual(lease.state, "active")
                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), STAGING_RECEIPT_KEYS)
                self.assertEqual(canonical["kind"], REPOSITORY_EXECUTABLE_STAGING_KIND)
                self.assertEqual(canonical["schema_version"], 1)
                self.assertEqual(canonical["measurement_source"], MEASUREMENT_SOURCE)
                self.assertEqual(canonical["resolution_scope"], RESOLUTION_SCOPE)
                self.assertEqual(canonical["staging_source"], STAGING_SOURCE)
                self.assertEqual(canonical["staging_scope"], STAGING_SCOPE)
                self.assertEqual(canonical["registration_digest"], registration.registration_digest)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                self.assertEqual(
                    receipt.expected_resolution_receipt_digest,
                    expected.receipt_digest,
                )
                self.assertEqual(
                    {
                        receipt.expected_resolution_receipt_digest,
                        receipt.action_resolution_receipt_digest,
                        receipt.post_stage_resolution_receipt_digest,
                    },
                    {expected.receipt_digest},
                )
                self.assertEqual(receipt.unique_file_count, 2)
                self.assertEqual(len(receipt.staged_files), 2)
                self.assertEqual(len(receipt.bindings), 2)
                self.assertEqual(
                    receipt.total_staged_bytes,
                    len(b"first-controller-tool\n")
                    + len(b"repository-relative-tool\n"),
                )
                self.assertEqual(
                    {value.staged_file_ref for value in receipt.staged_files},
                    {value.staged_file_ref for value in receipt.bindings},
                )
                for value in receipt.staged_files:
                    self.assertIsInstance(value, RepositoryExecutableStagedFile)
                    self.assertEqual(set(value.to_canonical()), STAGED_FILE_KEYS)
                for value in receipt.bindings:
                    self.assertIsInstance(value, RepositoryExecutableStageBinding)
                    self.assertEqual(set(value.to_canonical()), STAGE_BINDING_KEYS)

                evidence = receipt.to_evidence()
                self.assertEqual(set(evidence), STAGING_EVIDENCE_KEYS)
                self.assertEqual(
                    evidence["kind"],
                    REPOSITORY_EXECUTABLE_STAGING_EVIDENCE_KIND,
                )
                self.assertEqual(evidence["validation_mode"], "local_staging")
                self.assertEqual(evidence["effect_class"], 1)
                self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
                self.assertEqual(evidence["staged_file_count"], 2)
                self.assertEqual(
                    evidence["total_staged_bytes"],
                    receipt.total_staged_bytes,
                )
                for true_fact in (
                    "action_boundary_remeasurement_complete",
                    "controller_write_descriptors_closed",
                    "expected_resolution_correspondence_verified",
                    "lease_scoped_filesystem_stage_established",
                    "lease_process_binding_established",
                    "post_stage_resolution_correspondence_verified",
                    "read_only_descriptor_lease_established",
                    "staged_byte_correspondence_verified",
                    "staged_readback_complete",
                ):
                    self.assertIs(evidence[true_fact], True)
                for false_fact in (
                    STAGING_EVIDENCE_KEYS
                    - {
                        "action_boundary_remeasurement_complete",
                        "controller_write_descriptors_closed",
                        "effect_class",
                        "expected_resolution_correspondence_verified",
                        "kind",
                        "lease_scoped_filesystem_stage_established",
                        "lease_process_binding_established",
                        "measurement_source",
                        "post_stage_resolution_correspondence_verified",
                        "read_only_descriptor_lease_established",
                        "receipt_digest",
                        "registration_digest",
                        "repository_ref",
                        "resolution_context_digest",
                        "resolution_scope",
                        "schema_version",
                        "staged_byte_correspondence_verified",
                        "staged_file_count",
                        "staged_readback_complete",
                        "staging_scope",
                        "staging_source",
                        "total_staged_bytes",
                        "validation_mode",
                    }
                ):
                    self.assertIs(evidence[false_fact], False, false_fact)

                aggregate = "\n".join(
                    (
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        repr(lease),
                        *(repr(value) for value in receipt.staged_files),
                        *(repr(value) for value in receipt.bindings),
                    )
                )
                private_values = (
                    str(root),
                    str(search_one),
                    str(search_two),
                    str(staging_root),
                    "private-bare-command-marker",
                    "private-relative-command-marker",
                    "private-bare-tool-marker",
                    "private-relative-tool-marker",
                    *(value.content_digest for value in receipt.staged_files),
                )
                for private_value in private_values:
                    self.assertNotIn(private_value, aggregate)
                with self.assertRaises(FrozenInstanceError):
                    receipt.unique_file_count = 0
                self.assertEqual(tuple(staging_root.iterdir()), ())
            finally:
                lease.close()

    def test_shared_inode_is_staged_once_and_bound_twice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two, staging_root = (
                self._workspace(temporary)
            )
            payload = self._versioned_payload(4)
            payload["verification_commands"]["test"][0]["argv"][0] = (
                "private-bare-tool-marker"
            )
            payload["baseline_command_results"] = self._baseline(payload)
            payload["executable_toolchain_identities"] = self._identities(payload)
            registration = self._registration(root, payload=payload)
            expected, lease, receipt = self._stage(
                registration,
                (search_one,),
                staging_root,
            )
            try:
                self.assertEqual(len(expected.measurements), 2)
                self.assertEqual(expected.unique_file_count, 1)
                self.assertEqual(receipt.unique_file_count, 1)
                self.assertEqual(len(receipt.staged_files), 1)
                self.assertEqual(len(receipt.bindings), 2)
                self.assertEqual(
                    {binding.staged_file_ref for binding in receipt.bindings},
                    {receipt.staged_files[0].staged_file_ref},
                )
                self.assertEqual(
                    receipt.total_staged_bytes,
                    len(b"first-controller-tool\n"),
                )
                self.assertEqual(len(lease._files), 1)
            finally:
                lease.close()

    def test_lease_is_anonymous_read_only_noninheritable_and_nonexecutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            _expected, lease, receipt = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            expected_content = {
                "sha256:" + hashlib.sha256(content).hexdigest(): content
                for content in (
                    b"first-controller-tool\n",
                    b"repository-relative-tool\n",
                )
            }
            try:
                self.assertEqual(tuple(staging_root.iterdir()), ())
                self.assertIsNone(lease._root_descriptor)
                self.assertEqual(len(lease._files), receipt.unique_file_count)
                for retained in lease._files:
                    descriptor = retained.descriptor
                    metadata = os.fstat(descriptor)
                    self.assertTrue(stat.S_ISREG(metadata.st_mode))
                    self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
                    self.assertEqual(metadata.st_nlink, 0)
                    self.assertFalse(os.get_inheritable(descriptor))
                    self.assertEqual(
                        fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE,
                        os.O_RDONLY,
                    )
                    content = expected_content[retained.staged_file.content_digest]
                    self.assertEqual(os.pread(descriptor, len(content), 0), content)
                    self.assertEqual(os.pread(descriptor, 1, len(content)), b"")
                    with self.assertRaises(OSError):
                        os.write(descriptor, b"forbidden")
            finally:
                lease.close()

    def test_cleanup_is_context_managed_idempotent_and_lease_noncopyable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            _expected, lease, receipt = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            descriptors = tuple(value.descriptor for value in lease._files)
            for operation in (copy, deepcopy, pickle.dumps):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaises(TypeError) as caught:
                        operation(lease)
                    self.assertEqual(str(caught.exception), FIXED_COPY_ERROR)

            with lease as entered:
                self.assertIs(entered, lease)
                self.assertEqual(lease.state, "active")
            self.assertEqual(lease.state, "cleaned")
            cleanup = lease.cleanup_receipt
            self.assertIsInstance(cleanup, RepositoryExecutableStageCleanupReceipt)
            self.assertEqual(set(cleanup.to_canonical()), CLEANUP_RECEIPT_KEYS)
            self.assertEqual(cleanup.kind, REPOSITORY_EXECUTABLE_STAGE_CLEANUP_KIND)
            self.assertEqual(cleanup.outcome, "already_absent_verified")
            self.assertEqual(cleanup.staging_receipt_digest, receipt.receipt_digest)
            self.assertTrue(cleanup.owned_namespace_absence_verified)
            self.assertTrue(cleanup.descriptor_release_complete)
            self.assertFalse(cleanup.staging_root_identity_verified)
            self.assertFalse(cleanup.staging_root_metadata_restored)
            self.assertFalse(cleanup.secure_erasure_verified)
            self.assertIs(lease.close(), cleanup)
            self.assertIs(cleanup_repository_executable_stage(lease), cleanup)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(tuple(staging_root.iterdir()), ())

            new_lease = RepositoryExecutableStageLease(staging_root)
            with self.assertRaises(ValidationError) as caught:
                with new_lease:
                    self.fail("an inactive lease entered its context")
            self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
            self.assertIsNone(caught.exception.__cause__)
            cleanup_new = new_lease.close()
            self.assertEqual(cleanup_new.outcome, "already_absent_verified")
            self.assertIsNone(cleanup_new.staging_receipt_digest)

    def test_receipt_swap_is_rejected_and_cleanup_keeps_original_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            second_root = Path(temporary).resolve() / "second-stage"
            second_root.mkdir(mode=0o700)
            second_root.chmod(0o700)
            registration = self._registration(root)
            _expected_a, lease_a, receipt_a = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            _expected_b, lease_b, receipt_b = self._stage(
                registration,
                (search_one, search_two),
                second_root,
            )
            self.assertNotEqual(receipt_a.receipt_digest, receipt_b.receipt_digest)
            with self.assertRaises(AttributeError):
                lease_a.receipt = receipt_b

            lease_a._receipt = receipt_b
            with self.assertRaises(ConfigurationError) as caught:
                lease_a.close()
            self.assertEqual(str(caught.exception), FIXED_CLEANUP_ERROR)
            self.assertEqual(lease_a.state, "cleanup_unverifiable")
            recovered = lease_a.cleanup()
            self.assertEqual(lease_a.state, "cleaned")
            self.assertEqual(
                recovered.staging_receipt_digest,
                receipt_a.receipt_digest,
            )
            self.assertNotEqual(
                recovered.staging_receipt_digest,
                receipt_b.receipt_digest,
            )
            with self.assertRaises(AttributeError):
                lease_a.cleanup_receipt = lease_b.cleanup_receipt
            lease_b.close()

    def test_stale_and_tampered_expected_receipts_leave_no_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            self._write_executable(
                search_one / "private-bare-tool-marker",
                b"changed-after-preflight\n",
            )
            stale_lease = RepositoryExecutableStageLease(staging_root)
            self._assert_staging_invalid(
                registration,
                search_directories=(search_one, search_two),
                expected_resolution=expected,
                lease=stale_lease,
            )
            self.assertEqual(stale_lease.state, "new")
            self.assertIsNone(stale_lease.receipt)
            self.assertEqual(stale_lease._files, ())
            self.assertIsNone(stale_lease._root_descriptor)
            self.assertEqual(tuple(staging_root.iterdir()), ())
            stale_lease.close()

            current = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            tampered = replace(
                current,
                resolution_context_digest="sha256:" + "0" * 64,
            )
            tampered_lease = RepositoryExecutableStageLease(staging_root)
            self._assert_staging_invalid(
                registration,
                search_directories=(search_one, search_two),
                expected_resolution=tampered,
                lease=tampered_lease,
            )
            self.assertEqual(tampered_lease.state, "new")
            self.assertEqual(tuple(staging_root.iterdir()), ())
            tampered_lease.close()

    def test_staging_root_shape_mode_symlink_and_overlap_fail_closed(self) -> None:
        private_marker = "private-invalid-staging-root-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            missing = Path(temporary) / f"{private_marker}-missing"
            ordinary_file = Path(temporary) / f"{private_marker}-file"
            ordinary_file.write_text("not a directory\n", encoding="utf-8")
            symlink_target = Path(temporary) / f"{private_marker}-target"
            symlink_target.mkdir(mode=0o700)
            symlink = Path(temporary) / f"{private_marker}-symlink"
            symlink.symlink_to(symlink_target, target_is_directory=True)
            wrong_mode = Path(temporary) / f"{private_marker}-mode"
            wrong_mode.mkdir(mode=0o755)
            wrong_mode.chmod(0o755)
            nonempty = Path(temporary) / f"{private_marker}-nonempty"
            nonempty.mkdir(mode=0o700)
            nonempty.chmod(0o700)
            sentinel = nonempty / "sentinel"
            sentinel.write_text("untouched\n", encoding="utf-8")
            inside_repository = root / f"{private_marker}-repository"
            inside_repository.mkdir(mode=0o700)
            inside_repository.chmod(0o700)
            inside_search = search_one / f"{private_marker}-search"
            inside_search.mkdir(mode=0o700)
            inside_search.chmod(0o700)
            cases: tuple[tuple[str, object], ...] = (
                ("string", str(staging_root)),
                ("relative", Path(private_marker)),
                ("missing", missing),
                ("ordinary-file", ordinary_file),
                ("symlink", symlink),
                ("wrong-mode", wrong_mode),
                ("nonempty", nonempty),
                ("inside-repository", inside_repository),
                ("inside-search", inside_search),
            )
            for case, candidate in cases:
                with self.subTest(case=case):
                    lease = RepositoryExecutableStageLease(candidate)
                    self._assert_staging_invalid(
                        registration,
                        search_directories=(search_one, search_two),
                        expected_resolution=expected,
                        lease=lease,
                        private_marker=private_marker,
                    )
                    self.assertEqual(lease._files, ())
                    self.assertIsNone(lease.receipt)
                    if lease._root_descriptor is not None:
                        self.fail("invalid staging root retained a descriptor")
                    if lease.state == "new":
                        lease.close()
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"),
                "untouched\n",
            )

    def test_v1_through_v3_reject_before_expected_or_resolution_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, _search_one, _search_two, _staging_root = (
                self._workspace(temporary)
            )
            registrations = tuple(
                self._registration(root, schema_version=version)
                for version in (1, 2, 3)
            )
            missing_root = Path(temporary) / "private-uninspected-root-marker"
            with (
                patch.object(
                    staging_module,
                    "_BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION",
                    side_effect=AssertionError("must not revalidate"),
                ) as revalidate,
                patch.object(
                    staging_module,
                    "_BUILTIN_RESOLUTION_PROJECTION",
                    side_effect=AssertionError("must not inspect expected"),
                ) as project_expected,
                patch.object(
                    staging_module,
                    "_BUILTIN_RESOLVE_REPOSITORY_EXECUTABLES",
                    side_effect=AssertionError("must not resolve"),
                ) as resolve,
                patch.object(
                    staging_module,
                    "_prepare_staging_root",
                    side_effect=AssertionError("must not inspect root"),
                ) as prepare_root,
            ):
                for registration in registrations:
                    with self.subTest(schema_version=registration.schema_version):
                        lease = RepositoryExecutableStageLease(missing_root)
                        self._assert_staging_invalid(
                            registration,
                            search_directories=object(),
                            expected_resolution=object(),
                            lease=lease,
                        )
                        self.assertEqual(lease.state, "new")
            for observed in (
                revalidate,
                project_expected,
                resolve,
                prepare_root,
            ):
                observed.assert_not_called()

    def test_source_capture_and_post_stage_source_races_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            selected = search_one / "private-bare-tool-marker"
            real_capture = staging_module._CaptureSink.__call__
            changed = False

            def mutate_before_capture(
                sink: object,
                descriptor: int,
                metadata: os.stat_result,
                measured: object,
            ) -> None:
                nonlocal changed
                if not changed:
                    changed = True
                    self._write_executable(selected, b"capture-race-change\n")
                real_capture(sink, descriptor, metadata, measured)

            lease = RepositoryExecutableStageLease(staging_root)
            with patch.object(
                staging_module._CaptureSink,
                "__call__",
                new=mutate_before_capture,
            ):
                self._assert_staging_invalid(
                    registration,
                    search_directories=(search_one, search_two),
                    expected_resolution=expected,
                    lease=lease,
                )
            self.assertTrue(changed)
            self.assertEqual(lease.state, "new")
            self.assertEqual(tuple(staging_root.iterdir()), ())
            lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            selected = search_one / "private-bare-tool-marker"
            real_stage = staging_module._stage_captured_file
            changed = False

            def mutate_after_stage(
                lease_value: RepositoryExecutableStageLease,
                captured: object,
                *,
                staging_context_digest: str,
            ) -> object:
                nonlocal changed
                retained = real_stage(
                    lease_value,
                    captured,
                    staging_context_digest=staging_context_digest,
                )
                if not changed:
                    changed = True
                    self._write_executable(selected, b"post-stage-race-change\n")
                return retained

            lease = RepositoryExecutableStageLease(staging_root)
            with patch.object(
                staging_module,
                "_stage_captured_file",
                new=mutate_after_stage,
            ):
                self._assert_staging_invalid(
                    registration,
                    search_directories=(search_one, search_two),
                    expected_resolution=expected,
                    lease=lease,
                )
            self.assertTrue(changed)
            self.assertEqual(lease.state, "cleaned")
            self.assertEqual(lease._files, ())
            self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_staged_entry_and_root_identity_races_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            real_entry_metadata = staging_module._entry_metadata
            injected = False

            def mismatching_entry(
                directory_descriptor: int,
                name: str,
            ) -> object:
                nonlocal injected
                observed = real_entry_metadata(directory_descriptor, name)
                if observed is not None and not injected:
                    injected = True
                    return SimpleNamespace(
                        st_mode=observed.st_mode,
                        st_dev=observed.st_dev,
                        st_ino=observed.st_ino + 1,
                    )
                return observed

            lease = RepositoryExecutableStageLease(staging_root)
            with patch.object(
                staging_module,
                "_entry_metadata",
                side_effect=mismatching_entry,
            ):
                self._assert_staging_invalid(
                    registration,
                    search_directories=(search_one, search_two),
                    expected_resolution=expected,
                    lease=lease,
                )
            self.assertTrue(injected)
            self.assertEqual(lease.state, "cleaned")
            self.assertEqual(tuple(staging_root.iterdir()), ())

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            real_identity_check = staging_module._root_path_identity_matches
            checks = 0

            def transient_root_mismatch(
                lease_value: RepositoryExecutableStageLease,
            ) -> bool:
                nonlocal checks
                checks += 1
                if checks == 1:
                    return False
                return real_identity_check(lease_value)

            lease = RepositoryExecutableStageLease(staging_root)
            with patch.object(
                staging_module,
                "_root_path_identity_matches",
                side_effect=transient_root_mismatch,
            ):
                self._assert_staging_invalid(
                    registration,
                    search_directories=(search_one, search_two),
                    expected_resolution=expected,
                    lease=lease,
                )
            self.assertGreaterEqual(checks, 2)
            self.assertEqual(lease.state, "cleaned")
            self.assertEqual(lease._files, ())
            self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_cleanup_uncertainty_uses_fixed_private_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            _expected, lease, _receipt = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            stale_descriptor = lease._files[0].descriptor
            os.close(stale_descriptor)
            replacement_descriptors: list[int] = []
            for _ in range(16):
                descriptor = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
                replacement_descriptors.append(descriptor)
                if descriptor == stale_descriptor:
                    break
            self.assertIn(stale_descriptor, replacement_descriptors)
            with self.assertRaises(ConfigurationError) as caught:
                lease.close()
            self.assertEqual(str(caught.exception), FIXED_CLEANUP_ERROR)
            self.assertNotIn("private-staging", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertEqual(lease.state, "cleanup_unverifiable")
            cleanup = lease.cleanup_receipt
            self.assertIsInstance(cleanup, RepositoryExecutableStageCleanupReceipt)
            self.assertEqual(cleanup.outcome, "unverifiable")
            self.assertFalse(cleanup.owned_namespace_absence_verified)
            self.assertFalse(cleanup.descriptor_release_complete)
            self.assertFalse(cleanup.staging_root_identity_verified)
            self.assertFalse(cleanup.secure_erasure_verified)
            refreshed_cleanup = lease.cleanup()
            self.assertEqual(refreshed_cleanup, cleanup)
            self.assertEqual(lease.state, "cleanup_unverifiable")
            self.assertEqual(lease._files, ())
            self.assertTrue(stat.S_ISREG(os.fstat(stale_descriptor).st_mode))
            self.assertEqual(tuple(staging_root.iterdir()), ())
            for descriptor in replacement_descriptors:
                os.close(descriptor)

    def test_no_process_environment_state_or_artifact_integration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            repository_before = self._tree_snapshot(root)
            outside_before = self._tree_snapshot(outside)
            search_one_before = self._tree_snapshot(search_one)
            search_two_before = self._tree_snapshot(search_two)
            lease = RepositoryExecutableStageLease(staging_root)

            with (
                patch.object(
                    shutil,
                    "which",
                    side_effect=AssertionError("ambient executable lookup"),
                ) as which,
                patch.object(
                    os,
                    "getenv",
                    side_effect=AssertionError("environment lookup"),
                ) as getenv,
                patch.object(
                    os,
                    "get_exec_path",
                    side_effect=AssertionError("PATH lookup"),
                ) as get_exec_path,
                patch.object(
                    subprocess,
                    "run",
                    side_effect=AssertionError("command execution"),
                ) as run,
                patch.object(
                    subprocess,
                    "Popen",
                    side_effect=AssertionError("process creation"),
                ) as popen,
                patch.object(
                    subprocess,
                    "call",
                    side_effect=AssertionError("process call"),
                ) as call,
                patch.object(
                    subprocess,
                    "check_call",
                    side_effect=AssertionError("checked process call"),
                ) as check_call,
                patch.object(
                    subprocess,
                    "check_output",
                    side_effect=AssertionError("process output"),
                ) as check_output,
                patch.object(
                    asyncio,
                    "create_subprocess_exec",
                    side_effect=AssertionError("worker creation"),
                ) as create_subprocess,
                patch.object(
                    asyncio,
                    "create_subprocess_shell",
                    side_effect=AssertionError("shell worker creation"),
                ) as create_subprocess_shell,
                patch.object(
                    os,
                    "system",
                    side_effect=AssertionError("shell execution"),
                ) as system,
                patch.object(
                    artifact_filesystem_module,
                    "stage_artifact",
                    side_effect=AssertionError("artifact staging"),
                ) as stage_artifact,
                patch.object(
                    artifact_filesystem_module,
                    "publish_staged_artifact",
                    side_effect=AssertionError("artifact publication"),
                ) as publish_artifact,
                patch.object(
                    state_module.SQLiteStateStore,
                    "__init__",
                    side_effect=AssertionError("state initialization"),
                ) as state_store,
            ):
                receipt = stage_repository_executable_bytes(
                    registration,
                    search_directories=(search_one, search_two),
                    expected_resolution=expected,
                    lease=lease,
                )
                evidence = receipt.to_evidence()
                cleanup = lease.close()
            self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
            self.assertEqual(cleanup.outcome, "already_absent_verified")
            for observed in (
                which,
                getenv,
                get_exec_path,
                run,
                popen,
                call,
                check_call,
                check_output,
                create_subprocess,
                create_subprocess_shell,
                system,
                stage_artifact,
                publish_artifact,
                state_store,
            ):
                observed.assert_not_called()
            self.assertEqual(self._tree_snapshot(root), repository_before)
            self.assertEqual(self._tree_snapshot(outside), outside_before)
            self.assertEqual(self._tree_snapshot(search_one), search_one_before)
            self.assertEqual(self._tree_snapshot(search_two), search_two_before)
            self.assertEqual(tuple(staging_root.iterdir()), ())
            self.assertFalse((root / ".ordomata").exists())
            self.assertFalse((root / ".git" / "worktrees").exists())

    def test_root_descriptor_handoff_survives_baseexception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            lease = RepositoryExecutableStageLease(staging_root)
            real_open_directory = staging_module._open_absolute_directory
            real_setattr = RepositoryExecutableStageLease.__setattr__
            tracked_descriptor: int | None = None
            tracked_identity: tuple[int, int] | None = None
            interrupted = False

            def track_staging_root_open(path: Path) -> object:
                nonlocal tracked_descriptor, tracked_identity
                pinned = real_open_directory(path)
                if path == staging_root and tracked_descriptor is None:
                    tracked_descriptor = pinned.descriptor
                    metadata = os.fstat(pinned.descriptor)
                    tracked_identity = (metadata.st_dev, metadata.st_ino)
                return pinned

            def interrupt_root_install(
                lease_value: RepositoryExecutableStageLease,
                name: str,
                value: object,
            ) -> None:
                nonlocal interrupted
                if (
                    lease_value is lease
                    and name == "_root_descriptor"
                    and value == tracked_descriptor
                    and not interrupted
                ):
                    interrupted = True
                    raise KeyboardInterrupt("injected root descriptor handoff")
                real_setattr(lease_value, name, value)

            try:
                with (
                    patch.object(
                        staging_module,
                        "_open_absolute_directory",
                        side_effect=track_staging_root_open,
                    ),
                    patch.object(
                        RepositoryExecutableStageLease,
                        "__setattr__",
                        new=interrupt_root_install,
                    ),
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        stage_repository_executable_bytes(
                            registration,
                            search_directories=(search_one, search_two),
                            expected_resolution=expected,
                            lease=lease,
                        )
                self.assertTrue(interrupted)
                self.assertIsNotNone(tracked_descriptor)
                with self.assertRaises(OSError):
                    os.fstat(tracked_descriptor)
                self.assertIsNone(lease._root_descriptor)
                self.assertEqual(lease._files, ())
                self.assertEqual(tuple(staging_root.iterdir()), ())
            finally:
                if tracked_descriptor is not None and tracked_identity is not None:
                    try:
                        metadata = os.fstat(tracked_descriptor)
                    except OSError:
                        pass
                    else:
                        if (metadata.st_dev, metadata.st_ino) == tracked_identity:
                            os.close(tracked_descriptor)

    def test_staged_reader_handoff_survives_baseexception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            lease = RepositoryExecutableStageLease(staging_root)
            real_setattr = RepositoryExecutableStageLease.__setattr__
            tracked_descriptor: int | None = None
            tracked_identity: tuple[int, int] | None = None
            interrupted = False

            def interrupt_files_install(
                lease_value: RepositoryExecutableStageLease,
                name: str,
                value: object,
            ) -> None:
                nonlocal interrupted, tracked_descriptor, tracked_identity
                if (
                    lease_value is lease
                    and name == "_files"
                    and type(value) is tuple
                    and bool(value)
                    and not interrupted
                ):
                    retained = value[-1]
                    tracked_descriptor = retained.descriptor
                    metadata = os.fstat(tracked_descriptor)
                    tracked_identity = (metadata.st_dev, metadata.st_ino)
                    interrupted = True
                    raise KeyboardInterrupt("injected staged reader handoff")
                real_setattr(lease_value, name, value)

            try:
                with patch.object(
                    RepositoryExecutableStageLease,
                    "__setattr__",
                    new=interrupt_files_install,
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        stage_repository_executable_bytes(
                            registration,
                            search_directories=(search_one, search_two),
                            expected_resolution=expected,
                            lease=lease,
                        )
                self.assertTrue(interrupted)
                self.assertIsNotNone(tracked_descriptor)
                with self.assertRaises(OSError):
                    os.fstat(tracked_descriptor)
                self.assertEqual(lease._files, ())
                self.assertIsNone(lease._root_descriptor)
                self.assertEqual(tuple(staging_root.iterdir()), ())
            finally:
                if tracked_descriptor is not None and tracked_identity is not None:
                    try:
                        metadata = os.fstat(tracked_descriptor)
                    except OSError:
                        pass
                    else:
                        if (metadata.st_dev, metadata.st_ino) == tracked_identity:
                            os.close(tracked_descriptor)

    def test_descriptors_return_to_baseline_after_cleanup_and_failure(self) -> None:
        descriptor_directory = Path("/dev/fd")
        if not descriptor_directory.is_dir():
            descriptor_directory = Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            self.skipTest("no process descriptor directory is available")

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            expected = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            descriptors_before = frozenset(os.listdir(descriptor_directory))
            lease = RepositoryExecutableStageLease(staging_root)
            stage_repository_executable_bytes(
                registration,
                search_directories=(search_one, search_two),
                expected_resolution=expected,
                lease=lease,
            )
            lease.close()
            self.assertEqual(
                frozenset(os.listdir(descriptor_directory)),
                descriptors_before,
            )

            real_identity_check = staging_module._root_path_identity_matches
            calls = 0

            def one_failed_check(
                lease_value: RepositoryExecutableStageLease,
            ) -> bool:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return False
                return real_identity_check(lease_value)

            failing_lease = RepositoryExecutableStageLease(staging_root)
            with patch.object(
                staging_module,
                "_root_path_identity_matches",
                side_effect=one_failed_check,
            ):
                self._assert_staging_invalid(
                    registration,
                    search_directories=(search_one, search_two),
                    expected_resolution=expected,
                    lease=failing_lease,
                )
            self.assertEqual(
                frozenset(os.listdir(descriptor_directory)),
                descriptors_before,
            )


if __name__ == "__main__":
    unittest.main()
