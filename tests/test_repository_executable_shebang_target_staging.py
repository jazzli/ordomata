from __future__ import annotations

import asyncio
from contextlib import ExitStack
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

import ordomata.artifact_filesystem as artifact_filesystem_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
import ordomata.repository_executable_shebang_target_staging as target_staging_module
from ordomata.repository_executable_shebang_target_resolution import (
    RepositoryExecutableShebangTargetResolutionReceipt,
    inspect_staged_executable_shebang_targets,
)
from ordomata.repository_executable_shebang_target_staging import (
    RepositoryExecutableShebangTargetStagedFile,
    RepositoryExecutableShebangTargetStageBinding,
    RepositoryExecutableShebangTargetStageCleanupReceipt,
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStageRequirement,
    RepositoryExecutableShebangTargetStagingReceipt,
    cleanup_repository_executable_shebang_target_stage,
    stage_repository_executable_shebang_target_bytes,
)
from ordomata.repository_executable_staging import (
    RepositoryExecutableStageLease,
)
import ordomata.state as state_module

if __package__:
    from . import (
        test_repository_executable_shebang_target_resolution
        as target_resolution_test_module,
    )
else:
    import test_repository_executable_shebang_target_resolution as target_resolution_test_module


FIXED_STAGING_ERROR = "repository executable shebang target staging is invalid"
FIXED_CLEANUP_ERROR = (
    "repository executable shebang target staging cleanup is uncertain"
)
FIXED_COPY_ERROR = (
    "repository executable shebang target staging lease cannot be copied"
)
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
STAGED_FILE_KEYS = {
    "content_bytes",
    "content_digest",
    "kind",
    "source_filesystem_identity_ref",
    "source_metadata_digest",
    "staged_filesystem_identity_ref",
    "staged_metadata_digest",
    "target_measurement_ref",
    "target_path_ref",
    "target_staged_file_ref",
}
STAGE_REQUIREMENT_KEYS = {
    "disposition",
    "kind",
    "requirement_ref",
    "runtime_classification",
    "runtime_file_ref",
    "schema_version",
    "staged_file_ref",
    "target_measurement_ref",
    "target_requirement_ref",
    "target_stage_requirement_ref",
    "target_staged_file_ref",
}
STAGE_BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
    "target_stage_requirement_ref",
}
STAGING_RECEIPT_KEYS = {
    "action_target_resolution_receipt_digest",
    "bindings",
    "command_count",
    "direct_target_requirement_count",
    "expected_target_resolution_receipt_digest",
    "kind",
    "measurement_source",
    "native_not_applicable_count",
    "post_stage_target_resolution_receipt_digest",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "resolution_context_digest",
    "resolution_scope",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shebang_requirements_receipt_digest",
    "source_staging_context_digest",
    "staged_files",
    "staging_receipt_digest",
    "staging_root_used",
    "staging_scope",
    "staging_source",
    "target_path_context_digest",
    "target_staging_context_digest",
    "total_staged_bytes",
    "unique_target_count",
    "verification_commands_digest",
}
CLEANUP_RECEIPT_KEYS = {
    "descriptor_release_complete",
    "kind",
    "outcome",
    "owned_namespace_absence_verified",
    "schema_version",
    "secure_erasure_verified",
    "staging_root_identity_verified",
    "staging_root_metadata_restored",
    "target_staging_receipt_digest",
}


@unittest.skipUnless(os.name == "posix", "target staging requires POSIX")
class RepositoryExecutableShebangTargetStagingTests(unittest.TestCase):
    fixture = (
        target_resolution_test_module
        .RepositoryExecutableShebangTargetResolutionTests
    )

    @classmethod
    def _workspace(
        cls,
        temporary: str,
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        root, outside, search_one, search_two, executable_stage_root = (
            cls.fixture._workspace(temporary)
        )
        target_stage_root = (
            Path(temporary).resolve(strict=True)
            / "private-target-stage-root-marker"
        )
        target_stage_root.mkdir(mode=0o700)
        target_stage_root.chmod(0o700)
        return (
            root,
            outside,
            search_one,
            search_two,
            executable_stage_root,
            target_stage_root,
        )

    @classmethod
    def _registration(cls, root: Path, *, shared: bool = False):
        return cls.fixture._registration(root, shared=shared)

    @classmethod
    def _set_contents(
        cls,
        root: Path,
        search_one: Path,
        *,
        bare: bytes,
        relative: bytes | None = None,
    ) -> None:
        cls.fixture._set_contents(
            root,
            search_one,
            bare=bare,
            relative=relative,
        )

    @classmethod
    def _write_target(cls, path: Path, content: bytes) -> None:
        cls.fixture._write_target(path, content)

    @classmethod
    def _tree_snapshot(cls, path: Path) -> tuple[object, ...]:
        return cls.fixture._tree_snapshot(path)

    @classmethod
    def _executable_lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    @staticmethod
    def _descriptor_directory() -> Path | None:
        for candidate in (Path("/dev/fd"), Path("/proc/self/fd")):
            if candidate.is_dir():
                return candidate
        return None

    @classmethod
    def _resolution_chain(
        cls,
        registration: object,
        search_directories: tuple[Path, ...],
        executable_stage_root: Path,
        target_paths: tuple[Path, ...],
    ) -> tuple[object, object, object, object, object]:
        executable_lease, staging, runtime, requirements = (
            cls.fixture._stage_requirements(
                registration,
                search_directories,
                executable_stage_root,
            )
        )
        target_resolution = inspect_staged_executable_shebang_targets(
            requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=executable_lease,
            expected_target_paths=target_paths,
        )
        return (
            executable_lease,
            staging,
            runtime,
            requirements,
            target_resolution,
        )

    @staticmethod
    def _stage(
        registration: object,
        *,
        search_directories: tuple[Path, ...],
        target_resolution: object,
        requirements: object,
        runtime: object,
        staging: object,
        executable_lease: object,
        target_paths: object,
        target_lease: object,
    ) -> RepositoryExecutableShebangTargetStagingReceipt:
        return stage_repository_executable_shebang_target_bytes(
            registration,
            search_directories=search_directories,
            expected_target_resolution=target_resolution,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            executable_lease=executable_lease,
            expected_target_paths=target_paths,
            lease=target_lease,
        )

    def _assert_invalid(
        self,
        registration: object,
        *,
        search_directories: object,
        target_resolution: object,
        requirements: object,
        runtime: object,
        staging: object,
        executable_lease: object,
        target_paths: object,
        target_lease: object,
        private_marker: str = "private-target-staging-error-marker",
    ) -> ValidationError:
        with self.assertRaises(ValidationError) as caught:
            self._stage(
                registration,
                search_directories=search_directories,
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=target_paths,
                target_lease=target_lease,
            )
        self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    @staticmethod
    def _common_fields(
        left: dict[str, object],
        right: dict[str, object],
        fields: tuple[str, ...],
    ) -> None:
        for field in fields:
            if field in left and field in right:
                if left[field] != right[field]:
                    raise AssertionError(
                        f"field {field!r} differs: "
                        f"{left[field]!r} != {right[field]!r}"
                    )

    def test_receipt_evidence_correspondence_privacy_and_source_lease_unchanged(
        self,
    ) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        target_content = b"private-target-stage-content-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = (
                Path(temporary).resolve(strict=True)
                / "private-target-source-directory-marker"
                / "private-target-source-file-marker"
            )
            self._write_target(target, target_content)
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=b"#!" + os.fsencode(target) + b" -I\nbody\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            source_before = self._executable_lease_snapshot(executable_lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
            )
            try:
                receipt = self._stage(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(target,),
                    target_lease=target_lease,
                )
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangTargetStagingReceipt,
                )
                self.assertIs(target_lease.receipt, receipt)
                self.assertEqual(target_lease.state, "active")
                self.assertEqual(
                    self._executable_lease_snapshot(executable_lease),
                    source_before,
                )
                self.assertEqual(
                    tuple(
                        self._tree_snapshot(path)
                        for path in (
                            root,
                            outside,
                            search_one,
                            search_two,
                            target.parent,
                        )
                    ),
                    trees_before,
                )
                self.assertEqual(tuple(target_stage_root.iterdir()), ())

                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), STAGING_RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                self.assertEqual(
                    receipt.expected_target_resolution_receipt_digest,
                    target_resolution.receipt_digest,
                )
                self.assertEqual(
                    {
                        receipt.expected_target_resolution_receipt_digest,
                        receipt.action_target_resolution_receipt_digest,
                        receipt.post_stage_target_resolution_receipt_digest,
                    },
                    {target_resolution.receipt_digest},
                )
                for field, upstream in (
                    ("shebang_requirements_receipt_digest", requirements),
                    ("runtime_manifest_receipt_digest", runtime),
                    ("staging_receipt_digest", staging),
                ):
                    self.assertEqual(getattr(receipt, field), upstream.receipt_digest)
                for field in (
                    "registration_digest",
                    "repository_ref",
                    "verification_commands_digest",
                    "resolution_context_digest",
                    "target_path_context_digest",
                ):
                    self.assertEqual(
                        getattr(receipt, field),
                        getattr(target_resolution, field),
                    )
                self.assertEqual(
                    receipt.source_staging_context_digest,
                    target_resolution.staging_context_digest,
                )
                self.assertRegex(receipt.target_staging_context_digest, _DIGEST_PATTERN)
                self.assertTrue(receipt.staging_root_used)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(receipt.total_staged_bytes, len(target_content))
                self.assertEqual(len(receipt.staged_files), 1)
                self.assertEqual(len(receipt.requirements), 2)
                self.assertEqual(len(receipt.bindings), 2)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.direct_target_requirement_count, 1)
                self.assertEqual(receipt.native_not_applicable_count, 1)

                staged_file = receipt.staged_files[0]
                self.assertIsInstance(
                    staged_file,
                    RepositoryExecutableShebangTargetStagedFile,
                )
                self.assertEqual(
                    set(staged_file.to_canonical()),
                    STAGED_FILE_KEYS,
                )
                self.assertEqual(staged_file.content_bytes, len(target_content))
                self.assertEqual(
                    staged_file.content_digest,
                    "sha256:" + hashlib.sha256(target_content).hexdigest(),
                )
                self.assertEqual(
                    staged_file.target_measurement_ref,
                    target_resolution.measurements[0].measurement_ref,
                )
                self.assertEqual(
                    staged_file.target_path_ref,
                    target_resolution.measurements[0].path_ref,
                )
                for value in receipt.requirements:
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangTargetStageRequirement,
                    )
                    self.assertEqual(
                        set(value.to_canonical()),
                        STAGE_REQUIREMENT_KEYS,
                    )
                for value in receipt.bindings:
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangTargetStageBinding,
                    )
                    self.assertEqual(
                        set(value.to_canonical()),
                        STAGE_BINDING_KEYS,
                    )

                by_target_requirement = {
                    item.target_requirement_ref: item
                    for item in receipt.requirements
                }
                for item, upstream in zip(
                    receipt.requirements,
                    target_resolution.requirements,
                    strict=True,
                ):
                    self._common_fields(
                        item.to_canonical(),
                        upstream.to_canonical(),
                        (
                            "staged_file_ref",
                            "runtime_file_ref",
                            "requirement_ref",
                            "runtime_classification",
                            "target_measurement_ref",
                            "target_requirement_ref",
                        ),
                    )
                    if upstream.target_measurement_ref is None:
                        self.assertIsNone(item.target_staged_file_ref)
                    else:
                        self.assertEqual(
                            item.target_staged_file_ref,
                            staged_file.target_staged_file_ref,
                        )
                for item, upstream in zip(
                    receipt.bindings,
                    target_resolution.bindings,
                    strict=True,
                ):
                    self._common_fields(
                        item.to_canonical(),
                        upstream.to_canonical(),
                        (
                            "command_kind",
                            "command_id",
                            "command_digest",
                            "staged_file_ref",
                            "runtime_file_ref",
                            "requirement_ref",
                            "target_requirement_ref",
                        ),
                    )
                    self.assertEqual(
                        item.target_stage_requirement_ref,
                        by_target_requirement[
                            item.target_requirement_ref
                        ].target_stage_requirement_ref,
                    )

                evidence = receipt.to_evidence()
                self.assertEqual(evidence["effect_class"], 1)
                self.assertEqual(evidence["validation_mode"], "local_staging")
                self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
                for true_fact in (
                    "action_boundary_target_remeasurement_complete",
                    "controller_write_descriptors_closed",
                    "exact_receipt_chain_verified",
                    "lease_process_binding_established",
                    "post_stage_target_resolution_correspondence_verified",
                    "read_only_descriptor_lease_established",
                    "staged_byte_correspondence_verified",
                    "staged_readback_complete",
                ):
                    self.assertIs(evidence[true_fact], True, true_fact)
                for false_fact in (
                    "authority_granted",
                    "authorization_verified",
                    "billing_eligible",
                    "capacity_eligible",
                    "circuit_eligible",
                    "dispatch_enabled",
                    "durable_control_plane_persistence_enabled",
                    "effective_invocability_verified",
                    "execution_enabled",
                    "external_hardlink_alias_excluded",
                    "filesystem_immutability_verified",
                    "future_execution_correspondence_verified",
                    "hardlink_alias_exclusion_verified",
                    "interpreter_identity_verified",
                    "interpreter_provenance_verified",
                    "live_execution_eligible",
                    "proposal_lineage_extended",
                    "receipt_authenticity_verified",
                    "route_eligible",
                    "same_uid_tamper_exclusion_verified",
                    "secure_erasure_verified",
                    "toolchain_completeness_verified",
                ):
                    self.assertIs(evidence[false_fact], False, false_fact)

                aggregate = "\n".join(
                    (
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        repr(target_lease),
                        *(repr(item) for item in receipt.staged_files),
                        *(repr(item) for item in receipt.requirements),
                        *(repr(item) for item in receipt.bindings),
                    )
                )
                for private_value in (
                    str(root),
                    str(search_one),
                    str(search_two),
                    str(executable_stage_root),
                    str(target_stage_root),
                    str(target),
                    "private-target-source-file-marker",
                    "private-target-stage-content-marker",
                    staged_file.content_digest,
                ):
                    self.assertNotIn(private_value, aggregate)
                with self.assertRaises(FrozenInstanceError):
                    receipt.unique_file_count = 0
                with self.assertRaises(FrozenInstanceError):
                    staged_file.content_bytes = 0
            finally:
                target_lease.close()
                executable_lease.close()

    def test_shared_target_is_staged_once_and_bound_deterministically(self) -> None:
        target_content = b"one-private-shared-target-stage\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "shared-stage-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            try:
                receipt = self._stage(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(target,),
                    target_lease=target_lease,
                )
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(len(receipt.staged_files), 1)
                self.assertEqual(len(receipt.requirements), 2)
                self.assertEqual(len(receipt.bindings), 2)
                self.assertEqual(
                    receipt.total_staged_bytes,
                    len(target_content),
                )
                self.assertEqual(
                    {
                        item.target_staged_file_ref
                        for item in receipt.requirements
                    },
                    {receipt.staged_files[0].target_staged_file_ref},
                )
                self.assertEqual(
                    tuple(item.command_id for item in receipt.bindings),
                    tuple(item.command_id for item in target_resolution.bindings),
                )
                self.assertEqual(len(target_lease._files), 1)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_native_only_establishes_active_empty_lease_without_touching_root(
        self,
    ) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target_stage_root.rmdir()
            self._set_contents(root, search_one, bare=elf, relative=elf)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            try:
                receipt = self._stage(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(),
                    target_lease=target_lease,
                )
                self.assertEqual(target_lease.state, "active")
                self.assertEqual(receipt.unique_target_count, 0)
                self.assertEqual(receipt.total_staged_bytes, 0)
                self.assertFalse(receipt.staging_root_used)
                self.assertEqual(receipt.staged_files, ())
                self.assertEqual(target_lease._files, ())
                self.assertIsNone(target_lease._root_descriptor)
                self.assertFalse(target_stage_root.exists())
                evidence = receipt.to_evidence()
                self.assertEqual(evidence["effect_class"], 1)
                self.assertFalse(evidence["staging_root_used"])
                self.assertFalse(evidence["read_only_descriptor_lease_established"])
                self.assertFalse(evidence["controller_write_descriptors_closed"])
                self.assertFalse(evidence["staged_readback_complete"])
            finally:
                target_lease.close()
                executable_lease.close()
            self.assertFalse(target_stage_root.exists())

    def test_retained_descriptor_has_exact_anonymous_read_only_bytes(self) -> None:
        target_content = b"private-exact-retained-target-bytes\x00\xff\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "retained-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            try:
                receipt = self._stage(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(target,),
                    target_lease=target_lease,
                )
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
                self.assertIsNone(target_lease._root_descriptor)
                self.assertEqual(len(target_lease._files), 1)
                retained = target_lease._files[0]
                descriptor = retained.descriptor
                metadata = os.fstat(descriptor)
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
                self.assertEqual(metadata.st_nlink, 0)
                self.assertEqual(metadata.st_size, len(target_content))
                self.assertFalse(os.get_inheritable(descriptor))
                self.assertEqual(
                    fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE,
                    os.O_RDONLY,
                )
                self.assertEqual(
                    os.pread(descriptor, len(target_content), 0),
                    target_content,
                )
                self.assertEqual(
                    os.pread(descriptor, 1, len(target_content)),
                    b"",
                )
                self.assertEqual(
                    retained.staged_file.content_digest,
                    "sha256:" + hashlib.sha256(target_content).hexdigest(),
                )
                self.assertEqual(retained.staged_file, receipt.staged_files[0])
                with self.assertRaises(OSError):
                    os.write(descriptor, b"forbidden")
            finally:
                target_lease.close()
                executable_lease.close()

    def test_staged_bytes_are_independent_of_target_path_after_success(self) -> None:
        original = b"captured-target-before-source-change\n"
        changed = b"changed-target-after-success\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "mutable-source-target"
            self._write_target(target, original)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            try:
                self._stage(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(target,),
                    target_lease=target_lease,
                )
                descriptor = target_lease._files[0].descriptor
                self._write_target(target, changed)
                self.assertEqual(os.pread(descriptor, len(original), 0), original)
                self.assertEqual(target.read_bytes(), changed)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_cleanup_context_idempotence_noncopy_and_original_anchors(self) -> None:
        target_content = b"cleanup-target-content\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "cleanup-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            receipt = self._stage(
                registration,
                search_directories=(search_one, search_two),
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=(target,),
                target_lease=target_lease,
            )
            descriptors = tuple(item.descriptor for item in target_lease._files)
            for operation in (copy, deepcopy, pickle.dumps):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaises(TypeError) as caught:
                        operation(target_lease)
                    self.assertEqual(str(caught.exception), FIXED_COPY_ERROR)

            with target_lease as entered:
                self.assertIs(entered, target_lease)
                self.assertEqual(target_lease.state, "active")
            self.assertEqual(target_lease.state, "cleaned")
            cleanup = target_lease.cleanup_receipt
            self.assertIsInstance(
                cleanup,
                RepositoryExecutableShebangTargetStageCleanupReceipt,
            )
            self.assertEqual(set(cleanup.to_canonical()), CLEANUP_RECEIPT_KEYS)
            self.assertEqual(
                cleanup.target_staging_receipt_digest,
                receipt.receipt_digest,
            )
            self.assertEqual(cleanup.outcome, "already_absent_verified")
            self.assertTrue(cleanup.owned_namespace_absence_verified)
            self.assertTrue(cleanup.descriptor_release_complete)
            self.assertFalse(cleanup.secure_erasure_verified)
            self.assertIs(target_lease.close(), cleanup)
            self.assertIs(
                cleanup_repository_executable_shebang_target_stage(target_lease),
                cleanup,
            )
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(tuple(target_stage_root.iterdir()), ())
            executable_lease.close()

            new_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            with self.assertRaises(ValidationError) as caught:
                with new_lease:
                    self.fail("an inactive target lease entered its context")
            self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
            self.assertIsNone(caught.exception.__cause__)
            new_cleanup = new_lease.close()
            self.assertEqual(new_cleanup.outcome, "already_absent_verified")
            self.assertIsNone(new_cleanup.target_staging_receipt_digest)

    def test_receipt_swap_cleanup_uses_original_digest_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            second_target_stage_root = (
                Path(temporary).resolve(strict=True) / "second-target-stage-root"
            )
            second_target_stage_root.mkdir(mode=0o700)
            second_target_stage_root.chmod(0o700)
            target = Path(temporary).resolve(strict=True) / "anchor-target"
            self._write_target(target, b"anchor-target-content\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            lease_a = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            lease_b = RepositoryExecutableShebangTargetStageLease(
                second_target_stage_root
            )
            receipt_a = self._stage(
                registration,
                search_directories=(search_one, search_two),
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=(target,),
                target_lease=lease_a,
            )
            receipt_b = self._stage(
                registration,
                search_directories=(search_one, search_two),
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=(target,),
                target_lease=lease_b,
            )
            self.assertNotEqual(receipt_a.receipt_digest, receipt_b.receipt_digest)
            with self.assertRaises(AttributeError):
                lease_a.receipt = receipt_b

            lease_a._receipt = receipt_b
            with self.assertRaises(ConfigurationError) as caught:
                lease_a.close()
            self.assertEqual(str(caught.exception), FIXED_CLEANUP_ERROR)
            self.assertIsNone(caught.exception.__cause__)
            self.assertEqual(lease_a.state, "cleanup_unverifiable")
            recovered = lease_a.cleanup()
            self.assertEqual(lease_a.state, "cleaned")
            self.assertEqual(
                recovered.target_staging_receipt_digest,
                receipt_a.receipt_digest,
            )
            self.assertNotEqual(
                recovered.target_staging_receipt_digest,
                receipt_b.receipt_digest,
            )
            lease_b.close()
            executable_lease.close()

    def test_cleanup_uncertainty_never_closes_a_reused_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "cleanup-race-target"
            self._write_target(target, b"cleanup-race-content\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            receipt = self._stage(
                registration,
                search_directories=(search_one, search_two),
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=(target,),
                target_lease=target_lease,
            )
            stale_descriptor = target_lease._files[0].descriptor
            os.close(stale_descriptor)
            replacements: list[int] = []
            try:
                for _ in range(32):
                    descriptor = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
                    replacements.append(descriptor)
                    if descriptor == stale_descriptor:
                        break
                self.assertIn(stale_descriptor, replacements)

                with self.assertRaises(ConfigurationError) as caught:
                    target_lease.close()
                self.assertEqual(str(caught.exception), FIXED_CLEANUP_ERROR)
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(target_lease.state, "cleanup_unverifiable")
                cleanup = target_lease.cleanup_receipt
                self.assertIsInstance(
                    cleanup,
                    RepositoryExecutableShebangTargetStageCleanupReceipt,
                )
                self.assertEqual(cleanup.outcome, "unverifiable")
                self.assertEqual(
                    cleanup.target_staging_receipt_digest,
                    receipt.receipt_digest,
                )
                self.assertFalse(cleanup.owned_namespace_absence_verified)
                self.assertFalse(cleanup.descriptor_release_complete)
                self.assertFalse(cleanup.secure_erasure_verified)
                self.assertEqual(len(target_lease._files), 1)
                self.assertTrue(
                    stat.S_ISREG(os.fstat(stale_descriptor).st_mode)
                )
                refreshed = target_lease.cleanup()
                self.assertEqual(refreshed, cleanup)
                self.assertEqual(target_lease._files, ())
                self.assertEqual(target_lease.state, "cleanup_unverifiable")
                self.assertTrue(
                    stat.S_ISREG(os.fstat(stale_descriptor).st_mode)
                )
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
            finally:
                for descriptor in replacements:
                    os.close(descriptor)
                executable_lease.close()

    def test_stale_tampered_reordered_and_wrong_inputs_fail_before_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target_one = Path(temporary).resolve(strict=True) / "input-target-one"
            target_two = Path(temporary).resolve(strict=True) / "input-target-two"
            self._write_target(target_one, b"target-one\n")
            self._write_target(target_two, b"target-two\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target_one) + b"\n",
                relative=b"#!" + os.fsencode(target_two) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target_one, target_two),
            )
            tampered = replace(
                target_resolution,
                target_path_context_digest="sha256:" + "0" * 64,
            )
            cases = (
                ("wrong-resolution-type", object(), requirements, runtime, staging,
                 executable_lease, (target_one, target_two)),
                ("wrong-requirements", target_resolution, object(), runtime, staging,
                 executable_lease, (target_one, target_two)),
                ("wrong-runtime", target_resolution, requirements, object(), staging,
                 executable_lease, (target_one, target_two)),
                ("wrong-staging", target_resolution, requirements, runtime, object(),
                 executable_lease, (target_one, target_two)),
                ("wrong-source-lease", target_resolution, requirements, runtime,
                 staging, object(), (target_one, target_two)),
                ("tampered", tampered, requirements, runtime, staging,
                 executable_lease, (target_one, target_two)),
                ("reordered-paths", target_resolution, requirements, runtime, staging,
                 executable_lease, (target_two, target_one)),
                ("wrong-path-type", target_resolution, requirements, runtime, staging,
                 executable_lease, (str(target_one), str(target_two))),
            )
            try:
                for (
                    case,
                    expected,
                    expected_requirements,
                    expected_runtime,
                    expected_staging,
                    source_lease,
                    paths,
                ) in cases:
                    with self.subTest(case=case):
                        lease = RepositoryExecutableShebangTargetStageLease(
                            target_stage_root
                        )
                        self._assert_invalid(
                            registration,
                            search_directories=(search_one, search_two),
                            target_resolution=expected,
                            requirements=expected_requirements,
                            runtime=expected_runtime,
                            staging=expected_staging,
                            executable_lease=source_lease,
                            target_paths=paths,
                            target_lease=lease,
                        )
                        self.assertEqual(lease.state, "new")
                        self.assertIsNone(lease.receipt)
                        self.assertEqual(lease._files, ())
                        self.assertIsNone(lease._root_descriptor)
                        self.assertEqual(tuple(target_stage_root.iterdir()), ())
                        lease.close()

                self._write_target(target_one, b"changed-after-resolution\n")
                stale_lease = RepositoryExecutableShebangTargetStageLease(
                    target_stage_root
                )
                self._assert_invalid(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(target_one, target_two),
                    target_lease=stale_lease,
                )
                self.assertEqual(stale_lease.state, "new")
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
                stale_lease.close()
            finally:
                executable_lease.close()

    def test_target_staging_root_shape_mode_empty_and_overlap_fail_closed(
        self,
    ) -> None:
        marker = "private-invalid-target-stage-root-marker"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = (
                Path(temporary).resolve(strict=True)
                / "target-parent-for-overlap"
                / "target-file-for-overlap"
            )
            self._write_target(target, b"overlap-target\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )

            missing = Path(temporary) / f"{marker}-missing"
            ordinary = Path(temporary) / f"{marker}-file"
            ordinary.write_text("not a directory\n", encoding="utf-8")
            symlink_target = Path(temporary) / f"{marker}-symlink-target"
            symlink_target.mkdir(mode=0o700)
            symlink = Path(temporary) / f"{marker}-symlink"
            symlink.symlink_to(symlink_target, target_is_directory=True)
            wrong_mode = Path(temporary) / f"{marker}-wrong-mode"
            wrong_mode.mkdir(mode=0o755)
            wrong_mode.chmod(0o755)
            nonempty = Path(temporary) / f"{marker}-nonempty"
            nonempty.mkdir(mode=0o700)
            nonempty.chmod(0o700)
            (nonempty / "sentinel").write_text("untouched\n", encoding="utf-8")
            inside_repository = root / f"{marker}-repository"
            inside_repository.mkdir(mode=0o700)
            inside_repository.chmod(0o700)
            inside_search = search_one / f"{marker}-search"
            inside_search.mkdir(mode=0o700)
            inside_search.chmod(0o700)
            cases: tuple[tuple[str, object], ...] = (
                ("string", str(target_stage_root)),
                ("relative", Path(marker)),
                ("missing", missing),
                ("ordinary-file", ordinary),
                ("symlink", symlink),
                ("wrong-mode", wrong_mode),
                ("nonempty", nonempty),
                ("inside-repository", inside_repository),
                ("inside-search", inside_search),
                ("source-stage-root", executable_stage_root),
                ("target-path", target),
            )
            try:
                for case, candidate in cases:
                    with self.subTest(case=case):
                        lease = RepositoryExecutableShebangTargetStageLease(
                            candidate
                        )
                        self._assert_invalid(
                            registration,
                            search_directories=(search_one, search_two),
                            target_resolution=target_resolution,
                            requirements=requirements,
                            runtime=runtime,
                            staging=staging,
                            executable_lease=executable_lease,
                            target_paths=(target,),
                            target_lease=lease,
                            private_marker=marker,
                        )
                        self.assertEqual(lease._files, ())
                        self.assertIsNone(lease.receipt)
                        self.assertIsNone(lease._root_descriptor)
                        if lease.state == "new":
                            lease.close()
                self.assertEqual(
                    (nonempty / "sentinel").read_text(encoding="utf-8"),
                    "untouched\n",
                )
            finally:
                executable_lease.close()

    def test_action_capture_and_post_stage_target_races_fail_closed(self) -> None:
        for race in ("capture", "post-stage"):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as temporary:
                (
                    root,
                    _outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                target = Path(temporary).resolve(strict=True) / f"{race}-target"
                original = f"{race}-original-target\n".encode()
                changed = f"{race}-changed-target\n".encode()
                self._write_target(target, original)
                shebang = b"#!" + os.fsencode(target) + b"\n"
                self._set_contents(
                    root,
                    search_one,
                    bare=shebang,
                    relative=shebang,
                )
                registration = self._registration(root)
                (
                    executable_lease,
                    staging,
                    runtime,
                    requirements,
                    target_resolution,
                ) = self._resolution_chain(
                    registration,
                    (search_one, search_two),
                    executable_stage_root,
                    (target,),
                )
                target_lease = RepositoryExecutableShebangTargetStageLease(
                    target_stage_root
                )
                descriptor_directory = self._descriptor_directory()
                descriptors_before = (
                    None
                    if descriptor_directory is None
                    else frozenset(os.listdir(descriptor_directory))
                )
                mutated = False

                if race == "capture":
                    real_inspect = target_staging_module._BUILTIN_INSPECT_TARGETS

                    def inspect_with_capture_mutation(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        consumer = kwargs.get("unique_target_consumer")
                        if consumer is None:
                            return real_inspect(*args, **kwargs)

                        def mutate_after_capture(
                            descriptor: int,
                            metadata: os.stat_result,
                            measured: object,
                        ) -> None:
                            nonlocal mutated
                            consumer(descriptor, metadata, measured)
                            if not mutated:
                                mutated = True
                                self._write_target(target, changed)

                        kwargs["unique_target_consumer"] = mutate_after_capture
                        return real_inspect(*args, **kwargs)

                    context = patch.object(
                        target_staging_module,
                        "_BUILTIN_INSPECT_TARGETS",
                        side_effect=inspect_with_capture_mutation,
                    )
                else:
                    real_stage = target_staging_module._stage_captured_target

                    def stage_then_mutate(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        nonlocal mutated
                        retained = real_stage(*args, **kwargs)
                        if not mutated:
                            mutated = True
                            self._write_target(target, changed)
                        return retained

                    context = patch.object(
                        target_staging_module,
                        "_stage_captured_target",
                        side_effect=stage_then_mutate,
                    )

                try:
                    with context:
                        self._assert_invalid(
                            registration,
                            search_directories=(search_one, search_two),
                            target_resolution=target_resolution,
                            requirements=requirements,
                            runtime=runtime,
                            staging=staging,
                            executable_lease=executable_lease,
                            target_paths=(target,),
                            target_lease=target_lease,
                        )
                    self.assertTrue(mutated)
                    self.assertIsNone(target_lease.receipt)
                    self.assertEqual(target_lease._files, ())
                    self.assertIsNone(target_lease._root_descriptor)
                    self.assertEqual(tuple(target_stage_root.iterdir()), ())
                    if descriptor_directory is not None:
                        self.assertEqual(
                            frozenset(os.listdir(descriptor_directory)),
                            descriptors_before,
                        )
                    self.assertIn(target_lease.state, {"new", "cleaned"})
                finally:
                    if target_lease.state == "new":
                        target_lease.close()
                    executable_lease.close()

    def test_stage_namespace_mismatch_and_readback_corruption_fail_closed(
        self,
    ) -> None:
        for failure in ("namespace", "readback"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    root,
                    _outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                target = Path(temporary).resolve(strict=True) / f"{failure}-target"
                self._write_target(target, f"{failure}-target-content\n".encode())
                shebang = b"#!" + os.fsencode(target) + b"\n"
                self._set_contents(
                    root,
                    search_one,
                    bare=shebang,
                    relative=shebang,
                )
                registration = self._registration(root)
                (
                    executable_lease,
                    staging,
                    runtime,
                    requirements,
                    target_resolution,
                ) = self._resolution_chain(
                    registration,
                    (search_one, search_two),
                    executable_stage_root,
                    (target,),
                )
                target_lease = RepositoryExecutableShebangTargetStageLease(
                    target_stage_root
                )

                if failure == "namespace":
                    real_entry_metadata = target_staging_module._entry_metadata
                    injected = False

                    def mismatching_entry(
                        directory_descriptor: int,
                        name: str,
                    ) -> object:
                        nonlocal injected
                        observed = real_entry_metadata(
                            directory_descriptor,
                            name,
                        )
                        if observed is not None and not injected:
                            injected = True
                            return SimpleNamespace(
                                st_mode=observed.st_mode,
                                st_dev=observed.st_dev,
                                st_ino=observed.st_ino + 1,
                            )
                        return observed

                    context = patch.object(
                        target_staging_module,
                        "_entry_metadata",
                        side_effect=mismatching_entry,
                    )
                else:
                    injected = True
                    context = patch.object(
                        target_staging_module,
                        "_descriptor_digest",
                        return_value="sha256:" + "0" * 64,
                    )

                descriptor_directory = self._descriptor_directory()
                descriptors_before = (
                    None
                    if descriptor_directory is None
                    else frozenset(os.listdir(descriptor_directory))
                )

                try:
                    with context:
                        self._assert_invalid(
                            registration,
                            search_directories=(search_one, search_two),
                            target_resolution=target_resolution,
                            requirements=requirements,
                            runtime=runtime,
                            staging=staging,
                            executable_lease=executable_lease,
                            target_paths=(target,),
                            target_lease=target_lease,
                        )
                    self.assertTrue(injected)
                    self.assertEqual(target_lease.state, "cleaned")
                    self.assertIsNone(target_lease.receipt)
                    self.assertEqual(target_lease._files, ())
                    self.assertIsNone(target_lease._root_descriptor)
                    self.assertEqual(tuple(target_stage_root.iterdir()), ())
                    if descriptor_directory is not None:
                        self.assertEqual(
                            frozenset(os.listdir(descriptor_directory)),
                            descriptors_before,
                        )
                finally:
                    if target_lease.state == "new":
                        target_lease.close()
                    executable_lease.close()

    def test_stage_name_collision_is_skipped_without_retaining_a_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "collision-target"
            content = b"collision-target-content\n"
            self._write_target(target, content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            real_entry_metadata = target_staging_module._entry_metadata
            injected = False

            def one_observed_collision(
                directory_descriptor: int,
                name: str,
            ) -> object:
                nonlocal injected
                if not injected:
                    injected = True
                    return SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o600,
                        st_dev=0,
                        st_ino=0,
                    )
                return real_entry_metadata(directory_descriptor, name)

            try:
                with patch.object(
                    target_staging_module,
                    "_entry_metadata",
                    side_effect=one_observed_collision,
                ):
                    receipt = self._stage(
                        registration,
                        search_directories=(search_one, search_two),
                        target_resolution=target_resolution,
                        requirements=requirements,
                        runtime=runtime,
                        staging=staging,
                        executable_lease=executable_lease,
                        target_paths=(target,),
                        target_lease=target_lease,
                    )
                self.assertTrue(injected)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(receipt.total_staged_bytes, len(content))
                self.assertEqual(target_lease.state, "active")
                self.assertIsNone(target_lease._pending_name)
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
            finally:
                target_lease.close()
                executable_lease.close()

    def test_zero_length_target_is_staged_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "zero-length-target"
            self._write_target(target, b"")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            try:
                receipt = self._stage(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(target,),
                    target_lease=target_lease,
                )
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(receipt.total_staged_bytes, 0)
                self.assertEqual(receipt.staged_files[0].content_bytes, 0)
                descriptor = target_lease._files[0].descriptor
                self.assertEqual(os.pread(descriptor, 1, 0), b"")
                self.assertEqual(os.fstat(descriptor).st_size, 0)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_no_process_environment_state_artifact_or_harness_effects(self) -> None:
        target_content = b"no-external-effects-target\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "effects-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            snapshots = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            try:
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
                    receipt = self._stage(
                        registration,
                        search_directories=(search_one, search_two),
                        target_resolution=target_resolution,
                        requirements=requirements,
                        runtime=runtime,
                        staging=staging,
                        executable_lease=executable_lease,
                        target_paths=(target,),
                        target_lease=target_lease,
                    )
                    evidence = receipt.to_evidence()
                    cleanup = target_lease.close()
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
                self.assertEqual(
                    tuple(
                        self._tree_snapshot(path)
                        for path in (
                            root,
                            outside,
                            search_one,
                            search_two,
                            target.parent,
                        )
                    ),
                    snapshots,
                )
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
                self.assertFalse((root / ".ordomata").exists())
                self.assertFalse((root / ".git" / "worktrees").exists())
            finally:
                if target_lease.state != "cleaned":
                    target_lease.close()
                executable_lease.close()

    def test_ownership_handoffs_survive_baseexception(self) -> None:
        for handoff in ("root", "writer", "reader", "retained"):
            with (
                self.subTest(handoff=handoff),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    root,
                    _outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                target = Path(temporary).resolve(strict=True) / f"{handoff}-target"
                content = f"{handoff}-handoff-target\n".encode()
                self._write_target(target, content)
                shebang = b"#!" + os.fsencode(target) + b"\n"
                self._set_contents(
                    root,
                    search_one,
                    bare=shebang,
                    relative=shebang,
                )
                registration = self._registration(root)
                (
                    executable_lease,
                    staging,
                    runtime,
                    requirements,
                    target_resolution,
                ) = self._resolution_chain(
                    registration,
                    (search_one, search_two),
                    executable_stage_root,
                    (target,),
                )
                lease = RepositoryExecutableShebangTargetStageLease(
                    target_stage_root
                )
                descriptor_directory = self._descriptor_directory()
                descriptors_before = (
                    None
                    if descriptor_directory is None
                    else frozenset(os.listdir(descriptor_directory))
                )
                real_setattr = (
                    RepositoryExecutableShebangTargetStageLease.__setattr__
                )
                real_open_directory = (
                    target_staging_module._BUILTIN_OPEN_ABSOLUTE_DIRECTORY
                )
                tracked_descriptor: int | None = None
                tracked_identity: tuple[int, int] | None = None
                interrupted = False

                def track_root_open(path: Path) -> object:
                    nonlocal tracked_descriptor, tracked_identity
                    pinned = real_open_directory(path)
                    if path == target_stage_root and tracked_descriptor is None:
                        tracked_descriptor = pinned.descriptor
                        metadata = os.fstat(pinned.descriptor)
                        tracked_identity = (metadata.st_dev, metadata.st_ino)
                    return pinned

                def interrupt_handoff(
                    lease_value: RepositoryExecutableShebangTargetStageLease,
                    name: str,
                    value: object,
                ) -> None:
                    nonlocal interrupted, tracked_descriptor, tracked_identity
                    should_interrupt = False
                    if handoff == "root":
                        should_interrupt = (
                            name == "_root_descriptor"
                            and value == tracked_descriptor
                        )
                    elif handoff == "writer":
                        should_interrupt = (
                            name == "_pending_name" and type(value) is str
                        )
                    elif handoff == "retained":
                        should_interrupt = (
                            name == "_files"
                            and type(value) is tuple
                            and len(value) == 1
                        )
                        if should_interrupt:
                            retained_descriptor = value[0].descriptor
                            tracked_descriptor = retained_descriptor
                            metadata = os.fstat(retained_descriptor)
                            tracked_identity = (
                                metadata.st_dev,
                                metadata.st_ino,
                            )
                    elif (
                        name == "_pending_descriptors"
                        and type(value) is tuple
                        and len(value) == 2
                    ):
                        reader_descriptor = value[1]
                        if type(reader_descriptor) is int:
                            tracked_descriptor = reader_descriptor
                            metadata = os.fstat(reader_descriptor)
                            tracked_identity = (
                                metadata.st_dev,
                                metadata.st_ino,
                            )
                            should_interrupt = True
                    if lease_value is lease and should_interrupt and not interrupted:
                        interrupted = True
                        raise KeyboardInterrupt(f"injected {handoff} handoff")
                    real_setattr(lease_value, name, value)

                try:
                    with ExitStack() as stack:
                        stack.enter_context(
                            patch.object(
                                RepositoryExecutableShebangTargetStageLease,
                                "__setattr__",
                                new=interrupt_handoff,
                            )
                        )
                        if handoff == "root":
                            stack.enter_context(
                                patch.object(
                                    target_staging_module,
                                    "_BUILTIN_OPEN_ABSOLUTE_DIRECTORY",
                                    side_effect=track_root_open,
                                )
                            )
                        with self.assertRaises(KeyboardInterrupt):
                            self._stage(
                                registration,
                                search_directories=(search_one, search_two),
                                target_resolution=target_resolution,
                                requirements=requirements,
                                runtime=runtime,
                                staging=staging,
                                executable_lease=executable_lease,
                                target_paths=(target,),
                                target_lease=lease,
                            )
                    self.assertTrue(interrupted)
                    self.assertEqual(lease._files, ())
                    self.assertIsNone(lease._root_descriptor)
                    self.assertIsNone(lease._pending_name)
                    self.assertEqual(lease._pending_descriptors, ())
                    self.assertEqual(tuple(target_stage_root.iterdir()), ())
                    if tracked_descriptor is not None:
                        with self.assertRaises(OSError):
                            os.fstat(tracked_descriptor)
                    if descriptor_directory is not None:
                        self.assertEqual(
                            frozenset(os.listdir(descriptor_directory)),
                            descriptors_before,
                        )
                finally:
                    if lease.state == "new":
                        lease.close()
                    if (
                        tracked_descriptor is not None
                        and tracked_identity is not None
                    ):
                        try:
                            metadata = os.fstat(tracked_descriptor)
                        except OSError:
                            pass
                        else:
                            if (
                                metadata.st_dev,
                                metadata.st_ino,
                            ) == tracked_identity:
                                os.close(tracked_descriptor)
                    executable_lease.close()

    def test_tampered_source_stage_root_is_rejected_by_context_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            alternate_source_root = (
                Path(temporary).resolve(strict=True) / "alternate-source-root"
            )
            alternate_source_root.mkdir(mode=0o700)
            alternate_source_root.chmod(0o700)
            target = Path(temporary).resolve(strict=True) / "source-root-target"
            self._write_target(target, b"source-root-target\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            original_root = executable_lease.staging_root
            original_metadata = executable_lease._root_metadata
            executable_lease.staging_root = alternate_source_root
            executable_lease._root_metadata = (
                target_staging_module._metadata_signature(
                    os.stat(alternate_source_root, follow_symlinks=False)
                )
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                executable_stage_root
            )
            try:
                self._assert_invalid(
                    registration,
                    search_directories=(search_one, search_two),
                    target_resolution=target_resolution,
                    requirements=requirements,
                    runtime=runtime,
                    staging=staging,
                    executable_lease=executable_lease,
                    target_paths=(target,),
                    target_lease=target_lease,
                )
                self.assertEqual(target_lease.state, "new")
                self.assertEqual(tuple(executable_stage_root.iterdir()), ())
            finally:
                executable_lease.staging_root = original_root
                executable_lease._root_metadata = original_metadata
                if target_lease.state == "new":
                    target_lease.close()
                executable_lease.close()

    def test_post_stage_source_root_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            moved_source_root = (
                Path(temporary).resolve(strict=True) / "moved-source-stage-root"
            )
            target = Path(temporary).resolve(strict=True) / "source-drift-target"
            self._write_target(target, b"source-drift-target\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            real_stage = target_staging_module._stage_captured_target
            drifted = False

            def stage_then_drift(*args: object, **kwargs: object) -> object:
                nonlocal drifted
                result = real_stage(*args, **kwargs)
                if not drifted:
                    executable_stage_root.rename(moved_source_root)
                    executable_stage_root.mkdir(mode=0o700)
                    executable_stage_root.chmod(0o700)
                    drifted = True
                return result

            try:
                with patch.object(
                    target_staging_module,
                    "_stage_captured_target",
                    side_effect=stage_then_drift,
                ):
                    self._assert_invalid(
                        registration,
                        search_directories=(search_one, search_two),
                        target_resolution=target_resolution,
                        requirements=requirements,
                        runtime=runtime,
                        staging=staging,
                        executable_lease=executable_lease,
                        target_paths=(target,),
                        target_lease=target_lease,
                    )
                self.assertTrue(drifted)
                self.assertEqual(target_lease.state, "cleaned")
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
            finally:
                if drifted:
                    executable_stage_root.rmdir()
                    moved_source_root.rename(executable_stage_root)
                if target_lease.state == "new":
                    target_lease.close()
                executable_lease.close()

    def test_post_stage_target_root_replacement_is_cleanup_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            moved_target_root = (
                Path(temporary).resolve(strict=True) / "moved-target-stage-root"
            )
            target = Path(temporary).resolve(strict=True) / "root-drift-target"
            self._write_target(target, b"root-drift-target\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            real_stage = target_staging_module._stage_captured_target
            replaced = False

            def stage_then_replace_root(
                *args: object,
                **kwargs: object,
            ) -> object:
                nonlocal replaced
                result = real_stage(*args, **kwargs)
                if not replaced:
                    target_stage_root.rename(moved_target_root)
                    target_stage_root.mkdir(mode=0o700)
                    target_stage_root.chmod(0o700)
                    replaced = True
                return result

            try:
                with patch.object(
                    target_staging_module,
                    "_stage_captured_target",
                    side_effect=stage_then_replace_root,
                ):
                    with self.assertRaises(ConfigurationError) as caught:
                        self._stage(
                            registration,
                            search_directories=(search_one, search_two),
                            target_resolution=target_resolution,
                            requirements=requirements,
                            runtime=runtime,
                            staging=staging,
                            executable_lease=executable_lease,
                            target_paths=(target,),
                            target_lease=target_lease,
                        )
                self.assertEqual(str(caught.exception), FIXED_CLEANUP_ERROR)
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(replaced)
                self.assertEqual(target_lease.state, "cleanup_unverifiable")
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
            finally:
                if replaced:
                    target_stage_root.rmdir()
                    moved_target_root.rename(target_stage_root)
                if target_lease.state != "cleaned":
                    cleanup = target_lease.cleanup()
                    self.assertEqual(cleanup.outcome, "already_absent_verified")
                executable_lease.close()

    def test_descriptors_return_to_baseline_after_cleanup_and_failure(self) -> None:
        descriptor_directory = self._descriptor_directory()
        if descriptor_directory is None:
            self.skipTest("no process descriptor directory is available")

        target_content = b"descriptor-baseline-target\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "descriptor-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                runtime,
                requirements,
                target_resolution,
            ) = self._resolution_chain(
                registration,
                (search_one, search_two),
                executable_stage_root,
                (target,),
            )
            descriptors_before = frozenset(os.listdir(descriptor_directory))
            target_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            self._stage(
                registration,
                search_directories=(search_one, search_two),
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=(target,),
                target_lease=target_lease,
            )
            target_lease.close()
            self.assertEqual(
                frozenset(os.listdir(descriptor_directory)),
                descriptors_before,
            )

            self._write_target(target, b"stale-descriptor-target\n")
            failing_lease = RepositoryExecutableShebangTargetStageLease(
                target_stage_root
            )
            self._assert_invalid(
                registration,
                search_directories=(search_one, search_two),
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=(target,),
                target_lease=failing_lease,
            )
            self.assertEqual(
                frozenset(os.listdir(descriptor_directory)),
                descriptors_before,
            )
            failing_lease.close()
            executable_lease.close()


if __name__ == "__main__":
    unittest.main()
