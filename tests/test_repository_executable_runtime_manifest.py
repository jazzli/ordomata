from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, replace
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch

import ordomata.artifact_filesystem as artifact_filesystem_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
import ordomata.repository_executable_runtime_manifest as runtime_module
from ordomata.repository_executable_runtime_manifest import (
    MANIFEST_SCOPE,
    MANIFEST_SOURCE,
    REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND,
    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION,
    RepositoryExecutableRuntimeBinding,
    RepositoryExecutableRuntimeFile,
    RepositoryExecutableRuntimeManifestReceipt,
    inspect_staged_executable_runtime_manifest,
)
from ordomata.repository_executable_resolution import (
    resolve_repository_executables,
)
import ordomata.repository_executable_staging as staging_module
from ordomata.repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    stage_repository_executable_bytes,
)
import ordomata.state as state_module

if __package__:
    from . import test_repository_executable_staging as staging_test_module
else:
    import test_repository_executable_staging as staging_test_module


FIXED_RUNTIME_MANIFEST_ERROR = (
    "repository executable runtime manifest is invalid"
)
RUNTIME_FILE_KEYS = {
    "classification",
    "content_bytes",
    "content_digest",
    "header_bytes",
    "header_digest",
    "kind",
    "runtime_file_ref",
    "shebang_directive_ref",
    "staged_file_ref",
    "staged_filesystem_identity_ref",
}
RUNTIME_BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "runtime_file_ref",
    "staged_file_ref",
}
RUNTIME_RECEIPT_KEYS = {
    "bindings",
    "command_count",
    "file_count",
    "files",
    "kind",
    "manifest_scope",
    "manifest_source",
    "registration_digest",
    "repository_ref",
    "resolution_context_digest",
    "schema_version",
    "staging_context_digest",
    "staging_receipt_digest",
    "total_content_bytes",
    "total_header_bytes",
    "verification_commands_digest",
}
RUNTIME_EVIDENCE_KEYS = {
    "action_receipt_issued",
    "active_lease_verified_at_measurement",
    "atomic_snapshot_verified",
    "authority_granted",
    "authorization_verified",
    "baseline_execution_correspondence_verified",
    "billing_eligible",
    "bounded_header_measurement_complete",
    "bounded_shebang_syntax_classification_complete",
    "capacity_eligible",
    "circuit_eligible",
    "command_count",
    "configuration_coverage_verified",
    "current_lease_activity_verified",
    "current_source_freshness_verified",
    "dependency_environment_coverage_verified",
    "dispatch_enabled",
    "durable_control_plane_persistence_enabled",
    "dynamic_loader_identity_verified",
    "effect_class",
    "effective_invocability_verified",
    "elf_file_count",
    "environment_coverage_verified",
    "execution_enabled",
    "file_count",
    "fixed_runtime_format_classification_complete",
    "future_execution_correspondence_verified",
    "interpreter_authenticity_verified",
    "interpreter_identity_verified",
    "interpreter_resolution_verified",
    "kind",
    "launcher_identity_verified",
    "lease_cleanup_performed",
    "lease_mutated",
    "live_execution_eligible",
    "mach_o_file_count",
    "manifest_scope",
    "manifest_source",
    "module_identity_verified",
    "package_identity_verified",
    "plugin_identity_verified",
    "posix_shebang_file_count",
    "proposal_lineage_extended",
    "receipt_authenticity_verified",
    "receipt_digest",
    "registration_digest",
    "repository_ref",
    "resolution_context_digest",
    "route_eligible",
    "runtime_manifest_complete",
    "schema_version",
    "shared_library_identity_verified",
    "source_path_reopen_performed",
    "staged_byte_correspondence_verified",
    "staged_descriptor_full_remeasurement_complete",
    "staging_receipt_digest",
    "toolchain_completeness_verified",
    "total_content_bytes",
    "total_header_bytes",
    "unknown_file_count",
    "unsupported_shebang_file_count",
    "validation_mode",
}


@unittest.skipUnless(os.name == "posix", "runtime manifests require POSIX")
class RepositoryExecutableRuntimeManifestTests(unittest.TestCase):
    fixture = staging_test_module.RepositoryExecutableStagingTests

    @classmethod
    def _workspace(cls, temporary: str) -> tuple[Path, Path, Path, Path, Path]:
        return cls.fixture._workspace(temporary)

    @classmethod
    def _registration(cls, root: Path, *, shared: bool = False):
        if not shared:
            return cls.fixture._registration(root)
        payload = cls.fixture._versioned_payload(4)
        payload["verification_commands"]["test"][0]["argv"][0] = (
            "private-bare-tool-marker"
        )
        payload["baseline_command_results"] = cls.fixture._baseline(payload)
        payload["executable_toolchain_identities"] = (
            cls.fixture._identities(payload)
        )
        return cls.fixture._registration(root, payload=payload)

    @classmethod
    def _set_contents(
        cls,
        root: Path,
        search_one: Path,
        *,
        bare: bytes,
        relative: bytes | None = None,
    ) -> None:
        paths_and_contents = (
            (search_one / "private-bare-tool-marker", bare),
            (
                root
                / "private-source-path-marker"
                / "private-relative-tool-marker",
                bare if relative is None else relative,
            ),
        )
        for path, content in paths_and_contents:
            cls.fixture._write_executable(path, content)
            with path.open("rb") as stream:
                os.fsync(stream.fileno())

    @staticmethod
    def _stage(
        registration: object,
        search_directories: tuple[Path, ...],
        staging_root: Path,
    ) -> tuple[RepositoryExecutableStageLease, RepositoryExecutableStagingReceipt]:
        expected = resolve_repository_executables(
            registration,
            search_directories=search_directories,
        )
        lease = RepositoryExecutableStageLease(staging_root)
        staging = stage_repository_executable_bytes(
            registration,
            search_directories=search_directories,
            expected_resolution=expected,
            lease=lease,
        )
        return lease, staging

    @staticmethod
    def _descriptor_facts(descriptor: int) -> tuple[object, ...]:
        metadata = os.fstat(descriptor)
        return (
            descriptor,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            os.get_inheritable(descriptor),
            fcntl.fcntl(descriptor, fcntl.F_GETFL),
            os.lseek(descriptor, 0, os.SEEK_CUR),
        )

    @classmethod
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return (
            lease.state,
            lease.receipt,
            lease.cleanup_receipt,
            lease._receipt_digest_anchor,
            lease._receipt_staged_file_refs_anchor,
            lease._cleanup_receipt_digest_anchor,
            lease._owner_pid,
            id(lease._files),
            tuple(
                (
                    id(value),
                    value.staged_file,
                    value.metadata,
                    cls._descriptor_facts(value.descriptor),
                )
                for value in lease._files
            ),
            lease._root_descriptor,
            lease._root_metadata,
            lease._pending_name,
            lease._pending_identity,
            lease._pending_descriptors,
            lease._descriptor_release_unverifiable,
        )

    def _assert_invalid(
        self,
        expected_staging: object,
        lease: object,
        *,
        private_marker: str = "private-runtime-manifest-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_runtime_manifest(
                expected_staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_RUNTIME_MANIFEST_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_receipt_evidence_correspondence_privacy_and_lease_immutability(
        self,
    ) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        shebang = b"#!/usr/bin/env python3\nprint('private-header-marker')\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=shebang,
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            try:
                receipt = inspect_staged_executable_runtime_manifest(
                    staging,
                    lease=lease,
                )
                repeated = inspect_staged_executable_runtime_manifest(
                    staging,
                    lease=lease,
                )
                self.assertEqual(receipt, repeated)
                self.assertEqual(self._lease_snapshot(lease), before)
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableRuntimeManifestReceipt,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION,
                    1,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND,
                    "repository_executable_runtime_manifest",
                )
                self.assertEqual(MANIFEST_SOURCE, "controller_inspected")
                self.assertEqual(MANIFEST_SCOPE, "posix_staged_runtime_header_v1")
                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), RUNTIME_RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                self.assertEqual(receipt.staging_receipt_digest, staging.receipt_digest)
                self.assertEqual(
                    receipt.registration_digest,
                    staging.registration_digest,
                )
                self.assertEqual(receipt.repository_ref, staging.repository_ref)
                self.assertEqual(
                    receipt.verification_commands_digest,
                    staging.verification_commands_digest,
                )
                self.assertEqual(
                    receipt.resolution_context_digest,
                    staging.resolution_context_digest,
                )
                self.assertEqual(
                    receipt.staging_context_digest,
                    staging.staging_context_digest,
                )
                self.assertEqual(receipt.file_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.total_content_bytes, len(elf) + len(shebang))
                self.assertEqual(
                    {value.classification for value in receipt.files},
                    {"elf", "posix_shebang"},
                )
                for value in receipt.files:
                    self.assertIsInstance(value, RepositoryExecutableRuntimeFile)
                    self.assertEqual(set(value.to_canonical()), RUNTIME_FILE_KEYS)
                    self.assertEqual(value.header_bytes, value.content_bytes)
                    self.assertEqual(
                        value.shebang_directive_ref is not None,
                        value.classification == "posix_shebang",
                    )
                for value in receipt.bindings:
                    self.assertIsInstance(value, RepositoryExecutableRuntimeBinding)
                    self.assertEqual(set(value.to_canonical()), RUNTIME_BINDING_KEYS)
                self.assertEqual(
                    {value.staged_file_ref for value in receipt.files},
                    {value.staged_file_ref for value in staging.staged_files},
                )
                self.assertEqual(
                    {value.runtime_file_ref for value in receipt.files},
                    {value.runtime_file_ref for value in receipt.bindings},
                )
                runtime_by_staged_ref = {
                    value.staged_file_ref: value for value in receipt.files
                }
                for runtime_file, staged_file in zip(
                    receipt.files,
                    staging.staged_files,
                    strict=True,
                ):
                    self.assertEqual(
                        runtime_file.staged_file_ref,
                        staged_file.staged_file_ref,
                    )
                    self.assertEqual(
                        runtime_file.staged_filesystem_identity_ref,
                        staged_file.staged_filesystem_identity_ref,
                    )
                    self.assertEqual(
                        runtime_file.content_digest,
                        staged_file.content_digest,
                    )
                    self.assertEqual(
                        runtime_file.content_bytes,
                        staged_file.content_bytes,
                    )
                for runtime_binding, staging_binding in zip(
                    receipt.bindings,
                    staging.bindings,
                    strict=True,
                ):
                    self.assertEqual(
                        runtime_binding.command_kind,
                        staging_binding.command_kind,
                    )
                    self.assertEqual(
                        runtime_binding.command_id,
                        staging_binding.command_id,
                    )
                    self.assertEqual(
                        runtime_binding.command_digest,
                        staging_binding.command_digest,
                    )
                    self.assertEqual(
                        runtime_binding.staged_file_ref,
                        staging_binding.staged_file_ref,
                    )
                    self.assertEqual(
                        runtime_binding.runtime_file_ref,
                        runtime_by_staged_ref[
                            staging_binding.staged_file_ref
                        ].runtime_file_ref,
                    )

                evidence = receipt.to_evidence()
                self.assertEqual(set(evidence), RUNTIME_EVIDENCE_KEYS)
                self.assertEqual(
                    evidence["kind"],
                    REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_EVIDENCE_KIND,
                )
                self.assertEqual(evidence["effect_class"], 0)
                self.assertEqual(evidence["validation_mode"], "read_only")
                self.assertEqual(evidence["elf_file_count"], 1)
                self.assertEqual(evidence["posix_shebang_file_count"], 1)
                for true_fact in (
                    "active_lease_verified_at_measurement",
                    "bounded_header_measurement_complete",
                    "bounded_shebang_syntax_classification_complete",
                    "fixed_runtime_format_classification_complete",
                    "staged_byte_correspondence_verified",
                    "staged_descriptor_full_remeasurement_complete",
                ):
                    self.assertIs(evidence[true_fact], True)
                for false_fact in (
                    "action_receipt_issued",
                    "atomic_snapshot_verified",
                    "authority_granted",
                    "authorization_verified",
                    "baseline_execution_correspondence_verified",
                    "billing_eligible",
                    "capacity_eligible",
                    "circuit_eligible",
                    "configuration_coverage_verified",
                    "current_lease_activity_verified",
                    "current_source_freshness_verified",
                    "dependency_environment_coverage_verified",
                    "dispatch_enabled",
                    "durable_control_plane_persistence_enabled",
                    "dynamic_loader_identity_verified",
                    "effective_invocability_verified",
                    "environment_coverage_verified",
                    "execution_enabled",
                    "future_execution_correspondence_verified",
                    "interpreter_authenticity_verified",
                    "interpreter_identity_verified",
                    "interpreter_resolution_verified",
                    "launcher_identity_verified",
                    "lease_cleanup_performed",
                    "lease_mutated",
                    "live_execution_eligible",
                    "module_identity_verified",
                    "package_identity_verified",
                    "plugin_identity_verified",
                    "proposal_lineage_extended",
                    "receipt_authenticity_verified",
                    "route_eligible",
                    "runtime_manifest_complete",
                    "shared_library_identity_verified",
                    "source_path_reopen_performed",
                    "toolchain_completeness_verified",
                ):
                    self.assertIs(evidence[false_fact], False, false_fact)

                aggregate = "\n".join(
                    (
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        *(repr(value) for value in receipt.files),
                        *(repr(value) for value in receipt.bindings),
                    )
                )
                for private_value in (
                    str(root),
                    str(search_one),
                    str(staging_root),
                    "private-bare-command-marker",
                    "private-relative-command-marker",
                    "private-header-marker",
                    "/usr/bin/env python3",
                    *(value.content_digest for value in receipt.files),
                ):
                    self.assertNotIn(private_value, aggregate)
                with self.assertRaises(FrozenInstanceError):
                    receipt.file_count = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.files[0].classification = "unknown"
                with self.assertRaises(FrozenInstanceError):
                    receipt.bindings[0].command_kind = "test"
            finally:
                lease.close()

    def test_fixed_binary_classification_and_minimum_headers(self) -> None:
        staged_file_ref = "sha256:" + "a" * 64
        cases = (
            ("elf", b"\x7fELF\x02\x01\x01" + b"\x00" * 9, "elf"),
            ("bad-elf-class", b"\x7fELF\x03\x01\x01" + b"\x00" * 9, "unknown"),
            ("bad-elf-short", b"\x7fELF\x02\x01\x01", "unknown"),
            ("mach-o-32", b"\xfe\xed\xfa\xce" + b"\x00" * 24, "mach_o"),
            ("mach-o-64", b"\xcf\xfa\xed\xfe" + b"\x00" * 28, "mach_o"),
            ("mach-o-fat64", b"\xca\xfe\xba\xbf" + b"\x00" * 36, "mach_o"),
            ("mach-o-short", b"\xfe\xed\xfa\xce" + b"\x00" * 23, "unknown"),
            ("unknown", b"ordinary executable bytes\n", "unknown"),
        )
        for case, header, expected in cases:
            with self.subTest(case=case):
                classification, directive_ref = runtime_module._classify_header(
                    staged_file_ref,
                    header,
                )
                self.assertEqual(classification, expected)
                self.assertIsNone(directive_ref)

    def test_shebang_grammar_and_header_size_boundaries(self) -> None:
        staged_file_ref = "sha256:" + "b" * 64
        cases = (
            ("valid", b"#!/usr/bin/python3\n", "posix_shebang"),
            ("valid-env-uninterpreted", b"#!/usr/bin/env python3\n", "posix_shebang"),
            ("valid-max", b"#!" + b"a" * 255 + b"\n", "posix_shebang"),
            ("empty", b"#!\n", "unsupported_shebang"),
            ("leading-space", b"#! /usr/bin/python3\n", "unsupported_shebang"),
            ("trailing-space", b"#!/usr/bin/python3 \n", "unsupported_shebang"),
            ("nul", b"#!/usr/bin/py\x00thon\n", "unsupported_shebang"),
            ("control", b"#!/usr/bin/py\x1fthon\n", "unsupported_shebang"),
            ("non-ascii", b"#!/usr/bin/py\xc3\xa9\n", "unsupported_shebang"),
            ("crlf", b"#!/usr/bin/python3\r\n", "unsupported_shebang"),
            ("overlong", b"#!" + b"a" * 256 + b"\n", "unsupported_shebang"),
            ("no-newline", b"#!/usr/bin/python3", "unsupported_shebang"),
            (
                "newline-past-header",
                b"#!" + b"a" * 4_095 + b"\n",
                "unsupported_shebang",
            ),
        )
        for case, header, expected in cases:
            with self.subTest(case=case):
                classification, directive_ref = runtime_module._classify_header(
                    staged_file_ref,
                    header[:4_096],
                )
                self.assertEqual(classification, expected)
                self.assertEqual(
                    directive_ref is not None,
                    expected == "posix_shebang",
                )
                if directive_ref is not None:
                    self.assertRegex(directive_ref, r"^sha256:[0-9a-f]{64}$")

        with tempfile.TemporaryFile() as stream:
            for size in (0, 1, 4_095, 4_096, 4_097):
                with self.subTest(size=size):
                    stream.seek(0)
                    stream.truncate()
                    stream.write(b"x" * size)
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.seek(min(size, 1))
                    offset_before = stream.tell()
                    with patch.object(
                        runtime_module.os,
                        "pread",
                        wraps=os.pread,
                    ) as pread:
                        header = runtime_module._read_exact_header(
                            stream.fileno(),
                            size,
                        )
                    self.assertEqual(header, b"x" * min(size, 4_096))
                    self.assertEqual(stream.tell(), offset_before)
                    self.assertTrue(pread.called)
                    self.assertIn(
                        call(
                            stream.fileno(),
                            1,
                            min(size, 4_096),
                        ),
                        pread.call_args_list,
                    )
                    self.assertLessEqual(
                        max(call.args[1] for call in pread.call_args_list),
                        4_096,
                    )

        for size in (4_096, 4_097):
            with self.subTest(invalid_boundary_probe=size):
                with tempfile.TemporaryFile() as stream:
                    stream.write(b"x" * size)
                    stream.flush()
                    os.fsync(stream.fileno())
                    real_pread = os.pread

                    def wrong_boundary_probe(
                        descriptor: int,
                        count: int,
                        offset: int,
                    ) -> bytes:
                        if count == 1 and offset == min(size, 4_096):
                            return b"x" if size == 4_096 else b""
                        return real_pread(descriptor, count, offset)

                    with patch.object(
                        runtime_module.os,
                        "pread",
                        side_effect=wrong_boundary_probe,
                    ):
                        with self.assertRaises(ValueError):
                            runtime_module._read_exact_header(
                                stream.fileno(),
                                size,
                            )

    def test_shared_staged_file_is_manifested_once_and_bound_twice(self) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(root, search_one, bare=elf)
            registration = self._registration(root, shared=True)
            lease, staging = self._stage(registration, (search_one,), staging_root)
            try:
                receipt = inspect_staged_executable_runtime_manifest(
                    staging,
                    lease=lease,
                )
                self.assertEqual(staging.unique_file_count, 1)
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(len(receipt.bindings), 2)
                self.assertEqual(
                    {value.runtime_file_ref for value in receipt.bindings},
                    {receipt.files[0].runtime_file_ref},
                )
            finally:
                lease.close()

    def test_inactive_closed_and_cross_process_leases_reject_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            new_lease = RepositoryExecutableStageLease(staging_root)
            with patch.object(
                runtime_module.os,
                "pread",
                side_effect=AssertionError("descriptor read before validation"),
            ) as pread:
                self._assert_invalid(staging, new_lease)
                with patch.object(
                    runtime_module.os,
                    "getpid",
                    return_value=lease._owner_pid + 1,
                ):
                    self._assert_invalid(staging, lease)
            pread.assert_not_called()

            lease.close()
            with patch.object(
                runtime_module.os,
                "pread",
                side_effect=AssertionError("closed descriptor read"),
            ) as pread:
                self._assert_invalid(staging, lease)
            pread.assert_not_called()
            new_lease.close()

    def test_swapped_tampered_and_reordered_receipts_fail_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            other_root = staging_root.parent / "private-other-stage-marker"
            other_root.mkdir(mode=0o700)
            other_root.chmod(0o700)
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            other_lease, other_staging = self._stage(
                registration,
                (search_one, search_two),
                other_root,
            )
            try:
                cases = (
                    other_staging,
                    replace(staging, staging_context_digest="sha256:" + "0" * 64),
                    replace(
                        staging,
                        staged_files=tuple(reversed(staging.staged_files)),
                    ),
                )
                with patch.object(
                    runtime_module.os,
                    "pread",
                    side_effect=AssertionError("read before receipt validation"),
                ) as pread:
                    for value in cases:
                        with self.subTest(value=value.staging_context_digest):
                            self._assert_invalid(value, lease)
                pread.assert_not_called()
            finally:
                lease.close()
                other_lease.close()

    def test_tampered_lease_anchors_files_and_cleanup_anchor_fail_before_read(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            original_digest = lease._receipt_digest_anchor
            original_refs = lease._receipt_staged_file_refs_anchor
            original_files = lease._files
            original_cleanup_anchor = lease._cleanup_receipt_digest_anchor
            try:
                with patch.object(
                    runtime_module.os,
                    "pread",
                    side_effect=AssertionError("read before lease validation"),
                ) as pread:
                    lease._receipt_digest_anchor = "sha256:" + "0" * 64
                    self._assert_invalid(staging, lease)
                    lease._receipt_digest_anchor = original_digest

                    lease._receipt_staged_file_refs_anchor = tuple(
                        reversed(original_refs)
                    )
                    self._assert_invalid(staging, lease)
                    lease._receipt_staged_file_refs_anchor = original_refs

                    lease._files = tuple(reversed(original_files))
                    self._assert_invalid(staging, lease)
                    lease._files = original_files

                    lease._cleanup_receipt_digest_anchor = "sha256:" + "1" * 64
                    self._assert_invalid(staging, lease)
                pread.assert_not_called()
            finally:
                lease._receipt_digest_anchor = original_digest
                lease._receipt_staged_file_refs_anchor = original_refs
                lease._files = original_files
                lease._cleanup_receipt_digest_anchor = original_cleanup_anchor
                lease.close()

    def test_altered_content_same_ref_and_same_content_other_inode_are_rejected(
        self,
    ) -> None:
        original_content = b"#!/usr/bin/python3\noriginal\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            same_root = staging_root.parent / "private-same-stage-marker"
            changed_root = staging_root.parent / "private-changed-stage-marker"
            for directory in (same_root, changed_root):
                directory.mkdir(mode=0o700)
                directory.chmod(0o700)
            self._set_contents(root, search_one, bare=original_content)
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            same_lease, _same_staging = self._stage(
                registration,
                (search_one, search_two),
                same_root,
            )
            self._set_contents(root, search_one, bare=b"changed anonymous bytes\n")
            changed_lease, _changed_staging = self._stage(
                registration,
                (search_one, search_two),
                changed_root,
            )
            original_files = lease._files
            try:
                same_inode_forgery = staging_module._RetainedStagedFile(
                    staged_file=staging.staged_files[0],
                    descriptor=same_lease._files[0].descriptor,
                    metadata=same_lease._files[0].metadata,
                )
                lease._files = (same_inode_forgery, *original_files[1:])
                self._assert_invalid(staging, lease)

                changed_staged_file = replace(
                    changed_lease._files[0].staged_file,
                    staged_file_ref=staging.staged_files[0].staged_file_ref,
                )
                changed_content_forgery = staging_module._RetainedStagedFile(
                    staged_file=changed_staged_file,
                    descriptor=changed_lease._files[0].descriptor,
                    metadata=changed_lease._files[0].metadata,
                )
                lease._files = (changed_content_forgery, *original_files[1:])
                self._assert_invalid(staging, lease)
            finally:
                lease._files = original_files
                lease.close()
                same_lease.close()
                changed_lease.close()

    def test_descriptor_retarget_metadata_and_corrupt_reads_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            retained = lease._files[0]
            descriptor = retained.descriptor
            backup = os.dup(descriptor)
            foreign = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
            original_metadata = retained.metadata
            try:
                os.dup2(foreign, descriptor, inheritable=False)
                self._assert_invalid(staging, lease)
                os.dup2(backup, descriptor, inheritable=False)

                lease._files = (
                    replace(
                        retained,
                        metadata=(
                            *original_metadata[:-1],
                            original_metadata[-1] + 1,
                        ),
                    ),
                    *lease._files[1:],
                )
                with patch.object(
                    runtime_module.os,
                    "pread",
                    side_effect=AssertionError("read after metadata mismatch"),
                ) as pread:
                    self._assert_invalid(staging, lease)
                pread.assert_not_called()
                lease._files = (retained, *lease._files[1:])

                real_pread = os.pread
                corrupted = False

                def corrupt_once(fd: int, count: int, offset: int) -> bytes:
                    nonlocal corrupted
                    value = real_pread(fd, count, offset)
                    if fd == descriptor and value and not corrupted:
                        corrupted = True
                        return bytes((value[0] ^ 1,)) + value[1:]
                    return value

                with patch.object(runtime_module.os, "pread", side_effect=corrupt_once):
                    self._assert_invalid(staging, lease)
                self.assertTrue(corrupted)
            finally:
                os.dup2(backup, descriptor, inheritable=False)
                lease._files = (retained, *lease._files[1:])
                os.close(foreign)
                os.close(backup)
                lease.close()

    def test_cleanup_after_header_read_fails_closed_but_cleanup_is_verified(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            real_read = runtime_module._read_exact_header
            cleaned = False

            def cleanup_after_read(descriptor: int, content_bytes: int) -> bytes:
                nonlocal cleaned
                header = real_read(descriptor, content_bytes)
                if not cleaned:
                    cleaned = True
                    lease.close()
                return header

            with patch.object(
                runtime_module,
                "_read_exact_header",
                side_effect=cleanup_after_read,
            ):
                self._assert_invalid(staging, lease)
            self.assertTrue(cleaned)
            self.assertEqual(lease.state, "cleaned")
            self.assertTrue(lease.cleanup_receipt.descriptor_release_complete)
            self.assertTrue(lease.cleanup_receipt.owned_namespace_absence_verified)
            self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_header_read_must_match_full_remeasurement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!/usr/bin/python3\n",
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            real_read = runtime_module._read_exact_header
            corrupted = False

            def corrupt_header(
                descriptor: int,
                content_bytes: int,
            ) -> bytes:
                nonlocal corrupted
                header = real_read(descriptor, content_bytes)
                if not corrupted and header:
                    corrupted = True
                    return bytes((header[0] ^ 1,)) + header[1:]
                return header

            try:
                with patch.object(
                    runtime_module,
                    "_read_exact_header",
                    side_effect=corrupt_header,
                ):
                    self._assert_invalid(staging, lease)
                self.assertTrue(corrupted)
                self.assertEqual(self._lease_snapshot(lease), before)
            finally:
                lease.close()

    def test_baseexception_during_header_read_leaves_lease_exactly_unchanged(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            try:
                with patch.object(
                    runtime_module,
                    "_read_exact_header",
                    side_effect=KeyboardInterrupt("injected header interruption"),
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        inspect_staged_executable_runtime_manifest(
                            staging,
                            lease=lease,
                        )
                self.assertEqual(self._lease_snapshot(lease), before)
                self.assertEqual(tuple(staging_root.iterdir()), ())
            finally:
                lease.close()

    def test_forged_runtime_classification_minima_are_rejected(self) -> None:
        cases = (
            ("elf", 15, None),
            ("mach_o", 27, None),
            ("posix_shebang", 3, "sha256:" + "a" * 64),
            ("unsupported_shebang", 1, None),
        )
        for classification, size, directive_ref in cases:
            with self.subTest(classification=classification):
                staged_file_ref = "sha256:" + "1" * 64
                staged_identity_ref = "sha256:" + "2" * 64
                content_digest = "sha256:" + "3" * 64
                header_digest = "sha256:" + "4" * 64
                runtime_projection = runtime_module._runtime_file_ref_projection(
                    staged_file_ref=staged_file_ref,
                    staged_filesystem_identity_ref=staged_identity_ref,
                    content_digest=content_digest,
                    content_bytes=size,
                    header_digest=header_digest,
                    header_bytes=size,
                    classification=classification,
                    shebang_directive_ref=directive_ref,
                )
                runtime_file_ref = canonical_digest(runtime_projection)
                forged = RepositoryExecutableRuntimeFile(
                    kind=REPOSITORY_EXECUTABLE_RUNTIME_FILE_KIND,
                    staged_file_ref=staged_file_ref,
                    staged_filesystem_identity_ref=staged_identity_ref,
                    content_digest=content_digest,
                    content_bytes=size,
                    runtime_file_ref=runtime_file_ref,
                    header_digest=header_digest,
                    header_bytes=size,
                    classification=classification,
                    shebang_directive_ref=directive_ref,
                )
                binding = RepositoryExecutableRuntimeBinding(
                    kind=REPOSITORY_EXECUTABLE_RUNTIME_BINDING_KIND,
                    command_kind="test",
                    command_id="private-command-marker",
                    command_digest="sha256:" + "5" * 64,
                    staged_file_ref=staged_file_ref,
                    runtime_file_ref=runtime_file_ref,
                )
                forged_receipt = RepositoryExecutableRuntimeManifestReceipt(
                    kind=REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_KIND,
                    schema_version=(
                        REPOSITORY_EXECUTABLE_RUNTIME_MANIFEST_SCHEMA_VERSION
                    ),
                    manifest_source=MANIFEST_SOURCE,
                    manifest_scope=MANIFEST_SCOPE,
                    staging_receipt_digest="sha256:" + "6" * 64,
                    registration_digest="sha256:" + "7" * 64,
                    repository_ref="sha256:" + "8" * 64,
                    verification_commands_digest="sha256:" + "9" * 64,
                    resolution_context_digest="sha256:" + "a" * 64,
                    staging_context_digest="sha256:" + "b" * 64,
                    files=(forged,),
                    bindings=(binding,),
                    file_count=1,
                    command_count=1,
                    total_content_bytes=size,
                    total_header_bytes=size,
                )
                with self.assertRaises(ValueError):
                    forged.to_canonical()
                with self.assertRaises(ValueError):
                    forged_receipt.to_canonical()

    def test_no_environment_process_state_artifact_write_or_cleanup_integration(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging = self._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            tree_before = tuple(
                self.fixture._tree_snapshot(value)
                for value in (root, outside, search_one, search_two)
            )
            with (
                patch.object(
                    shutil,
                    "which",
                    side_effect=AssertionError("PATH"),
                ) as which,
                patch.object(
                    os,
                    "getenv",
                    side_effect=AssertionError("environment"),
                ) as getenv,
                patch.object(
                    os,
                    "get_exec_path",
                    side_effect=AssertionError("PATH"),
                ) as get_exec_path,
                patch.object(
                    os,
                    "open",
                    side_effect=AssertionError("path reopen"),
                ) as open_path,
                patch.object(
                    os,
                    "write",
                    side_effect=AssertionError("write"),
                ) as write,
                patch.object(
                    os,
                    "fchmod",
                    side_effect=AssertionError("chmod"),
                ) as fchmod,
                patch.object(
                    os,
                    "close",
                    side_effect=AssertionError("close"),
                ) as close,
                patch.object(
                    os,
                    "dup",
                    side_effect=AssertionError("duplicate descriptor"),
                ) as duplicate,
                patch.object(
                    os,
                    "dup2",
                    side_effect=AssertionError("retarget descriptor"),
                ) as duplicate_to,
                patch.object(
                    os,
                    "system",
                    side_effect=AssertionError("shell"),
                ) as system,
                patch.object(
                    subprocess,
                    "run",
                    side_effect=AssertionError("process"),
                ) as run,
                patch.object(
                    subprocess,
                    "Popen",
                    side_effect=AssertionError("process"),
                ) as popen,
                patch.object(
                    asyncio,
                    "create_subprocess_exec",
                    side_effect=AssertionError("process"),
                ) as create_exec,
                patch.object(
                    asyncio,
                    "create_subprocess_shell",
                    side_effect=AssertionError("process"),
                ) as create_shell,
                patch.object(
                    artifact_filesystem_module,
                    "stage_artifact",
                    side_effect=AssertionError("artifact"),
                ) as stage_artifact,
                patch.object(
                    artifact_filesystem_module,
                    "publish_staged_artifact",
                    side_effect=AssertionError("artifact"),
                ) as publish_artifact,
                patch.object(
                    state_module.SQLiteStateStore,
                    "__init__",
                    side_effect=AssertionError("state"),
                ) as state,
                patch.object(
                    staging_module,
                    "cleanup_repository_executable_stage",
                    side_effect=AssertionError("cleanup"),
                ) as cleanup,
            ):
                receipt = inspect_staged_executable_runtime_manifest(
                    staging,
                    lease=lease,
                )
            self.assertEqual(receipt.file_count, 2)
            self.assertEqual(self._lease_snapshot(lease), before)
            for observed in (
                which,
                getenv,
                get_exec_path,
                open_path,
                write,
                fchmod,
                close,
                duplicate,
                duplicate_to,
                system,
                run,
                popen,
                create_exec,
                create_shell,
                stage_artifact,
                publish_artifact,
                state,
                cleanup,
            ):
                observed.assert_not_called()
            self.assertEqual(
                tuple(
                    self.fixture._tree_snapshot(value)
                    for value in (root, outside, search_one, search_two)
                ),
                tree_before,
            )
            self.assertEqual(tuple(staging_root.iterdir()), ())
            lease.close()


if __name__ == "__main__":
    unittest.main()
