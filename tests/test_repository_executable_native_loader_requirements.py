from __future__ import annotations

import builtins
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import inspect
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
import ordomata.repository_executable_native_loader_requirements as loader_module
from ordomata.repository_executable_native_loader_requirements import (
    REQUIREMENTS_SCOPE,
    REQUIREMENTS_SOURCE,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_BINDING_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_SCHEMA_VERSION,
    RepositoryExecutableNativeLoaderRequirement,
    RepositoryExecutableNativeLoaderRequirementBinding,
    RepositoryExecutableNativeLoaderRequirementsReceipt,
    inspect_staged_executable_native_loader_requirements,
)
from ordomata.repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
    inspect_staged_executable_runtime_manifest,
)
from ordomata.repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
)

if __package__:
    from . import test_repository_executable_runtime_manifest as runtime_test_module
else:
    import test_repository_executable_runtime_manifest as runtime_test_module


FIXED_REQUIREMENTS_ERROR = (
    "repository executable native loader requirements are invalid"
)
REQUIREMENT_KEYS = {
    "byte_order",
    "disposition",
    "format_class",
    "image_kind",
    "kind",
    "layout_supported",
    "loader_path_absolute",
    "loader_path_bytes",
    "loader_path_ref",
    "requirement_ref",
    "requirements_scope",
    "runtime_classification",
    "runtime_file_ref",
    "schema_version",
    "staged_file_ref",
}
BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
}
RECEIPT_KEYS = {
    "bindings",
    "command_count",
    "kind",
    "loader_declared_count",
    "native_requirement_count",
    "non_native_not_applicable_count",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "requirements_scope",
    "requirements_source",
    "resolution_context_digest",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "staging_context_digest",
    "staging_receipt_digest",
    "total_loader_path_bytes",
    "unsupported_native_layout_count",
    "verification_commands_digest",
}
EVIDENCE_KEYS = {
    "action_receipt_issued",
    "active_lease_verified_at_measurement",
    "authority_granted",
    "authorization_verified",
    "billing_eligible",
    "bounded_native_loader_declaration_inspection_complete",
    "capacity_eligible",
    "circuit_eligible",
    "command_count",
    "current_lease_activity_verified",
    "current_source_freshness_verified",
    "dispatch_enabled",
    "durable_control_plane_persistence_enabled",
    "dynamic_loader_declaration_syntax_verified",
    "dynamic_loader_identity_verified",
    "effect_class",
    "elf_interpreter_absent_count",
    "elf_interpreter_declared_count",
    "environment_coverage_verified",
    "execution_enabled",
    "fat_mach_o_architecture_selection_performed",
    "future_execution_correspondence_verified",
    "kind",
    "lease_cleanup_performed",
    "lease_mutated",
    "live_execution_eligible",
    "loader_path_lookup_performed",
    "loader_path_raw_bytes_exposed",
    "loader_path_resolution_verified",
    "mach_o_dylinker_absent_count",
    "mach_o_dylinker_declared_count",
    "model_invocation_performed",
    "native_requirement_count",
    "network_access_performed",
    "non_native_not_applicable_count",
    "path_lookup_performed",
    "proposal_lineage_extended",
    "receipt_authenticity_verified",
    "receipt_digest",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements_scope",
    "requirements_source",
    "resolution_context_digest",
    "route_eligible",
    "runtime_manifest_complete",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shared_library_closure_verified",
    "shared_library_identity_verified",
    "source_path_reopen_performed",
    "staged_byte_correspondence_verified",
    "staged_descriptor_full_remeasurement_complete",
    "staging_receipt_digest",
    "subprocess_invocation_performed",
    "toolchain_completeness_verified",
    "total_loader_path_bytes",
    "unsupported_native_layout_count",
    "validation_mode",
    "worker_authorized",
    "worktree_integration_enabled",
}


def _elf64(
    path: bytes | None = b"/lib64/ld-linux-x86-64.so.2",
    *,
    duplicate: bool = False,
    header_size: int = 64,
) -> bytes:
    count = 0 if path is None else 2 if duplicate else 1
    path_offset = 256
    size = max(64 + count * 56, path_offset + (len(path) + 1 if path else 0))
    data = bytearray(size)
    data[:7] = b"\x7fELF\x02\x01\x01"
    data[16:18] = (2).to_bytes(2, "little")
    data[20:24] = (1).to_bytes(4, "little")
    data[32:40] = (64).to_bytes(8, "little")
    data[52:54] = header_size.to_bytes(2, "little")
    data[54:56] = (56).to_bytes(2, "little")
    data[56:58] = count.to_bytes(2, "little")
    if path is not None:
        for index in range(count):
            offset = 64 + index * 56
            data[offset : offset + 4] = (3).to_bytes(4, "little")
            data[offset + 8 : offset + 16] = path_offset.to_bytes(8, "little")
            data[offset + 32 : offset + 40] = (len(path) + 1).to_bytes(
                8,
                "little",
            )
        data[path_offset : path_offset + len(path) + 1] = path + b"\x00"
    return bytes(data)


def _elf32_big_absent() -> bytes:
    data = bytearray(52)
    data[:7] = b"\x7fELF\x01\x02\x01"
    data[16:18] = (3).to_bytes(2, "big")
    data[20:24] = (1).to_bytes(4, "big")
    data[28:32] = (52).to_bytes(4, "big")
    data[40:42] = (52).to_bytes(2, "big")
    data[42:44] = (32).to_bytes(2, "big")
    data[44:46] = (0).to_bytes(2, "big")
    return bytes(data)


def _mach64(path: bytes | None = b"/usr/lib/dyld") -> bytes:
    if path is None:
        command = b""
        command_count = 0
    else:
        command_size = ((12 + len(path) + 1 + 3) // 4) * 4
        payload = bytearray(command_size)
        payload[0:4] = (0xE).to_bytes(4, "little")
        payload[4:8] = command_size.to_bytes(4, "little")
        payload[8:12] = (12).to_bytes(4, "little")
        payload[12 : 12 + len(path) + 1] = path + b"\x00"
        command = bytes(payload)
        command_count = 1
    data = bytearray(32 + len(command))
    data[:4] = b"\xcf\xfa\xed\xfe"
    data[12:16] = (2).to_bytes(4, "little")
    data[16:20] = command_count.to_bytes(4, "little")
    data[20:24] = len(command).to_bytes(4, "little")
    data[32:] = command
    return bytes(data)


def _fat_mach64() -> bytes:
    return b"\xca\xfe\xba\xbf" + b"\x00" * 36


@unittest.skipUnless(os.name == "posix", "native loader inspection requires POSIX")
class RepositoryExecutableNativeLoaderRequirementsTests(unittest.TestCase):
    fixture = runtime_test_module.RepositoryExecutableRuntimeManifestTests

    @classmethod
    def _workspace(cls, temporary: str) -> tuple[Path, Path, Path, Path, Path]:
        return cls.fixture._workspace(temporary)

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
    def _stage_runtime(
        cls,
        registration: object,
        search_directories: tuple[Path, ...],
        staging_root: Path,
    ) -> tuple[
        RepositoryExecutableStageLease,
        RepositoryExecutableStagingReceipt,
        RepositoryExecutableRuntimeManifestReceipt,
    ]:
        lease, staging = cls.fixture._stage(
            registration,
            search_directories,
            staging_root,
        )
        runtime = inspect_staged_executable_runtime_manifest(
            staging,
            lease=lease,
        )
        return lease, staging, runtime

    @classmethod
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    def _inspect_pair(
        self,
        bare: bytes,
        relative: bytes,
    ) -> tuple[
        RepositoryExecutableNativeLoaderRequirementsReceipt,
        RepositoryExecutableStageLease,
        RepositoryExecutableStagingReceipt,
        RepositoryExecutableRuntimeManifestReceipt,
        str,
    ]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, _outside, search_one, search_two, staging_root = self._workspace(
            temporary.name
        )
        self._set_contents(root, search_one, bare=bare, relative=relative)
        registration = self._registration(root)
        lease, staging, runtime = self._stage_runtime(
            registration,
            (search_one, search_two),
            staging_root,
        )
        self.addCleanup(lease.close)
        receipt = inspect_staged_executable_native_loader_requirements(
            runtime,
            expected_staging=staging,
            lease=lease,
        )
        return receipt, lease, staging, runtime, str(root)

    def _assert_invalid(
        self,
        runtime: object,
        staging: object,
        lease: object,
        *,
        private_marker: str = "private-native-loader-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_loader_requirements(
                runtime,
                expected_staging=staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_REQUIREMENTS_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_declared_elf_and_mach_o_receipt_privacy_and_immutability(self) -> None:
        elf_path = b"/lib64/ld-linux-x86-64.so.2"
        mach_path = b"/usr/lib/dyld"
        receipt, lease, staging, runtime, root = self._inspect_pair(
            _elf64(elf_path),
            _mach64(mach_path),
        )
        before = self._lease_snapshot(lease)
        repeated = inspect_staged_executable_native_loader_requirements(
            runtime,
            expected_staging=staging,
            lease=lease,
        )
        self.assertEqual(receipt, repeated)
        self.assertEqual(before, self._lease_snapshot(lease))
        self.assertIsInstance(
            receipt,
            RepositoryExecutableNativeLoaderRequirementsReceipt,
        )
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_SCHEMA_VERSION,
            1,
        )
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_KIND,
            "repository_executable_native_loader_requirements",
        )
        self.assertEqual(REQUIREMENTS_SOURCE, "controller_inspected")
        self.assertEqual(
            REQUIREMENTS_SCOPE,
            "staged_native_loader_declarations_v1",
        )
        canonical = receipt.to_canonical()
        self.assertEqual(set(canonical), RECEIPT_KEYS)
        self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
        self.assertEqual(
            receipt.runtime_manifest_receipt_digest,
            runtime.receipt_digest,
        )
        self.assertEqual(receipt.staging_receipt_digest, staging.receipt_digest)
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.native_requirement_count, 2)
        self.assertEqual(receipt.loader_declared_count, 2)
        self.assertEqual(receipt.unsupported_native_layout_count, 0)
        self.assertEqual(receipt.non_native_not_applicable_count, 0)
        self.assertEqual(
            receipt.total_loader_path_bytes,
            len(elf_path) + len(mach_path),
        )
        by_class = {
            item.runtime_classification: item for item in receipt.requirements
        }
        self.assertEqual(
            by_class["elf"].disposition,
            "elf_interpreter_declared",
        )
        self.assertEqual(by_class["elf"].format_class, "elf64")
        self.assertEqual(by_class["elf"].byte_order, "little")
        self.assertEqual(by_class["elf"].image_kind, "executable")
        self.assertEqual(
            by_class["mach_o"].disposition,
            "mach_o_dylinker_declared",
        )
        self.assertEqual(by_class["mach_o"].format_class, "mach_o64")
        for requirement in receipt.requirements:
            self.assertIsInstance(
                requirement,
                RepositoryExecutableNativeLoaderRequirement,
            )
            self.assertEqual(set(requirement.to_canonical()), REQUIREMENT_KEYS)
            self.assertRegex(
                requirement.loader_path_ref or "",
                r"^sha256:[0-9a-f]{64}$",
            )
            self.assertIs(requirement.loader_path_absolute, True)
            self.assertIs(requirement.layout_supported, True)
        for binding in receipt.bindings:
            self.assertIsInstance(
                binding,
                RepositoryExecutableNativeLoaderRequirementBinding,
            )
            self.assertEqual(set(binding.to_canonical()), BINDING_KEYS)
            self.assertEqual(
                binding.kind,
                REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_BINDING_KIND,
            )
        self.assertTrue(
            all(
                item.kind == REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_KIND
                for item in receipt.requirements
            )
        )

        evidence = receipt.to_evidence()
        self.assertEqual(set(evidence), EVIDENCE_KEYS)
        self.assertEqual(
            evidence["kind"],
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_EVIDENCE_KIND,
        )
        self.assertEqual(evidence["effect_class"], 0)
        self.assertEqual(evidence["validation_mode"], "read_only")
        for true_fact in (
            "active_lease_verified_at_measurement",
            "bounded_native_loader_declaration_inspection_complete",
            "dynamic_loader_declaration_syntax_verified",
            "staged_byte_correspondence_verified",
            "staged_descriptor_full_remeasurement_complete",
        ):
            self.assertIs(evidence[true_fact], True, true_fact)
        for false_fact in (
            "authority_granted",
            "authorization_verified",
            "dispatch_enabled",
            "dynamic_loader_identity_verified",
            "execution_enabled",
            "fat_mach_o_architecture_selection_performed",
            "live_execution_eligible",
            "loader_path_lookup_performed",
            "loader_path_raw_bytes_exposed",
            "loader_path_resolution_verified",
            "model_invocation_performed",
            "network_access_performed",
            "path_lookup_performed",
            "shared_library_closure_verified",
            "shared_library_identity_verified",
            "subprocess_invocation_performed",
            "worker_authorized",
        ):
            self.assertIs(evidence[false_fact], False, false_fact)

        aggregate = "\n".join(
            (
                json.dumps(canonical, sort_keys=True),
                json.dumps(evidence, sort_keys=True),
                repr(receipt),
                *(repr(item) for item in receipt.requirements),
                *(repr(item) for item in receipt.bindings),
            )
        )
        for private_value in (
            root,
            elf_path.decode("ascii"),
            mach_path.decode("ascii"),
        ):
            self.assertNotIn(private_value, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.requirement_count = 0
        with self.assertRaises(FrozenInstanceError):
            receipt.requirements[0].disposition = "unsupported_native_layout"
        with self.assertRaises(FrozenInstanceError):
            receipt.bindings[0].command_kind = "test"

    def test_absent_fat_and_non_native_dispositions_are_fixed(self) -> None:
        cases = (
            (
                _elf32_big_absent(),
                _mach64(None),
                {
                    "elf": ("elf_interpreter_absent", "elf32", "big", True),
                    "mach_o": (
                        "mach_o_dylinker_absent",
                        "mach_o64",
                        "little",
                        True,
                    ),
                },
            ),
            (
                _fat_mach64(),
                b"#!/usr/bin/python3\n",
                {
                    "mach_o": (
                        "unsupported_native_layout",
                        "mach_o_fat64",
                        "big",
                        False,
                    ),
                    "posix_shebang": (
                        "non_native_not_applicable",
                        None,
                        None,
                        False,
                    ),
                },
            ),
            (
                b"ordinary executable bytes\n",
                b"#!broken",
                {
                    "unknown": (
                        "non_native_not_applicable",
                        None,
                        None,
                        False,
                    ),
                    "unsupported_shebang": (
                        "non_native_not_applicable",
                        None,
                        None,
                        False,
                    ),
                },
            ),
        )
        for bare, relative, expected in cases:
            with self.subTest(expected=expected):
                receipt, *_ = self._inspect_pair(bare, relative)
                actual = {
                    item.runtime_classification: (
                        item.disposition,
                        item.format_class,
                        item.byte_order,
                        item.layout_supported,
                    )
                    for item in receipt.requirements
                }
                self.assertEqual(actual, expected)
                for item in receipt.requirements:
                    self.assertIsNone(item.loader_path_ref)
                    self.assertEqual(item.loader_path_bytes, 0)
                    self.assertIsNone(item.loader_path_absolute)

    def test_malformed_native_layouts_collapse_to_unsupported(self) -> None:
        malformed_mach = bytearray(_mach64())
        malformed_mach[36:40] = (10).to_bytes(4, "little")
        cases = (
            _elf64(header_size=63),
            _elf64(duplicate=True),
            _elf64(b"relative/loader"),
            bytes(malformed_mach),
        )
        for native in cases:
            with self.subTest(prefix=native[:8].hex()):
                receipt, *_ = self._inspect_pair(
                    native,
                    b"#!/usr/bin/python3\n",
                )
                requirement = next(
                    item
                    for item in receipt.requirements
                    if item.runtime_classification in {"elf", "mach_o"}
                )
                self.assertEqual(
                    requirement.disposition,
                    "unsupported_native_layout",
                )
                self.assertFalse(requirement.layout_supported)
                self.assertIsNone(requirement.image_kind)
                self.assertIsNone(requirement.loader_path_ref)

    def test_shared_runtime_file_has_one_requirement_and_two_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(root, search_one, bare=_elf64())
            registration = self._registration(root, shared=True)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one,),
                staging_root,
            )
            try:
                receipt = inspect_staged_executable_native_loader_requirements(
                    runtime,
                    expected_staging=staging,
                    lease=lease,
                )
                self.assertEqual(receipt.requirement_count, 1)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(
                    {item.requirement_ref for item in receipt.bindings},
                    {receipt.requirements[0].requirement_ref},
                )
            finally:
                lease.close()

    def test_wrong_inputs_lineage_forgery_and_inactive_lease_fail_closed(self) -> None:
        receipt, lease, staging, runtime, _root = self._inspect_pair(
            _elf64(),
            _mach64(),
        )
        self.assertIsNotNone(receipt)
        self._assert_invalid(None, staging, lease)
        self._assert_invalid(runtime, None, lease)
        self._assert_invalid(runtime, staging, None)
        self._assert_invalid(
            replace(runtime, repository_ref="sha256:" + "0" * 64),
            staging,
            lease,
        )
        self._assert_invalid(
            replace(staging, staging_context_digest="sha256:" + "1" * 64),
            staging,
            lease,
        )
        lease.close()
        self._assert_invalid(runtime, staging, lease)

    def test_output_projection_rejects_forged_records_counts_and_order(self) -> None:
        receipt, *_ = self._inspect_pair(_elf64(), _mach64())
        for forged in (
            replace(receipt, loader_declared_count=1),
            replace(
                receipt,
                total_loader_path_bytes=receipt.total_loader_path_bytes + 1,
            ),
            replace(
                receipt,
                requirements=tuple(reversed(receipt.requirements)),
            ),
            replace(
                receipt,
                bindings=(
                    replace(
                        receipt.bindings[0],
                        requirement_ref=receipt.bindings[1].requirement_ref,
                    ),
                    receipt.bindings[1],
                ),
            ),
        ):
            with self.subTest(forged=repr(forged)):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

        requirement = receipt.requirements[0]
        for forged_requirement in (
            replace(requirement, image_kind=None),
            replace(requirement, loader_path_bytes=0),
            replace(requirement, layout_supported=False),
            replace(requirement, requirement_ref="sha256:" + "2" * 64),
        ):
            with self.subTest(requirement=repr(forged_requirement)):
                with self.assertRaises(ValueError):
                    forged_requirement.to_canonical()

        with self.assertRaises(ValueError):
            replace(
                receipt.bindings[0],
                command_kind="unknown",
            ).to_canonical()

    def test_public_module_monkeypatches_do_not_bypass_captured_boundaries(
        self,
    ) -> None:
        _receipt, lease, staging, runtime, _root = self._inspect_pair(
            _elf64(),
            _mach64(),
        )
        poison = AssertionError("private-public-monkeypatch-marker")
        poisoned_functions = (
            "inspect_staged_executable_runtime_manifest",
            "_active_stage_snapshot",
            "_runtime_manifest_projection",
            "_staging_receipt_projection",
            "_staged_file_projection",
            "_requirement_ref_projection",
            "_requirement_projection",
            "_binding_projection",
            "_receipt_projection",
            "_evidence_projection",
            "_integer",
            "_read_exact_range",
            "_descriptor_signature",
            "_independent_descriptor_remeasurement",
            "_header_digest",
            "_canonical_absolute_path",
            "_loader_path_ref",
            "_terminated_loader_path",
            "_elf_requirement_fields",
            "_mach_o_requirement_fields",
            "_build_requirement",
            "_remeasure_requirements",
        )
        poisoned_types = (
            "RepositoryExecutableNativeLoaderRequirement",
            "RepositoryExecutableNativeLoaderRequirementBinding",
            "RepositoryExecutableNativeLoaderRequirementsReceipt",
        )
        with ExitStack() as stack:
            for name in poisoned_functions:
                stack.enter_context(
                    patch.object(loader_module, name, side_effect=poison)
                )
            for name in poisoned_types:
                stack.enter_context(patch.object(loader_module, name, None))
            repeated = inspect_staged_executable_native_loader_requirements(
                runtime,
                expected_staging=staging,
                lease=lease,
            )
        self.assertEqual(repeated.loader_declared_count, 2)

    def test_reinspection_and_descriptor_remeasurement_are_repeated(self) -> None:
        _receipt, lease, staging, runtime, _root = self._inspect_pair(
            _elf64(),
            _mach64(),
        )
        with (
            patch.object(
                loader_module,
                "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
                wraps=loader_module._BUILTIN_INSPECT_RUNTIME_MANIFEST,
            ) as inspect_runtime,
            patch.object(
                loader_module,
                "_BUILTIN_DESCRIPTOR_REMEASUREMENT",
                wraps=loader_module._BUILTIN_DESCRIPTOR_REMEASUREMENT,
            ) as remeasure,
            patch.object(
                loader_module,
                "_BUILTIN_ACTIVE_STAGE_SNAPSHOT",
                wraps=loader_module._BUILTIN_ACTIVE_STAGE_SNAPSHOT,
            ) as snapshot,
        ):
            inspect_staged_executable_native_loader_requirements(
                runtime,
                expected_staging=staging,
                lease=lease,
            )
        self.assertEqual(inspect_runtime.call_count, 2)
        self.assertEqual(remeasure.call_count, 8)
        self.assertEqual(snapshot.call_count, 3)

    def test_descriptor_anchor_tamper_and_cleanup_race_fail_closed(self) -> None:
        _receipt, lease, staging, runtime, _root = self._inspect_pair(
            _elf64(),
            _mach64(),
        )
        original_files = lease._files
        retained = original_files[0]
        lease._files = (
            replace(
                retained,
                metadata=(retained.metadata[0] + 1, *retained.metadata[1:]),
            ),
            *original_files[1:],
        )
        self._assert_invalid(runtime, staging, lease)
        lease._files = original_files

        real_inspect = loader_module._BUILTIN_INSPECT_RUNTIME_MANIFEST
        calls = 0

        def close_after_reinspection(*args: object, **kwargs: object):
            nonlocal calls
            calls += 1
            result = real_inspect(*args, **kwargs)
            if calls == 2:
                lease.close()
            return result

        with patch.object(
            loader_module,
            "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
            side_effect=close_after_reinspection,
        ):
            self._assert_invalid(runtime, staging, lease)
        self.assertEqual(lease.state, "cleaned")
        self.assertIsNotNone(lease.cleanup_receipt)

    def test_no_path_open_process_write_or_cleanup_effect_is_integrated(self) -> None:
        _receipt, lease, staging, runtime, _root = self._inspect_pair(
            _elf64(),
            _mach64(),
        )
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-side-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as builtin_open,
            patch.object(os, "open", side_effect=poison) as os_open,
            patch.object(os, "write", side_effect=poison) as os_write,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
        ):
            receipt = inspect_staged_executable_native_loader_requirements(
                runtime,
                expected_staging=staging,
                lease=lease,
            )
        self.assertEqual(receipt.loader_declared_count, 2)
        self.assertEqual(before, self._lease_snapshot(lease))
        builtin_open.assert_not_called()
        os_open.assert_not_called()
        os_write.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()

    def test_bounded_position_independent_range_reads(self) -> None:
        with tempfile.TemporaryFile() as stream:
            stream.write(b"0123456789")
            stream.flush()
            os.fsync(stream.fileno())
            stream.seek(7)
            with patch.object(
                loader_module,
                "_BUILTIN_PREAD",
                wraps=os.pread,
            ) as pread:
                result = loader_module._read_exact_range(
                    stream.fileno(),
                    offset=2,
                    size=4,
                    content_bytes=10,
                    maximum_bytes=4,
                )
            self.assertEqual(result, b"2345")
            self.assertEqual(stream.tell(), 7)
            self.assertEqual(pread.call_count, 1)
            self.assertEqual(pread.call_args.args[1:], (4, 2))
            with self.assertRaises(ValueError):
                loader_module._read_exact_range(
                    stream.fileno(),
                    offset=8,
                    size=3,
                    content_bytes=10,
                    maximum_bytes=4,
                )

    def test_fixed_error_redaction_exports_and_signature(self) -> None:
        _receipt, lease, staging, runtime, _root = self._inspect_pair(
            _elf64(),
            _mach64(),
        )
        marker = "private-native-loader-base-exception-marker"
        with patch.object(
            loader_module,
            "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(
                runtime,
                staging,
                lease,
                private_marker=marker,
            )
        for interruption in (KeyboardInterrupt(), SystemExit(7)):
            with (
                self.subTest(interruption=type(interruption).__name__),
                patch.object(
                    loader_module,
                    "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
                    side_effect=interruption,
                ),
                self.assertRaises(type(interruption)),
            ):
                inspect_staged_executable_native_loader_requirements(
                    runtime,
                    expected_staging=staging,
                    lease=lease,
                )
        self.assertEqual(
            tuple(inspect.signature(
                inspect_staged_executable_native_loader_requirements
            ).parameters),
            ("expected_runtime", "expected_staging", "lease"),
        )
        self.assertEqual(
            loader_module.__all__,
            [
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENT_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_EVIDENCE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_REQUIREMENTS_SCHEMA_VERSION",
                "REQUIREMENTS_SCOPE",
                "REQUIREMENTS_SOURCE",
                "RepositoryExecutableNativeLoaderRequirement",
                "RepositoryExecutableNativeLoaderRequirementBinding",
                "RepositoryExecutableNativeLoaderRequirementsReceipt",
                "inspect_staged_executable_native_loader_requirements",
            ],
        )


if __name__ == "__main__":
    unittest.main()
