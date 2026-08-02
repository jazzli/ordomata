from __future__ import annotations

import builtins
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata import (
    repository_executable_native_dependency_requirements as dependency_module,
)
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_requirements import (
    RepositoryExecutableNativeDependencyRequirementsReceipt,
    inspect_staged_executable_native_dependency_requirements,
)
from ordomata.repository_executable_native_loader_requirements import (
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
    from . import (
        test_repository_executable_native_loader_requirements as loader_fixture,
    )
else:
    import test_repository_executable_native_loader_requirements as loader_fixture


FIXED_ERROR = (
    "repository executable native dependency requirements are invalid"
)


def _elf64_dependencies(
    names: tuple[bytes, ...],
    *,
    loader_path: bytes | None = None,
    malformed: str | None = None,
) -> bytes:
    string_table = bytearray(b"\x00")
    name_offsets: list[int] = []
    for name in names:
        name_offsets.append(len(string_table))
        string_table.extend(name)
        string_table.append(0)
    program_count = 2 + int(loader_path is not None)
    string_offset = 0x300
    string_address = 0x400300
    dynamic_offset = 0x500
    dynamic_entries = [(5, string_address), (10, len(string_table))]
    dynamic_entries.extend((1, offset) for offset in name_offsets)
    dynamic_entries.append((0, 0))
    dynamic = bytearray()
    for tag, value in dynamic_entries:
        dynamic.extend(tag.to_bytes(8, "little"))
        dynamic.extend(value.to_bytes(8, "little"))
    if malformed == "missing_null":
        dynamic = dynamic[:-16]
    if malformed == "unmapped_strtab":
        dynamic[8:16] = (0x900000).to_bytes(8, "little")
    size = max(
        64 + program_count * 56,
        string_offset + len(string_table),
        dynamic_offset + len(dynamic),
        0x200 + (len(loader_path) + 1 if loader_path else 0),
    )
    data = bytearray(size)
    data[:7] = b"\x7fELF\x02\x01\x01"
    data[16:18] = (2).to_bytes(2, "little")
    data[20:24] = (1).to_bytes(4, "little")
    data[32:40] = (64).to_bytes(8, "little")
    data[52:54] = (64).to_bytes(2, "little")
    data[54:56] = (56).to_bytes(2, "little")
    data[56:58] = program_count.to_bytes(2, "little")

    load = 64
    data[load : load + 4] = (1).to_bytes(4, "little")
    data[load + 8 : load + 16] = string_offset.to_bytes(8, "little")
    data[load + 16 : load + 24] = string_address.to_bytes(8, "little")
    data[load + 32 : load + 40] = len(string_table).to_bytes(8, "little")
    data[load + 40 : load + 48] = len(string_table).to_bytes(8, "little")

    dynamic_header = 64 + 56
    data[dynamic_header : dynamic_header + 4] = (2).to_bytes(4, "little")
    data[dynamic_header + 8 : dynamic_header + 16] = dynamic_offset.to_bytes(
        8,
        "little",
    )
    data[dynamic_header + 32 : dynamic_header + 40] = len(dynamic).to_bytes(
        8,
        "little",
    )
    data[dynamic_header + 40 : dynamic_header + 48] = len(dynamic).to_bytes(
        8,
        "little",
    )

    if loader_path is not None:
        interpreter = 64 + 112
        data[interpreter : interpreter + 4] = (3).to_bytes(4, "little")
        data[interpreter + 8 : interpreter + 16] = (0x200).to_bytes(
            8,
            "little",
        )
        data[interpreter + 32 : interpreter + 40] = (
            len(loader_path) + 1
        ).to_bytes(8, "little")
        data[0x200 : 0x200 + len(loader_path) + 1] = loader_path + b"\x00"
    data[string_offset : string_offset + len(string_table)] = string_table
    data[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    return bytes(data)


def _elf32_big_dependencies(names: tuple[bytes, ...]) -> bytes:
    string_table = bytearray(b"\x00")
    name_offsets: list[int] = []
    for name in names:
        name_offsets.append(len(string_table))
        string_table.extend(name)
        string_table.append(0)
    string_offset = 0x200
    string_address = 0x400200
    dynamic_offset = 0x300
    dynamic_entries = [(5, string_address), (10, len(string_table))]
    dynamic_entries.extend((1, offset) for offset in name_offsets)
    dynamic_entries.append((0, 0))
    dynamic = bytearray()
    for tag, value in dynamic_entries:
        dynamic.extend(tag.to_bytes(4, "big"))
        dynamic.extend(value.to_bytes(4, "big"))
    size = max(
        52 + 2 * 32,
        string_offset + len(string_table),
        dynamic_offset + len(dynamic),
    )
    data = bytearray(size)
    data[:7] = b"\x7fELF\x01\x02\x01"
    data[16:18] = (3).to_bytes(2, "big")
    data[20:24] = (1).to_bytes(4, "big")
    data[28:32] = (52).to_bytes(4, "big")
    data[40:42] = (52).to_bytes(2, "big")
    data[42:44] = (32).to_bytes(2, "big")
    data[44:46] = (2).to_bytes(2, "big")

    load = 52
    data[load : load + 4] = (1).to_bytes(4, "big")
    data[load + 4 : load + 8] = string_offset.to_bytes(4, "big")
    data[load + 8 : load + 12] = string_address.to_bytes(4, "big")
    data[load + 16 : load + 20] = len(string_table).to_bytes(4, "big")
    data[load + 20 : load + 24] = len(string_table).to_bytes(4, "big")

    dynamic_header = 52 + 32
    data[dynamic_header : dynamic_header + 4] = (2).to_bytes(4, "big")
    data[dynamic_header + 4 : dynamic_header + 8] = dynamic_offset.to_bytes(
        4,
        "big",
    )
    data[dynamic_header + 16 : dynamic_header + 20] = len(dynamic).to_bytes(
        4,
        "big",
    )
    data[dynamic_header + 20 : dynamic_header + 24] = len(dynamic).to_bytes(
        4,
        "big",
    )
    data[string_offset : string_offset + len(string_table)] = string_table
    data[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    return bytes(data)


def _mach_dylib_command(
    command: int,
    name: bytes,
    *,
    current_version: int = 0x00020003,
    compatibility_version: int = 0x00010000,
    byte_order: str = "little",
) -> bytes:
    command_size = ((24 + len(name) + 1 + 7) // 8) * 8
    data = bytearray(command_size)
    data[0:4] = command.to_bytes(4, byte_order)
    data[4:8] = command_size.to_bytes(4, byte_order)
    data[8:12] = (24).to_bytes(4, byte_order)
    data[16:20] = current_version.to_bytes(4, byte_order)
    data[20:24] = compatibility_version.to_bytes(4, byte_order)
    data[24 : 24 + len(name) + 1] = name + b"\x00"
    return bytes(data)


def _mach64_dependencies(
    declarations: tuple[tuple[int, bytes], ...],
    *,
    loader_path: bytes | None = None,
    malformed_name: bool = False,
) -> bytes:
    commands: list[bytes] = []
    if loader_path is not None:
        command_size = ((12 + len(loader_path) + 1 + 3) // 4) * 4
        command = bytearray(command_size)
        command[0:4] = (0xE).to_bytes(4, "little")
        command[4:8] = command_size.to_bytes(4, "little")
        command[8:12] = (12).to_bytes(4, "little")
        command[12 : 12 + len(loader_path) + 1] = loader_path + b"\x00"
        commands.append(bytes(command))
    commands.extend(
        _mach_dylib_command(command, name)
        for command, name in declarations
    )
    if malformed_name and commands:
        damaged = bytearray(commands[-1])
        damaged[-1] = 1
        commands[-1] = bytes(damaged)
    table = b"".join(commands)
    data = bytearray(32 + len(table))
    data[:4] = b"\xcf\xfa\xed\xfe"
    data[12:16] = (2).to_bytes(4, "little")
    data[16:20] = len(commands).to_bytes(4, "little")
    data[20:24] = len(table).to_bytes(4, "little")
    data[32:] = table
    return bytes(data)


def _mach32_big_dependencies(
    declarations: tuple[tuple[int, bytes], ...],
) -> bytes:
    commands = tuple(
        _mach_dylib_command(command, name, byte_order="big")
        for command, name in declarations
    )
    table = b"".join(commands)
    data = bytearray(28 + len(table))
    data[:4] = b"\xfe\xed\xfa\xce"
    data[12:16] = (6).to_bytes(4, "big")
    data[16:20] = len(commands).to_bytes(4, "big")
    data[20:24] = len(table).to_bytes(4, "big")
    data[28:] = table
    return bytes(data)


@unittest.skipUnless(os.name == "posix", "dependency inspection requires POSIX")
class RepositoryExecutableNativeDependencyRequirementsTests(unittest.TestCase):
    fixture = loader_fixture.RepositoryExecutableNativeLoaderRequirementsTests

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
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    def _inspect_pair(
        self,
        bare: bytes,
        relative: bytes,
        *,
        shared: bool = False,
    ) -> tuple[
        RepositoryExecutableNativeDependencyRequirementsReceipt,
        RepositoryExecutableNativeLoaderRequirementsReceipt,
        RepositoryExecutableRuntimeManifestReceipt,
        RepositoryExecutableStagingReceipt,
        RepositoryExecutableStageLease,
        str,
    ]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, _outside, search_one, search_two, staging_root = self._workspace(
            temporary.name
        )
        self._set_contents(root, search_one, bare=bare, relative=relative)
        registration = self._registration(root, shared=shared)
        lease, staging, runtime = self.fixture._stage_runtime(
            registration,
            (search_one, search_two),
            staging_root,
        )
        self.addCleanup(lease.close)
        loader = inspect_staged_executable_native_loader_requirements(
            runtime,
            expected_staging=staging,
            lease=lease,
        )
        receipt = inspect_staged_executable_native_dependency_requirements(
            loader,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
        )
        return receipt, loader, runtime, staging, lease, str(root)

    def _assert_invalid(
        self,
        loader: object,
        runtime: object,
        staging: object,
        lease: object,
        *,
        marker: str = "private-dependency-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_dependency_requirements(
                loader,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_elf_and_mach_dependency_metadata_is_digest_only(self) -> None:
        elf_names = (b"libprivate-one.so", b"/private/libprivate-two.so")
        mach_names = (
            (0xC, b"@rpath/private-required.dylib"),
            (0x80000018, b"@loader_path/private-weak.dylib"),
            (0x8000001F, b"/private/reexport.dylib"),
        )
        receipt, loader, runtime, staging, lease, root = self._inspect_pair(
            _elf64_dependencies(elf_names, loader_path=b"/private/ld.so"),
            _mach64_dependencies(mach_names, loader_path=b"/private/dyld"),
        )
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.dependency_declared_requirement_count, 2)
        self.assertEqual(receipt.dependency_declaration_count, 5)
        self.assertEqual(receipt.required_dependency_count, 4)
        self.assertEqual(receipt.weak_dependency_count, 1)
        self.assertEqual(
            receipt.native_loader_requirements_receipt_digest,
            loader.receipt_digest,
        )
        declarations = tuple(
            declaration
            for requirement in receipt.requirements
            for declaration in requirement.declarations
        )
        self.assertEqual(
            {item.path_style for item in declarations},
            {"bare", "absolute", "at_rpath", "at_loader_path"},
        )
        self.assertEqual(
            {item.load_kind for item in declarations},
            {"required", "weak", "reexport"},
        )
        self.assertTrue(
            all(
                item.dependency_name_ref.startswith("sha256:")
                for item in declarations
            )
        )
        before = self._lease_snapshot(lease)
        repeated = inspect_staged_executable_native_dependency_requirements(
            loader,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
        )
        self.assertEqual(repeated, receipt)
        self.assertEqual(self._lease_snapshot(lease), before)
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(
            evidence["dependency_declaration_syntax_inspection_complete"]
        )
        self.assertFalse(evidence["dependency_closure_verified"])
        aggregate = "\n".join(
            (
                json.dumps(receipt.to_canonical(), sort_keys=True),
                json.dumps(evidence, sort_keys=True),
                repr(receipt),
            )
        )
        for private in (
            *(name.decode() for name in elf_names),
            *(name.decode() for _command, name in mach_names),
            root,
        ):
            self.assertNotIn(private, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.requirement_count = 0

    def test_32_bit_big_endian_dependency_layouts_are_bounded(self) -> None:
        receipt, *_unused = self._inspect_pair(
            _elf32_big_dependencies((b"relative/private.so",)),
            _mach32_big_dependencies(
                (
                    (0x20, b"@executable_path/private-lazy.dylib"),
                    (0x80000023, b"private-upward.dylib"),
                )
            ),
        )
        by_format = {
            requirement.format_class: requirement
            for requirement in receipt.requirements
        }
        self.assertEqual(set(by_format), {"elf32", "mach_o32"})
        self.assertTrue(
            all(
                requirement.byte_order == "big"
                and requirement.layout_supported
                for requirement in by_format.values()
            )
        )
        self.assertEqual(
            tuple(
                declaration.path_style
                for declaration in by_format["elf32"].declarations
            ),
            ("relative",),
        )
        mach_declarations = by_format["mach_o32"].declarations
        self.assertEqual(
            tuple(item.load_kind for item in mach_declarations),
            ("lazy", "upward"),
        )
        self.assertEqual(
            tuple(item.path_style for item in mach_declarations),
            ("at_executable_path", "bare"),
        )
        self.assertTrue(
            all(
                item.current_version == 0x00020003
                and item.compatibility_version == 0x00010000
                for item in mach_declarations
            )
        )

    def test_absent_unsupported_and_non_native_dispositions_are_fixed(self) -> None:
        cases = (
            (
                _elf64_dependencies(()),
                _mach64_dependencies(()),
                {"elf_dependencies_absent", "mach_o_dependencies_absent"},
            ),
            (
                loader_fixture._fat_mach64(),
                b"#!/usr/bin/python3 -I\nprivate\n",
                {"unsupported_native_layout", "non_native_not_applicable"},
            ),
        )
        for bare, relative, dispositions in cases:
            with self.subTest(dispositions=dispositions):
                receipt, *_unused = self._inspect_pair(bare, relative)
                self.assertEqual(
                    {item.disposition for item in receipt.requirements},
                    dispositions,
                )
                self.assertEqual(receipt.dependency_declaration_count, 0)
                self.assertEqual(receipt.total_dependency_name_bytes, 0)

    def test_malformed_dependency_layouts_collapse_to_unsupported(self) -> None:
        cases = (
            _elf64_dependencies((b"libprivate.so",), malformed="missing_null"),
            _elf64_dependencies((b"libprivate.so",), malformed="unmapped_strtab"),
            _mach64_dependencies(
                ((0xC, b"@rpath/private.dylib"),),
                malformed_name=True,
            ),
        )
        for content in cases:
            with self.subTest(size=len(content)):
                receipt, *_unused = self._inspect_pair(
                    content,
                    _elf64_dependencies(()),
                )
                self.assertEqual(
                    receipt.requirements[0].disposition,
                    "unsupported_native_layout",
                )

    def test_shared_runtime_file_has_one_requirement_and_two_bindings(self) -> None:
        content = _elf64_dependencies((b"libprivate-shared.so",))
        receipt, loader, *_unused = self._inspect_pair(
            content,
            content,
            shared=True,
        )
        self.assertEqual(receipt.requirement_count, 1)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.dependency_declaration_count, 1)
        requirement = receipt.requirements[0]
        self.assertEqual(
            {item.dependency_requirement_ref for item in receipt.bindings},
            {requirement.requirement_ref},
        )
        self.assertEqual(
            {item.native_loader_requirement_ref for item in receipt.bindings},
            {loader.requirements[0].requirement_ref},
        )

    def test_wrong_inputs_forgery_and_inactive_lease_fail_closed(self) -> None:
        _receipt, loader, runtime, staging, lease, _root = self._inspect_pair(
            _elf64_dependencies(()),
            _mach64_dependencies(()),
        )
        for forged_loader, forged_runtime, forged_staging in (
            (None, runtime, staging),
            (loader, None, staging),
            (loader, runtime, None),
            (
                replace(
                    loader,
                    runtime_manifest_receipt_digest="sha256:" + "0" * 64,
                ),
                runtime,
                staging,
            ),
            (loader, replace(runtime, file_count=0), staging),
            (loader, runtime, replace(staging, unique_file_count=0)),
        ):
            with self.subTest(loader=repr(forged_loader)):
                self._assert_invalid(
                    forged_loader,
                    forged_runtime,
                    forged_staging,
                    lease,
                )
        lease.close()
        self._assert_invalid(loader, runtime, staging, lease)

    def test_projection_rejects_forged_counts_order_and_declarations(self) -> None:
        receipt, *_unused = self._inspect_pair(
            _elf64_dependencies((b"libprivate.so",)),
            _mach64_dependencies(()),
        )
        declaration = receipt.requirements[0].declarations[0]
        for forged in (
            replace(receipt, requirement_count=0),
            replace(receipt, dependency_declaration_count=0),
            replace(receipt, required_dependency_count=0),
            replace(receipt, requirements=tuple(reversed(receipt.requirements))),
            replace(
                receipt,
                requirements=(
                    replace(
                        receipt.requirements[0],
                        declarations=(replace(declaration, ordinal=1),),
                    ),
                    receipt.requirements[1],
                ),
            ),
        ):
            with self.subTest(forged=repr(forged)):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

    def test_fresh_loader_and_remeasurement_drift_fail_closed(self) -> None:
        _receipt, loader, runtime, staging, lease, _root = self._inspect_pair(
            _elf64_dependencies((b"libprivate.so",)),
            _mach64_dependencies(()),
        )
        real_loader = dependency_module._BUILTIN_INSPECT_NATIVE_LOADER
        calls = 0

        def drift(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_loader(*args, **kwargs)
            if calls == 2:
                return replace(result, total_loader_path_bytes=1)
            return result

        with patch.object(
            dependency_module,
            "_BUILTIN_INSPECT_NATIVE_LOADER",
            side_effect=drift,
        ):
            self._assert_invalid(loader, runtime, staging, lease)

        real_remeasure = dependency_module._BUILTIN_REMEASURE_REQUIREMENTS
        remeasure_calls = 0

        def changed(*args, **kwargs):
            nonlocal remeasure_calls
            remeasure_calls += 1
            result = real_remeasure(*args, **kwargs)
            if remeasure_calls == 2:
                return tuple(reversed(result))
            return result

        with patch.object(
            dependency_module,
            "_BUILTIN_REMEASURE_REQUIREMENTS",
            side_effect=changed,
        ):
            self._assert_invalid(loader, runtime, staging, lease)

    def test_public_helpers_cannot_replace_frozen_proof_graph(self) -> None:
        _receipt, loader, runtime, staging, lease, _root = self._inspect_pair(
            _elf64_dependencies((b"libprivate.so",)),
            _mach64_dependencies(()),
        )
        poison = AssertionError("private-public-helper-marker")
        names = (
            "_declaration_ref_projection",
            "_declaration_projection",
            "_requirement_ref_projection",
            "_requirement_projection",
            "_binding_projection",
            "_receipt_projection",
            "_evidence_projection",
            "_dependency_name_ref",
            "_dependency_path_style",
            "_build_declaration",
            "_elf_dependency_fields",
            "_mach_o_dependency_fields",
            "_build_requirement",
            "_remeasure_requirements",
            "_validate_correspondence",
        )
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(
                    patch.object(dependency_module, name, side_effect=poison)
                )
            receipt = inspect_staged_executable_native_dependency_requirements(
                loader,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
            )
        self.assertEqual(receipt.dependency_declaration_count, 1)

    def test_no_path_process_network_write_cleanup_or_lease_effects(self) -> None:
        _receipt, loader, runtime, staging, lease, _root = self._inspect_pair(
            _elf64_dependencies((b"libprivate.so",)),
            _mach64_dependencies(()),
        )
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(os, "open", side_effect=poison) as os_opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_dependency_requirements(
                loader,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
            )
        self.assertEqual(receipt.dependency_declaration_count, 1)
        self.assertEqual(self._lease_snapshot(lease), before)
        opened.assert_not_called()
        os_opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_exports_signature_interrupts_and_errors_are_fixed(self) -> None:
        expected_exports = {
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_DECLARATION_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_BINDING_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENT_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_EVIDENCE_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_REQUIREMENTS_SCHEMA_VERSION",
            "REQUIREMENTS_SCOPE",
            "REQUIREMENTS_SOURCE",
            "RepositoryExecutableNativeDependencyDeclaration",
            "RepositoryExecutableNativeDependencyRequirement",
            "RepositoryExecutableNativeDependencyRequirementBinding",
            "RepositoryExecutableNativeDependencyRequirementsReceipt",
            "inspect_staged_executable_native_dependency_requirements",
        }
        self.assertEqual(set(dependency_module.__all__), expected_exports)
        signature = inspect.signature(
            inspect_staged_executable_native_dependency_requirements
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_native_loader_requirements",
                "expected_runtime",
                "expected_staging",
                "lease",
            ),
        )
        for name in ("expected_runtime", "expected_staging", "lease"):
            self.assertEqual(
                signature.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )

        _receipt, loader, runtime, staging, lease, _root = self._inspect_pair(
            _elf64_dependencies(()),
            _mach64_dependencies(()),
        )
        with patch.object(
            dependency_module,
            "_BUILTIN_REMEASURE_REQUIREMENTS",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                inspect_staged_executable_native_dependency_requirements(
                    loader,
                    expected_runtime=runtime,
                    expected_staging=staging,
                    lease=lease,
                )
        marker = "private-parser-error-marker"
        with patch.object(
            dependency_module,
            "_BUILTIN_REMEASURE_REQUIREMENTS",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(
                loader,
                runtime,
                staging,
                lease,
                marker=marker,
            )


if __name__ == "__main__":
    unittest.main()
