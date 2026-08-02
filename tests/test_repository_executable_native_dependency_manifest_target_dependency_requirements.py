from __future__ import annotations

import builtins
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata import repository_executable_native_dependency_manifest_target_dependency_requirements as dependency_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_manifest_target_dependency_requirements import (
    RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt,
    inspect_staged_executable_native_dependency_manifest_target_dependency_requirements,
)
from ordomata.repository_executable_native_dependency_manifest_target_runtime_manifest import (
    inspect_staged_executable_native_dependency_manifest_target_runtime_manifest,
)
from ordomata.repository_executable_native_dependency_manifest_target_staging import (
    RepositoryExecutableNativeDependencyManifestTargetStageLease,
    stage_repository_executable_native_dependency_manifest_target_bytes,
)

if __package__:
    from . import test_repository_executable_native_dependency_manifest_target_staging as stage_test
    from . import test_repository_executable_native_dependency_requirements as source_dependency_test
else:
    import test_repository_executable_native_dependency_manifest_target_staging as stage_test
    import test_repository_executable_native_dependency_requirements as source_dependency_test


FIXED_ERROR = "repository executable native dependency manifest target dependency requirements are invalid"


@unittest.skipUnless(os.name == "posix", "manifest-target dependency inspection requires POSIX")
class RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsTests(unittest.TestCase):
    def _prepare(self, *, content: bytes | None = None, terminal: bool = False) -> tuple[object, ...]:
        source = stage_test.RepositoryExecutableNativeDependencyManifestTargetStagingTests("runTest")
        self.addCleanup(source.doCleanups)
        if content is None:
            values = source._prepare(source_mode="terminal" if terminal else "mixed")
        else:
            target_case = stage_test.targets_test.RepositoryExecutableNativeDependencyManifestTargetsTests
            original_writer = target_case._write_target

            def write_target(path: Path, unused: bytes) -> None:
                original_writer(path, content)

            with patch.object(target_case, "_write_target", staticmethod(write_target)):
                values = source._prepare(source_mode="mixed")
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, private = values
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "dependency-stage-root"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        lease = RepositoryExecutableNativeDependencyManifestTargetStageLease(root)
        staging = stage_repository_executable_native_dependency_manifest_target_bytes(
            targets,
            expected_manifest=manifest_receipt,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=source_staging,
            executable_lease=executable_lease,
            expected_non_absolute_dependency_manifest=manifest,
            lease=lease,
        )
        self.addCleanup(lease.close)
        target_runtime = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(staging, lease=lease)
        return staging, target_runtime, lease, root, private

    @staticmethod
    def _snapshot(lease: object) -> tuple[object, ...]:
        return (lease.state, lease.receipt, lease.cleanup_receipt, lease._receipt_anchor, lease._receipt_digest_anchor, lease._files_anchor, lease._files)

    def _assert_invalid(self, runtime: object, staging: object, lease: object, *, marker: str = "private-dependency-marker") -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(runtime, expected_target_staging=staging, lease=lease)
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_elf_needed_declarations_are_digest_only_and_do_not_resolve_names(self) -> None:
        content = source_dependency_test._elf64_dependencies((b"private-one.so", b"@rpath/private-weak.dylib"))
        staging, runtime, lease, root, private = self._prepare(content=content)
        before = self._snapshot(lease)
        receipt = inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(runtime, expected_target_staging=staging, lease=lease)
        self.assertIsInstance(receipt, RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsReceipt)
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.native_requirement_count, 2)
        self.assertEqual(receipt.dependency_declared_requirement_count, 2)
        self.assertEqual(receipt.dependency_declaration_count, 4)
        self.assertEqual(receipt.required_dependency_count, 4)
        self.assertEqual(self._snapshot(lease), before)
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertFalse(evidence["dependency_path_lookup_performed"])
        self.assertFalse(evidence["execution_enabled"])
        aggregate = "\n".join((json.dumps(receipt.to_canonical(), sort_keys=True), json.dumps(evidence, sort_keys=True), repr(receipt)))
        for value in (*private, os.fspath(root), "private-one.so", "@rpath/private-weak.dylib"):
            self.assertNotIn(value, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.requirement_count = 0

    def test_terminal_stage_performs_no_descriptor_read_or_root_mutation(self) -> None:
        staging, runtime, lease, root, _private = self._prepare(terminal=True)
        marker = root / "caller-root-stays-untouched"
        marker.write_text("marker", encoding="utf-8")
        with patch.object(dependency_module, "_BUILTIN_READ_AND_VERIFY", side_effect=AssertionError("private-unexpected-read")) as read:
            receipt = inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(runtime, expected_target_staging=staging, lease=lease)
        self.assertEqual(receipt.requirement_count, 0)
        self.assertEqual(receipt.dependency_declaration_count, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "marker")
        read.assert_not_called()

    def test_thin_mach_o_load_declarations_are_recorded_without_lookup(self) -> None:
        content = source_dependency_test._mach64_dependencies(
            ((0xC, b"private-required.dylib"), (0x80000018, b"@rpath/private-weak.dylib"))
        )
        staging, runtime, lease, _root, _private = self._prepare(content=content)
        receipt = inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(runtime, expected_target_staging=staging, lease=lease)
        self.assertEqual([item.disposition for item in receipt.requirements], ["mach_o_dependencies_declared", "mach_o_dependencies_declared"])
        self.assertEqual(receipt.dependency_declaration_count, 4)
        self.assertEqual(receipt.required_dependency_count, 2)
        self.assertEqual(receipt.weak_dependency_count, 2)

    def test_tampered_runtime_stage_and_descriptor_state_fail_closed(self) -> None:
        content = source_dependency_test._elf64_dependencies((b"private-only.so",))
        staging, runtime, lease, _root, _private = self._prepare(content=content)
        for forged_runtime, forged_stage in ((None, staging), (replace(runtime, repository_ref="sha256:" + "0" * 64), staging), (runtime, replace(staging, unique_target_count=0)), (replace(runtime, files=()), staging)):
            self._assert_invalid(forged_runtime, forged_stage, lease)
        original = lease._files
        lease._files = tuple(reversed(original))
        self._assert_invalid(runtime, staging, lease)
        lease._files = original
        real = dependency_module._BUILTIN_READ_AND_VERIFY
        with patch.object(dependency_module, "_BUILTIN_READ_AND_VERIFY", side_effect=lambda *args: real(*args) + b"private-header-drift"):
            self._assert_invalid(runtime, staging, lease, marker="private-header-drift")

    def test_no_path_network_process_or_public_helper_route_is_used(self) -> None:
        content = source_dependency_test._elf64_dependencies((b"private-only.so",))
        staging, runtime, lease, _root, _private = self._prepare(content=content)
        before = self._snapshot(lease)
        poison = AssertionError("private-prohibited-effect")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(os, "open", side_effect=poison) as os_opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
            patch.object(dependency_module, "_requirement_projection", side_effect=poison),
            patch.object(dependency_module, "_receipt_projection", side_effect=poison),
            patch.object(dependency_module, "_build_requirement", side_effect=poison),
            patch.object(dependency_module, "_loader_context", side_effect=poison),
        ):
            receipt = inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(runtime, expected_target_staging=staging, lease=lease)
        self.assertEqual(receipt.dependency_declaration_count, 2)
        self.assertEqual(self._snapshot(lease), before)
        opened.assert_not_called()
        os_opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
