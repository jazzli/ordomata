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

from ordomata import repository_executable_native_dependency_manifest_target_dependency_manifest as manifest_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_manifest_target_dependency_manifest import (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND,
    RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry,
    RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt,
    inspect_staged_executable_native_dependency_manifest_target_dependency_manifest,
)
from ordomata.repository_executable_native_dependency_manifest_target_dependency_requirements import (
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


FIXED_ERROR = "repository executable native dependency manifest target dependency manifest is invalid"
_NAMES = (b"private-one.so", b"@rpath/private-two.dylib")


@unittest.skipUnless(os.name == "posix", "manifest-target dependency mapping requires POSIX")
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTests(unittest.TestCase):
    def _prepare(self, *, terminal: bool = False) -> tuple[object, ...]:
        source = stage_test.RepositoryExecutableNativeDependencyManifestTargetStagingTests("runTest")
        self.addCleanup(source.doCleanups)
        if terminal:
            values = source._prepare(source_mode="terminal")
        else:
            target_case = stage_test.targets_test.RepositoryExecutableNativeDependencyManifestTargetsTests
            original_writer = target_case._write_target
            content = source_dependency_test._elf64_dependencies(_NAMES)

            def write_target(path: Path, unused: bytes) -> None:
                original_writer(path, content)

            with patch.object(target_case, "_write_target", staticmethod(write_target)):
                values = source._prepare(source_mode="mixed")
        targets, target_manifest, requirements, runtime, source_staging, executable_lease, source_manifest, private = values
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "dependency-mapping-stage-root"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        lease = RepositoryExecutableNativeDependencyManifestTargetStageLease(root)
        staging = stage_repository_executable_native_dependency_manifest_target_bytes(
            targets,
            expected_manifest=target_manifest,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=source_staging,
            executable_lease=executable_lease,
            expected_non_absolute_dependency_manifest=source_manifest,
            lease=lease,
        )
        self.addCleanup(lease.close)
        target_runtime = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(staging, lease=lease)
        dependencies = inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(
            target_runtime, expected_target_staging=staging, lease=lease
        )
        return dependencies, target_runtime, staging, lease, root, private, Path(temporary.name) / "private-next-hop-mappings"

    @staticmethod
    def _snapshot(lease: object) -> tuple[object, ...]:
        return (
            lease.state,
            lease.receipt,
            lease.cleanup_receipt,
            lease._receipt_anchor,
            lease._receipt_digest_anchor,
            lease._files_anchor,
            lease._files,
        )

    @staticmethod
    def _entries(dependencies: object, mapping_root: Path) -> tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry, ...]:
        declarations = tuple(
            (requirement, declaration)
            for requirement in dependencies.requirements
            for declaration in requirement.declarations
            if declaration.path_style != "absolute"
        )
        names = _NAMES * (len(declarations) // len(_NAMES))
        if len(names) != len(declarations):
            raise AssertionError("test fixture has an unexpected dependency count")
        return tuple(
            RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry(
                kind=REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND,
                target_runtime_file_ref=requirement.target_runtime_file_ref,
                dependency_declaration_ref=declaration.declaration_ref,
                dependency_name=name,
                target_path=mapping_root / f"private-next-hop-{ordinal}",
            )
            for ordinal, ((requirement, declaration), name) in enumerate(zip(declarations, names, strict=True))
        )

    def _inspect(self, dependencies: object, runtime: object, staging: object, lease: object, entries: tuple[object, ...]) -> object:
        return inspect_staged_executable_native_dependency_manifest_target_dependency_manifest(
            dependencies,
            expected_target_runtime=runtime,
            expected_target_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=entries,
        )

    def _assert_invalid(self, dependencies: object, runtime: object, staging: object, lease: object, entries: tuple[object, ...], *, marker: str = "private-mapping-marker") -> None:
        with self.assertRaises(ValidationError) as caught:
            self._inspect(dependencies, runtime, staging, lease, entries)
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_exact_explicit_mapping_is_digest_only_and_does_not_open_targets(self) -> None:
        dependencies, runtime, staging, lease, root, private, mapping_root = self._prepare()
        entries = self._entries(dependencies, mapping_root)
        before = self._snapshot(lease)
        receipt = self._inspect(dependencies, runtime, staging, lease, entries)
        self.assertIsInstance(receipt, RepositoryExecutableNativeDependencyManifestTargetDependencyManifestReceipt)
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.dependency_declaration_count, 4)
        self.assertEqual(receipt.non_absolute_dependency_declaration_count, 4)
        self.assertEqual(receipt.manifest_bound_dependency_count, 4)
        self.assertEqual(receipt.unique_manifest_target_count, 4)
        self.assertEqual(self._snapshot(lease), before)
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(evidence["controller_explicit_mapping_reproduced"])
        self.assertFalse(evidence["dependency_path_lookup_performed"])
        self.assertFalse(evidence["path_open_performed"])
        self.assertFalse(evidence["tokenized_loader_path_expansion_performed"])
        aggregate = "\n".join((json.dumps(receipt.to_canonical(), sort_keys=True), json.dumps(evidence, sort_keys=True), repr(receipt)))
        for value in (*private, os.fspath(root), os.fspath(mapping_root), *(name.decode("ascii") for name in _NAMES)):
            self.assertNotIn(value, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.manifest_bound_dependency_count = 0

    def test_mapping_must_exactly_cover_ordered_fresh_nonabsolute_declarations(self) -> None:
        dependencies, runtime, staging, lease, _root, _private, mapping_root = self._prepare()
        entries = self._entries(dependencies, mapping_root)
        self._assert_invalid(dependencies, runtime, staging, lease, entries[:-1])
        self._assert_invalid(dependencies, runtime, staging, lease, tuple(reversed(entries)))
        self._assert_invalid(dependencies, runtime, staging, lease, (replace(entries[0], kind="forged"), *entries[1:]))
        self._assert_invalid(dependencies, runtime, staging, lease, (replace(entries[0], dependency_name=b"private-mapping-marker"), *entries[1:]))
        self._assert_invalid(dependencies, runtime, staging, lease, (replace(entries[0], target_path=Path("relative-target")), *entries[1:]))

    def test_terminal_stage_requires_empty_mapping_and_does_not_read_or_mutate_root(self) -> None:
        dependencies, runtime, staging, lease, root, _private, mapping_root = self._prepare(terminal=True)
        marker = root / "caller-root-stays-untouched"
        marker.write_text("marker", encoding="utf-8")
        with patch.object(manifest_module, "_BUILTIN_INSPECT_DEPENDENCIES", wraps=manifest_module._BUILTIN_INSPECT_DEPENDENCIES) as inspect:
            receipt = self._inspect(dependencies, runtime, staging, lease, ())
        self.assertEqual(receipt.requirement_count, 0)
        self.assertEqual(receipt.manifest_bound_dependency_count, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "marker")
        self.assertEqual(inspect.call_count, 3)
        unexpected = RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry(
            kind=REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND,
            target_runtime_file_ref="sha256:" + "0" * 64,
            dependency_declaration_ref="sha256:" + "0" * 64,
            dependency_name=b"private-mapping-marker",
            target_path=mapping_root / "unexpected",
        )
        self._assert_invalid(dependencies, runtime, staging, lease, (unexpected,))

    def test_upstream_receipt_or_lease_drift_fails_closed(self) -> None:
        dependencies, runtime, staging, lease, _root, _private, mapping_root = self._prepare()
        entries = self._entries(dependencies, mapping_root)
        for forged_dependencies, forged_runtime, forged_staging in (
            (replace(dependencies, repository_ref="sha256:" + "0" * 64), runtime, staging),
            (dependencies, replace(runtime, repository_ref="sha256:" + "0" * 64), staging),
            (dependencies, runtime, replace(staging, unique_target_count=0)),
        ):
            self._assert_invalid(forged_dependencies, forged_runtime, forged_staging, lease, entries)
        original = lease._files
        lease._files = tuple(reversed(original))
        self._assert_invalid(dependencies, runtime, staging, lease, entries)
        lease._files = original

    def test_no_path_network_process_or_public_helper_route_is_used(self) -> None:
        dependencies, runtime, staging, lease, _root, _private, mapping_root = self._prepare()
        entries = self._entries(dependencies, mapping_root)
        before = self._snapshot(lease)
        poison = AssertionError("private-prohibited-effect")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(os, "open", side_effect=poison) as os_opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
            patch.object(manifest_module, "_canonical_target_path", side_effect=poison),
            patch.object(manifest_module, "_target_ref", side_effect=poison),
            patch.object(manifest_module, "_binding_ref_projection", side_effect=poison),
            patch.object(manifest_module, "_requirement_ref_projection", side_effect=poison),
            patch.object(manifest_module, "_binding_projection", side_effect=poison),
            patch.object(manifest_module, "_requirement_projection", side_effect=poison),
            patch.object(manifest_module, "_receipt_projection", side_effect=poison),
            patch.object(manifest_module, "_reproduce", side_effect=poison),
        ):
            receipt = self._inspect(dependencies, runtime, staging, lease, entries)
        self.assertEqual(receipt.manifest_bound_dependency_count, 4)
        self.assertEqual(self._snapshot(lease), before)
        opened.assert_not_called()
        os_opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
