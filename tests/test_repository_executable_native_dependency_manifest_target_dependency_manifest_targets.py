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

from ordomata import repository_executable_native_dependency_manifest_target_dependency_manifest_targets as targets_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_manifest_target_dependency_manifest import (
    REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND,
    RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry,
    inspect_staged_executable_native_dependency_manifest_target_dependency_manifest,
)
from ordomata.repository_executable_native_dependency_manifest_target_dependency_manifest_targets import (
    RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetsReceipt,
    inspect_staged_executable_native_dependency_manifest_target_dependency_manifest_targets,
)
from ordomata.repository_executable_native_dependency_manifest_target_dependency_requirements import (
    inspect_staged_executable_native_dependency_manifest_target_dependency_requirements,
)

if __package__:
    from . import test_repository_executable_native_dependency_manifest_target_dependency_requirements as dependency_test
    from . import test_repository_executable_native_dependency_requirements as source_dependency_test
else:
    import test_repository_executable_native_dependency_manifest_target_dependency_requirements as dependency_test
    import test_repository_executable_native_dependency_requirements as source_dependency_test


FIXED_ERROR = "repository executable native dependency manifest target dependency manifest targets are invalid"
_NAMES = (b"private-one.so", b"@rpath/private-two.dylib")


@unittest.skipUnless(os.name == "posix", "mapped manifest target measurement requires POSIX")
class RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetsTests(unittest.TestCase):
    def _prepare(self, *, terminal: bool = False) -> tuple[object, ...]:
        source = dependency_test.RepositoryExecutableNativeDependencyManifestTargetDependencyRequirementsTests("runTest")
        self.addCleanup(source.doCleanups)
        content = None if terminal else source_dependency_test._elf64_dependencies(_NAMES)
        staging, runtime, lease, stage_root, private = source._prepare(content=content, terminal=terminal)
        dependencies = inspect_staged_executable_native_dependency_manifest_target_dependency_requirements(
            runtime, expected_target_staging=staging, lease=lease
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        mapping_root = Path(temporary.name).resolve(strict=True) / "private-next-hop-targets"
        mapping_root.mkdir(mode=0o700)
        target_one = mapping_root / "private-next-hop-one"
        target_two = mapping_root / "private-next-hop-two"
        target_one.write_bytes(b"private-next-hop-one-content")
        target_two.write_bytes(b"private-next-hop-two-content")
        target_one.chmod(0o755)
        target_two.chmod(0o755)
        entries = self._entries(dependencies, (target_one, target_two))
        manifest = inspect_staged_executable_native_dependency_manifest_target_dependency_manifest(
            dependencies,
            expected_target_runtime=runtime,
            expected_target_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=entries,
        )
        private_values = (*private, os.fspath(stage_root), os.fspath(mapping_root), "private-next-hop-one-content", "private-next-hop-two-content", *(item.decode("ascii") for item in _NAMES))
        return manifest, dependencies, runtime, staging, lease, entries, private_values

    @staticmethod
    def _entries(dependencies: object, paths: tuple[Path, Path]) -> tuple[RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry, ...]:
        declarations = tuple(
            (requirement, declaration)
            for requirement in dependencies.requirements
            for declaration in requirement.declarations
            if declaration.path_style != "absolute"
        )
        names = _NAMES * (len(declarations) // len(_NAMES))
        if len(names) != len(declarations):
            raise AssertionError("unexpected fixture declaration count")
        return tuple(
            RepositoryExecutableNativeDependencyManifestTargetDependencyManifestEntry(
                kind=REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_DEPENDENCY_MANIFEST_ENTRY_KIND,
                target_runtime_file_ref=requirement.target_runtime_file_ref,
                dependency_declaration_ref=declaration.declaration_ref,
                dependency_name=name,
                target_path=paths[ordinal % len(paths)],
            )
            for ordinal, ((requirement, declaration), name) in enumerate(zip(declarations, names, strict=True))
        )

    @staticmethod
    def _snapshot(lease: object) -> tuple[object, ...]:
        return (lease.state, lease.receipt, lease.cleanup_receipt, lease._receipt_anchor, lease._receipt_digest_anchor, lease._files_anchor, lease._files)

    def _inspect(self, manifest: object, dependencies: object, runtime: object, staging: object, lease: object, entries: tuple[object, ...]) -> object:
        return inspect_staged_executable_native_dependency_manifest_target_dependency_manifest_targets(
            manifest,
            expected_dependencies=dependencies,
            expected_target_runtime=runtime,
            expected_target_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=entries,
        )

    def _assert_invalid(self, manifest: object, dependencies: object, runtime: object, staging: object, lease: object, entries: tuple[object, ...], *, marker: str = "private-target-marker") -> None:
        with self.assertRaises(ValidationError) as caught:
            self._inspect(manifest, dependencies, runtime, staging, lease, entries)
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_mapped_targets_are_nofollow_measured_and_digest_only(self) -> None:
        manifest, dependencies, runtime, staging, lease, entries, private_values = self._prepare()
        before = self._snapshot(lease)
        receipt = self._inspect(manifest, dependencies, runtime, staging, lease, entries)
        self.assertIsInstance(receipt, RepositoryExecutableNativeDependencyManifestTargetDependencyManifestTargetsReceipt)
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.dependency_declaration_count, 4)
        self.assertEqual(receipt.manifest_bound_dependency_count, 4)
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertGreater(receipt.total_measured_bytes, 0)
        self.assertEqual(self._snapshot(lease), before)
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(evidence["target_nofollow_measurement_complete"])
        self.assertFalse(evidence["ambient_loader_environment_consulted"])
        self.assertFalse(evidence["tokenized_loader_path_expansion_performed"])
        self.assertFalse(evidence["dependency_closure_verified"])
        aggregate = "\n".join((json.dumps(receipt.to_canonical(), sort_keys=True), json.dumps(evidence, sort_keys=True), repr(receipt)))
        for value in private_values:
            self.assertNotIn(value, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.unique_target_count = 0

    def test_terminal_manifest_measures_empty_set_only(self) -> None:
        manifest, dependencies, runtime, staging, lease, entries, _private = self._prepare(terminal=True)
        real_measure = targets_module._BUILTIN_MEASURE_TARGET_SET
        observed: list[tuple[Path, ...]] = []

        def empty_only(paths: tuple[Path, ...]) -> object:
            observed.append(paths)
            if paths:
                raise AssertionError("private-unexpected-target-read")
            return real_measure(paths)

        with patch.object(targets_module, "_BUILTIN_MEASURE_TARGET_SET", side_effect=empty_only):
            receipt = self._inspect(manifest, dependencies, runtime, staging, lease, entries)
        self.assertEqual(observed, [(), ()])
        self.assertEqual(receipt.requirement_count, 0)
        self.assertEqual(receipt.manifest_bound_dependency_count, 0)
        self.assertEqual(receipt.unique_target_count, 0)

    def test_mapping_drift_symlink_and_lease_drift_fail_closed(self) -> None:
        manifest, dependencies, runtime, staging, lease, entries, _private = self._prepare()
        self._assert_invalid(replace(manifest, requirement_count=0), dependencies, runtime, staging, lease, entries)
        self._assert_invalid(manifest, dependencies, runtime, staging, lease, tuple(reversed(entries)))
        target = entries[0].target_path
        real = target.with_name("private-next-hop-real")
        target.rename(real)
        target.symlink_to(real)
        self._assert_invalid(manifest, dependencies, runtime, staging, lease, entries)
        target.unlink()
        real.rename(target)
        original = lease._files
        lease._files = tuple(reversed(original))
        self._assert_invalid(manifest, dependencies, runtime, staging, lease, entries)
        lease._files = original

    def test_public_helpers_cannot_replace_the_frozen_proof_graph(self) -> None:
        manifest, dependencies, runtime, staging, lease, entries, _private = self._prepare()
        poison = AssertionError("private-public-helper-marker")
        with (
            patch.object(targets_module, "_measurement_ref_projection", side_effect=poison),
            patch.object(targets_module, "_measurement_projection", side_effect=poison),
            patch.object(targets_module, "_binding_ref_projection", side_effect=poison),
            patch.object(targets_module, "_binding_projection", side_effect=poison),
            patch.object(targets_module, "_receipt_projection", side_effect=poison),
            patch.object(targets_module, "_evidence_projection", side_effect=poison),
            patch.object(targets_module, "_reproduce", side_effect=poison),
            patch.object(targets_module, "_identity_ref", side_effect=poison),
            patch.object(targets_module, "_public_measurement", side_effect=poison),
            patch.object(targets_module, "_public_binding", side_effect=poison),
        ):
            receipt = self._inspect(manifest, dependencies, runtime, staging, lease, entries)
        self.assertEqual(receipt.unique_target_count, 2)

    def test_no_write_process_network_or_lease_effects(self) -> None:
        manifest, dependencies, runtime, staging, lease, entries, _private = self._prepare()
        before = self._snapshot(lease)
        poison = AssertionError("private-prohibited-effect")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = self._inspect(manifest, dependencies, runtime, staging, lease, entries)
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertEqual(self._snapshot(lease), before)
        opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
