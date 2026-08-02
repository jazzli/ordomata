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

from ordomata import repository_executable_native_dependency_manifest_targets as targets_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_manifest import (
    RepositoryExecutableNativeDependencyManifestEntry,
    inspect_staged_executable_native_dependency_manifest,
)
from ordomata.repository_executable_native_dependency_manifest_targets import (
    RepositoryExecutableNativeDependencyManifestTargetsReceipt,
    inspect_staged_executable_native_dependency_manifest_targets,
)
from ordomata.repository_executable_native_dependency_requirements import (
    inspect_staged_executable_native_dependency_requirements,
)
from ordomata.repository_executable_native_loader_requirements import (
    inspect_staged_executable_native_loader_requirements,
)
from ordomata.repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
)
from ordomata.repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
)

if __package__:
    from . import test_repository_executable_native_dependency_requirements as dependency_test
else:
    import test_repository_executable_native_dependency_requirements as dependency_test


FIXED_ERROR = "repository executable native dependency manifest targets are invalid"


@unittest.skipUnless(
    os.name == "posix", "native dependency manifest targets require POSIX"
)
class RepositoryExecutableNativeDependencyManifestTargetsTests(unittest.TestCase):
    fixture = dependency_test.RepositoryExecutableNativeDependencyRequirementsTests

    @staticmethod
    def _write_target(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o755)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())

    @classmethod
    def _lease_snapshot(cls, lease: RepositoryExecutableStageLease) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    @staticmethod
    def _manifest(
        requirements: object,
        names: tuple[bytes, ...],
        paths: tuple[Path, ...],
    ) -> tuple[RepositoryExecutableNativeDependencyManifestEntry, ...]:
        declarations = tuple(
            declaration
            for requirement in requirements.requirements
            for declaration in requirement.declarations
            if declaration.path_style != "absolute"
        )
        if len(declarations) != len(names) or len(names) != len(paths):
            raise AssertionError("fixture manifest mismatch")
        return tuple(
            RepositoryExecutableNativeDependencyManifestEntry(
                kind="repository_executable_native_dependency_manifest_entry",
                runtime_file_ref=declaration.runtime_file_ref,
                dependency_declaration_ref=declaration.declaration_ref,
                dependency_name=name,
                target_path=path,
            )
            for declaration, name, path in zip(declarations, names, paths, strict=True)
        )

    def _prepare(
        self,
        *,
        source_mode: str = "mixed",
        shared_target: bool = False,
    ) -> tuple[
        RepositoryExecutableNativeDependencyManifestTargetsReceipt,
        object,
        object,
        RepositoryExecutableRuntimeManifestReceipt,
        RepositoryExecutableStagingReceipt,
        RepositoryExecutableStageLease,
        tuple[RepositoryExecutableNativeDependencyManifestEntry, ...],
        tuple[str, ...],
    ]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, outside, search_one, search_two, staging_root = self.fixture._workspace(
            temporary.name
        )
        target_one = outside / "private-manifest-measure-one"
        target_two = outside / "private-manifest-measure-two"
        target_contents = (b"private-manifest-measure-one-content", b"private-manifest-measure-two-content")
        self._write_target(target_one, target_contents[0])
        self._write_target(target_two, target_contents[1])
        if source_mode == "mixed":
            bare = dependency_test._elf64_dependencies((os.fsencode(target_one), b"private-bare.so"))
            relative = dependency_test._mach64_dependencies(
                ((0xC, os.fsencode(target_two)), (0x80000018, b"@rpath/private-weak.dylib"))
            )
            names = (b"private-bare.so", b"@rpath/private-weak.dylib")
            paths = (target_one, target_one if shared_target else target_two)
        elif source_mode == "terminal":
            bare = dependency_test._elf64_dependencies(())
            relative = b"#!/usr/bin/python3 -I\nprivate\n"
            names = ()
            paths = ()
        else:
            raise AssertionError(source_mode)
        self.fixture._set_contents(root, search_one, bare=bare, relative=relative)
        registration = self.fixture._registration(root)
        lease, staging, runtime = self.fixture.fixture._stage_runtime(
            registration, (search_one, search_two), staging_root
        )
        self.addCleanup(lease.close)
        loader = inspect_staged_executable_native_loader_requirements(
            runtime, expected_staging=staging, lease=lease
        )
        requirements = inspect_staged_executable_native_dependency_requirements(
            loader, expected_runtime=runtime, expected_staging=staging, lease=lease
        )
        manifest = self._manifest(requirements, names, paths)
        manifest_receipt = inspect_staged_executable_native_dependency_manifest(
            requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=manifest,
        )
        receipt = inspect_staged_executable_native_dependency_manifest_targets(
            manifest_receipt,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=manifest,
        )
        private_values = (
            str(root),
            os.fspath(target_one),
            os.fspath(target_two),
            *[item.decode() for item in target_contents],
            "private-bare.so",
            "@rpath/private-weak.dylib",
        )
        return receipt, manifest_receipt, requirements, runtime, staging, lease, manifest, private_values

    def _assert_invalid(
        self,
        manifest_receipt: object,
        requirements: object,
        runtime: object,
        staging: object,
        lease: object,
        manifest: object,
        *,
        marker: str = "private-manifest-targets-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_dependency_manifest_targets(
                manifest_receipt,
                expected_requirements=requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_non_absolute_dependency_manifest=manifest,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_manifest_targets_are_measured_and_digest_only(self) -> None:
        receipt, manifest_receipt, requirements, runtime, staging, lease, manifest, private_values = self._prepare()
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.manifest_binding_count, 2)
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertGreater(receipt.total_measured_bytes, 0)
        before = self._lease_snapshot(lease)
        repeated = inspect_staged_executable_native_dependency_manifest_targets(
            manifest_receipt,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=manifest,
        )
        self.assertEqual(repeated, receipt)
        self.assertEqual(self._lease_snapshot(lease), before)
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(evidence["controller_explicit_manifest_reproduced"])
        self.assertTrue(evidence["target_nofollow_measurement_complete"])
        self.assertFalse(evidence["ambient_loader_environment_consulted"])
        self.assertFalse(evidence["tokenized_loader_path_expansion_performed"])
        self.assertFalse(evidence["dependency_closure_verified"])
        aggregate = "\n".join((json.dumps(receipt.to_canonical(), sort_keys=True), json.dumps(evidence, sort_keys=True), repr(receipt)))
        for private in private_values:
            self.assertNotIn(private, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.unique_target_count = 0

    def test_shared_target_is_measured_once(self) -> None:
        receipt, *_unused = self._prepare(shared_target=True)
        self.assertEqual(receipt.manifest_binding_count, 2)
        self.assertEqual(receipt.unique_target_count, 1)
        self.assertEqual(len({item.target_measurement_ref for item in receipt.bindings}), 1)

    def test_terminal_manifest_measures_no_target(self) -> None:
        real_measure = targets_module._BUILTIN_MEASURE_TARGET_SET
        observed: list[tuple[Path, ...]] = []

        def empty_only(paths):
            observed.append(paths)
            if paths:
                raise AssertionError("private-unexpected-target-read")
            return real_measure(paths)

        with patch.object(targets_module, "_BUILTIN_MEASURE_TARGET_SET", side_effect=empty_only):
            receipt, *_unused = self._prepare(source_mode="terminal")
        self.assertEqual(observed, [(), ()])
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.manifest_binding_count, 0)
        self.assertEqual(receipt.unique_target_count, 0)

    def test_wrong_manifest_and_symlink_targets_fail_before_or_during_measurement(self) -> None:
        _receipt, manifest_receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        first, second = manifest
        poison = AssertionError("private-measurement-must-not-run")
        for bad in (
            manifest[:-1],
            tuple(reversed(manifest)),
            (replace(first, target_path=Path("relative-private-target")), second),
        ):
            with self.subTest(manifest=repr(bad)):
                with patch.object(targets_module, "_BUILTIN_MEASURE_TARGET_SET", side_effect=poison) as measured:
                    self._assert_invalid(manifest_receipt, requirements, runtime, staging, lease, bad, marker=str(poison))
                measured.assert_not_called()
        target = first.target_path
        real = target.with_name("private-manifest-real")
        target.rename(real)
        target.symlink_to(real)
        self._assert_invalid(manifest_receipt, requirements, runtime, staging, lease, manifest)

    def test_drift_namespace_forgery_and_closed_lease_fail_closed(self) -> None:
        _receipt, manifest_receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        real_snapshot = targets_module._BUILTIN_VALIDATE_INPUTS_AND_REPRODUCE_MANIFEST
        calls = 0

        def drift(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_snapshot(*args, **kwargs)
            if calls == 2:
                return (*result[:-1], {"private": "forged"})
            return result

        with patch.object(targets_module, "_BUILTIN_VALIDATE_INPUTS_AND_REPRODUCE_MANIFEST", side_effect=drift):
            self._assert_invalid(manifest_receipt, requirements, runtime, staging, lease, manifest)
        with patch.object(targets_module, "_BUILTIN_TARGET_NAMESPACE_MATCHES", return_value=False):
            self._assert_invalid(manifest_receipt, requirements, runtime, staging, lease, manifest)
        self._assert_invalid(replace(manifest_receipt, requirement_count=0), requirements, runtime, staging, lease, manifest)
        lease.close()
        self._assert_invalid(manifest_receipt, requirements, runtime, staging, lease, manifest)

    def test_public_helpers_do_not_replace_frozen_proof_graph(self) -> None:
        _receipt, manifest_receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        poison = AssertionError("private-public-helper-marker")
        names = (
            "_measurement_ref_projection", "_measurement_projection", "_binding_ref_projection",
            "_binding_projection", "_command_binding_ref_projection", "_command_binding_projection",
            "_receipt_projection", "_evidence_projection", "_validate_inputs_and_reproduce_manifest",
            "_measurement_identity_ref", "_measurement_metadata_digest", "_public_measurement",
            "_public_binding", "_public_command_binding",
        )
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(patch.object(targets_module, name, side_effect=poison))
            receipt = inspect_staged_executable_native_dependency_manifest_targets(
                manifest_receipt,
                expected_requirements=requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_non_absolute_dependency_manifest=manifest,
            )
        self.assertEqual(receipt.unique_target_count, 2)

    def test_no_write_process_network_or_lease_effects(self) -> None:
        _receipt, manifest_receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_dependency_manifest_targets(
                manifest_receipt,
                expected_requirements=requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_non_absolute_dependency_manifest=manifest,
            )
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertEqual(self._lease_snapshot(lease), before)
        opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_projection_exports_signature_and_errors(self) -> None:
        receipt, manifest_receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        first = receipt.bindings[0]
        for forged in (
            replace(receipt, unique_target_count=0),
            replace(receipt, bindings=tuple(reversed(receipt.bindings))),
            replace(receipt, bindings=(replace(first, ordinal=99), *receipt.bindings[1:])),
        ):
            with self.assertRaises(ValueError):
                forged.to_canonical()
        self.assertEqual(
            set(targets_module.__all__),
            {
                "MEASUREMENT_SCOPE", "MEASUREMENT_SOURCE",
                "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_COMMAND_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGET_MEASUREMENT_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_EVIDENCE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_TARGETS_SCHEMA_VERSION",
                "RepositoryExecutableNativeDependencyManifestTargetBinding",
                "RepositoryExecutableNativeDependencyManifestTargetCommandBinding",
                "RepositoryExecutableNativeDependencyManifestTargetMeasurement",
                "RepositoryExecutableNativeDependencyManifestTargetsReceipt",
                "inspect_staged_executable_native_dependency_manifest_targets",
            },
        )
        signature = inspect.signature(inspect_staged_executable_native_dependency_manifest_targets)
        self.assertEqual(tuple(signature.parameters), ("expected_manifest", "expected_requirements", "expected_runtime", "expected_staging", "lease", "expected_non_absolute_dependency_manifest"))
        for name in tuple(signature.parameters)[1:]:
            self.assertEqual(signature.parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
        with patch.object(targets_module, "_BUILTIN_VALIDATE_INPUTS_AND_REPRODUCE_MANIFEST", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                inspect_staged_executable_native_dependency_manifest_targets(
                    manifest_receipt,
                    expected_requirements=requirements,
                    expected_runtime=runtime,
                    expected_staging=staging,
                    lease=lease,
                    expected_non_absolute_dependency_manifest=manifest,
                )


if __name__ == "__main__":
    unittest.main()
