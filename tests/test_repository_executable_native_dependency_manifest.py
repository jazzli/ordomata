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

from ordomata import repository_executable_native_dependency_manifest as manifest_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_manifest import (
    RepositoryExecutableNativeDependencyManifestEntry,
    RepositoryExecutableNativeDependencyManifestReceipt,
    inspect_staged_executable_native_dependency_manifest,
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


FIXED_ERROR = "repository executable native dependency manifest is invalid"


@unittest.skipUnless(
    os.name == "posix", "native dependency manifest requires POSIX staging"
)
class RepositoryExecutableNativeDependencyManifestTests(unittest.TestCase):
    fixture = dependency_test.RepositoryExecutableNativeDependencyRequirementsTests

    @classmethod
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    @classmethod
    def _manifest(
        cls,
        requirements: object,
        *,
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
            raise AssertionError("fixture manifest does not match declarations")
        return tuple(
            RepositoryExecutableNativeDependencyManifestEntry(
                kind=(
                    "repository_executable_native_dependency_manifest_entry"
                ),
                runtime_file_ref=declaration.runtime_file_ref,
                dependency_declaration_ref=declaration.declaration_ref,
                dependency_name=name,
                target_path=path,
            )
            for declaration, name, path in zip(
                declarations, names, paths, strict=True
            )
        )

    def _prepare(
        self,
        *,
        source_mode: str = "mixed",
        shared_target: bool = False,
    ) -> tuple[
        RepositoryExecutableNativeDependencyManifestReceipt,
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
        target_one = outside / "private-manifest-target-one"
        target_two = outside / "private-manifest-target-two"
        target_one.write_bytes(b"private-manifest-target-one-content")
        target_two.write_bytes(b"private-manifest-target-two-content")
        target_one.chmod(0o755)
        target_two.chmod(0o755)
        if source_mode == "mixed":
            bare = dependency_test._elf64_dependencies(
                (os.fsencode(target_one), b"private-bare.so")
            )
            relative = dependency_test._mach64_dependencies(
                (
                    (0xC, os.fsencode(target_two)),
                    (0x80000018, b"@rpath/private-weak.dylib"),
                )
            )
            names = (b"private-bare.so", b"@rpath/private-weak.dylib")
            paths = (target_one, target_one if shared_target else target_two)
        elif source_mode == "non_absolute":
            bare = dependency_test._elf64_dependencies((b"private-bare.so",))
            relative = dependency_test._mach64_dependencies(
                ((0xC, b"@loader_path/private.dylib"),)
            )
            names = (b"private-bare.so", b"@loader_path/private.dylib")
            paths = (target_one, target_two)
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
        manifest = self._manifest(requirements, names=names, paths=paths)
        receipt = inspect_staged_executable_native_dependency_manifest(
            requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=manifest,
        )
        private_values = (
            str(root),
            os.fspath(target_one),
            os.fspath(target_two),
            "private-bare.so",
            "@rpath/private-weak.dylib",
            "@loader_path/private.dylib",
            "private-manifest-target-one-content",
            "private-manifest-target-two-content",
        )
        return receipt, requirements, runtime, staging, lease, manifest, private_values

    def _assert_invalid(
        self,
        requirements: object,
        runtime: object,
        staging: object,
        lease: object,
        manifest: object,
        *,
        marker: str = "private-manifest-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_dependency_manifest(
                requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_non_absolute_dependency_manifest=manifest,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_mixed_declarations_are_explicitly_manifest_bound_and_private(self) -> None:
        receipt, requirements, runtime, staging, lease, manifest, private_values = self._prepare()
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.dependency_declaration_count, 4)
        self.assertEqual(receipt.non_absolute_dependency_declaration_count, 2)
        self.assertEqual(receipt.manifest_bound_dependency_count, 2)
        self.assertEqual(receipt.unique_manifest_target_count, 2)
        self.assertEqual(
            tuple(
                binding.path_style
                for requirement in receipt.requirements
                for binding in requirement.bindings
            ),
            ("bare", "at_rpath"),
        )
        before = self._lease_snapshot(lease)
        repeated = inspect_staged_executable_native_dependency_manifest(
            requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_non_absolute_dependency_manifest=manifest,
        )
        self.assertEqual(repeated, receipt)
        self.assertEqual(self._lease_snapshot(lease), before)
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(evidence["controller_explicit_manifest_complete"])
        self.assertFalse(evidence["ambient_loader_environment_consulted"])
        self.assertFalse(evidence["ambient_loader_search_semantics_applied"])
        self.assertFalse(evidence["tokenized_loader_path_expansion_performed"])
        self.assertFalse(evidence["path_lookup_performed"])
        aggregate = "\n".join(
            (
                json.dumps(receipt.to_canonical(), sort_keys=True),
                json.dumps(evidence, sort_keys=True),
                repr(receipt),
            )
        )
        for private in private_values:
            self.assertNotIn(private, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.unique_manifest_target_count = 0

    def test_shared_manifest_target_is_bound_without_a_target_read(self) -> None:
        receipt, *_unused = self._prepare(shared_target=True)
        self.assertEqual(receipt.manifest_bound_dependency_count, 2)
        self.assertEqual(receipt.unique_manifest_target_count, 1)

    def test_terminal_and_absolute_only_inputs_require_an_empty_manifest(self) -> None:
        receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare(
            source_mode="terminal"
        )
        self.assertEqual(manifest, ())
        self.assertEqual(receipt.manifest_bound_dependency_count, 0)
        self.assertEqual(receipt.unique_manifest_target_count, 0)
        self._assert_invalid(
            requirements,
            runtime,
            staging,
            lease,
            (object(),),
        )

    def test_exact_order_name_declaration_and_canonical_path_are_required(self) -> None:
        _receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        first, second = manifest
        bad_manifests = (
            manifest[:-1],
            tuple(reversed(manifest)),
            manifest + (first,),
            list(manifest),
            (
                replace(first, dependency_name=b"private-wrong.so"),
                second,
            ),
            (
                replace(first, dependency_declaration_ref=second.dependency_declaration_ref),
                second,
            ),
            (
                replace(first, target_path=Path("relative-private-target")),
                second,
            ),
        )
        poison = AssertionError("private-manifest-must-not-bind")
        for bad in bad_manifests:
            with self.subTest(manifest=repr(bad)):
                with patch.object(
                    manifest_module,
                    "_BUILTIN_PUBLIC_MANIFEST_BINDING",
                    side_effect=poison,
                ) as bound:
                    self._assert_invalid(
                        requirements, runtime, staging, lease, bad, marker=str(poison)
                    )
                bound.assert_not_called()

    def test_fresh_chain_drift_and_closed_lease_fail_closed(self) -> None:
        _receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        real_snapshot = manifest_module._BUILTIN_VALIDATED_CHAIN_SNAPSHOT
        calls = 0

        def drift(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_snapshot(*args, **kwargs)
            if calls == 2:
                return (*result[:-1], "sha256:" + "0" * 64)
            return result

        with patch.object(
            manifest_module, "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT", side_effect=drift
        ):
            self._assert_invalid(requirements, runtime, staging, lease, manifest)
        lease.close()
        self._assert_invalid(requirements, runtime, staging, lease, manifest)

    def test_public_helpers_do_not_replace_the_frozen_proof_graph(self) -> None:
        _receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        poison = AssertionError("private-public-helper-marker")
        names = (
            "_binding_ref_projection",
            "_binding_projection",
            "_dependency_disposition_matches_classification",
            "_requirement_ref_projection",
            "_requirement_projection",
            "_command_binding_projection",
            "_manifest_context_digest",
            "_receipt_projection",
            "_evidence_projection",
            "_canonical_target_path",
            "_manifest_target_ref",
            "_validate_manifest_entry",
            "_validate_expected_manifest",
            "_validated_chain_snapshot",
            "_public_manifest_binding",
            "_public_requirement",
        )
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(patch.object(manifest_module, name, side_effect=poison))
            receipt = inspect_staged_executable_native_dependency_manifest(
                requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_non_absolute_dependency_manifest=manifest,
            )
        self.assertEqual(receipt.manifest_bound_dependency_count, 2)

    def test_no_write_process_network_or_target_read_effects(self) -> None:
        _receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_dependency_manifest(
                requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_non_absolute_dependency_manifest=manifest,
            )
        self.assertEqual(receipt.manifest_bound_dependency_count, 2)
        self.assertEqual(self._lease_snapshot(lease), before)
        opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_projection_rejects_forged_lineage_counts_and_bindings(self) -> None:
        receipt, *_unused = self._prepare()
        first_requirement = receipt.requirements[0]
        first_binding = first_requirement.bindings[0]
        for name, forged in (
            ("target_count", replace(receipt, unique_manifest_target_count=0)),
            ("bound_count", replace(receipt, manifest_bound_dependency_count=0)),
            ("requirement_order", replace(receipt, requirements=tuple(reversed(receipt.requirements)))),
            (
                "binding_ordinal",
                replace(
                    receipt,
                    requirements=(
                        replace(
                            first_requirement,
                            bindings=(replace(first_binding, ordinal=2),),
                        ),
                        receipt.requirements[1],
                    ),
                ),
            ),
        ):
            with self.subTest(forged=name):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

    def test_exports_signature_interrupts_and_errors_are_fixed(self) -> None:
        expected_exports = {
            "MANIFEST_SCOPE",
            "MANIFEST_SOURCE",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_BINDING_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_COMMAND_BINDING_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_ENTRY_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_EVIDENCE_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_REQUIREMENT_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_MANIFEST_SCHEMA_VERSION",
            "RepositoryExecutableNativeDependencyManifestBinding",
            "RepositoryExecutableNativeDependencyManifestCommandBinding",
            "RepositoryExecutableNativeDependencyManifestEntry",
            "RepositoryExecutableNativeDependencyManifestReceipt",
            "RepositoryExecutableNativeDependencyManifestRequirement",
            "inspect_staged_executable_native_dependency_manifest",
        }
        self.assertEqual(set(manifest_module.__all__), expected_exports)
        signature = inspect.signature(inspect_staged_executable_native_dependency_manifest)
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_requirements",
                "expected_runtime",
                "expected_staging",
                "lease",
                "expected_non_absolute_dependency_manifest",
            ),
        )
        for name in tuple(signature.parameters)[1:]:
            self.assertEqual(signature.parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
        _receipt, requirements, runtime, staging, lease, manifest, _private = self._prepare()
        with patch.object(
            manifest_module,
            "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                inspect_staged_executable_native_dependency_manifest(
                    requirements,
                    expected_runtime=runtime,
                    expected_staging=staging,
                    lease=lease,
                    expected_non_absolute_dependency_manifest=manifest,
                )
        marker = "private-unexpected-error-marker"
        with patch.object(
            manifest_module,
            "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(
                requirements, runtime, staging, lease, manifest, marker=marker
            )


if __name__ == "__main__":
    unittest.main()
