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
    repository_executable_native_dependency_target_resolution as target_module,
)
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_requirements import (
    inspect_staged_executable_native_dependency_requirements,
)
from ordomata.repository_executable_native_dependency_target_resolution import (
    RepositoryExecutableNativeDependencyTargetResolutionReceipt,
    inspect_staged_executable_native_dependency_targets,
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
    from . import (
        test_repository_executable_native_dependency_requirements as dependency_test,
    )
else:
    import test_repository_executable_native_dependency_requirements as dependency_test


FIXED_ERROR = (
    "repository executable native dependency target resolution is invalid"
)


@unittest.skipUnless(
    os.name == "posix",
    "native dependency target measurement requires POSIX",
)
class RepositoryExecutableNativeDependencyTargetResolutionTests(
    unittest.TestCase
):
    fixture = (
        dependency_test.RepositoryExecutableNativeDependencyRequirementsTests
    )

    @staticmethod
    def _write_target(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o755)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())

    @classmethod
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    def _prepare(
        self,
        *,
        source_mode: str = "mixed",
        shared_absolute: bool = False,
    ) -> tuple[
        RepositoryExecutableNativeDependencyTargetResolutionReceipt,
        object,
        RepositoryExecutableRuntimeManifestReceipt,
        RepositoryExecutableStagingReceipt,
        RepositoryExecutableStageLease,
        tuple[Path, ...],
        tuple[str, ...],
    ]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, outside, search_one, search_two, staging_root = (
            self.fixture._workspace(temporary.name)
        )
        target_one = outside / "private-dependency-one"
        target_two = outside / "private-dependency-two"
        target_contents = (
            "private-target-content-one",
            "private-target-content-two",
        )
        self._write_target(target_one, target_contents[0].encode())
        self._write_target(target_two, target_contents[1].encode())

        if source_mode == "mixed":
            bare_names = (os.fsencode(target_one), b"private-bare.so")
            second_absolute = target_one if shared_absolute else target_two
            relative_names = (
                (0xC, os.fsencode(second_absolute)),
                (0x80000018, b"@rpath/private-weak.dylib"),
            )
            expected_paths = (
                (target_one,)
                if shared_absolute
                else (target_one, target_two)
            )
            bare = dependency_test._elf64_dependencies(bare_names)
            relative = dependency_test._mach64_dependencies(relative_names)
        elif source_mode == "non_absolute":
            bare = dependency_test._elf64_dependencies((b"private-bare.so",))
            relative = dependency_test._mach64_dependencies(
                ((0xC, b"@loader_path/private.dylib"),)
            )
            expected_paths = ()
        elif source_mode == "terminal":
            bare = dependency_test._elf64_dependencies(())
            relative = b"#!/usr/bin/python3 -I\nprivate\n"
            expected_paths = ()
        else:
            raise AssertionError(source_mode)

        self.fixture._set_contents(
            root,
            search_one,
            bare=bare,
            relative=relative,
        )
        registration = self.fixture._registration(root)
        lease, staging, runtime = self.fixture.fixture._stage_runtime(
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
        requirements = inspect_staged_executable_native_dependency_requirements(
            loader,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
        )
        receipt = inspect_staged_executable_native_dependency_targets(
            requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_absolute_dependency_paths=expected_paths,
        )
        private_values = (
            str(root),
            os.fspath(target_one),
            os.fspath(target_two),
            *target_contents,
            "private-bare.so",
            "@rpath/private-weak.dylib",
        )
        return (
            receipt,
            requirements,
            runtime,
            staging,
            lease,
            expected_paths,
            private_values,
        )

    def _assert_invalid(
        self,
        requirements: object,
        runtime: object,
        staging: object,
        lease: object,
        paths: object,
        *,
        marker: str = "private-target-resolution-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_dependency_targets(
                requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_absolute_dependency_paths=paths,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_mixed_dependency_targets_are_measured_and_digest_only(self) -> None:
        (
            receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            private_values,
        ) = self._prepare()
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.dependency_declaration_count, 4)
        self.assertEqual(receipt.absolute_dependency_declaration_count, 2)
        self.assertEqual(receipt.unresolved_dependency_declaration_count, 2)
        self.assertEqual(receipt.unique_target_count, 2)
        dispositions = tuple(
            declaration.target_disposition
            for requirement in receipt.requirements
            for declaration in requirement.target_declarations
        )
        self.assertEqual(
            dispositions.count("absolute_dependency_target_measured"),
            2,
        )
        self.assertEqual(
            dispositions.count("non_absolute_dependency_unresolved"),
            2,
        )
        before = self._lease_snapshot(lease)
        repeated = inspect_staged_executable_native_dependency_targets(
            requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_absolute_dependency_paths=paths,
        )
        self.assertEqual(repeated, receipt)
        self.assertEqual(self._lease_snapshot(lease), before)
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(
            evidence["absolute_dependency_target_measurement_complete"]
        )
        self.assertFalse(evidence["dependency_closure_verified"])
        self.assertFalse(evidence["dependency_search_semantics_applied"])
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
            receipt.unique_target_count = 0

    def test_shared_absolute_target_is_measured_once(self) -> None:
        receipt, *_unused = self._prepare(shared_absolute=True)
        self.assertEqual(receipt.absolute_dependency_declaration_count, 2)
        self.assertEqual(receipt.unique_target_count, 1)
        measured_refs = {
            declaration.target_measurement_ref
            for requirement in receipt.requirements
            for declaration in requirement.target_declarations
            if declaration.target_measurement_ref is not None
        }
        self.assertEqual(
            measured_refs,
            {receipt.measurements[0].measurement_ref},
        )

    def test_non_absolute_and_terminal_inputs_perform_zero_target_reads(self) -> None:
        for source_mode, expected_unresolved in (
            ("non_absolute", 2),
            ("terminal", 0),
        ):
            with self.subTest(source_mode=source_mode):
                real_measure = target_module._BUILTIN_MEASURE_TARGET_SET
                observed: list[tuple[Path, ...]] = []

                def empty_only(paths):
                    observed.append(paths)
                    if paths:
                        raise AssertionError("private-unexpected-target-read")
                    return real_measure(paths)

                with patch.object(
                    target_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    side_effect=empty_only,
                ):
                    receipt, *_unused = self._prepare(
                        source_mode=source_mode
                    )
                self.assertEqual(observed, [(), ()])
                self.assertEqual(receipt.unique_target_count, 0)
                self.assertEqual(
                    receipt.unresolved_dependency_declaration_count,
                    expected_unresolved,
                )

    def test_exact_expected_path_set_rejects_before_measurement(self) -> None:
        (
            _receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            _private,
        ) = self._prepare()
        extra = paths[0].parent / "private-extra"
        self._write_target(extra, b"private-extra-content")
        bad_sets = (
            paths[:-1],
            tuple(reversed(paths)),
            paths + (extra,),
            paths + (paths[0],),
            list(paths),
            (Path("relative-target"),),
        )
        poison = AssertionError("private-measurement-must-not-run")
        for bad in bad_sets:
            with self.subTest(paths=repr(bad)):
                with patch.object(
                    target_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    side_effect=poison,
                ) as measured:
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        bad,
                        marker=str(poison),
                    )
                measured.assert_not_called()

    def test_symlink_target_and_identity_alias_fail_closed(self) -> None:
        (
            _receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            _private,
        ) = self._prepare()
        first, second = paths
        real_first = first.with_name("private-real-first")
        first.rename(real_first)
        first.symlink_to(real_first)
        self._assert_invalid(
            requirements,
            runtime,
            staging,
            lease,
            paths,
        )
        first.unlink()
        os.link(real_first, first)
        second.unlink()
        os.link(real_first, second)
        self._assert_invalid(
            requirements,
            runtime,
            staging,
            lease,
            paths,
        )

    def test_fresh_chain_measurement_and_namespace_drift_fail_closed(self) -> None:
        (
            _receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            _private,
        ) = self._prepare()
        real_snapshot = target_module._BUILTIN_VALIDATED_CHAIN_SNAPSHOT
        calls = 0

        def drift(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_snapshot(*args, **kwargs)
            if calls == 2:
                return (*result[:-1], "sha256:" + "0" * 64)
            return result

        with patch.object(
            target_module,
            "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT",
            side_effect=drift,
        ):
            self._assert_invalid(
                requirements,
                runtime,
                staging,
                lease,
                paths,
            )

        real_measure = target_module._BUILTIN_MEASURE_TARGET_SET
        measure_calls = 0

        def changed(*args, **kwargs):
            nonlocal measure_calls
            measure_calls += 1
            result = real_measure(*args, **kwargs)
            if measure_calls == 2:
                return tuple(reversed(result))
            return result

        with patch.object(
            target_module,
            "_BUILTIN_MEASURE_TARGET_SET",
            side_effect=changed,
        ):
            self._assert_invalid(
                requirements,
                runtime,
                staging,
                lease,
                paths,
            )
        with patch.object(
            target_module,
            "_BUILTIN_TARGET_NAMESPACE_MATCHES",
            return_value=False,
        ):
            self._assert_invalid(
                requirements,
                runtime,
                staging,
                lease,
                paths,
            )

    def test_wrong_inputs_forgery_and_closed_lease_fail_closed(self) -> None:
        (
            _receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            _private,
        ) = self._prepare()
        for forged_requirements, forged_runtime, forged_staging in (
            (None, runtime, staging),
            (requirements, None, staging),
            (requirements, runtime, None),
            (
                replace(requirements, requirement_count=0),
                runtime,
                staging,
            ),
            (requirements, replace(runtime, file_count=0), staging),
            (
                requirements,
                runtime,
                replace(staging, unique_file_count=0),
            ),
        ):
            with self.subTest(requirements=repr(forged_requirements)):
                self._assert_invalid(
                    forged_requirements,
                    forged_runtime,
                    forged_staging,
                    lease,
                    paths,
                )
        lease.close()
        self._assert_invalid(
            requirements,
            runtime,
            staging,
            lease,
            paths,
        )

    def test_projection_rejects_forged_lineage_order_and_counts(self) -> None:
        receipt, *_unused = self._prepare()
        first_requirement = receipt.requirements[0]
        first_declaration = first_requirement.target_declarations[0]
        for forged in (
            replace(receipt, unique_target_count=0),
            replace(receipt, dependency_declaration_count=0),
            replace(receipt, requirements=tuple(reversed(receipt.requirements))),
            replace(receipt, measurements=tuple(reversed(receipt.measurements))),
            replace(
                receipt,
                requirements=(
                    replace(
                        first_requirement,
                        target_declarations=(
                            replace(first_declaration, ordinal=1),
                            *first_requirement.target_declarations[1:],
                        ),
                    ),
                    receipt.requirements[1],
                ),
            ),
        ):
            with self.subTest(forged=repr(forged)):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

    def test_public_helpers_do_not_replace_frozen_proof_graph(self) -> None:
        (
            _receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            _private,
        ) = self._prepare()
        poison = AssertionError("private-public-helper-marker")
        names = (
            "_measurement_ref_projection",
            "_measurement_projection",
            "_target_declaration_ref_projection",
            "_declaration_projection",
            "_dependency_disposition_matches_classification",
            "_target_requirement_ref_projection",
            "_requirement_projection",
            "_binding_projection",
            "_receipt_projection",
            "_evidence_projection",
            "_validated_path",
            "_path_ref",
            "_dependency_path_context_digest",
            "_expected_dependency_name_ref",
            "_validate_expected_dependency_paths",
            "_validated_chain_snapshot",
            "_measurement_identity_ref",
            "_measurement_metadata_digest",
            "_public_measurement",
            "_public_target_declaration",
            "_public_requirement",
        )
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(
                    patch.object(target_module, name, side_effect=poison)
                )
            receipt = inspect_staged_executable_native_dependency_targets(
                requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_absolute_dependency_paths=paths,
            )
        self.assertEqual(receipt.unique_target_count, 2)

    def test_no_write_process_network_cleanup_or_lease_effects(self) -> None:
        (
            _receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            _private,
        ) = self._prepare()
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_dependency_targets(
                requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_absolute_dependency_paths=paths,
            )
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertEqual(self._lease_snapshot(lease), before)
        opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_exports_signature_interrupts_and_errors_are_fixed(self) -> None:
        expected_exports = {
            "MEASUREMENT_SOURCE",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_BINDING_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_DECLARATION_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_MEASUREMENT_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_REQUIREMENT_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_EVIDENCE_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_DEPENDENCY_TARGET_RESOLUTION_SCHEMA_VERSION",
            "RESOLUTION_SCOPE",
            "RepositoryExecutableNativeDependencyTargetBinding",
            "RepositoryExecutableNativeDependencyTargetDeclaration",
            "RepositoryExecutableNativeDependencyTargetMeasurement",
            "RepositoryExecutableNativeDependencyTargetRequirement",
            "RepositoryExecutableNativeDependencyTargetResolutionReceipt",
            "inspect_staged_executable_native_dependency_targets",
        }
        self.assertEqual(set(target_module.__all__), expected_exports)
        signature = inspect.signature(
            inspect_staged_executable_native_dependency_targets
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_requirements",
                "expected_runtime",
                "expected_staging",
                "lease",
                "expected_absolute_dependency_paths",
            ),
        )
        for name in tuple(signature.parameters)[1:]:
            self.assertEqual(
                signature.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )

        (
            _receipt,
            requirements,
            runtime,
            staging,
            lease,
            paths,
            _private,
        ) = self._prepare()
        with patch.object(
            target_module,
            "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                inspect_staged_executable_native_dependency_targets(
                    requirements,
                    expected_runtime=runtime,
                    expected_staging=staging,
                    lease=lease,
                    expected_absolute_dependency_paths=paths,
                )
        marker = "private-parser-error-marker"
        with patch.object(
            target_module,
            "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(
                requirements,
                runtime,
                staging,
                lease,
                paths,
                marker=marker,
            )


if __name__ == "__main__":
    unittest.main()
