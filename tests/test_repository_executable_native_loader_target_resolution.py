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

from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_loader_requirements import (
    inspect_staged_executable_native_loader_requirements,
)
import ordomata.repository_executable_native_loader_target_resolution as target_module
from ordomata.repository_executable_native_loader_target_resolution import (
    MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_BINDING_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_MEASUREMENT_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_REQUIREMENT_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_SCHEMA_VERSION,
    RESOLUTION_SCOPE,
    RepositoryExecutableNativeLoaderTargetBinding,
    RepositoryExecutableNativeLoaderTargetMeasurement,
    RepositoryExecutableNativeLoaderTargetRequirement,
    RepositoryExecutableNativeLoaderTargetResolutionReceipt,
    inspect_staged_executable_native_loader_targets,
)
from ordomata.repository_executable_runtime_manifest import (
    inspect_staged_executable_runtime_manifest,
)
from ordomata.repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
)

if __package__:
    from . import (
        test_repository_executable_native_loader_requirements as native_test_module,
    )
else:
    import test_repository_executable_native_loader_requirements as native_test_module


FIXED_ERROR = (
    "repository executable native loader target resolution is invalid"
)
MEASUREMENT_KEYS = {
    "content_bytes",
    "content_digest",
    "filesystem_identity_ref",
    "kind",
    "measurement_ref",
    "measurement_source",
    "metadata_digest",
    "path_ref",
    "resolution_scope",
    "schema_version",
}
REQUIREMENT_KEYS = {
    "kind",
    "loader_disposition",
    "loader_path_ref",
    "native_loader_requirement_ref",
    "resolution_scope",
    "runtime_classification",
    "runtime_file_ref",
    "schema_version",
    "staged_file_ref",
    "target_disposition",
    "target_measurement_ref",
    "target_requirement_ref",
}
BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "native_loader_requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
}
RECEIPT_KEYS = {
    "bindings",
    "command_count",
    "declared_target_requirement_count",
    "kind",
    "loader_path_context_digest",
    "measurement_source",
    "measurements",
    "native_loader_requirements_receipt_digest",
    "no_target_requirement_count",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "resolution_context_digest",
    "resolution_scope",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "staging_context_digest",
    "staging_receipt_digest",
    "total_measured_bytes",
    "unique_target_count",
    "verification_commands_digest",
}
EVIDENCE_KEYS = {
    "action_receipt_issued",
    "active_lease_verified_at_measurement",
    "authority_granted",
    "authorization_verified",
    "billing_eligible",
    "bounded_native_loader_target_measurement_complete",
    "capacity_eligible",
    "circuit_eligible",
    "command_count",
    "current_lease_activity_verified",
    "current_source_freshness_verified",
    "declared_loader_target_measured_count",
    "dependency_closure_verified",
    "dispatch_enabled",
    "durable_control_plane_persistence_enabled",
    "dynamic_loader_identity_verified",
    "effect_class",
    "environment_coverage_verified",
    "exact_loader_path_expectation_verified",
    "execution_enabled",
    "fat_mach_o_architecture_selection_performed",
    "future_execution_correspondence_verified",
    "kind",
    "lease_cleanup_performed",
    "lease_mutated",
    "live_execution_eligible",
    "loader_declaration_absent_count",
    "loader_path_raw_bytes_exposed",
    "loader_target_nofollow_measurement_complete",
    "model_invocation_performed",
    "native_loader_requirements_receipt_digest",
    "network_access_performed",
    "non_native_not_applicable_count",
    "proposal_lineage_extended",
    "receipt_authenticity_verified",
    "receipt_digest",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "resolution_context_digest",
    "resolution_scope",
    "route_eligible",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shared_library_closure_verified",
    "shared_library_identity_verified",
    "staged_source_path_reopen_performed",
    "staged_byte_correspondence_verified",
    "staging_receipt_digest",
    "subprocess_invocation_performed",
    "target_file_identity_measured",
    "target_path_raw_value_exposed",
    "target_path_resolution_mode",
    "toolchain_completeness_verified",
    "total_measured_bytes",
    "unique_target_count",
    "unsupported_native_layout_count",
    "validation_mode",
    "worker_authorized",
    "worktree_integration_enabled",
}


@unittest.skipUnless(os.name == "posix", "loader target measurement requires POSIX")
class RepositoryExecutableNativeLoaderTargetResolutionTests(unittest.TestCase):
    fixture = (
        native_test_module.RepositoryExecutableNativeLoaderRequirementsTests.fixture
    )

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

    @staticmethod
    def _write_target(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o755)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())

    @classmethod
    def _stage_chain(
        cls,
        registration: object,
        search_directories: tuple[Path, ...],
        staging_root: Path,
    ):
        lease, staging = cls.fixture._stage(
            registration,
            search_directories,
            staging_root,
        )
        runtime = inspect_staged_executable_runtime_manifest(
            staging,
            lease=lease,
        )
        requirements = inspect_staged_executable_native_loader_requirements(
            runtime,
            expected_staging=staging,
            lease=lease,
        )
        return lease, staging, runtime, requirements

    @classmethod
    def _lease_snapshot(cls, lease: RepositoryExecutableStageLease):
        return cls.fixture._lease_snapshot(lease)

    def _fixture_chain(
        self,
        *,
        same_target: bool = False,
        bare: bytes | None = None,
        relative: bytes | None = None,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, _outside, search_one, search_two, staging_root = self._workspace(
            temporary.name
        )
        target_one = root.parent / "private-native-loader-target-one"
        target_two = (
            target_one
            if same_target
            else root.parent / "private-native-loader-target-two"
        )
        self._write_target(target_one, b"private-loader-target-one-bytes\n")
        if target_two != target_one:
            self._write_target(
                target_two,
                b"private-loader-target-two-bytes\n",
            )
        bare_bytes = (
            native_test_module._elf64(os.fsencode(target_one))
            if bare is None
            else bare
        )
        relative_bytes = (
            native_test_module._mach64(os.fsencode(target_two))
            if relative is None
            else relative
        )
        self._set_contents(
            root,
            search_one,
            bare=bare_bytes,
            relative=relative_bytes,
        )
        registration = self._registration(root)
        lease, staging, runtime, requirements = self._stage_chain(
            registration,
            (search_one, search_two),
            staging_root,
        )
        self.addCleanup(lease.close)
        paths = (target_one,) if same_target else (target_one, target_two)
        return (
            lease,
            staging,
            runtime,
            requirements,
            paths,
            root,
        )

    def _assert_invalid(
        self,
        requirements: object,
        runtime: object,
        staging: object,
        lease: object,
        paths: object,
        *,
        marker: str = "private-loader-target-resolution-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_loader_targets(
                requirements,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_loader_paths=paths,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_receipt_correspondence_privacy_and_lease_immutability(self) -> None:
        lease, staging, runtime, upstream, paths, root = self._fixture_chain()
        before = self._lease_snapshot(lease)
        receipt = inspect_staged_executable_native_loader_targets(
            upstream,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_loader_paths=paths,
        )
        repeated = inspect_staged_executable_native_loader_targets(
            upstream,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_loader_paths=paths,
        )
        self.assertEqual(receipt, repeated)
        self.assertEqual(before, self._lease_snapshot(lease))
        self.assertIsInstance(
            receipt,
            RepositoryExecutableNativeLoaderTargetResolutionReceipt,
        )
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_SCHEMA_VERSION,
            1,
        )
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_KIND,
            "repository_executable_native_loader_target_resolution",
        )
        self.assertEqual(MEASUREMENT_SOURCE, "controller_measured")
        self.assertEqual(
            RESOLUTION_SCOPE,
            "native_loader_declared_absolute_target_nofollow_v1",
        )
        canonical = receipt.to_canonical()
        self.assertEqual(set(canonical), RECEIPT_KEYS)
        self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
        self.assertEqual(
            receipt.native_loader_requirements_receipt_digest,
            upstream.receipt_digest,
        )
        self.assertEqual(
            receipt.runtime_manifest_receipt_digest,
            runtime.receipt_digest,
        )
        self.assertEqual(receipt.staging_receipt_digest, staging.receipt_digest)
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.declared_target_requirement_count, 2)
        self.assertEqual(receipt.no_target_requirement_count, 0)
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertEqual(
            receipt.total_measured_bytes,
            sum(path.stat().st_size for path in paths),
        )
        for measurement in receipt.measurements:
            self.assertIsInstance(
                measurement,
                RepositoryExecutableNativeLoaderTargetMeasurement,
            )
            self.assertEqual(set(measurement.to_canonical()), MEASUREMENT_KEYS)
            self.assertEqual(
                measurement.kind,
                REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_MEASUREMENT_KIND,
            )
        for requirement in receipt.requirements:
            self.assertIsInstance(
                requirement,
                RepositoryExecutableNativeLoaderTargetRequirement,
            )
            self.assertEqual(set(requirement.to_canonical()), REQUIREMENT_KEYS)
            self.assertEqual(
                requirement.kind,
                REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_REQUIREMENT_KIND,
            )
            self.assertEqual(
                requirement.target_disposition,
                "declared_loader_target_measured",
            )
        for binding in receipt.bindings:
            self.assertIsInstance(
                binding,
                RepositoryExecutableNativeLoaderTargetBinding,
            )
            self.assertEqual(set(binding.to_canonical()), BINDING_KEYS)
            self.assertEqual(
                binding.kind,
                REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_BINDING_KIND,
            )

        evidence = receipt.to_evidence()
        self.assertEqual(set(evidence), EVIDENCE_KEYS)
        self.assertEqual(
            evidence["kind"],
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_EVIDENCE_KIND,
        )
        self.assertEqual(evidence["effect_class"], 0)
        self.assertEqual(evidence["validation_mode"], "read_only")
        for true_fact in (
            "active_lease_verified_at_measurement",
            "bounded_native_loader_target_measurement_complete",
            "exact_loader_path_expectation_verified",
            "loader_target_nofollow_measurement_complete",
            "staged_byte_correspondence_verified",
            "target_file_identity_measured",
        ):
            self.assertIs(evidence[true_fact], True, true_fact)
        for false_fact in (
            "authority_granted",
            "authorization_verified",
            "dependency_closure_verified",
            "dispatch_enabled",
            "dynamic_loader_identity_verified",
            "execution_enabled",
            "fat_mach_o_architecture_selection_performed",
            "live_execution_eligible",
            "loader_path_raw_bytes_exposed",
            "model_invocation_performed",
            "network_access_performed",
            "shared_library_closure_verified",
            "shared_library_identity_verified",
            "subprocess_invocation_performed",
            "target_path_raw_value_exposed",
            "worker_authorized",
        ):
            self.assertIs(evidence[false_fact], False, false_fact)
        aggregate = "\n".join(
            (
                json.dumps(canonical, sort_keys=True),
                json.dumps(evidence, sort_keys=True),
                repr(receipt),
                *(repr(item) for item in receipt.measurements),
                *(repr(item) for item in receipt.requirements),
                *(repr(item) for item in receipt.bindings),
            )
        )
        for private_value in (
            str(root),
            *(os.fspath(path) for path in paths),
            "private-loader-target-one-bytes",
            "private-loader-target-two-bytes",
        ):
            self.assertNotIn(private_value, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.unique_target_count = 0
        with self.assertRaises(FrozenInstanceError):
            receipt.measurements[0].content_bytes = 0

    def test_same_declared_target_is_measured_once_with_two_requirements(self) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain(
            same_target=True
        )
        receipt = inspect_staged_executable_native_loader_targets(
            upstream,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_loader_paths=paths,
        )
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.unique_target_count, 1)
        self.assertEqual(
            {item.target_measurement_ref for item in receipt.requirements},
            {receipt.measurements[0].measurement_ref},
        )

    def test_absent_unsupported_and_non_native_require_no_target_read(self) -> None:
        cases = (
            (
                native_test_module._elf64(None),
                b"#!/usr/bin/python3\n",
                {"loader_declaration_absent", "non_native_not_applicable"},
            ),
            (
                native_test_module._fat_mach64(),
                b"ordinary executable bytes\n",
                {"unsupported_native_layout", "non_native_not_applicable"},
            ),
        )
        for bare, relative, expected_dispositions in cases:
            with self.subTest(expected=expected_dispositions):
                (
                    lease,
                    staging,
                    runtime,
                    upstream,
                    _paths,
                    _root,
                ) = self._fixture_chain(bare=bare, relative=relative)
                with patch.object(
                    target_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    wraps=target_module._BUILTIN_MEASURE_TARGET_SET,
                ) as measure:
                    receipt = inspect_staged_executable_native_loader_targets(
                        upstream,
                        expected_runtime=runtime,
                        expected_staging=staging,
                        lease=lease,
                        expected_loader_paths=(),
                    )
                self.assertEqual(receipt.unique_target_count, 0)
                self.assertEqual(receipt.total_measured_bytes, 0)
                self.assertFalse(
                    receipt.to_evidence()["target_file_identity_measured"]
                )
                self.assertEqual(
                    {item.target_disposition for item in receipt.requirements},
                    expected_dispositions,
                )
                self.assertEqual(measure.call_count, 2)
                self.assertTrue(
                    all(call.args == ((),) for call in measure.call_args_list)
                )

    def test_exact_expected_path_set_rejects_before_target_measurement(self) -> None:
        lease, staging, runtime, upstream, paths, root = self._fixture_chain()
        wrong = root.parent / "private-wrong-loader-target"
        self._write_target(wrong, b"wrong target\n")
        cases: tuple[object, ...] = (
            list(paths),
            tuple(reversed(paths)),
            (paths[0],),
            (*paths, paths[0]),
            (wrong, *paths[1:]),
        )
        for candidate in cases:
            with self.subTest(candidate=repr(candidate)):
                with patch.object(
                    target_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    side_effect=AssertionError("target measured too early"),
                ) as measure:
                    self._assert_invalid(
                        upstream,
                        runtime,
                        staging,
                        lease,
                        candidate,
                    )
                measure.assert_not_called()

    def test_missing_symlink_directory_and_nonexecutable_targets_reject(self) -> None:
        mutations = ("missing", "symlink", "directory", "nonexecutable")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                lease, staging, runtime, upstream, paths, root = (
                    self._fixture_chain()
                )
                target = paths[0]
                if mutation == "missing":
                    target.unlink()
                elif mutation == "symlink":
                    target.unlink()
                    target.symlink_to(paths[1])
                elif mutation == "directory":
                    target.unlink()
                    target.mkdir()
                else:
                    target.chmod(0o600)
                self._assert_invalid(
                    upstream,
                    runtime,
                    staging,
                    lease,
                    paths,
                )

    def test_target_content_drift_between_measurements_fails_closed(self) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain()
        real_measure = target_module._BUILTIN_MEASURE_TARGET_SET
        calls = 0

        def mutate_after_first(expected_paths: tuple[Path, ...]):
            nonlocal calls
            calls += 1
            result = real_measure(expected_paths)
            if calls == 1:
                self._write_target(
                    paths[0],
                    b"changed-private-loader-target-bytes\n",
                )
            return result

        with patch.object(
            target_module,
            "_BUILTIN_MEASURE_TARGET_SET",
            side_effect=mutate_after_first,
        ):
            self._assert_invalid(
                upstream,
                runtime,
                staging,
                lease,
                paths,
            )

    def test_wrong_types_lineage_forgery_and_closed_lease_fail_closed(self) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain()
        self._assert_invalid(None, runtime, staging, lease, paths)
        self._assert_invalid(upstream, None, staging, lease, paths)
        self._assert_invalid(upstream, runtime, None, lease, paths)
        self._assert_invalid(upstream, runtime, staging, None, paths)
        self._assert_invalid(
            replace(upstream, repository_ref="sha256:" + "0" * 64),
            runtime,
            staging,
            lease,
            paths,
        )
        self._assert_invalid(
            upstream,
            replace(runtime, repository_ref="sha256:" + "1" * 64),
            staging,
            lease,
            paths,
        )
        lease.close()
        self._assert_invalid(upstream, runtime, staging, lease, paths)

    def test_public_monkeypatches_cannot_replace_captured_proof_graph(self) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain()
        poison = AssertionError("private-public-monkeypatch-marker")
        poisoned_functions = (
            "_native_requirements_projection",
            "_runtime_projection",
            "_staging_projection",
            "inspect_staged_executable_native_loader_requirements",
            "_active_stage_snapshot",
            "_canonical_target_path",
            "_measure_target_set",
            "_target_namespace_matches",
            "_measurement_ref_projection",
            "_measurement_projection",
            "_target_requirement_ref_projection",
            "_expected_target_disposition",
            "_loader_disposition_matches_classification",
            "_requirement_projection",
            "_binding_projection",
            "_receipt_projection",
            "_evidence_projection",
            "_validated_path",
            "_path_ref",
            "_loader_path_context_digest",
            "_declaration_kind",
            "_expected_loader_path_ref",
            "_validate_expected_loader_paths",
            "_validated_chain_snapshot",
            "_measurement_identity_ref",
            "_measurement_metadata_digest",
            "_public_measurement",
            "_public_requirement",
        )
        poisoned_types = (
            "RepositoryExecutableNativeLoaderTargetBinding",
            "RepositoryExecutableNativeLoaderTargetMeasurement",
            "RepositoryExecutableNativeLoaderTargetRequirement",
            "RepositoryExecutableNativeLoaderTargetResolutionReceipt",
        )
        with ExitStack() as stack:
            for name in poisoned_functions:
                stack.enter_context(
                    patch.object(target_module, name, side_effect=poison)
                )
            for name in poisoned_types:
                stack.enter_context(patch.object(target_module, name, None))
            receipt = inspect_staged_executable_native_loader_targets(
                upstream,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_loader_paths=paths,
            )
        self.assertEqual(receipt.unique_target_count, 2)

    def test_three_chain_reproductions_two_measurements_and_closing_anchor(
        self,
    ) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain()
        with (
            patch.object(
                target_module,
                "_BUILTIN_INSPECT_NATIVE_REQUIREMENTS",
                wraps=target_module._BUILTIN_INSPECT_NATIVE_REQUIREMENTS,
            ) as inspect_requirements,
            patch.object(
                target_module,
                "_BUILTIN_MEASURE_TARGET_SET",
                wraps=target_module._BUILTIN_MEASURE_TARGET_SET,
            ) as measure,
            patch.object(
                target_module,
                "_BUILTIN_ACTIVE_STAGE_SNAPSHOT",
                wraps=target_module._BUILTIN_ACTIVE_STAGE_SNAPSHOT,
            ) as snapshot,
        ):
            inspect_staged_executable_native_loader_targets(
                upstream,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_loader_paths=paths,
            )
        self.assertEqual(inspect_requirements.call_count, 3)
        self.assertEqual(measure.call_count, 2)
        self.assertEqual(snapshot.call_count, 4)

    def test_no_write_process_network_state_or_cleanup_effects(self) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain()
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-side-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as builtin_open,
            patch.object(os, "write", side_effect=poison) as os_write,
            patch.object(os, "rename", side_effect=poison) as os_rename,
            patch.object(os, "replace", side_effect=poison) as os_replace,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_loader_targets(
                upstream,
                expected_runtime=runtime,
                expected_staging=staging,
                lease=lease,
                expected_loader_paths=paths,
            )
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertEqual(before, self._lease_snapshot(lease))
        builtin_open.assert_not_called()
        os_write.assert_not_called()
        os_rename.assert_not_called()
        os_replace.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_output_projection_rejects_forged_records_and_counts(self) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain()
        receipt = inspect_staged_executable_native_loader_targets(
            upstream,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_loader_paths=paths,
        )
        for forged in (
            replace(receipt, unique_target_count=1),
            replace(receipt, total_measured_bytes=0),
            replace(
                receipt,
                loader_path_context_digest="sha256:" + "3" * 64,
            ),
            replace(
                receipt,
                measurements=tuple(reversed(receipt.measurements)),
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
                        target_requirement_ref=(
                            receipt.bindings[1].target_requirement_ref
                        ),
                    ),
                    receipt.bindings[1],
                ),
            ),
        ):
            with self.subTest(forged=repr(forged)):
                with self.assertRaises(ValueError):
                    forged.to_canonical()
        with self.assertRaises(ValueError):
            replace(
                receipt.measurements[0],
                content_bytes=0,
            ).to_canonical()
        with self.assertRaises(ValueError):
            replace(
                receipt.requirements[0],
                target_measurement_ref=None,
            ).to_canonical()

    def test_fixed_error_interrupts_exports_and_signature(self) -> None:
        lease, staging, runtime, upstream, paths, _root = self._fixture_chain()
        marker = "private-loader-target-base-exception-marker"
        with patch.object(
            target_module,
            "_BUILTIN_INSPECT_NATIVE_REQUIREMENTS",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(
                upstream,
                runtime,
                staging,
                lease,
                paths,
                marker=marker,
            )
        for interruption in (KeyboardInterrupt(), SystemExit(9)):
            with (
                self.subTest(interruption=type(interruption).__name__),
                patch.object(
                    target_module,
                    "_BUILTIN_INSPECT_NATIVE_REQUIREMENTS",
                    side_effect=interruption,
                ),
                self.assertRaises(type(interruption)),
            ):
                inspect_staged_executable_native_loader_targets(
                    upstream,
                    expected_runtime=runtime,
                    expected_staging=staging,
                    lease=lease,
                    expected_loader_paths=paths,
                )
        self.assertEqual(
            tuple(
                inspect.signature(
                    inspect_staged_executable_native_loader_targets
                ).parameters
            ),
            (
                "expected_requirements",
                "expected_runtime",
                "expected_staging",
                "lease",
                "expected_loader_paths",
            ),
        )
        self.assertEqual(
            target_module.__all__,
            [
                "MEASUREMENT_SOURCE",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_MEASUREMENT_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_REQUIREMENT_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_EVIDENCE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_RESOLUTION_SCHEMA_VERSION",
                "RESOLUTION_SCOPE",
                "RepositoryExecutableNativeLoaderTargetBinding",
                "RepositoryExecutableNativeLoaderTargetMeasurement",
                "RepositoryExecutableNativeLoaderTargetRequirement",
                "RepositoryExecutableNativeLoaderTargetResolutionReceipt",
                "inspect_staged_executable_native_loader_targets",
            ],
        )


if __name__ == "__main__":
    unittest.main()
