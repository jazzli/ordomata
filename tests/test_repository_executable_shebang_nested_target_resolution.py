from __future__ import annotations

import asyncio
import builtins
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ordomata.artifact_filesystem as artifact_filesystem_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
import ordomata.repository_executable_shebang_nested_target_resolution as nested_module
from ordomata.repository_executable_shebang_nested_target_resolution import (
    CYCLE_SCOPE,
    MAXIMUM_RESOLUTION_DEPTH,
    MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_BINDING_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_MEASUREMENT_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENT_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION,
    RESOLUTION_DEPTH,
    RESOLUTION_SCOPE,
    RepositoryExecutableShebangNestedTargetBinding,
    RepositoryExecutableShebangNestedTargetMeasurement,
    RepositoryExecutableShebangNestedTargetRequirement,
    RepositoryExecutableShebangNestedTargetResolutionReceipt,
    inspect_staged_executable_shebang_nested_targets,
)
import ordomata.repository_executable_shebang_target_requirements as target_requirements_module
from ordomata.repository_executable_shebang_target_requirements import (
    RepositoryExecutableShebangTargetRequirementsReceipt,
    inspect_staged_executable_shebang_target_requirements,
)
from ordomata.repository_executable_shebang_target_runtime_manifest import (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
)
from ordomata.repository_executable_shebang_target_staging import (
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStagingReceipt,
)
import ordomata.state as state_module

if __package__:
    from . import (
        test_repository_executable_shebang_target_requirements
        as target_requirements_test_module,
    )
else:
    import test_repository_executable_shebang_target_requirements \
        as target_requirements_test_module


FIXED_NESTED_TARGET_ERROR = (
    "repository executable shebang nested target resolution is invalid"
)
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
_MACH_O = b"\xcf\xfa\xed\xfe" + b"\x00" * 28

MEASUREMENT_KEYS = {
    "content_bytes",
    "content_digest",
    "filesystem_identity_ref",
    "kind",
    "metadata_digest",
    "nested_target_measurement_ref",
    "nested_target_path_ref",
}
REQUIREMENT_KEYS = {
    "argument_tail_ref",
    "disposition",
    "interpreter_token_ref",
    "kind",
    "nested_target_measurement_ref",
    "nested_target_requirement_ref",
    "requirement_ref",
    "runtime_classification",
    "runtime_file_ref",
    "staged_file_ref",
    "target_measurement_ref",
    "target_requirement_ref",
    "target_runtime_classification",
    "target_runtime_file_ref",
    "target_runtime_requirement_ref",
    "target_shebang_directive_ref",
    "target_shebang_requirement_ref",
    "target_stage_requirement_ref",
    "target_staged_file_ref",
}
BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "nested_target_requirement_ref",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
    "target_runtime_requirement_ref",
    "target_shebang_requirement_ref",
    "target_stage_requirement_ref",
}
RECEIPT_KEYS = {
    "bindings",
    "command_count",
    "cycle_scope",
    "kind",
    "maximum_resolution_depth",
    "measurement_source",
    "measurements",
    "nested_target_path_context_digest",
    "nested_target_requirement_count",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "resolution_context_digest",
    "resolution_depth",
    "resolution_scope",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shebang_requirements_receipt_digest",
    "source_native_not_applicable_count",
    "source_staging_context_digest",
    "staging_receipt_digest",
    "target_native_not_applicable_count",
    "target_path_context_digest",
    "target_resolution_receipt_digest",
    "target_runtime_manifest_receipt_digest",
    "target_shebang_requirements_receipt_digest",
    "target_staging_context_digest",
    "target_staging_receipt_digest",
    "total_measured_bytes",
    "unique_nested_target_count",
    "verification_commands_digest",
}
EVIDENCE_KEYS = {
    "action_receipt_issued",
    "active_target_stage_lease_verified_at_measurement",
    "ambient_path_search_performed",
    "atomic_snapshot_verified",
    "authority_granted",
    "authorization_verified",
    "billing_eligible",
    "bounded_resolution_depth_enforced",
    "broader_protected_root_exclusion_verified",
    "capacity_eligible",
    "circuit_eligible",
    "command_count",
    "current_lease_activity_verified",
    "current_source_freshness_verified",
    "cycle_scope",
    "dependency_environment_coverage_verified",
    "dispatch_enabled",
    "durable_control_plane_persistence_enabled",
    "dynamic_loader_identity_verified",
    "effect_class",
    "effective_interpreter_resolution_verified",
    "effective_invocability_verified",
    "environment_coverage_verified",
    "exact_nested_target_path_lookup_performed",
    "exact_nested_target_path_set_verified",
    "exact_target_requirements_correspondence_verified",
    "execution_enabled",
    "external_hardlink_alias_excluded",
    "external_mount_alias_excluded",
    "external_writable_descriptor_absence_verified",
    "filesystem_immutability_verified",
    "first_hop_target_path_reopen_performed",
    "future_execution_correspondence_verified",
    "generic_cycle_exclusion_verified",
    "harness_invocation_performed",
    "immediate_target_identity_reentry_excluded",
    "immediate_target_path_reentry_excluded",
    "interpreter_argument_semantics_verified",
    "interpreter_authenticity_verified",
    "interpreter_compatibility_verified",
    "interpreter_identity_verified",
    "interpreter_provenance_verified",
    "kind",
    "launcher_semantics_verified",
    "lease_cleanup_performed",
    "lease_mutated",
    "live_execution_eligible",
    "maximum_resolution_depth",
    "measurement_source",
    "nested_target_namespace_reopen_verified",
    "nested_target_path_context_digest",
    "nested_target_path_reopen_performed",
    "nested_target_requirement_count",
    "nested_target_runtime_classification_verified",
    "path_lookup_performed",
    "proposal_lineage_extended",
    "receipt_authenticity_verified",
    "receipt_digest",
    "recursive_shebang_resolution_verified",
    "registration_digest",
    "repository_ref",
    "requirement_binding_correspondence_verified",
    "requirement_count",
    "resolution_context_digest",
    "resolution_depth",
    "resolution_scope",
    "route_eligible",
    "same_uid_tamper_exclusion_verified",
    "schema_version",
    "sequential_nested_target_measurement_complete",
    "source_chain_cycle_exclusion_verified",
    "source_native_not_applicable_count",
    "source_path_reentry_exclusion_verified",
    "source_staging_root_reentry_exclusion_verified",
    "staged_byte_correspondence_verified",
    "subprocess_invocation_performed",
    "target_native_not_applicable_count",
    "target_shebang_requirements_receipt_digest",
    "target_staging_root_ancestor_excluded",
    "target_staging_root_path_reopen_performed",
    "toolchain_completeness_verified",
    "total_measured_bytes",
    "two_pass_nested_target_measurement_verified",
    "unique_nested_target_count",
    "validation_mode",
    "worktree_integration_enabled",
}


@unittest.skipUnless(
    os.name == "posix",
    "nested shebang target resolution requires POSIX",
)
class RepositoryExecutableShebangNestedTargetResolutionTests(
    unittest.TestCase
):
    fixture = (
        target_requirements_test_module
        .RepositoryExecutableShebangTargetRequirementsTests
    )

    @classmethod
    def _workspace(
        cls,
        temporary: str,
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
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
    def _write_target(cls, path: Path, content: bytes) -> None:
        cls.fixture._write_target(path, content)

    @classmethod
    def _tree_snapshot(cls, path: Path) -> tuple[object, ...]:
        return cls.fixture._tree_snapshot(path)

    @classmethod
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableShebangTargetStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    @staticmethod
    def _descriptor_directory() -> Path | None:
        for candidate in (Path("/dev/fd"), Path("/proc/self/fd")):
            if candidate.is_dir():
                return candidate
        return None

    @classmethod
    def _stage_target_requirements(
        cls,
        registration: object,
        *,
        search_directories: tuple[Path, ...],
        executable_stage_root: Path,
        target_stage_root: Path,
        target_paths: tuple[Path, ...],
    ) -> tuple[object, ...]:
        chain = cls.fixture._stage_target_runtime(
            registration,
            search_directories=search_directories,
            executable_stage_root=executable_stage_root,
            target_stage_root=target_stage_root,
            target_paths=target_paths,
        )
        target_lease = chain[-3]
        target_staging = chain[-2]
        target_runtime = chain[-1]
        target_requirements = (
            inspect_staged_executable_shebang_target_requirements(
                target_runtime,
                expected_target_staging=target_staging,
                lease=target_lease,
            )
        )
        return (*chain, target_requirements)

    @staticmethod
    def _inspect(
        target_requirements: object,
        target_runtime: object,
        target_staging: object,
        lease: object,
        expected_nested_target_paths: object,
    ) -> RepositoryExecutableShebangNestedTargetResolutionReceipt:
        return inspect_staged_executable_shebang_nested_targets(
            target_requirements,
            expected_target_runtime=target_runtime,
            expected_target_staging=target_staging,
            lease=lease,
            expected_nested_target_paths=expected_nested_target_paths,
        )

    def _assert_invalid(
        self,
        target_requirements: object,
        target_runtime: object,
        target_staging: object,
        lease: object,
        expected_nested_target_paths: object,
        *,
        private_marker: str = "private-nested-target-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            self._inspect(
                target_requirements,
                target_runtime,
                target_staging,
                lease,
                expected_nested_target_paths,
            )
        self.assertEqual(str(caught.exception), FIXED_NESTED_TARGET_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    @classmethod
    def _one_nested_chain(
        cls,
        temporary: str,
        *,
        first_target_content: bytes | None = None,
        nested_target_content: bytes = b"private nested target bytes\n",
        include_source_native: bool = False,
        shared_source_target: bool = True,
    ) -> tuple[object, ...]:
        (
            root,
            outside,
            search_one,
            search_two,
            executable_stage_root,
            target_stage_root,
        ) = cls._workspace(temporary)
        base = Path(temporary).resolve(strict=True)
        first_target = base / "private-depth-one-target"
        nested_target = base / "private-depth-two-target"
        if first_target_content is None:
            first_target_content = (
                b"#!"
                + os.fsencode(nested_target)
                + b" --private-opaque-tail\nprivate-first-body\n"
            )
        cls._write_target(first_target, first_target_content)
        cls._write_target(nested_target, nested_target_content)
        source_shebang = b"#!" + os.fsencode(first_target) + b"\n"
        if include_source_native:
            bare = _ELF
            relative = source_shebang
        elif shared_source_target:
            bare = source_shebang
            relative = source_shebang
        else:
            bare = source_shebang
            relative = None
        cls._set_contents(
            root,
            search_one,
            bare=bare,
            relative=relative,
        )
        registration = cls._registration(root)
        chain = cls._stage_target_requirements(
            registration,
            search_directories=(search_one, search_two),
            executable_stage_root=executable_stage_root,
            target_stage_root=target_stage_root,
            target_paths=(first_target,),
        )
        return (
            root,
            outside,
            search_one,
            search_two,
            executable_stage_root,
            target_stage_root,
            first_target,
            nested_target,
            *chain,
        )

    def test_receipt_correspondence_privacy_depth_and_lease_immutability(
        self,
    ) -> None:
        nested_content = b"private-depth-two-content-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(
                temporary,
                nested_target_content=nested_content,
                include_source_native=True,
            )
            (
                root,
                outside,
                search_one,
                search_two,
                _executable_stage_root,
                target_stage_root,
                first_target,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            before = self._lease_snapshot(target_lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (
                    root,
                    outside,
                    search_one,
                    search_two,
                    first_target.parent,
                    target_stage_root,
                )
            )
            try:
                receipt = self._inspect(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                repeated = self._inspect(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                self.assertEqual(receipt, repeated)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangNestedTargetResolutionReceipt,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION,
                    1,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_KIND,
                    "repository_executable_shebang_nested_target_resolution",
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND,
                    (
                        "repository_executable_shebang_nested_target_"
                        "resolution_validation"
                    ),
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_MEASUREMENT_KIND,
                    (
                        "repository_executable_shebang_nested_target_"
                        "measurement"
                    ),
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENT_KIND,
                    (
                        "repository_executable_shebang_nested_target_"
                        "requirement"
                    ),
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_BINDING_KIND,
                    "repository_executable_shebang_nested_target_binding",
                )
                self.assertEqual(MEASUREMENT_SOURCE, "controller_measured")
                self.assertEqual(
                    RESOLUTION_SCOPE,
                    "posix_absolute_shebang_nested_target_nofollow_v1",
                )
                self.assertEqual(RESOLUTION_DEPTH, 2)
                self.assertEqual(MAXIMUM_RESOLUTION_DEPTH, 2)
                self.assertEqual(
                    CYCLE_SCOPE,
                    "immediate_target_reentry_v1",
                )

                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                self.assertEqual(
                    receipt.target_shebang_requirements_receipt_digest,
                    target_requirements.receipt_digest,
                )
                self.assertEqual(
                    receipt.target_runtime_manifest_receipt_digest,
                    target_runtime.receipt_digest,
                )
                for field in (
                    "target_staging_receipt_digest",
                    "target_resolution_receipt_digest",
                    "shebang_requirements_receipt_digest",
                    "runtime_manifest_receipt_digest",
                    "staging_receipt_digest",
                    "registration_digest",
                    "repository_ref",
                    "verification_commands_digest",
                    "resolution_context_digest",
                    "source_staging_context_digest",
                    "target_path_context_digest",
                    "target_staging_context_digest",
                ):
                    self.assertEqual(
                        getattr(receipt, field),
                        getattr(target_requirements, field),
                    )
                self.assertEqual(receipt.resolution_depth, 2)
                self.assertEqual(receipt.maximum_resolution_depth, 2)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.nested_target_requirement_count, 1)
                self.assertEqual(receipt.target_native_not_applicable_count, 0)
                self.assertEqual(receipt.source_native_not_applicable_count, 1)
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(receipt.total_measured_bytes, len(nested_content))
                self.assertEqual(len(receipt.measurements), 1)

                measurement = receipt.measurements[0]
                self.assertIsInstance(
                    measurement,
                    RepositoryExecutableShebangNestedTargetMeasurement,
                )
                self.assertEqual(set(measurement.to_canonical()), MEASUREMENT_KEYS)
                self.assertEqual(measurement.content_bytes, len(nested_content))
                self.assertEqual(
                    measurement.content_digest,
                    "sha256:" + hashlib.sha256(nested_content).hexdigest(),
                )
                for value in (
                    measurement.nested_target_path_ref,
                    measurement.filesystem_identity_ref,
                    measurement.metadata_digest,
                    measurement.nested_target_measurement_ref,
                    receipt.nested_target_path_context_digest,
                ):
                    self.assertRegex(value, _DIGEST_PATTERN)

                by_upstream_ref = {
                    value.target_shebang_requirement_ref: value
                    for value in target_requirements.requirements
                }
                requirement_by_ref = {}
                for value in receipt.requirements:
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangNestedTargetRequirement,
                    )
                    self.assertEqual(set(value.to_canonical()), REQUIREMENT_KEYS)
                    upstream = by_upstream_ref[
                        value.target_shebang_requirement_ref
                    ]
                    for field in (
                        "staged_file_ref",
                        "runtime_file_ref",
                        "requirement_ref",
                        "target_requirement_ref",
                        "target_stage_requirement_ref",
                        "target_runtime_requirement_ref",
                        "target_shebang_requirement_ref",
                        "runtime_classification",
                        "target_measurement_ref",
                        "target_staged_file_ref",
                        "target_runtime_file_ref",
                        "target_runtime_classification",
                        "target_shebang_directive_ref",
                        "interpreter_token_ref",
                        "argument_tail_ref",
                    ):
                        self.assertEqual(
                            getattr(value, field),
                            getattr(upstream, field),
                        )
                    if upstream.disposition == "native_not_applicable":
                        self.assertEqual(
                            value.disposition,
                            "source_native_not_applicable",
                        )
                        self.assertIsNone(value.nested_target_measurement_ref)
                    else:
                        self.assertEqual(
                            value.disposition,
                            "direct_absolute_nested_target_measured",
                        )
                        self.assertEqual(
                            value.nested_target_measurement_ref,
                            measurement.nested_target_measurement_ref,
                        )
                    self.assertRegex(
                        value.nested_target_requirement_ref,
                        _DIGEST_PATTERN,
                    )
                    requirement_by_ref[
                        value.nested_target_requirement_ref
                    ] = value

                for value, upstream in zip(
                    receipt.bindings,
                    target_requirements.bindings,
                    strict=True,
                ):
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangNestedTargetBinding,
                    )
                    self.assertEqual(set(value.to_canonical()), BINDING_KEYS)
                    for field in (
                        "command_kind",
                        "command_id",
                        "command_digest",
                        "staged_file_ref",
                        "runtime_file_ref",
                        "requirement_ref",
                        "target_requirement_ref",
                        "target_stage_requirement_ref",
                        "target_runtime_requirement_ref",
                        "target_shebang_requirement_ref",
                    ):
                        self.assertEqual(
                            getattr(value, field),
                            getattr(upstream, field),
                        )
                    self.assertIn(
                        value.nested_target_requirement_ref,
                        requirement_by_ref,
                    )

                evidence = receipt.to_evidence()
                self.assertEqual(set(evidence), EVIDENCE_KEYS)
                self.assertEqual(
                    evidence["kind"],
                    REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND,
                )
                self.assertEqual(evidence["effect_class"], 0)
                self.assertEqual(evidence["validation_mode"], "read_only")
                self.assertEqual(evidence["resolution_depth"], 2)
                self.assertEqual(evidence["maximum_resolution_depth"], 2)
                self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
                for field in (
                    "requirement_count",
                    "command_count",
                    "nested_target_requirement_count",
                    "target_native_not_applicable_count",
                    "source_native_not_applicable_count",
                    "unique_nested_target_count",
                    "total_measured_bytes",
                ):
                    self.assertEqual(evidence[field], getattr(receipt, field))
                for true_fact in (
                    "active_target_stage_lease_verified_at_measurement",
                    "bounded_resolution_depth_enforced",
                    "exact_nested_target_path_lookup_performed",
                    "exact_nested_target_path_set_verified",
                    "exact_target_requirements_correspondence_verified",
                    "immediate_target_identity_reentry_excluded",
                    "immediate_target_path_reentry_excluded",
                    "nested_target_namespace_reopen_verified",
                    "nested_target_path_reopen_performed",
                    "path_lookup_performed",
                    "requirement_binding_correspondence_verified",
                    "sequential_nested_target_measurement_complete",
                    "staged_byte_correspondence_verified",
                    "target_staging_root_ancestor_excluded",
                    "two_pass_nested_target_measurement_verified",
                ):
                    self.assertIs(evidence[true_fact], True, true_fact)
                for false_fact in (
                    "action_receipt_issued",
                    "ambient_path_search_performed",
                    "atomic_snapshot_verified",
                    "authority_granted",
                    "authorization_verified",
                    "billing_eligible",
                    "broader_protected_root_exclusion_verified",
                    "capacity_eligible",
                    "circuit_eligible",
                    "current_lease_activity_verified",
                    "current_source_freshness_verified",
                    "dependency_environment_coverage_verified",
                    "dispatch_enabled",
                    "durable_control_plane_persistence_enabled",
                    "dynamic_loader_identity_verified",
                    "effective_interpreter_resolution_verified",
                    "effective_invocability_verified",
                    "environment_coverage_verified",
                    "execution_enabled",
                    "external_hardlink_alias_excluded",
                    "external_mount_alias_excluded",
                    "external_writable_descriptor_absence_verified",
                    "filesystem_immutability_verified",
                    "first_hop_target_path_reopen_performed",
                    "future_execution_correspondence_verified",
                    "generic_cycle_exclusion_verified",
                    "harness_invocation_performed",
                    "interpreter_argument_semantics_verified",
                    "interpreter_authenticity_verified",
                    "interpreter_compatibility_verified",
                    "interpreter_identity_verified",
                    "interpreter_provenance_verified",
                    "launcher_semantics_verified",
                    "lease_cleanup_performed",
                    "lease_mutated",
                    "live_execution_eligible",
                    "nested_target_runtime_classification_verified",
                    "proposal_lineage_extended",
                    "receipt_authenticity_verified",
                    "recursive_shebang_resolution_verified",
                    "route_eligible",
                    "same_uid_tamper_exclusion_verified",
                    "source_chain_cycle_exclusion_verified",
                    "source_path_reentry_exclusion_verified",
                    "source_staging_root_reentry_exclusion_verified",
                    "subprocess_invocation_performed",
                    "target_staging_root_path_reopen_performed",
                    "toolchain_completeness_verified",
                    "worktree_integration_enabled",
                ):
                    self.assertIs(evidence[false_fact], False, false_fact)

                aggregate = "\n".join(
                    (
                        json.dumps(canonical, sort_keys=True),
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        *(repr(value) for value in receipt.measurements),
                        *(repr(value) for value in receipt.requirements),
                        *(repr(value) for value in receipt.bindings),
                    )
                )
                for private_value in (
                    str(first_target),
                    str(nested_target),
                    nested_content.decode("ascii").strip(),
                    "private-opaque-tail",
                    "private-first-body",
                ):
                    self.assertNotIn(private_value, aggregate)
                self.assertFalse(hasattr(receipt, "__dict__"))
                self.assertFalse(hasattr(measurement, "__dict__"))
                with self.assertRaises(FrozenInstanceError):
                    receipt.resolution_depth = 3
                with self.assertRaises(FrozenInstanceError):
                    measurement.content_bytes = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirements[0].disposition = "forged"
                self.assertEqual(
                    tuple(
                        self._tree_snapshot(path)
                        for path in (
                            root,
                            outside,
                            search_one,
                            search_two,
                            first_target.parent,
                            target_stage_root,
                        )
                    ),
                    trees_before,
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_fixed_depth_leaves_new_target_shebang_opaque_and_unopened(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve(strict=True)
            third_target = base / "private-depth-three-never-opened"
            second_content = (
                b"#!"
                + os.fsencode(third_target)
                + b" --private-third-tail\nprivate-second-body\n"
            )
            values = self._one_nested_chain(
                temporary,
                nested_target_content=second_content,
            )
            (
                _root,
                _outside,
                _search_one,
                _search_two,
                _executable_stage_root,
                _target_stage_root,
                _first_target,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            measured_paths: list[tuple[str, ...]] = []
            real_measure = nested_module._BUILTIN_MEASURE_TARGET_SET

            def observe(
                paths: tuple[Path, ...],
                **kwargs: object,
            ):
                measured_paths.append(paths)
                return real_measure(paths, **kwargs)

            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    side_effect=observe,
                ):
                    receipt = self._inspect(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                self.assertEqual(
                    measured_paths,
                    [(str(nested_target),), (str(nested_target),)],
                )
                self.assertFalse(third_target.exists())
                self.assertEqual(receipt.resolution_depth, 2)
                self.assertEqual(receipt.maximum_resolution_depth, 2)
                evidence = receipt.to_evidence()
                self.assertIs(
                    evidence["recursive_shebang_resolution_verified"],
                    False,
                )
                self.assertIs(
                    evidence["bounded_resolution_depth_enforced"],
                    True,
                )
                aggregate = json.dumps(receipt.to_canonical(), sort_keys=True)
                self.assertNotIn(str(third_target), aggregate)
                self.assertNotIn("private-third-tail", aggregate)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_shared_nested_target_is_measured_once_with_distinct_lineage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            try:
                receipt = self._inspect(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                self.assertEqual(target_requirements.requirement_count, 2)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.nested_target_requirement_count, 2)
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(len(receipt.measurements), 1)
                self.assertEqual(
                    {
                        value.nested_target_measurement_ref
                        for value in receipt.requirements
                    },
                    {receipt.measurements[0].nested_target_measurement_ref},
                )
                self.assertEqual(
                    len(
                        {
                            value.nested_target_requirement_ref
                            for value in receipt.requirements
                        }
                    ),
                    2,
                )
                self.assertEqual(
                    tuple(value.command_id for value in receipt.bindings),
                    tuple(value.command_id for value in target_requirements.bindings),
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_output_projection_rejects_split_measurements_for_one_shared_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            try:
                receipt = self._inspect(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                original_measurement = receipt.measurements[0]
                alternate_path_ref = "sha256:" + "1" * 64
                alternate_identity_ref = "sha256:" + "2" * 64
                alternate_metadata_digest = "sha256:" + "3" * 64
                alternate_content_digest = "sha256:" + "4" * 64
                measurement_reference = nested_module._measurement_ref_projection(
                    nested_target_path_ref=alternate_path_ref,
                    filesystem_identity_ref=alternate_identity_ref,
                    metadata_digest=alternate_metadata_digest,
                    content_digest=alternate_content_digest,
                    content_bytes=original_measurement.content_bytes,
                )
                alternate_measurement = replace(
                    original_measurement,
                    nested_target_path_ref=alternate_path_ref,
                    filesystem_identity_ref=alternate_identity_ref,
                    metadata_digest=alternate_metadata_digest,
                    content_digest=alternate_content_digest,
                    nested_target_measurement_ref=canonical_digest(
                        measurement_reference
                    ),
                )
                second = receipt.requirements[1]
                requirement_reference = nested_module._requirement_ref_projection(
                    staged_file_ref=second.staged_file_ref,
                    runtime_file_ref=second.runtime_file_ref,
                    requirement_ref=second.requirement_ref,
                    target_requirement_ref=second.target_requirement_ref,
                    target_stage_requirement_ref=(
                        second.target_stage_requirement_ref
                    ),
                    target_runtime_requirement_ref=(
                        second.target_runtime_requirement_ref
                    ),
                    target_shebang_requirement_ref=(
                        second.target_shebang_requirement_ref
                    ),
                    runtime_classification=second.runtime_classification,
                    target_measurement_ref=second.target_measurement_ref,
                    target_staged_file_ref=second.target_staged_file_ref,
                    target_runtime_file_ref=second.target_runtime_file_ref,
                    target_runtime_classification=(
                        second.target_runtime_classification
                    ),
                    target_shebang_directive_ref=(
                        second.target_shebang_directive_ref
                    ),
                    interpreter_token_ref=second.interpreter_token_ref,
                    argument_tail_ref=second.argument_tail_ref,
                    disposition=second.disposition,
                    nested_target_measurement_ref=(
                        alternate_measurement.nested_target_measurement_ref
                    ),
                )
                alternate_requirement = replace(
                    second,
                    nested_target_measurement_ref=(
                        alternate_measurement.nested_target_measurement_ref
                    ),
                    nested_target_requirement_ref=canonical_digest(
                        requirement_reference
                    ),
                )
                bindings = tuple(
                    replace(
                        value,
                        nested_target_requirement_ref=(
                            alternate_requirement
                            .nested_target_requirement_ref
                        ),
                    )
                    if value.target_shebang_requirement_ref
                    == second.target_shebang_requirement_ref
                    else value
                    for value in receipt.bindings
                )
                forged = replace(
                    receipt,
                    measurements=(
                        original_measurement,
                        alternate_measurement,
                    ),
                    requirements=(
                        receipt.requirements[0],
                        alternate_requirement,
                    ),
                    bindings=bindings,
                    unique_nested_target_count=2,
                    total_measured_bytes=(
                        original_measurement.content_bytes
                        + alternate_measurement.content_bytes
                    ),
                )
                # Every replacement record is independently canonical.  The
                # receipt must still reject because both rows name the same
                # staged depth-one runtime file but diverge at depth two.
                alternate_measurement.to_canonical()
                alternate_requirement.to_canonical()
                for value in bindings:
                    value.to_canonical()
                with self.assertRaises(ValueError):
                    forged.to_canonical()
            finally:
                target_lease.close()
                executable_lease.close()

    def test_source_native_zero_file_chain_uses_no_path_or_descriptor_read(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target_stage_root.rmdir()
            self._set_contents(root, search_one, bare=_ELF, relative=_ELF)
            registration = self._registration(root)
            (
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(),
            )
            before = self._lease_snapshot(target_lease)
            try:
                with (
                    patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_NESTED_TARGET_PATH",
                        side_effect=AssertionError("nested path measurement"),
                    ) as measure_path,
                    patch.object(
                        nested_module,
                        "_BUILTIN_TARGET_DESCRIPTOR_REMEASUREMENT",
                        side_effect=AssertionError("staged descriptor read"),
                    ) as remeasure,
                ):
                    receipt = self._inspect(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (),
                    )
                measure_path.assert_not_called()
                remeasure.assert_not_called()
                self.assertEqual(self._lease_snapshot(target_lease), before)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.nested_target_requirement_count, 0)
                self.assertEqual(receipt.target_native_not_applicable_count, 0)
                self.assertEqual(receipt.source_native_not_applicable_count, 2)
                self.assertEqual(receipt.unique_nested_target_count, 0)
                self.assertEqual(receipt.total_measured_bytes, 0)
                self.assertEqual(receipt.measurements, ())
                self.assertTrue(
                    all(
                        value.disposition == "source_native_not_applicable"
                        and value.nested_target_measurement_ref is None
                        for value in receipt.requirements
                    )
                )
                self.assertFalse(target_stage_root.exists())
            finally:
                target_lease.close()
                executable_lease.close()

    def test_direct_target_native_classifications_need_no_nested_path(
        self,
    ) -> None:
        for case, content in (("elf", _ELF), ("mach-o", _MACH_O)):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                values = self._one_nested_chain(
                    temporary,
                    first_target_content=content,
                )
                (
                    *_prefix,
                    executable_lease,
                    _source_staging,
                    _source_runtime,
                    _source_requirements,
                    _target_resolution,
                    target_lease,
                    target_staging,
                    target_runtime,
                    target_requirements,
                ) = values
                measured_paths: list[tuple[str, ...]] = []
                real_measure = nested_module._BUILTIN_MEASURE_TARGET_SET

                def observe(
                    paths: tuple[Path, ...],
                    **kwargs: object,
                ):
                    measured_paths.append(paths)
                    return real_measure(paths, **kwargs)

                try:
                    with patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_TARGET_SET",
                        side_effect=observe,
                    ):
                        receipt = self._inspect(
                            target_requirements,
                            target_runtime,
                            target_staging,
                            target_lease,
                            (),
                        )
                    self.assertEqual(measured_paths, [(), ()])
                    self.assertEqual(receipt.nested_target_requirement_count, 0)
                    self.assertEqual(
                        receipt.target_native_not_applicable_count,
                        2,
                    )
                    self.assertEqual(
                        receipt.source_native_not_applicable_count,
                        0,
                    )
                    self.assertEqual(receipt.unique_nested_target_count, 0)
                    self.assertTrue(
                        all(
                            value.disposition
                            == "target_native_not_applicable"
                            and value.nested_target_measurement_ref is None
                            for value in receipt.requirements
                        )
                    )
                finally:
                    target_lease.close()
                    executable_lease.close()

    def test_invalid_target_classifications_and_noncanonical_tokens_fail_before_lookup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as outer:
            base = Path(outer).resolve(strict=True)
            canonical = base / "canonical-nested-target"
            self._write_target(canonical, b"canonical nested target\n")
            cases: tuple[tuple[str, bytes, tuple[Path, ...]], ...] = (
                ("non-absolute", b"#!private-launcher\n", ()),
                ("unsupported", b"#! /private/launcher\n", ()),
                ("unknown", b"ordinary target bytes\n", ()),
                ("unknown-empty", b"", ()),
                ("root", b"#!/\n", (Path("/"),)),
                (
                    "repeated-slash",
                    b"#!" + os.fsencode(base) + b"//canonical-nested-target\n",
                    (canonical,),
                ),
                (
                    "trailing-slash",
                    b"#!" + os.fsencode(canonical) + b"/\n",
                    (canonical,),
                ),
                (
                    "dot-component",
                    b"#!" + os.fsencode(base) + b"/./canonical-nested-target\n",
                    (canonical,),
                ),
                (
                    "dot-dot-component",
                    b"#!"
                    + os.fsencode(base)
                    + b"/child/../canonical-nested-target\n",
                    (canonical,),
                ),
            )
            for case, first_content, expected_paths in cases:
                with (
                    self.subTest(case=case),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    values = self._one_nested_chain(
                        temporary,
                        first_target_content=first_content,
                    )
                    (
                        *_prefix,
                        executable_lease,
                        _source_staging,
                        _source_runtime,
                        _source_requirements,
                        _target_resolution,
                        target_lease,
                        target_staging,
                        target_runtime,
                        target_requirements,
                    ) = values
                    try:
                        with patch.object(
                            nested_module,
                            "_BUILTIN_MEASURE_TARGET_SET",
                            side_effect=AssertionError("nested lookup"),
                        ) as measure:
                            self._assert_invalid(
                                target_requirements,
                                target_runtime,
                                target_staging,
                                target_lease,
                                expected_paths,
                            )
                        measure.assert_not_called()
                    finally:
                        target_lease.close()
                        executable_lease.close()

    def test_expected_nested_paths_are_exact_typed_complete_and_ordered(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            base = Path(temporary).resolve(strict=True)
            first_one = base / "first-depth-one"
            first_two = base / "second-depth-one"
            nested_one = base / "first-depth-two"
            nested_two = base / "second-depth-two"
            other = base / "other-depth-two"
            self._write_target(
                first_one,
                b"#!" + os.fsencode(nested_one) + b"\n",
            )
            self._write_target(
                first_two,
                b"#!" + os.fsencode(nested_two) + b"\n",
            )
            for path, content in (
                (nested_one, b"first nested bytes\n"),
                (nested_two, b"second nested bytes\n"),
                (other, b"other nested bytes\n"),
            ):
                self._write_target(path, content)
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(first_one) + b"\n",
                relative=b"#!" + os.fsencode(first_two) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(first_one, first_two),
            )
            concrete_path_type = type(Path())

            class DerivedPath(concrete_path_type):
                pass

            try:
                for case, supplied in (
                    ("list", [nested_one, nested_two]),
                    ("path", nested_one),
                    ("string-entry", (str(nested_one), nested_two)),
                    ("derived-entry", (DerivedPath(nested_one), nested_two)),
                    ("missing", (nested_one,)),
                    ("extra", (nested_one, nested_two, other)),
                    ("duplicate", (nested_one, nested_one)),
                    ("reversed", (nested_two, nested_one)),
                    ("wrong", (other, nested_two)),
                    ("boolean", True),
                ):
                    with self.subTest(case=case):
                        self._assert_invalid(
                            target_requirements,
                            target_runtime,
                            target_staging,
                            target_lease,
                            supplied,
                        )
                receipt = self._inspect(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_one, nested_two),
                )
                self.assertEqual(receipt.unique_nested_target_count, 2)
                self.assertEqual(
                    tuple(value.content_bytes for value in receipt.measurements),
                    (len(b"first nested bytes\n"), len(b"second nested bytes\n")),
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_exact_path_reentry_cycles_reject_before_nested_lookup(self) -> None:
        for case in ("self", "other-known-target"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    root,
                    _outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                base = Path(temporary).resolve(strict=True)
                first = base / "cycle-first"
                other = base / "cycle-other"
                if case == "self":
                    self._write_target(
                        first,
                        b"#!" + os.fsencode(first) + b"\n",
                    )
                    self._set_contents(
                        root,
                        search_one,
                        bare=b"#!" + os.fsencode(first) + b"\n",
                    )
                    target_paths = (first,)
                    nested_paths = (first,)
                else:
                    self._write_target(
                        first,
                        b"#!" + os.fsencode(other) + b"\n",
                    )
                    self._write_target(other, _ELF)
                    self._set_contents(
                        root,
                        search_one,
                        bare=b"#!" + os.fsencode(first) + b"\n",
                        relative=b"#!" + os.fsencode(other) + b"\n",
                    )
                    target_paths = (first, other)
                    nested_paths = (other,)
                registration = self._registration(root)
                (
                    executable_lease,
                    _source_staging,
                    _source_runtime,
                    _source_requirements,
                    _target_resolution,
                    target_lease,
                    target_staging,
                    target_runtime,
                    target_requirements,
                ) = self._stage_target_requirements(
                    registration,
                    search_directories=(search_one, search_two),
                    executable_stage_root=executable_stage_root,
                    target_stage_root=target_stage_root,
                    target_paths=target_paths,
                )
                try:
                    with patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_TARGET_SET",
                        side_effect=AssertionError("cycle lookup"),
                    ) as measure:
                        self._assert_invalid(
                            target_requirements,
                            target_runtime,
                            target_staging,
                            target_lease,
                            nested_paths,
                        )
                    measure.assert_not_called()
                finally:
                    target_lease.close()
                    executable_lease.close()

    def test_hardlink_reentry_and_distinct_nested_aliases_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            base = Path(temporary).resolve(strict=True)
            first = base / "identity-cycle-first"
            alias = base / "identity-cycle-alias"
            self._write_target(
                first,
                b"#!" + os.fsencode(alias) + b"\n",
            )
            os.link(first, alias)
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(first) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(first,),
            )
            try:
                self._assert_invalid(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (alias,),
                )
            finally:
                target_lease.close()
                executable_lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            base = Path(temporary).resolve(strict=True)
            first_one = base / "alias-first-one"
            first_two = base / "alias-first-two"
            nested_one = base / "alias-nested-one"
            nested_two = base / "alias-nested-two"
            self._write_target(nested_one, b"shared nested inode\n")
            os.link(nested_one, nested_two)
            self._write_target(
                first_one,
                b"#!" + os.fsencode(nested_one) + b"\n",
            )
            self._write_target(
                first_two,
                b"#!" + os.fsencode(nested_two) + b"\n",
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(first_one) + b"\n",
                relative=b"#!" + os.fsencode(first_two) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(first_one, first_two),
            )
            try:
                self._assert_invalid(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_one, nested_two),
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_target_stage_root_descendant_is_rejected_without_measurement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            base = Path(temporary).resolve(strict=True)
            first = base / "stage-overlap-first"
            nested = target_stage_root / "private-stage-root-descendant"
            self._write_target(
                first,
                b"#!" + os.fsencode(nested) + b"\n",
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(first) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(first,),
            )
            self._write_target(nested, b"must not be measured\n")
            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    side_effect=AssertionError("overlap measurement"),
                ) as measure:
                    self._assert_invalid(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested,),
                    )
                measure.assert_not_called()
            finally:
                nested.unlink(missing_ok=True)
                target_lease.close()
                executable_lease.close()

    def test_missing_symlink_nonexecutable_and_nonregular_nested_targets_fail(
        self,
    ) -> None:
        cases = (
            "missing",
            "symlink",
            "non-executable",
            "directory",
            "intermediate-symlink",
        )
        for case in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    root,
                    _outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                base = Path(temporary).resolve(strict=True)
                first = base / "invalid-leaf-first"
                nested = base / "invalid-leaf-parent" / "invalid-leaf"
                if case == "missing":
                    nested.parent.mkdir()
                elif case == "symlink":
                    actual = base / "invalid-leaf-actual"
                    self._write_target(actual, b"actual nested bytes\n")
                    nested.parent.mkdir()
                    nested.symlink_to(actual)
                elif case == "non-executable":
                    self._write_target(nested, b"non-executable bytes\n")
                    nested.chmod(0o644)
                elif case == "directory":
                    nested.mkdir(parents=True)
                else:
                    actual_parent = base / "actual-nested-parent"
                    actual = actual_parent / "invalid-leaf"
                    self._write_target(actual, b"actual nested bytes\n")
                    linked_parent = base / "linked-nested-parent"
                    linked_parent.symlink_to(actual_parent, target_is_directory=True)
                    nested = linked_parent / "invalid-leaf"
                self._write_target(
                    first,
                    b"#!" + os.fsencode(nested) + b"\n",
                )
                self._set_contents(
                    root,
                    search_one,
                    bare=b"#!" + os.fsencode(first) + b"\n",
                )
                registration = self._registration(root)
                (
                    executable_lease,
                    _source_staging,
                    _source_runtime,
                    _source_requirements,
                    _target_resolution,
                    target_lease,
                    target_staging,
                    target_runtime,
                    target_requirements,
                ) = self._stage_target_requirements(
                    registration,
                    search_directories=(search_one, search_two),
                    executable_stage_root=executable_stage_root,
                    target_stage_root=target_stage_root,
                    target_paths=(first,),
                )
                before = self._lease_snapshot(target_lease)
                try:
                    self._assert_invalid(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested,),
                        private_marker=str(nested),
                    )
                    self.assertEqual(self._lease_snapshot(target_lease), before)
                finally:
                    target_lease.close()
                    executable_lease.close()

    def test_wrong_types_forged_reordered_transplanted_and_inactive_inputs(
        self,
    ) -> None:
        zero_digest = "sha256:" + "0" * 64
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as other_temporary,
        ):
            values = self._one_nested_chain(temporary)
            other_values = self._one_nested_chain(
                other_temporary,
                nested_target_content=b"other private nested bytes\n",
            )
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            (
                *_other_prefix,
                other_nested_target,
                other_executable_lease,
                _other_source_staging,
                _other_source_runtime,
                _other_source_requirements,
                _other_target_resolution,
                other_target_lease,
                other_target_staging,
                other_target_runtime,
                other_target_requirements,
            ) = other_values
            unused_root = Path(temporary) / "unused-target-stage-lease"
            unused_root.mkdir(mode=0o700)
            unused = RepositoryExecutableShebangTargetStageLease(unused_root)
            equal_staging = replace(target_staging)
            equal_runtime = replace(target_runtime)
            equal_requirements = replace(target_requirements)
            original_pid = target_lease._owner_pid
            original_files = target_lease._files
            before = self._lease_snapshot(target_lease)
            direct_index = next(
                index
                for index, value in enumerate(target_requirements.requirements)
                if value.disposition == "absolute_interpreter_token"
            )
            forged_item = replace(
                target_requirements.requirements[direct_index],
                interpreter_token_ref=zero_digest,
            )
            forged_items = list(target_requirements.requirements)
            forged_items[direct_index] = forged_item
            cases = (
                (
                    "requirements-type",
                    object(),
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "runtime-type",
                    target_requirements,
                    object(),
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "staging-type",
                    target_requirements,
                    target_runtime,
                    object(),
                    target_lease,
                    (nested_target,),
                ),
                (
                    "lease-type",
                    target_requirements,
                    target_runtime,
                    target_staging,
                    object(),
                    (nested_target,),
                ),
                (
                    "inactive-lease",
                    target_requirements,
                    target_runtime,
                    target_staging,
                    unused,
                    (nested_target,),
                ),
                (
                    "equal-distinct-staging",
                    target_requirements,
                    target_runtime,
                    equal_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "forged-requirement",
                    replace(
                        target_requirements,
                        requirements=tuple(forged_items),
                    ),
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "reordered-requirements",
                    replace(
                        target_requirements,
                        requirements=tuple(
                            reversed(target_requirements.requirements)
                        ),
                    ),
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "reordered-bindings",
                    replace(
                        target_requirements,
                        bindings=tuple(reversed(target_requirements.bindings)),
                    ),
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "forged-lineage",
                    replace(
                        target_requirements,
                        registration_digest=zero_digest,
                    ),
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "transplanted-requirements",
                    other_target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "transplanted-runtime",
                    target_requirements,
                    other_target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "transplanted-staging",
                    target_requirements,
                    target_runtime,
                    other_target_staging,
                    target_lease,
                    (nested_target,),
                ),
                (
                    "transplanted-lease",
                    target_requirements,
                    target_runtime,
                    target_staging,
                    other_target_lease,
                    (nested_target,),
                ),
            )
            try:
                for (
                    case,
                    candidate_requirements,
                    candidate_runtime,
                    candidate_staging,
                    candidate_lease,
                    candidate_paths,
                ) in cases:
                    with self.subTest(case=case):
                        self._assert_invalid(
                            candidate_requirements,
                            candidate_runtime,
                            candidate_staging,
                            candidate_lease,
                            candidate_paths,
                        )
                self.assertEqual(self._lease_snapshot(target_lease), before)

                equivalent = self._inspect(
                    equal_requirements,
                    equal_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                genuine = self._inspect(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                self.assertEqual(equivalent, genuine)

                target_lease._owner_pid = original_pid + 1
                self._assert_invalid(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                target_lease._owner_pid = original_pid
                target_lease._files = tuple(list(original_files))
                self._assert_invalid(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
                target_lease._files = original_files

                target_lease.close()
                self._assert_invalid(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
            finally:
                target_lease._owner_pid = original_pid
                target_lease._files = original_files
                target_lease.close()
                executable_lease.close()
                other_target_lease.close()
                other_executable_lease.close()
                unused.close()
            self.assertNotEqual(nested_target, other_nested_target)

    def test_public_and_upstream_monkeypatches_cannot_replace_frozen_proof_graph(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            baseline = self._inspect(
                target_requirements,
                target_runtime,
                target_staging,
                target_lease,
                (nested_target,),
            )
            patch_specs = (
                (
                    nested_module,
                    "_measurement_projection",
                    {"forged": "measurement"},
                ),
                (
                    nested_module,
                    "_requirement_projection",
                    {"forged": "requirement"},
                ),
                (
                    nested_module,
                    "_receipt_projection",
                    {"forged": "receipt"},
                ),
                (
                    nested_module,
                    "_target_requirements_projection_v1",
                    {"forged": "upstream"},
                ),
                (
                    nested_module,
                    "_target_split_directive_v1",
                    (b"/forged/interpreter", None, None),
                ),
                (
                    nested_module,
                    "canonical_json",
                    "{}",
                ),
                (
                    nested_module,
                    "Path",
                    AssertionError("public Path constructor bypass"),
                ),
                (
                    nested_module,
                    "_DerivedNestedRequirement",
                    AssertionError("live derived constructor bypass"),
                ),
                (
                    nested_module,
                    "_MeasuredNestedTarget",
                    AssertionError("live measured constructor bypass"),
                ),
                (
                    nested_module._DerivedNestedRequirement,
                    "__eq__",
                    AssertionError("derived dataclass equality bypass"),
                ),
                (
                    nested_module._MeasuredNestedTarget,
                    "__eq__",
                    AssertionError("measured dataclass equality bypass"),
                ),
                (
                    target_requirements_module,
                    "inspect_staged_executable_shebang_target_requirements",
                    AssertionError("dynamic target requirements inspector"),
                ),
                (
                    RepositoryExecutableShebangTargetRequirementsReceipt,
                    "to_canonical",
                    AssertionError("public upstream canonical"),
                ),
            )
            before = self._lease_snapshot(target_lease)
            try:
                with ExitStack() as stack:
                    bypasses = []
                    # Replace only this module's public library references.
                    # Mutating attributes on Python's singleton ``os`` module
                    # would also mutate the already-captured upstream
                    # inspectors and is correctly a fail-closed condition.
                    stack.enter_context(
                        patch.object(nested_module, "os", object())
                    )
                    stack.enter_context(
                        patch.object(nested_module, "hashlib", object())
                    )
                    stack.enter_context(
                        patch.object(nested_module, "unicodedata", object())
                    )
                    for owner, name, behavior in patch_specs:
                        kwargs = (
                            {"side_effect": behavior}
                            if isinstance(behavior, BaseException)
                            else {"return_value": behavior}
                        )
                        bypasses.append(
                            stack.enter_context(patch.object(owner, name, **kwargs))
                        )
                    observed = self._inspect(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                self.assertEqual(observed, baseline)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                for bypass in bypasses:
                    bypass.assert_not_called()
            finally:
                target_lease.close()
                executable_lease.close()

    def test_three_chain_reproductions_two_measurements_and_closing_anchors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            proof_order: list[str] = []
            real_snapshot = nested_module._BUILTIN_VALIDATED_CHAIN_SNAPSHOT
            real_measure = nested_module._BUILTIN_MEASURE_TARGET_SET

            def record_snapshot(*args: object, **kwargs: object):
                proof_order.append("chain_snapshot")
                return real_snapshot(*args, **kwargs)

            def record_measurement(*args: object, **kwargs: object):
                proof_order.append("nested_measurement")
                return real_measure(*args, **kwargs)

            before = self._lease_snapshot(target_lease)
            try:
                with (
                    patch.object(
                        nested_module,
                        "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT",
                        side_effect=record_snapshot,
                    ) as snapshot,
                    patch.object(
                        nested_module,
                        "_BUILTIN_INSPECT_TARGET_RUNTIME",
                        wraps=nested_module._BUILTIN_INSPECT_TARGET_RUNTIME,
                    ) as reproduce_runtime,
                    patch.object(
                        nested_module,
                        "_BUILTIN_INSPECT_TARGET_REQUIREMENTS",
                        wraps=(
                            nested_module._BUILTIN_INSPECT_TARGET_REQUIREMENTS
                        ),
                    ) as reproduce_requirements,
                    patch.object(
                        nested_module,
                        "_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT",
                        wraps=(
                            nested_module._BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT
                        ),
                    ) as active_snapshot,
                    patch.object(
                        nested_module,
                        "_BUILTIN_TARGET_DESCRIPTOR_REMEASUREMENT",
                        wraps=(
                            nested_module
                            ._BUILTIN_TARGET_DESCRIPTOR_REMEASUREMENT
                        ),
                    ) as target_remeasurement,
                    patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_TARGET_SET",
                        side_effect=record_measurement,
                    ) as measure_set,
                    patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_NESTED_TARGET_PATH",
                        wraps=(
                            nested_module._BUILTIN_MEASURE_NESTED_TARGET_PATH
                        ),
                    ) as measure_path,
                    patch.object(
                        nested_module,
                        "_BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES",
                        wraps=(
                            nested_module
                            ._BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES
                        ),
                    ) as namespace_matches,
                    patch.object(
                        nested_module,
                        "_BUILTIN_TARGET_CLOSING_DESCRIPTOR_ANCHOR",
                        wraps=(
                            nested_module
                            ._BUILTIN_TARGET_CLOSING_DESCRIPTOR_ANCHOR
                        ),
                    ) as closing_target_anchor,
                    patch.object(
                        nested_module,
                        "_BUILTIN_PUBLIC_MEASUREMENT",
                        wraps=nested_module._BUILTIN_PUBLIC_MEASUREMENT,
                    ) as public_measurement,
                    patch.object(
                        nested_module,
                        "_BUILTIN_PUBLIC_REQUIREMENT",
                        wraps=nested_module._BUILTIN_PUBLIC_REQUIREMENT,
                    ) as public_requirement,
                    patch.object(
                        nested_module,
                        "_BUILTIN_PUBLIC_BINDING",
                        wraps=nested_module._BUILTIN_PUBLIC_BINDING,
                    ) as public_binding,
                ):
                    receipt = self._inspect(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                self.assertEqual(snapshot.call_count, 3)
                self.assertEqual(reproduce_runtime.call_count, 3)
                self.assertEqual(reproduce_requirements.call_count, 3)
                self.assertEqual(active_snapshot.call_count, 4)
                self.assertEqual(
                    target_remeasurement.call_count,
                    3 * target_runtime.file_count,
                )
                self.assertEqual(measure_set.call_count, 2)
                self.assertEqual(measure_path.call_count, 2)
                self.assertEqual(namespace_matches.call_count, 4)
                self.assertEqual(
                    closing_target_anchor.call_count,
                    target_runtime.file_count,
                )
                self.assertEqual(public_measurement.call_count, 1)
                self.assertEqual(
                    public_requirement.call_count,
                    target_requirements.requirement_count,
                )
                self.assertEqual(
                    public_binding.call_count,
                    target_requirements.command_count,
                )
                self.assertEqual(
                    proof_order,
                    [
                        "chain_snapshot",
                        "nested_measurement",
                        "chain_snapshot",
                        "nested_measurement",
                        "chain_snapshot",
                    ],
                )
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(self._lease_snapshot(target_lease), before)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_nested_namespace_swap_between_complete_measurements_rejects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            moved = nested_target.with_name("nested-original-after-race")
            replacement = nested_target.with_name("nested-replacement")
            self._write_target(replacement, b"replacement nested target bytes\n")
            real_measure = nested_module._BUILTIN_MEASURE_TARGET_SET
            passes = 0

            def swap_after_first_pass(*args: object, **kwargs: object):
                nonlocal passes
                measured = real_measure(*args, **kwargs)
                passes += 1
                if passes == 1:
                    nested_target.rename(moved)
                    replacement.rename(nested_target)
                return measured

            before = self._lease_snapshot(target_lease)
            descriptors = self._descriptor_directory()
            descriptor_before = (
                None
                if descriptors is None
                else frozenset(os.listdir(descriptors))
            )
            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    side_effect=swap_after_first_pass,
                ):
                    self._assert_invalid(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                self.assertEqual(passes, 2)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                if descriptors is not None:
                    self.assertEqual(
                        frozenset(os.listdir(descriptors)),
                        descriptor_before,
                    )
            finally:
                if moved.exists():
                    if nested_target.exists():
                        nested_target.rename(replacement)
                    moved.rename(nested_target)
                target_lease.close()
                executable_lease.close()

    def test_final_leaf_ancestor_and_spelling_namespace_races_reject(self) -> None:
        for race_kind in ("leaf", "ancestor", "spelling"):
            with (
                self.subTest(race_kind=race_kind),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    root,
                    _outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                base = Path(temporary).resolve(strict=True)
                selected_parent = base / "selected-final-parent"
                nested_target = selected_parent / "selected-final-target"
                self._write_target(
                    nested_target,
                    b"selected final target bytes\n",
                )
                first = base / "final-race-first"
                self._write_target(
                    first,
                    b"#!" + os.fsencode(nested_target) + b"\n",
                )
                self._set_contents(
                    root,
                    search_one,
                    bare=b"#!" + os.fsencode(first) + b"\n",
                )
                registration = self._registration(root)
                (
                    executable_lease,
                    _source_staging,
                    _source_runtime,
                    _source_requirements,
                    _target_resolution,
                    target_lease,
                    target_staging,
                    target_runtime,
                    target_requirements,
                ) = self._stage_target_requirements(
                    registration,
                    search_directories=(search_one, search_two),
                    executable_stage_root=executable_stage_root,
                    target_stage_root=target_stage_root,
                    target_paths=(first,),
                )
                moved_target = selected_parent / "moved-final-target"
                replacement_target = selected_parent / "replacement-final-target"
                moved_parent = base / "moved-final-parent"
                replacement_parent = base / "replacement-final-parent"
                if race_kind == "leaf":
                    self._write_target(
                        replacement_target,
                        b"replacement final leaf bytes\n",
                    )
                elif race_kind == "ancestor":
                    self._write_target(
                        replacement_parent / nested_target.name,
                        b"replacement final subtree bytes\n",
                    )
                real_match = (
                    nested_module._BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES
                )
                real_spelling = nested_module._BUILTIN_ENTRY_SPELLING_STATE
                matches = 0
                collision = False

                def race_before_final_match(*args: object, **kwargs: object):
                    nonlocal matches, collision
                    matches += 1
                    if matches == 3:
                        if race_kind == "leaf":
                            nested_target.rename(moved_target)
                            replacement_target.rename(nested_target)
                        elif race_kind == "ancestor":
                            selected_parent.rename(moved_parent)
                            replacement_parent.rename(selected_parent)
                        else:
                            collision = True
                    return real_match(*args, **kwargs)

                def spelling_after_collision(
                    directory_descriptor: int,
                    name: str,
                ) -> str:
                    if collision and name == nested_target.name:
                        return "ambiguous"
                    return real_spelling(directory_descriptor, name)

                try:
                    with (
                        patch.object(
                            nested_module,
                            "_BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES",
                            side_effect=race_before_final_match,
                        ),
                        patch.object(
                            nested_module,
                            "_BUILTIN_ENTRY_SPELLING_STATE",
                            side_effect=spelling_after_collision,
                        ),
                    ):
                        self._assert_invalid(
                            target_requirements,
                            target_runtime,
                            target_staging,
                            target_lease,
                            (nested_target,),
                        )
                    self.assertGreaterEqual(matches, 3)
                finally:
                    if race_kind == "leaf" and moved_target.exists():
                        if nested_target.exists():
                            nested_target.rename(replacement_target)
                        moved_target.rename(nested_target)
                    if race_kind == "ancestor" and moved_parent.exists():
                        if selected_parent.exists():
                            selected_parent.rename(replacement_parent)
                        moved_parent.rename(selected_parent)
                    target_lease.close()
                    executable_lease.close()

    def test_content_metadata_and_post_projection_namespace_races_reject(
        self,
    ) -> None:
        for race_kind in ("content", "metadata"):
            with (
                self.subTest(race_kind=race_kind),
                tempfile.TemporaryDirectory() as temporary,
            ):
                values = self._one_nested_chain(temporary)
                (
                    *_prefix,
                    nested_target,
                    executable_lease,
                    _source_staging,
                    _source_runtime,
                    _source_requirements,
                    _target_resolution,
                    target_lease,
                    target_staging,
                    target_runtime,
                    target_requirements,
                ) = values
                real_measure = nested_module._BUILTIN_MEASURE_TARGET_SET
                passes = 0

                def mutate_after_first_pass(*args: object, **kwargs: object):
                    nonlocal passes
                    value = real_measure(*args, **kwargs)
                    passes += 1
                    if passes == 1:
                        if race_kind == "content":
                            self._write_target(
                                nested_target,
                                b"changed in-place nested target bytes\n",
                            )
                        else:
                            nested_target.chmod(0o700)
                    return value

                before = self._lease_snapshot(target_lease)
                try:
                    with patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_TARGET_SET",
                        side_effect=mutate_after_first_pass,
                    ):
                        self._assert_invalid(
                            target_requirements,
                            target_runtime,
                            target_staging,
                            target_lease,
                            (nested_target,),
                        )
                    self.assertEqual(passes, 2)
                    self.assertEqual(self._lease_snapshot(target_lease), before)
                finally:
                    target_lease.close()
                    executable_lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            moved = nested_target.with_name("post-projection-original")
            replacement = nested_target.with_name("post-projection-replacement")
            self._write_target(
                replacement,
                b"post-projection replacement bytes\n",
            )
            real_projection = nested_module._BUILTIN_RECEIPT_PROJECTION
            projected = False

            def swap_after_output_projection(value: object):
                nonlocal projected
                canonical = real_projection(value)
                if not projected:
                    nested_target.rename(moved)
                    replacement.rename(nested_target)
                    projected = True
                return canonical

            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_RECEIPT_PROJECTION",
                    side_effect=swap_after_output_projection,
                ):
                    self._assert_invalid(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                self.assertTrue(projected)
            finally:
                if moved.exists():
                    if nested_target.exists():
                        nested_target.rename(replacement)
                    moved.rename(nested_target)
                target_lease.close()
                executable_lease.close()

    def test_closing_lease_lineage_race_and_cleanup_during_reproduction_reject(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            original_files = target_lease._files
            real_measure = nested_module._BUILTIN_MEASURE_TARGET_SET
            calls = 0

            def swap_lease_after_second_pass(*args: object, **kwargs: object):
                nonlocal calls
                value = real_measure(*args, **kwargs)
                calls += 1
                if calls == 2:
                    target_lease._files = tuple(list(target_lease._files))
                return value

            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_MEASURE_TARGET_SET",
                    side_effect=swap_lease_after_second_pass,
                ):
                    self._assert_invalid(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                self.assertEqual(calls, 2)
            finally:
                target_lease._files = original_files
                target_lease.close()
                executable_lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            real_reproduce = nested_module._BUILTIN_INSPECT_TARGET_REQUIREMENTS
            cleaned = False

            def cleanup_after_reproduction(*args: object, **kwargs: object):
                nonlocal cleaned
                value = real_reproduce(*args, **kwargs)
                if not cleaned:
                    target_lease.close()
                    cleaned = True
                return value

            with patch.object(
                nested_module,
                "_BUILTIN_INSPECT_TARGET_REQUIREMENTS",
                side_effect=cleanup_after_reproduction,
            ):
                self._assert_invalid(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_target,),
                )
            self.assertTrue(cleaned)
            self.assertEqual(target_lease.state, "cleaned")
            self.assertTrue(
                target_lease.cleanup_receipt.descriptor_release_complete
            )
            self.assertTrue(
                target_lease.cleanup_receipt.owned_namespace_absence_verified
            )
            executable_lease.close()

    def test_staging_root_identity_alias_and_case_mismatch_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                *_prefix,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            simulated_alias_identity = (
                os.stat(nested_target.parent).st_dev,
                os.stat(nested_target.parent).st_ino,
            )
            real_root_match = nested_module._BUILTIN_ROOT_IDENTITY_MATCHES

            def simulate_alias(
                metadata: os.stat_result,
                protected_root_identity: tuple[int, int] | None,
            ) -> bool:
                if (metadata.st_dev, metadata.st_ino) == simulated_alias_identity:
                    return True
                return real_root_match(metadata, protected_root_identity)

            try:
                with (
                    patch.object(
                        nested_module,
                        "_BUILTIN_ROOT_IDENTITY_MATCHES",
                        side_effect=simulate_alias,
                    ),
                    patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_TARGET_SET",
                        side_effect=AssertionError("aliased-root measurement"),
                    ) as measure,
                ):
                    self._assert_invalid(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                measure.assert_not_called()
            finally:
                target_lease.close()
                executable_lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            base = Path(temporary).resolve(strict=True)
            first = base / "case-mismatch-first"
            actual = base / "CaseSensitiveNestedTarget"
            selected = base / "casesensitivenestedtarget"
            self._write_target(actual, b"case-sensitive nested bytes\n")
            self._write_target(
                first,
                b"#!" + os.fsencode(selected) + b"\n",
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(first) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(first,),
            )
            try:
                self._assert_invalid(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (selected,),
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_exports_signature_and_no_effect_surface_are_exact(self) -> None:
        expected_exports = {
            "CYCLE_SCOPE",
            "MAXIMUM_RESOLUTION_DEPTH",
            "MEASUREMENT_SOURCE",
            "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_BINDING_KIND",
            "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_MEASUREMENT_KIND",
            "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENT_KIND",
            "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_EVIDENCE_KIND",
            "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_KIND",
            "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION",
            "RESOLUTION_DEPTH",
            "RESOLUTION_SCOPE",
            "RepositoryExecutableShebangNestedTargetBinding",
            "RepositoryExecutableShebangNestedTargetMeasurement",
            "RepositoryExecutableShebangNestedTargetRequirement",
            "RepositoryExecutableShebangNestedTargetResolutionReceipt",
            "inspect_staged_executable_shebang_nested_targets",
        }
        self.assertEqual(set(nested_module.__all__), expected_exports)
        signature = inspect.signature(
            inspect_staged_executable_shebang_nested_targets
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_target_requirements",
                "expected_target_runtime",
                "expected_target_staging",
                "lease",
                "expected_nested_target_paths",
            ),
        )
        self.assertEqual(
            signature.parameters["expected_target_requirements"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in (
            "expected_target_runtime",
            "expected_target_staging",
            "lease",
            "expected_nested_target_paths",
        ):
            self.assertEqual(
                signature.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        self.assertNotIn("depth", signature.parameters)
        self.assertNotIn("maximum_resolution_depth", signature.parameters)

        with tempfile.TemporaryDirectory() as temporary:
            values = self._one_nested_chain(temporary)
            (
                root,
                outside,
                search_one,
                search_two,
                _executable_stage_root,
                target_stage_root,
                first_target,
                nested_target,
                executable_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            before = self._lease_snapshot(target_lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (
                    root,
                    outside,
                    search_one,
                    search_two,
                    first_target.parent,
                    target_stage_root,
                )
            )
            try:
                with (
                    patch.object(
                        builtins,
                        "open",
                        side_effect=AssertionError("builtin path open"),
                    ) as builtin_open,
                    patch.object(
                        Path,
                        "open",
                        side_effect=AssertionError("Path.open"),
                    ) as path_open,
                    patch.object(
                        shutil,
                        "which",
                        side_effect=AssertionError("ambient PATH"),
                    ) as which,
                    patch.object(
                        os,
                        "getenv",
                        side_effect=AssertionError("environment"),
                    ) as getenv,
                    patch.object(
                        os,
                        "get_exec_path",
                        side_effect=AssertionError("ambient PATH"),
                    ) as get_exec_path,
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
                ):
                    receipt = self._inspect(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_target,),
                    )
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                for observed in (
                    builtin_open,
                    path_open,
                    which,
                    getenv,
                    get_exec_path,
                    write,
                    fchmod,
                    system,
                    run,
                    popen,
                    create_exec,
                    create_shell,
                    stage_artifact,
                    publish_artifact,
                    state,
                ):
                    observed.assert_not_called()
                self.assertEqual(
                    tuple(
                        self._tree_snapshot(path)
                        for path in (
                            root,
                            outside,
                            search_one,
                            search_two,
                            first_target.parent,
                            target_stage_root,
                        )
                    ),
                    trees_before,
                )
            finally:
                target_lease.close()
                executable_lease.close()
