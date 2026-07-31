from __future__ import annotations

import asyncio
import builtins
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
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
import ordomata.repository_executable_shebang_target_requirements as requirements_module
from ordomata.repository_executable_shebang_target_requirements import (
    REQUIREMENTS_SCOPE,
    REQUIREMENTS_SOURCE,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_SCHEMA_VERSION,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_BINDING_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_KIND,
    RepositoryExecutableShebangTargetRequirementsReceipt,
    RepositoryExecutableShebangTargetShebangRequirement,
    RepositoryExecutableShebangTargetShebangRequirementBinding,
    inspect_staged_executable_shebang_target_requirements,
)
import ordomata.repository_executable_shebang_target_runtime_manifest as runtime_module
from ordomata.repository_executable_shebang_target_runtime_manifest import (
    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
    inspect_staged_executable_shebang_target_runtime_manifest,
)
import ordomata.repository_executable_shebang_target_staging as target_staging_module
from ordomata.repository_executable_shebang_target_staging import (
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStagingReceipt,
)
import ordomata.state as state_module

if __package__:
    from . import (
        test_repository_executable_shebang_target_runtime_manifest
        as runtime_test_module,
    )
else:
    import test_repository_executable_shebang_target_runtime_manifest as runtime_test_module


FIXED_REQUIREMENTS_ERROR = (
    "repository executable shebang target requirements are invalid"
)
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"

REQUIREMENT_KEYS = {
    "argument_separator_kind",
    "argument_tail_bytes",
    "argument_tail_ref",
    "disposition",
    "interpreter_token_bytes",
    "interpreter_token_ref",
    "kind",
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
REQUIREMENT_BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
    "target_runtime_requirement_ref",
    "target_shebang_requirement_ref",
    "target_stage_requirement_ref",
}
REQUIREMENTS_RECEIPT_KEYS = {
    "argument_tail_requirement_count",
    "bindings",
    "command_count",
    "direct_target_requirement_count",
    "kind",
    "native_not_applicable_count",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "requirements_scope",
    "requirements_source",
    "resolution_context_digest",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shebang_requirements_receipt_digest",
    "source_staging_context_digest",
    "staging_receipt_digest",
    "target_path_context_digest",
    "target_posix_shebang_requirement_count",
    "target_resolution_receipt_digest",
    "target_runtime_manifest_receipt_digest",
    "target_staging_context_digest",
    "target_staging_receipt_digest",
    "total_argument_tail_bytes",
    "total_interpreter_token_bytes",
    "unique_target_count",
    "verification_commands_digest",
}
REQUIREMENTS_EVIDENCE_KEYS = {
    "absolute_interpreter_token_count",
    "action_receipt_issued",
    "active_target_stage_lease_verified_at_measurement",
    "argument_tail_requirement_count",
    "atomic_snapshot_verified",
    "authority_granted",
    "authorization_verified",
    "billing_eligible",
    "bounded_target_shebang_requirement_extraction_complete",
    "capacity_eligible",
    "circuit_eligible",
    "command_count",
    "current_lease_activity_verified",
    "current_source_freshness_verified",
    "dependency_environment_coverage_verified",
    "direct_target_requirement_count",
    "dispatch_enabled",
    "durable_control_plane_persistence_enabled",
    "dynamic_loader_identity_verified",
    "effect_class",
    "effective_interpreter_resolution_verified",
    "effective_invocability_verified",
    "environment_coverage_verified",
    "exact_target_runtime_manifest_correspondence_verified",
    "execution_enabled",
    "external_hardlink_alias_excluded",
    "external_writable_descriptor_absence_verified",
    "filesystem_immutability_verified",
    "fork_descriptor_inheritance_excluded",
    "future_execution_correspondence_verified",
    "hardlink_alias_exclusion_verified",
    "harness_invocation_performed",
    "interpreter_argument_semantics_verified",
    "interpreter_authenticity_verified",
    "interpreter_compatibility_verified",
    "interpreter_identity_verified",
    "interpreter_provenance_verified",
    "interpreter_token_syntax_classification_complete",
    "kind",
    "launcher_semantics_verified",
    "lease_cleanup_performed",
    "lease_mutated",
    "live_execution_eligible",
    "mount_alias_exclusion_verified",
    "native_binary_no_shebang_count",
    "native_not_applicable_count",
    "native_runtime_dependency_coverage_verified",
    "non_absolute_interpreter_token_count",
    "path_lookup_performed",
    "proposal_lineage_extended",
    "receipt_authenticity_verified",
    "receipt_digest",
    "recursive_shebang_resolution_verified",
    "registration_digest",
    "repository_ref",
    "requirement_binding_correspondence_verified",
    "requirement_count",
    "requirements_scope",
    "requirements_source",
    "resolution_context_digest",
    "route_eligible",
    "runtime_manifest_complete",
    "same_uid_tamper_exclusion_verified",
    "schema_version",
    "shared_library_identity_verified",
    "source_path_reopen_performed",
    "staged_byte_correspondence_verified",
    "staged_descriptor_full_remeasurement_complete",
    "staging_root_path_reopen_performed",
    "subprocess_invocation_performed",
    "target_path_reopen_performed",
    "target_posix_shebang_requirement_count",
    "target_resolution_receipt_digest",
    "target_runtime_manifest_receipt_digest",
    "target_semantics_verified",
    "target_staging_receipt_digest",
    "toolchain_completeness_verified",
    "total_argument_tail_bytes",
    "total_interpreter_token_bytes",
    "unique_target_count",
    "unknown_runtime_format_count",
    "unsupported_shebang_count",
    "validation_mode",
    "worktree_integration_enabled",
}


@unittest.skipUnless(
    os.name == "posix",
    "target shebang requirements require POSIX",
)
class RepositoryExecutableShebangTargetRequirementsTests(unittest.TestCase):
    fixture = (
        runtime_test_module
        .RepositoryExecutableShebangTargetRuntimeManifestTests
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

    @classmethod
    def _stage_target_runtime(
        cls,
        registration: object,
        *,
        search_directories: tuple[Path, ...],
        executable_stage_root: Path,
        target_stage_root: Path,
        target_paths: tuple[Path, ...],
    ) -> tuple[object, ...]:
        chain = cls.fixture._stage_chain(
            registration,
            search_directories=search_directories,
            executable_stage_root=executable_stage_root,
            target_stage_root=target_stage_root,
            target_paths=target_paths,
        )
        target_staging = chain[-1]
        target_lease = chain[-2]
        target_runtime = (
            inspect_staged_executable_shebang_target_runtime_manifest(
                target_staging,
                lease=target_lease,
            )
        )
        return (*chain, target_runtime)

    @classmethod
    def _one_direct_runtime(
        cls,
        temporary: str,
        *,
        target_content: bytes = b"#!/bin/sh\n",
    ) -> tuple[
        object,
        RepositoryExecutableShebangTargetStageLease,
        RepositoryExecutableShebangTargetStagingReceipt,
        RepositoryExecutableShebangTargetRuntimeManifestReceipt,
    ]:
        executable_lease, target_lease, target_staging = (
            cls.fixture._one_direct_stage(
                temporary,
                target_content=target_content,
            )
        )
        target_runtime = (
            inspect_staged_executable_shebang_target_runtime_manifest(
                target_staging,
                lease=target_lease,
            )
        )
        return (
            executable_lease,
            target_lease,
            target_staging,
            target_runtime,
        )

    def _assert_invalid(
        self,
        expected_target_runtime: object,
        expected_target_staging: object,
        lease: object,
        *,
        private_marker: str = "private-target-requirements-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_shebang_target_requirements(
                expected_target_runtime,
                expected_target_staging=expected_target_staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_REQUIREMENTS_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    @staticmethod
    def _one_extraction_by_target_classification(
        receipt: RepositoryExecutableShebangTargetRequirementsReceipt,
        classification: str,
    ) -> RepositoryExecutableShebangTargetShebangRequirement:
        values = tuple(
            value
            for value in receipt.requirements
            if value.target_runtime_classification == classification
        )
        if not values:
            raise AssertionError(
                f"expected a {classification!r} requirement"
            )
        extraction_values = {
            (
                value.target_shebang_directive_ref,
                value.interpreter_token_ref,
                value.interpreter_token_bytes,
                value.argument_separator_kind,
                value.argument_tail_ref,
                value.argument_tail_bytes,
                value.disposition,
            )
            for value in values
        }
        if len(extraction_values) != 1:
            raise AssertionError(
                f"expected one {classification!r} extraction, "
                f"got {len(extraction_values)}"
            )
        return values[0]

    def test_receipt_correspondence_privacy_and_lease_immutability(self) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        token = b"/usr/bin/env"
        tail = b"python3 -I\tprivate-opaque-target-tail-marker"
        target_content = b"#!" + token + b"\t\t" + tail + b"\nprivate-body\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "private-target"
            self._write_target(target, target_content)
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=b"#!" + os.fsencode(target) + b" -I\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._stage_target_runtime(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            before = self._lease_snapshot(target_lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
            )
            try:
                receipt = inspect_staged_executable_shebang_target_requirements(
                    target_runtime,
                    expected_target_staging=target_staging,
                    lease=target_lease,
                )
                repeated = inspect_staged_executable_shebang_target_requirements(
                    target_runtime,
                    expected_target_staging=target_staging,
                    lease=target_lease,
                )
                self.assertEqual(receipt, repeated)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangTargetRequirementsReceipt,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_SCHEMA_VERSION,
                    1,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_KIND,
                    "repository_executable_shebang_target_requirements",
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_EVIDENCE_KIND,
                    (
                        "repository_executable_shebang_target_"
                        "requirements_validation"
                    ),
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_KIND,
                    (
                        "repository_executable_shebang_target_"
                        "shebang_requirement"
                    ),
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_SHEBANG_REQUIREMENT_BINDING_KIND,
                    (
                        "repository_executable_shebang_target_"
                        "shebang_requirement_binding"
                    ),
                )
                self.assertEqual(REQUIREMENTS_SOURCE, "controller_inspected")
                self.assertEqual(
                    REQUIREMENTS_SCOPE,
                    "posix_staged_shebang_target_requirements_v1",
                )

                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), REQUIREMENTS_RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
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
                        getattr(target_runtime, field),
                    )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.direct_target_requirement_count, 1)
                self.assertEqual(receipt.native_not_applicable_count, 1)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(
                    receipt.target_posix_shebang_requirement_count,
                    1,
                )
                self.assertEqual(receipt.argument_tail_requirement_count, 1)
                self.assertEqual(receipt.total_interpreter_token_bytes, len(token))
                self.assertEqual(receipt.total_argument_tail_bytes, len(tail))

                requirement_by_ref = {}
                runtime_file_by_ref = {
                    value.target_runtime_file_ref: value
                    for value in target_runtime.files
                }
                for value, upstream in zip(
                    receipt.requirements,
                    target_runtime.requirements,
                    strict=True,
                ):
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangTargetShebangRequirement,
                    )
                    self.assertEqual(set(value.to_canonical()), REQUIREMENT_KEYS)
                    for field in (
                        "staged_file_ref",
                        "runtime_file_ref",
                        "requirement_ref",
                        "target_requirement_ref",
                        "target_stage_requirement_ref",
                        "target_runtime_requirement_ref",
                        "runtime_classification",
                        "target_measurement_ref",
                        "target_staged_file_ref",
                        "target_runtime_file_ref",
                    ):
                        self.assertEqual(
                            getattr(value, field),
                            getattr(upstream, field),
                        )
                    if upstream.disposition == "native_not_applicable":
                        self.assertIsNone(value.target_runtime_classification)
                        self.assertEqual(value.disposition, "native_not_applicable")
                        self.assertIsNone(value.target_shebang_directive_ref)
                        self.assertIsNone(value.interpreter_token_ref)
                        self.assertEqual(value.interpreter_token_bytes, 0)
                        self.assertIsNone(value.argument_separator_kind)
                        self.assertIsNone(value.argument_tail_ref)
                        self.assertEqual(value.argument_tail_bytes, 0)
                    else:
                        runtime_file = runtime_file_by_ref[
                            upstream.target_runtime_file_ref
                        ]
                        self.assertEqual(
                            value.target_runtime_classification,
                            runtime_file.classification,
                        )
                        self.assertEqual(
                            value.target_shebang_directive_ref,
                            runtime_file.shebang_directive_ref,
                        )
                        self.assertEqual(
                            value.disposition,
                            "absolute_interpreter_token",
                        )
                        self.assertRegex(
                            value.interpreter_token_ref,
                            _DIGEST_PATTERN,
                        )
                        self.assertEqual(value.interpreter_token_bytes, len(token))
                        self.assertEqual(
                            value.argument_separator_kind,
                            "horizontal_tab",
                        )
                        self.assertRegex(value.argument_tail_ref, _DIGEST_PATTERN)
                        self.assertEqual(value.argument_tail_bytes, len(tail))
                    self.assertRegex(
                        value.target_shebang_requirement_ref,
                        _DIGEST_PATTERN,
                    )
                    requirement_by_ref[value.target_shebang_requirement_ref] = value

                for value, upstream in zip(
                    receipt.bindings,
                    target_runtime.bindings,
                    strict=True,
                ):
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangTargetShebangRequirementBinding,
                    )
                    self.assertEqual(
                        set(value.to_canonical()),
                        REQUIREMENT_BINDING_KEYS,
                    )
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
                    ):
                        self.assertEqual(
                            getattr(value, field),
                            getattr(upstream, field),
                        )
                    self.assertIn(
                        value.target_shebang_requirement_ref,
                        requirement_by_ref,
                    )

                evidence = receipt.to_evidence()
                self.assertEqual(set(evidence), REQUIREMENTS_EVIDENCE_KEYS)
                self.assertEqual(
                    evidence["kind"],
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_EVIDENCE_KIND,
                )
                self.assertEqual(evidence["effect_class"], 0)
                self.assertEqual(evidence["validation_mode"], "read_only")
                self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
                for field in (
                    "argument_tail_requirement_count",
                    "command_count",
                    "direct_target_requirement_count",
                    "native_not_applicable_count",
                    "requirement_count",
                    "target_posix_shebang_requirement_count",
                    "total_argument_tail_bytes",
                    "total_interpreter_token_bytes",
                    "unique_target_count",
                ):
                    self.assertEqual(evidence[field], getattr(receipt, field))
                for true_fact in (
                    "active_target_stage_lease_verified_at_measurement",
                    "bounded_target_shebang_requirement_extraction_complete",
                    "exact_target_runtime_manifest_correspondence_verified",
                    "interpreter_token_syntax_classification_complete",
                    "requirement_binding_correspondence_verified",
                    "staged_byte_correspondence_verified",
                    "staged_descriptor_full_remeasurement_complete",
                ):
                    self.assertIs(evidence[true_fact], True, true_fact)
                for false_fact in (
                    "action_receipt_issued",
                    "atomic_snapshot_verified",
                    "authority_granted",
                    "authorization_verified",
                    "billing_eligible",
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
                    "external_writable_descriptor_absence_verified",
                    "filesystem_immutability_verified",
                    "fork_descriptor_inheritance_excluded",
                    "future_execution_correspondence_verified",
                    "hardlink_alias_exclusion_verified",
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
                    "mount_alias_exclusion_verified",
                    "native_runtime_dependency_coverage_verified",
                    "path_lookup_performed",
                    "proposal_lineage_extended",
                    "receipt_authenticity_verified",
                    "recursive_shebang_resolution_verified",
                    "route_eligible",
                    "runtime_manifest_complete",
                    "same_uid_tamper_exclusion_verified",
                    "shared_library_identity_verified",
                    "source_path_reopen_performed",
                    "staging_root_path_reopen_performed",
                    "subprocess_invocation_performed",
                    "target_path_reopen_performed",
                    "target_semantics_verified",
                    "toolchain_completeness_verified",
                    "worktree_integration_enabled",
                ):
                    self.assertIs(evidence[false_fact], False, false_fact)

                canonical_text = json.dumps(canonical, sort_keys=True)
                aggregate = "\n".join(
                    (
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        *(repr(value) for value in receipt.requirements),
                        *(repr(value) for value in receipt.bindings),
                    )
                )
                for private_value in (
                    token.decode("ascii"),
                    tail.decode("ascii"),
                    "private-body",
                    str(target),
                ):
                    self.assertNotIn(private_value, canonical_text)
                direct = next(
                    value
                    for value in receipt.requirements
                    if value.disposition == "absolute_interpreter_token"
                )
                expected_token_ref = canonical_digest(
                    {
                        "interpreter_token_hex": token.hex(),
                        "kind": (
                            "repository_executable_shebang_target_"
                            "interpreter_token_ref"
                        ),
                        "schema_version": 1,
                        "target_runtime_file_ref": direct.target_runtime_file_ref,
                        "target_shebang_directive_ref": (
                            direct.target_shebang_directive_ref
                        ),
                    }
                )
                self.assertEqual(direct.interpreter_token_ref, expected_token_ref)
                self.assertEqual(
                    direct.argument_tail_ref,
                    canonical_digest(
                        {
                            "argument_separator_kind": "horizontal_tab",
                            "argument_tail_hex": tail.hex(),
                            "interpreter_token_ref": expected_token_ref,
                            "kind": (
                                "repository_executable_shebang_target_"
                                "argument_tail_ref"
                            ),
                            "schema_version": 1,
                            "target_runtime_file_ref": (
                                direct.target_runtime_file_ref
                            ),
                            "target_shebang_directive_ref": (
                                direct.target_shebang_directive_ref
                            ),
                        }
                    ),
                )
                self.assertEqual(
                    direct.target_shebang_requirement_ref,
                    canonical_digest(
                        {
                            "argument_separator_kind": (
                                direct.argument_separator_kind
                            ),
                            "argument_tail_bytes": direct.argument_tail_bytes,
                            "argument_tail_ref": direct.argument_tail_ref,
                            "disposition": direct.disposition,
                            "interpreter_token_bytes": (
                                direct.interpreter_token_bytes
                            ),
                            "interpreter_token_ref": (
                                direct.interpreter_token_ref
                            ),
                            "kind": (
                                "repository_executable_shebang_target_"
                                "shebang_requirement_ref"
                            ),
                            "requirement_ref": direct.requirement_ref,
                            "requirements_scope": REQUIREMENTS_SCOPE,
                            "runtime_classification": (
                                direct.runtime_classification
                            ),
                            "runtime_file_ref": direct.runtime_file_ref,
                            "schema_version": 1,
                            "staged_file_ref": direct.staged_file_ref,
                            "target_measurement_ref": (
                                direct.target_measurement_ref
                            ),
                            "target_requirement_ref": (
                                direct.target_requirement_ref
                            ),
                            "target_runtime_classification": (
                                direct.target_runtime_classification
                            ),
                            "target_runtime_file_ref": (
                                direct.target_runtime_file_ref
                            ),
                            "target_runtime_requirement_ref": (
                                direct.target_runtime_requirement_ref
                            ),
                            "target_shebang_directive_ref": (
                                direct.target_shebang_directive_ref
                            ),
                            "target_stage_requirement_ref": (
                                direct.target_stage_requirement_ref
                            ),
                            "target_staged_file_ref": (
                                direct.target_staged_file_ref
                            ),
                        }
                    ),
                )
                for private_value in (
                    str(root),
                    str(search_one),
                    str(target_stage_root),
                    str(target),
                    token.decode("ascii"),
                    tail.decode("ascii"),
                    "private-body",
                    direct.target_shebang_directive_ref,
                    direct.interpreter_token_ref,
                    direct.argument_tail_ref,
                    direct.target_shebang_requirement_ref,
                    target_runtime.files[0].content_digest,
                ):
                    self.assertNotIn(private_value, aggregate)
                self.assertFalse(hasattr(receipt, "__dict__"))
                self.assertFalse(hasattr(receipt.requirements[0], "__dict__"))
                self.assertFalse(hasattr(receipt.bindings[0], "__dict__"))
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirement_count = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirements[0].disposition = "unknown_runtime_format"
                with self.assertRaises(FrozenInstanceError):
                    receipt.bindings[0].command_kind = "test"
                self.assertEqual(
                    tuple(
                        self._tree_snapshot(path)
                        for path in (
                            root,
                            outside,
                            search_one,
                            search_two,
                            target.parent,
                        )
                    ),
                    trees_before,
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_parser_boundaries_are_one_hop_and_opaque(self) -> None:
        cases = (
            (
                "single-space",
                b"#!/opt/private-python --flag  opaque\tvalue\n",
                "absolute_interpreter_token",
                "space",
                b"/opt/private-python",
                b"--flag  opaque\tvalue",
            ),
            (
                "space-run",
                b"#!/opt/private-python   --flag\n",
                "absolute_interpreter_token",
                "space",
                b"/opt/private-python",
                b"--flag",
            ),
            (
                "tab-run",
                b"#!/opt/private-python\t\t--flag  opaque\n",
                "absolute_interpreter_token",
                "horizontal_tab",
                b"/opt/private-python",
                b"--flag  opaque",
            ),
            (
                "mixed-separator-run",
                b"#!/opt/private-python\t \t--flag\n",
                "absolute_interpreter_token",
                "horizontal_tab",
                b"/opt/private-python",
                b"--flag",
            ),
            (
                "no-tail",
                b"#!/bin/sh\n",
                "absolute_interpreter_token",
                None,
                b"/bin/sh",
                None,
            ),
            (
                "root-token",
                b"#!/\n",
                "absolute_interpreter_token",
                None,
                b"/",
                None,
            ),
            (
                "repeated-slash",
                b"#!/opt//private-python\n",
                "absolute_interpreter_token",
                None,
                b"/opt//private-python",
                None,
            ),
            (
                "dot-components",
                b"#!/opt/./../private-python/\n",
                "absolute_interpreter_token",
                None,
                b"/opt/./../private-python/",
                None,
            ),
            (
                "relative-token",
                b"#!private-python\targ with  spaces\n",
                "non_absolute_interpreter_token",
                "horizontal_tab",
                b"private-python",
                b"arg with  spaces",
            ),
            (
                "env-tail-remains-opaque",
                b"#!/usr/bin/env python3 -I private-module\n",
                "absolute_interpreter_token",
                "space",
                b"/usr/bin/env",
                b"python3 -I private-module",
            ),
        )
        for case, content, disposition, separator, token, tail in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    executable_lease,
                    target_lease,
                    target_staging,
                    target_runtime,
                ) = self._one_direct_runtime(
                    temporary,
                    target_content=content,
                )
                try:
                    receipt = (
                        inspect_staged_executable_shebang_target_requirements(
                            target_runtime,
                            expected_target_staging=target_staging,
                            lease=target_lease,
                        )
                    )
                    requirement = (
                        self._one_extraction_by_target_classification(
                            receipt,
                            "posix_shebang",
                        )
                    )
                    self.assertEqual(requirement.disposition, disposition)
                    self.assertEqual(
                        requirement.argument_separator_kind,
                        separator,
                    )
                    self.assertEqual(
                        requirement.interpreter_token_bytes,
                        len(token),
                    )
                    self.assertEqual(
                        requirement.argument_tail_bytes,
                        0 if tail is None else len(tail),
                    )
                    expected_token_ref = canonical_digest(
                        {
                            "interpreter_token_hex": token.hex(),
                            "kind": (
                                "repository_executable_shebang_target_"
                                "interpreter_token_ref"
                            ),
                            "schema_version": 1,
                            "target_runtime_file_ref": (
                                requirement.target_runtime_file_ref
                            ),
                            "target_shebang_directive_ref": (
                                requirement.target_shebang_directive_ref
                            ),
                        }
                    )
                    self.assertEqual(
                        requirement.interpreter_token_ref,
                        expected_token_ref,
                    )
                    self.assertEqual(
                        requirement.argument_tail_ref is None,
                        tail is None,
                    )
                    if tail is not None:
                        self.assertEqual(
                            requirement.argument_tail_ref,
                            canonical_digest(
                                {
                                    "argument_separator_kind": separator,
                                    "argument_tail_hex": tail.hex(),
                                    "interpreter_token_ref": expected_token_ref,
                                    "kind": (
                                        "repository_executable_shebang_target_"
                                        "argument_tail_ref"
                                    ),
                                    "schema_version": 1,
                                    "target_runtime_file_ref": (
                                        requirement.target_runtime_file_ref
                                    ),
                                    "target_shebang_directive_ref": (
                                        requirement.target_shebang_directive_ref
                                    ),
                                }
                            ),
                        )
                    self.assertEqual(receipt.unique_target_count, 1)
                    self.assertEqual(
                        receipt.total_interpreter_token_bytes,
                        len(token),
                    )
                    self.assertEqual(
                        receipt.total_argument_tail_bytes,
                        0 if tail is None else len(tail),
                    )
                finally:
                    target_lease.close()
                    executable_lease.close()

    def test_directive_boundaries_map_to_fixed_dispositions(self) -> None:
        cases = (
            (
                "valid-255-byte-directive",
                b"#!" + b"a" * 255 + b"\n",
                "posix_shebang",
                "non_absolute_interpreter_token",
                255,
            ),
            (
                "overlong-directive",
                b"#!" + b"a" * 256 + b"\n",
                "unsupported_shebang",
                "unsupported_shebang",
                0,
            ),
            (
                "no-newline",
                b"#!/bin/sh",
                "unsupported_shebang",
                "unsupported_shebang",
                0,
            ),
            (
                "leading-space",
                b"#! /bin/sh\n",
                "unsupported_shebang",
                "unsupported_shebang",
                0,
            ),
            (
                "trailing-tab",
                b"#!/bin/sh\t\n",
                "unsupported_shebang",
                "unsupported_shebang",
                0,
            ),
            (
                "crlf",
                b"#!/bin/sh\r\n",
                "unsupported_shebang",
                "unsupported_shebang",
                0,
            ),
            (
                "nul",
                b"#!/bin/s\x00h\n",
                "unsupported_shebang",
                "unsupported_shebang",
                0,
            ),
            (
                "non-ascii",
                b"#!/bin/py\xc3\xa9\n",
                "unsupported_shebang",
                "unsupported_shebang",
                0,
            ),
        )
        for case, content, classification, disposition, token_bytes in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    executable_lease,
                    target_lease,
                    target_staging,
                    target_runtime,
                ) = self._one_direct_runtime(
                    temporary,
                    target_content=content,
                )
                try:
                    self.assertEqual(
                        {value.classification for value in target_runtime.files},
                        {classification},
                    )
                    receipt = (
                        inspect_staged_executable_shebang_target_requirements(
                            target_runtime,
                            expected_target_staging=target_staging,
                            lease=target_lease,
                        )
                    )
                    requirement = (
                        self._one_extraction_by_target_classification(
                            receipt,
                            classification,
                        )
                    )
                    self.assertEqual(requirement.disposition, disposition)
                    self.assertEqual(
                        requirement.interpreter_token_bytes,
                        token_bytes,
                    )
                    if classification != "posix_shebang":
                        self.assertIsNone(
                            requirement.target_shebang_directive_ref
                        )
                        self.assertIsNone(requirement.interpreter_token_ref)
                        self.assertIsNone(requirement.argument_separator_kind)
                        self.assertIsNone(requirement.argument_tail_ref)
                        self.assertEqual(requirement.argument_tail_bytes, 0)
                finally:
                    target_lease.close()
                    executable_lease.close()

    def test_all_target_runtime_classifications_have_fixed_dispositions(
        self,
    ) -> None:
        cases = (
            (
                "elf",
                b"\x7fELF\x02\x01\x01" + b"\x00" * 25,
                "native_binary_no_shebang",
            ),
            (
                "mach_o",
                b"\xcf\xfa\xed\xfe" + b"\x00" * 28,
                "native_binary_no_shebang",
            ),
            (
                "posix-absolute",
                b"#!/bin/sh\n",
                "absolute_interpreter_token",
            ),
            (
                "posix-relative",
                b"#!private-launcher\n",
                "non_absolute_interpreter_token",
            ),
            (
                "unsupported_shebang",
                b"#! /bin/sh\n",
                "unsupported_shebang",
            ),
            (
                "unknown",
                b"ordinary private target bytes\n",
                "unknown_runtime_format",
            ),
            (
                "unknown-empty",
                b"",
                "unknown_runtime_format",
            ),
        )
        for case, content, disposition in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                (
                    executable_lease,
                    target_lease,
                    target_staging,
                    target_runtime,
                ) = self._one_direct_runtime(
                    temporary,
                    target_content=content,
                )
                try:
                    receipt = (
                        inspect_staged_executable_shebang_target_requirements(
                            target_runtime,
                            expected_target_staging=target_staging,
                            lease=target_lease,
                        )
                    )
                    self.assertEqual(
                        {value.disposition for value in receipt.requirements},
                        {disposition},
                    )
                    for requirement in receipt.requirements:
                        if not disposition.endswith("interpreter_token"):
                            self.assertIsNone(
                                requirement.target_shebang_directive_ref
                            )
                            self.assertIsNone(requirement.interpreter_token_ref)
                            self.assertEqual(
                                requirement.interpreter_token_bytes,
                                0,
                            )
                            self.assertIsNone(
                                requirement.argument_separator_kind
                            )
                            self.assertIsNone(requirement.argument_tail_ref)
                            self.assertEqual(requirement.argument_tail_bytes, 0)
                finally:
                    target_lease.close()
                    executable_lease.close()

    def test_shared_target_is_extracted_once_and_bound_twice(self) -> None:
        token = b"/bin/sh"
        tail = b"-eu"
        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(
                temporary,
                target_content=b"#!" + token + b" " + tail + b"\n",
            )
            before = self._lease_snapshot(target_lease)
            try:
                receipt = inspect_staged_executable_shebang_target_requirements(
                    target_runtime,
                    expected_target_staging=target_staging,
                    lease=target_lease,
                )
                self.assertEqual(target_runtime.file_count, 1)
                self.assertEqual(target_runtime.requirement_count, 2)
                self.assertEqual(target_runtime.command_count, 2)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(
                    receipt.target_posix_shebang_requirement_count,
                    1,
                )
                self.assertEqual(receipt.argument_tail_requirement_count, 1)
                self.assertEqual(receipt.total_interpreter_token_bytes, len(token))
                self.assertEqual(receipt.total_argument_tail_bytes, len(tail))
                self.assertEqual(
                    len(
                        {
                            value.interpreter_token_ref
                            for value in receipt.requirements
                        }
                    ),
                    1,
                )
                self.assertEqual(
                    len(
                        {
                            value.argument_tail_ref
                            for value in receipt.requirements
                        }
                    ),
                    1,
                )
                self.assertEqual(
                    len(
                        {
                            value.target_shebang_requirement_ref
                            for value in receipt.requirements
                        }
                    ),
                    2,
                )
                self.assertEqual(
                    tuple(value.command_id for value in receipt.bindings),
                    tuple(value.command_id for value in target_runtime.bindings),
                )
                by_runtime_requirement_ref = {
                    value.target_runtime_requirement_ref: value
                    for value in receipt.requirements
                }
                for binding in receipt.bindings:
                    self.assertEqual(
                        binding.target_shebang_requirement_ref,
                        by_runtime_requirement_ref[
                            binding.target_runtime_requirement_ref
                        ].target_shebang_requirement_ref,
                    )
                self.assertEqual(self._lease_snapshot(target_lease), before)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_two_targets_preserve_first_use_and_binding_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target_one = Path(temporary).resolve(strict=True) / "target-one"
            target_two = Path(temporary).resolve(strict=True) / "target-two"
            self._write_target(target_one, b"#!/bin/one\n")
            self._write_target(target_two, b"ordinary-two\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target_one) + b"\n",
                relative=b"#!" + os.fsencode(target_two) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._stage_target_runtime(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target_one, target_two),
            )
            try:
                receipt = inspect_staged_executable_shebang_target_requirements(
                    target_runtime,
                    expected_target_staging=target_staging,
                    lease=target_lease,
                )
                self.assertEqual(receipt.unique_target_count, 2)
                self.assertEqual(
                    tuple(
                        value.target_runtime_requirement_ref
                        for value in receipt.requirements
                    ),
                    tuple(
                        value.target_runtime_requirement_ref
                        for value in target_runtime.requirements
                    ),
                )
                self.assertEqual(
                    tuple(
                        value.target_runtime_classification
                        for value in receipt.requirements
                    ),
                    ("posix_shebang", "unknown"),
                )
                self.assertEqual(
                    tuple(value.command_id for value in receipt.bindings),
                    tuple(value.command_id for value in target_runtime.bindings),
                )
                self.assertEqual(
                    tuple(
                        value.target_runtime_requirement_ref
                        for value in receipt.bindings
                    ),
                    tuple(
                        value.target_runtime_requirement_ref
                        for value in target_runtime.bindings
                    ),
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_native_only_zero_file_lease_succeeds_without_reads(self) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
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
            self._set_contents(root, search_one, bare=elf, relative=elf)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._stage_target_runtime(
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
                        requirements_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("descriptor read"),
                    ) as pread,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET",
                        side_effect=AssertionError("target verification"),
                    ) as verify,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_CLOSING_DESCRIPTOR_ANCHOR",
                        side_effect=AssertionError("closing target anchor"),
                    ) as closing_anchor,
                    patch.object(
                        requirements_module.os,
                        "open",
                        side_effect=AssertionError("root/path open"),
                    ) as open_path,
                ):
                    receipt = (
                        inspect_staged_executable_shebang_target_requirements(
                            target_runtime,
                            expected_target_staging=target_staging,
                            lease=target_lease,
                        )
                    )
                pread.assert_not_called()
                verify.assert_not_called()
                closing_anchor.assert_not_called()
                open_path.assert_not_called()
                self.assertEqual(self._lease_snapshot(target_lease), before)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.direct_target_requirement_count, 0)
                self.assertEqual(receipt.native_not_applicable_count, 2)
                self.assertEqual(receipt.unique_target_count, 0)
                self.assertEqual(
                    receipt.target_posix_shebang_requirement_count,
                    0,
                )
                self.assertEqual(receipt.argument_tail_requirement_count, 0)
                self.assertEqual(receipt.total_interpreter_token_bytes, 0)
                self.assertEqual(receipt.total_argument_tail_bytes, 0)
                self.assertTrue(
                    all(
                        value.disposition == "native_not_applicable"
                        and value.target_measurement_ref is None
                        and value.target_staged_file_ref is None
                        and value.target_runtime_file_ref is None
                        and value.target_runtime_classification is None
                        and value.target_shebang_directive_ref is None
                        and value.interpreter_token_ref is None
                        and value.interpreter_token_bytes == 0
                        and value.argument_separator_kind is None
                        and value.argument_tail_ref is None
                        and value.argument_tail_bytes == 0
                        for value in receipt.requirements
                    )
                )
                self.assertFalse(target_stage_root.exists())
            finally:
                target_lease.close()
                executable_lease.close()

    def test_wrong_types_receipt_identity_and_inactive_leases_fail_before_read(
        self,
    ) -> None:
        class DeceptiveString(str):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(temporary)
            unused_root = Path(temporary) / "unused-target-stage"
            unused_root.mkdir(mode=0o700)
            unused = RepositoryExecutableShebangTargetStageLease(unused_root)
            equal_staging = replace(target_staging)
            equal_runtime = replace(target_runtime)
            self.assertEqual(equal_staging, target_staging)
            self.assertIsNot(equal_staging, target_staging)
            self.assertEqual(equal_runtime, target_runtime)
            self.assertIsNot(equal_runtime, target_runtime)
            original_pid = target_lease._owner_pid
            original_runtime_kind = target_runtime.kind
            try:
                with (
                    patch.object(
                        requirements_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("requirements read"),
                    ) as requirements_pread,
                    patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("runtime read"),
                    ) as runtime_pread,
                ):
                    for case, bad_runtime, bad_staging, bad_lease in (
                        (
                            "runtime-type",
                            object(),
                            target_staging,
                            target_lease,
                        ),
                        (
                            "staging-type",
                            target_runtime,
                            object(),
                            target_lease,
                        ),
                        (
                            "lease-type",
                            target_runtime,
                            target_staging,
                            object(),
                        ),
                        (
                            "equal-distinct-staging",
                            target_runtime,
                            equal_staging,
                            target_lease,
                        ),
                        (
                            "inactive-lease",
                            target_runtime,
                            target_staging,
                            unused,
                        ),
                    ):
                        with self.subTest(case=case):
                            self._assert_invalid(
                                bad_runtime,
                                bad_staging,
                                bad_lease,
                            )
                    target_lease._owner_pid = original_pid + 1
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                    target_lease._owner_pid = original_pid

                    object.__setattr__(
                        target_runtime,
                        "kind",
                        DeceptiveString(original_runtime_kind),
                    )
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                    object.__setattr__(
                        target_runtime,
                        "kind",
                        original_runtime_kind,
                    )
                requirements_pread.assert_not_called()
                runtime_pread.assert_not_called()

                equivalent = (
                    inspect_staged_executable_shebang_target_requirements(
                        equal_runtime,
                        expected_target_staging=target_staging,
                        lease=target_lease,
                    )
                )
                genuine = inspect_staged_executable_shebang_target_requirements(
                    target_runtime,
                    expected_target_staging=target_staging,
                    lease=target_lease,
                )
                self.assertEqual(equivalent, genuine)

                target_lease.close()
                with (
                    patch.object(
                        requirements_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("closed requirements read"),
                    ) as requirements_pread,
                    patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("closed runtime read"),
                    ) as runtime_pread,
                ):
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                requirements_pread.assert_not_called()
                runtime_pread.assert_not_called()
            finally:
                target_lease._owner_pid = original_pid
                object.__setattr__(
                    target_runtime,
                    "kind",
                    original_runtime_kind,
                )
                target_lease.close()
                unused.close()
                executable_lease.close()

    def test_forged_reordered_and_transplanted_inputs_are_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary_one,
            tempfile.TemporaryDirectory() as temporary_two,
        ):
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(
                temporary_one,
                target_content=b"#!/bin/sh -eu\n",
            )
            (
                other_executable_lease,
                other_target_lease,
                other_target_staging,
                other_target_runtime,
            ) = self._one_direct_runtime(
                temporary_two,
                target_content=b"ordinary-other-target\n",
            )
            reordered_requirements = replace(
                target_runtime,
                requirements=tuple(reversed(target_runtime.requirements)),
            )
            reordered_bindings = replace(
                target_runtime,
                bindings=tuple(reversed(target_runtime.bindings)),
            )
            forged_lineage = replace(
                target_runtime,
                registration_digest="sha256:" + "0" * 64,
            )
            forged_staging = replace(
                target_staging,
                target_staging_context_digest="sha256:" + "1" * 64,
            )
            try:
                with patch.object(
                    runtime_module.RepositoryExecutableShebangTargetRuntimeManifestReceipt,
                    "to_canonical",
                    return_value=target_runtime.to_canonical(),
                ) as public_canonical:
                    for case, bad_runtime, bad_staging, bad_lease in (
                        (
                            "reordered-requirements",
                            reordered_requirements,
                            target_staging,
                            target_lease,
                        ),
                        (
                            "reordered-bindings",
                            reordered_bindings,
                            target_staging,
                            target_lease,
                        ),
                        (
                            "forged-lineage",
                            forged_lineage,
                            target_staging,
                            target_lease,
                        ),
                        (
                            "forged-staging",
                            target_runtime,
                            forged_staging,
                            target_lease,
                        ),
                        (
                            "transplanted-runtime",
                            other_target_runtime,
                            target_staging,
                            target_lease,
                        ),
                        (
                            "transplanted-staging",
                            target_runtime,
                            other_target_staging,
                            target_lease,
                        ),
                        (
                            "transplanted-lease",
                            target_runtime,
                            target_staging,
                            other_target_lease,
                        ),
                    ):
                        with self.subTest(case=case):
                            self._assert_invalid(
                                bad_runtime,
                                bad_staging,
                                bad_lease,
                            )
                public_canonical.assert_not_called()
            finally:
                target_lease.close()
                executable_lease.close()
                other_target_lease.close()
                other_executable_lease.close()

    def test_forged_upstream_header_and_parser_are_independently_rejected(
        self,
    ) -> None:
        forged_digest = "sha256:" + "f" * 64
        for case, content, patch_name, forged_value in (
            (
                "header-digest",
                b"#!/bin/sh private-tail\n",
                "_BUILTIN_HEADER_DIGEST",
                forged_digest,
            ),
            (
                "parser",
                b"#! /bin/sh\nprivate-body\n",
                "_BUILTIN_CLASSIFY_HEADER",
                ("posix_shebang", forged_digest),
            ),
        ):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                executable_lease, target_lease, target_staging = (
                    self.fixture._one_direct_stage(
                        temporary,
                        target_content=content,
                    )
                )
                before = self._lease_snapshot(target_lease)
                try:
                    with patch.object(
                        runtime_module,
                        patch_name,
                        return_value=forged_value,
                    ):
                        forged_runtime = (
                            inspect_staged_executable_shebang_target_runtime_manifest(
                                target_staging,
                                lease=target_lease,
                            )
                        )
                        self.assertEqual(
                            forged_runtime.receipt_digest,
                            canonical_digest(forged_runtime.to_canonical()),
                        )
                        if case == "header-digest":
                            self.assertEqual(
                                {
                                    value.header_digest
                                    for value in forged_runtime.files
                                },
                                {forged_digest},
                            )
                        else:
                            self.assertEqual(
                                {
                                    value.classification
                                    for value in forged_runtime.files
                                },
                                {"posix_shebang"},
                            )
                        self._assert_invalid(
                            forged_runtime,
                            target_staging,
                            target_lease,
                        )
                    self.assertEqual(self._lease_snapshot(target_lease), before)
                finally:
                    target_lease.close()
                    executable_lease.close()

    def test_lease_anchor_descriptor_retarget_and_corrupt_read_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(
                temporary,
                target_content=b"#!/bin/sh private-tail\n",
            )
            original_files = target_lease._files
            retained = original_files[0]
            original_metadata = retained.metadata
            descriptor = retained.descriptor
            backup = os.dup(descriptor)
            foreign = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
            try:
                target_lease._files = (
                    replace(
                        retained,
                        metadata=(
                            *original_metadata[:-1],
                            original_metadata[-1] + 1,
                        ),
                    ),
                )
                with (
                    patch.object(
                        requirements_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("requirements early read"),
                    ) as requirements_pread,
                    patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("runtime early read"),
                    ) as runtime_pread,
                ):
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                requirements_pread.assert_not_called()
                runtime_pread.assert_not_called()
                target_lease._files = original_files

                os.dup2(foreign, descriptor, inheritable=False)
                self._assert_invalid(
                    target_runtime,
                    target_staging,
                    target_lease,
                )
                os.dup2(backup, descriptor, inheritable=False)

                real_pread = requirements_module._BUILTIN_PREAD
                corrupted = False

                def corrupt_once(fd: int, count: int, offset: int) -> bytes:
                    nonlocal corrupted
                    value = real_pread(fd, count, offset)
                    if fd == descriptor and value and not corrupted:
                        corrupted = True
                        return bytes((value[0] ^ 1,)) + value[1:]
                    return value

                with patch.object(
                    requirements_module,
                    "_BUILTIN_PREAD",
                    side_effect=corrupt_once,
                ):
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                self.assertTrue(corrupted)
            finally:
                target_lease._files = original_files
                os.dup2(backup, descriptor, inheritable=False)
                os.close(foreign)
                os.close(backup)
                target_lease.close()
                executable_lease.close()

    def test_captured_proof_graph_ignores_public_and_library_patches(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(
                temporary,
                target_content=b"#!/bin/sh -eu\n",
            )
            baseline = inspect_staged_executable_shebang_target_requirements(
                target_runtime,
                expected_target_staging=target_staging,
                lease=target_lease,
            )
            patch_specs = (
                (
                    requirements_module,
                    "_requirement_projection",
                    {"forged": "requirement"},
                ),
                (
                    requirements_module,
                    "_receipt_projection",
                    {"forged": "receipt"},
                ),
                (
                    requirements_module,
                    "_expected_disposition",
                    frozenset(),
                ),
                (
                    requirements_module,
                    "_closing_descriptor_anchor",
                    AssertionError("public closing anchor bypass"),
                ),
                (
                    requirements_module,
                    "_target_staging_receipt_projection",
                    {"forged": "staging"},
                ),
                (
                    requirements_module,
                    "_target_runtime_manifest_projection",
                    {"forged": "runtime"},
                ),
                (
                    requirements_module,
                    "canonical_digest",
                    "sha256:" + "0" * 64,
                ),
                (
                    requirements_module.hashlib,
                    "sha256",
                    AssertionError("public sha256 bypass"),
                ),
                (
                    requirements_module.os,
                    "pread",
                    b"forged-public-pread",
                ),
                (
                    requirements_module.os,
                    "fstat",
                    AssertionError("public fstat bypass"),
                ),
                (
                    runtime_module,
                    "inspect_staged_executable_shebang_target_runtime_manifest",
                    AssertionError("public runtime inspector bypass"),
                ),
                (
                    runtime_module.RepositoryExecutableShebangTargetRuntimeManifestReceipt,
                    "to_canonical",
                    AssertionError("public runtime canonical bypass"),
                ),
            )
            before = self._lease_snapshot(target_lease)
            try:
                with ExitStack() as stack:
                    bypasses = []
                    for owner, name, behavior in patch_specs:
                        kwargs = (
                            {"side_effect": behavior}
                            if isinstance(behavior, BaseException)
                            else {"return_value": behavior}
                        )
                        bypasses.append(
                            stack.enter_context(
                                patch.object(owner, name, **kwargs)
                            )
                        )
                    observed = (
                        inspect_staged_executable_shebang_target_requirements(
                            target_runtime,
                            expected_target_staging=target_staging,
                            lease=target_lease,
                        )
                    )
                self.assertEqual(observed, baseline)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                for bypass in bypasses:
                    bypass.assert_not_called()
            finally:
                target_lease.close()
                executable_lease.close()

    def test_two_reproductions_two_remeasurements_and_closing_snapshots(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(
                temporary,
                target_content=b"#!/bin/sh -eu\n",
            )
            before = self._lease_snapshot(target_lease)
            proof_order: list[str] = []
            real_reproduce_runtime = (
                requirements_module._BUILTIN_INSPECT_TARGET_RUNTIME_MANIFEST
            )
            real_extract = requirements_module._BUILTIN_EXTRACT_UNIQUE_TARGETS

            def record_reproduction(*args: object, **kwargs: object):
                proof_order.append("runtime_reproduction")
                return real_reproduce_runtime(*args, **kwargs)

            def record_extraction(*args: object, **kwargs: object):
                proof_order.append("descriptor_extraction")
                return real_extract(*args, **kwargs)

            try:
                with (
                    patch.object(
                        requirements_module,
                        "_BUILTIN_INSPECT_TARGET_RUNTIME_MANIFEST",
                        side_effect=record_reproduction,
                    ) as reproduce_runtime,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT",
                        wraps=(
                            requirements_module
                            ._BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT
                        ),
                    ) as stage_snapshot,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_EXTRACT_UNIQUE_TARGETS",
                        side_effect=record_extraction,
                    ) as extract,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET",
                        wraps=(
                            requirements_module
                            ._BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET
                        ),
                    ) as verify,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_DESCRIPTOR_REMEASUREMENT",
                        wraps=(
                            requirements_module
                            ._BUILTIN_DESCRIPTOR_REMEASUREMENT
                        ),
                    ) as remeasure,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_CLOSING_DESCRIPTOR_ANCHOR",
                        wraps=(
                            requirements_module
                            ._BUILTIN_CLOSING_DESCRIPTOR_ANCHOR
                        ),
                    ) as closing_anchor,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_BUILD_EXTRACTION",
                        wraps=requirements_module._BUILTIN_BUILD_EXTRACTION,
                    ) as build_extraction,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_BUILD_REQUIREMENT",
                        wraps=requirements_module._BUILTIN_BUILD_REQUIREMENT,
                    ) as build_requirement,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_BUILD_BINDING",
                        wraps=requirements_module._BUILTIN_BUILD_BINDING,
                    ) as build_binding,
                ):
                    receipt = (
                        inspect_staged_executable_shebang_target_requirements(
                            target_runtime,
                            expected_target_staging=target_staging,
                            lease=target_lease,
                        )
                    )
                self.assertEqual(reproduce_runtime.call_count, 2)
                self.assertEqual(stage_snapshot.call_count, 5)
                self.assertEqual(extract.call_count, 2)
                self.assertEqual(
                    proof_order,
                    [
                        "runtime_reproduction",
                        "descriptor_extraction",
                        "descriptor_extraction",
                        "runtime_reproduction",
                    ],
                )
                self.assertEqual(
                    verify.call_count,
                    2 * target_runtime.file_count,
                )
                self.assertEqual(
                    remeasure.call_count,
                    2 * target_runtime.file_count,
                )
                self.assertEqual(
                    closing_anchor.call_count,
                    target_runtime.file_count,
                )
                self.assertEqual(
                    build_extraction.call_count,
                    2 * target_runtime.file_count,
                )
                self.assertEqual(
                    build_requirement.call_count,
                    target_runtime.requirement_count,
                )
                self.assertEqual(
                    build_binding.call_count,
                    target_runtime.command_count,
                )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(self._lease_snapshot(target_lease), before)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_closing_snapshot_and_runtime_lineage_races_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(temporary)
            original_files = target_lease._files
            real_extract = requirements_module._BUILTIN_EXTRACT_UNIQUE_TARGETS
            extraction_calls = 0
            swapped = False

            def swap_after_second_pass(*args: object, **kwargs: object):
                nonlocal extraction_calls, swapped
                value = real_extract(*args, **kwargs)
                extraction_calls += 1
                if extraction_calls == 2:
                    target_lease._files = tuple(list(target_lease._files))
                    swapped = True
                return value

            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_EXTRACT_UNIQUE_TARGETS",
                    side_effect=swap_after_second_pass,
                ):
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                self.assertEqual(extraction_calls, 2)
                self.assertTrue(swapped)
            finally:
                target_lease._files = original_files
                target_lease.close()
                executable_lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(temporary)
            descriptor = target_lease._files[0].descriptor
            backup = os.dup(descriptor)
            foreign = os.open("/dev/null", os.O_RDONLY)
            real_receipt_projection = (
                requirements_module._BUILTIN_RECEIPT_PROJECTION
            )
            retargeted = False

            def retarget_after_receipt_validation(value: object):
                nonlocal retargeted
                canonical = real_receipt_projection(value)
                if not retargeted:
                    os.dup2(foreign, descriptor, inheritable=False)
                    retargeted = True
                return canonical

            before = self._lease_snapshot(target_lease)
            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_RECEIPT_PROJECTION",
                    side_effect=retarget_after_receipt_validation,
                ):
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                self.assertTrue(retargeted)
            finally:
                os.dup2(backup, descriptor, inheritable=False)
                os.close(foreign)
                os.close(backup)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                target_lease.close()
                executable_lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(temporary)
            original_registration_digest = target_runtime.registration_digest
            real_receipt_projection = (
                requirements_module._BUILTIN_RECEIPT_PROJECTION
            )
            projection_calls = 0
            mutated = False

            def mutate_after_receipt_validation(value: object):
                nonlocal projection_calls, mutated
                canonical = real_receipt_projection(value)
                projection_calls += 1
                if projection_calls == 1:
                    object.__setattr__(
                        target_runtime,
                        "registration_digest",
                        "sha256:" + "7" * 64,
                    )
                    mutated = True
                return canonical

            before = self._lease_snapshot(target_lease)
            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_RECEIPT_PROJECTION",
                    side_effect=mutate_after_receipt_validation,
                ):
                    self._assert_invalid(
                        target_runtime,
                        target_staging,
                        target_lease,
                    )
                self.assertTrue(mutated)
                self.assertEqual(projection_calls, 1)
            finally:
                object.__setattr__(
                    target_runtime,
                    "registration_digest",
                    original_registration_digest,
                )
                self.assertEqual(self._lease_snapshot(target_lease), before)
                target_lease.close()
                executable_lease.close()

    def test_cleanup_during_runtime_reproduction_fails_closed_and_stays_clean(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable_lease, target_lease, target_staging = (
                self.fixture._one_direct_stage(temporary)
            )
            target_stage_root = target_lease.staging_root
            target_runtime = (
                inspect_staged_executable_shebang_target_runtime_manifest(
                    target_staging,
                    lease=target_lease,
                )
            )
            real_inspect = (
                requirements_module._BUILTIN_INSPECT_TARGET_RUNTIME_MANIFEST
            )
            cleaned = False

            def cleanup_after_reproduction(*args: object, **kwargs: object):
                nonlocal cleaned
                value = real_inspect(*args, **kwargs)
                if not cleaned:
                    cleaned = True
                    target_lease.close()
                return value

            with patch.object(
                requirements_module,
                "_BUILTIN_INSPECT_TARGET_RUNTIME_MANIFEST",
                side_effect=cleanup_after_reproduction,
            ):
                self._assert_invalid(
                    target_runtime,
                    target_staging,
                    target_lease,
                )
            self.assertTrue(cleaned)
            self.assertEqual(target_lease.state, "cleaned")
            self.assertTrue(
                target_lease.cleanup_receipt.descriptor_release_complete
            )
            self.assertTrue(
                target_lease.cleanup_receipt.owned_namespace_absence_verified
            )
            self.assertEqual(tuple(target_stage_root.iterdir()), ())
            executable_lease.close()

    def test_output_structural_and_type_exactness(self) -> None:
        class DeceptiveString(str):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            (
                executable_lease,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._one_direct_runtime(
                temporary,
                target_content=b"#!a b\n",
            )
            receipt = inspect_staged_executable_shebang_target_requirements(
                target_runtime,
                expected_target_staging=target_staging,
                lease=target_lease,
            )
            try:
                first_requirement = receipt.requirements[0]
                first_binding = receipt.bindings[0]
                unit_receipt = replace(
                    receipt,
                    requirements=(first_requirement,),
                    bindings=(first_binding,),
                    requirement_count=1,
                    command_count=1,
                    direct_target_requirement_count=1,
                    native_not_applicable_count=0,
                    unique_target_count=1,
                    target_posix_shebang_requirement_count=1,
                    argument_tail_requirement_count=1,
                    total_interpreter_token_bytes=1,
                    total_argument_tail_bytes=1,
                )
                self.assertEqual(unit_receipt.to_canonical()["command_count"], 1)

                bool_as_int = {
                    "schema_version": True,
                    "requirement_count": True,
                    "command_count": True,
                    "direct_target_requirement_count": True,
                    "native_not_applicable_count": False,
                    "unique_target_count": True,
                    "target_posix_shebang_requirement_count": True,
                    "argument_tail_requirement_count": True,
                    "total_interpreter_token_bytes": True,
                    "total_argument_tail_bytes": True,
                }
                for field, deceptive in bool_as_int.items():
                    with self.subTest(bool_as_int=field):
                        self.assertEqual(
                            getattr(unit_receipt, field),
                            int(deceptive),
                        )
                        with self.assertRaises(ValueError):
                            replace(
                                unit_receipt,
                                **{field: deceptive},
                            ).to_canonical()

                deceptive_values = (
                    replace(
                        unit_receipt,
                        kind=DeceptiveString(unit_receipt.kind),
                    ),
                    replace(
                        first_requirement,
                        disposition=DeceptiveString(
                            first_requirement.disposition
                        ),
                    ),
                    replace(
                        first_requirement,
                        target_runtime_classification=DeceptiveString(
                            first_requirement.target_runtime_classification
                        ),
                    ),
                    replace(
                        first_requirement,
                        interpreter_token_ref=DeceptiveString(
                            first_requirement.interpreter_token_ref
                        ),
                    ),
                    replace(
                        first_binding,
                        command_kind=DeceptiveString(
                            first_binding.command_kind
                        ),
                    ),
                )
                for forged in deceptive_values:
                    with self.subTest(deceptive=type(forged).__name__):
                        with self.assertRaises(ValueError):
                            forged.to_canonical()

                forged_binding = replace(
                    first_binding,
                    target_shebang_requirement_ref="sha256:" + "9" * 64,
                )
                structural = {
                    "requirements-list": replace(
                        receipt,
                        requirements=list(receipt.requirements),
                    ),
                    "bindings-list": replace(
                        receipt,
                        bindings=list(receipt.bindings),
                    ),
                    "reordered-requirements": replace(
                        receipt,
                        requirements=tuple(reversed(receipt.requirements)),
                    ),
                    "reordered-bindings": replace(
                        receipt,
                        bindings=tuple(reversed(receipt.bindings)),
                    ),
                    "duplicate-requirement": replace(
                        receipt,
                        requirements=(first_requirement, first_requirement),
                    ),
                    "wrong-requirement-count": replace(
                        receipt,
                        requirement_count=receipt.requirement_count + 1,
                    ),
                    "wrong-command-count": replace(
                        receipt,
                        command_count=receipt.command_count + 1,
                    ),
                    "wrong-unique-count": replace(
                        receipt,
                        unique_target_count=receipt.unique_target_count + 1,
                    ),
                    "wrong-tail-count": replace(
                        receipt,
                        argument_tail_requirement_count=0,
                    ),
                    "wrong-token-total": replace(
                        receipt,
                        total_interpreter_token_bytes=2,
                    ),
                    "wrong-tail-total": replace(
                        receipt,
                        total_argument_tail_bytes=2,
                    ),
                    "wrong-binding-terminal-ref": replace(
                        receipt,
                        bindings=(forged_binding, *receipt.bindings[1:]),
                    ),
                }
                for case, forged in structural.items():
                    with self.subTest(case=case):
                        with self.assertRaises(ValueError):
                            forged.to_canonical()

                for forged_requirement in (
                    replace(
                        first_requirement,
                        disposition="unknown_runtime_format",
                    ),
                    replace(
                        first_requirement,
                        interpreter_token_bytes=2,
                    ),
                    replace(
                        first_requirement,
                        argument_separator_kind=None,
                    ),
                    replace(
                        first_requirement,
                        target_runtime_file_ref="sha256:" + "8" * 64,
                    ),
                ):
                    with self.assertRaises(ValueError):
                        forged_requirement.to_canonical()
            finally:
                target_lease.close()
                executable_lease.close()

    def test_exports_and_inspector_signature_are_exact(self) -> None:
        self.assertEqual(
            requirements_module.__all__,
            [
                "REQUIREMENTS_SCOPE",
                "REQUIREMENTS_SOURCE",
                (
                    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_"
                    "SHEBANG_REQUIREMENT_BINDING_KIND"
                ),
                (
                    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_"
                    "REQUIREMENTS_EVIDENCE_KIND"
                ),
                "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENTS_KIND",
                (
                    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_"
                    "REQUIREMENTS_SCHEMA_VERSION"
                ),
                (
                    "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_"
                    "SHEBANG_REQUIREMENT_KIND"
                ),
                "RepositoryExecutableShebangTargetShebangRequirementBinding",
                "RepositoryExecutableShebangTargetRequirementsReceipt",
                "RepositoryExecutableShebangTargetShebangRequirement",
                "inspect_staged_executable_shebang_target_requirements",
            ],
        )
        signature = inspect.signature(
            inspect_staged_executable_shebang_target_requirements
        )
        self.assertEqual(
            tuple(signature.parameters),
            ("expected_target_runtime", "expected_target_staging", "lease"),
        )
        runtime_parameter = signature.parameters["expected_target_runtime"]
        staging_parameter = signature.parameters["expected_target_staging"]
        lease_parameter = signature.parameters["lease"]
        self.assertIs(
            runtime_parameter.kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(runtime_parameter.default, inspect.Parameter.empty)
        self.assertIs(staging_parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(staging_parameter.default, inspect.Parameter.empty)
        self.assertIs(lease_parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(lease_parameter.default, inspect.Parameter.empty)

    def test_no_environment_path_process_state_write_or_cleanup_effects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "no-effect-target"
            self._write_target(target, b"#!/bin/sh private-tail\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
            ) = self._stage_target_runtime(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            before = self._lease_snapshot(target_lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
            )
            try:
                patch_specs = (
                    (builtins, "open", "path open"),
                    (Path, "open", "path open"),
                    (shutil, "which", "PATH"),
                    (os, "getenv", "environment"),
                    (os, "get_exec_path", "PATH"),
                    (os, "open", "path reopen"),
                    (os, "write", "write"),
                    (os, "fchmod", "chmod"),
                    (os, "close", "close"),
                    (os, "dup", "duplicate descriptor"),
                    (os, "dup2", "retarget descriptor"),
                    (os, "lseek", "seek"),
                    (os, "system", "shell"),
                    (subprocess, "run", "process"),
                    (subprocess, "Popen", "process"),
                    (asyncio, "create_subprocess_exec", "process"),
                    (asyncio, "create_subprocess_shell", "process"),
                    (artifact_filesystem_module, "stage_artifact", "artifact"),
                    (
                        artifact_filesystem_module,
                        "publish_staged_artifact",
                        "artifact",
                    ),
                    (state_module.SQLiteStateStore, "__init__", "state"),
                    (
                        target_staging_module,
                        (
                            "cleanup_repository_executable_"
                            "shebang_target_stage"
                        ),
                        "cleanup",
                    ),
                )
                with ExitStack() as stack:
                    observed_effects = tuple(
                        stack.enter_context(
                            patch.object(
                                owner,
                                name,
                                side_effect=AssertionError(message),
                            )
                        )
                        for owner, name, message in patch_specs
                    )
                    receipt = (
                        inspect_staged_executable_shebang_target_requirements(
                            target_runtime,
                            expected_target_staging=target_staging,
                            lease=target_lease,
                        )
                    )
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                for observed in observed_effects:
                    observed.assert_not_called()
                self.assertEqual(
                    tuple(
                        self._tree_snapshot(path)
                        for path in (
                            root,
                            outside,
                            search_one,
                            search_two,
                            target.parent,
                        )
                    ),
                    trees_before,
                )
            finally:
                target_lease.close()
                executable_lease.close()
