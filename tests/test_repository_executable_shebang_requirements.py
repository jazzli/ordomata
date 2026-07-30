from __future__ import annotations

import asyncio
import builtins
from dataclasses import FrozenInstanceError, replace
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
import ordomata.repository_executable_runtime_manifest as runtime_module
from ordomata.repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
    inspect_staged_executable_runtime_manifest,
)
import ordomata.repository_executable_shebang_requirements as requirements_module
from ordomata.repository_executable_shebang_requirements import (
    REQUIREMENTS_SCOPE,
    REQUIREMENTS_SOURCE,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION,
    RepositoryExecutableShebangRequirement,
    RepositoryExecutableShebangRequirementBinding,
    RepositoryExecutableShebangRequirementsReceipt,
    inspect_staged_executable_shebang_requirements,
)
import ordomata.repository_executable_staging as staging_module
from ordomata.repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
)
import ordomata.state as state_module

if __package__:
    from . import test_repository_executable_runtime_manifest as runtime_test_module
else:
    import test_repository_executable_runtime_manifest as runtime_test_module


FIXED_REQUIREMENTS_ERROR = (
    "repository executable shebang requirements are invalid"
)
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
    "shebang_directive_ref",
    "staged_file_ref",
}
REQUIREMENT_BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
}
REQUIREMENTS_RECEIPT_KEYS = {
    "argument_tail_requirement_count",
    "bindings",
    "command_count",
    "kind",
    "posix_shebang_requirement_count",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "requirements_scope",
    "requirements_source",
    "resolution_context_digest",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "staging_context_digest",
    "staging_receipt_digest",
    "total_argument_tail_bytes",
    "total_interpreter_token_bytes",
    "verification_commands_digest",
}
REQUIREMENTS_EVIDENCE_KEYS = {
    "absolute_interpreter_token_count",
    "action_receipt_issued",
    "active_lease_verified_at_measurement",
    "argument_tail_requirement_count",
    "authority_granted",
    "authorization_verified",
    "billing_eligible",
    "bounded_shebang_requirement_extraction_complete",
    "capacity_eligible",
    "circuit_eligible",
    "command_count",
    "current_lease_activity_verified",
    "current_source_freshness_verified",
    "dependency_environment_coverage_verified",
    "dispatch_enabled",
    "durable_control_plane_persistence_enabled",
    "dynamic_loader_identity_verified",
    "effect_class",
    "effective_invocability_verified",
    "environment_coverage_verified",
    "execution_enabled",
    "future_execution_correspondence_verified",
    "interpreter_argument_semantics_verified",
    "interpreter_authenticity_verified",
    "interpreter_compatibility_verified",
    "interpreter_identity_verified",
    "interpreter_resolution_verified",
    "interpreter_token_syntax_classification_complete",
    "kind",
    "launcher_semantics_verified",
    "lease_cleanup_performed",
    "lease_mutated",
    "live_execution_eligible",
    "native_binary_no_shebang_count",
    "native_runtime_dependency_coverage_verified",
    "non_absolute_interpreter_token_count",
    "path_lookup_performed",
    "posix_shebang_requirement_count",
    "proposal_lineage_extended",
    "receipt_authenticity_verified",
    "receipt_digest",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements_scope",
    "requirements_source",
    "resolution_context_digest",
    "route_eligible",
    "runtime_manifest_receipt_digest",
    "runtime_manifest_complete",
    "schema_version",
    "shared_library_identity_verified",
    "source_path_reopen_performed",
    "staged_byte_correspondence_verified",
    "staging_receipt_digest",
    "subprocess_invocation_performed",
    "toolchain_completeness_verified",
    "total_argument_tail_bytes",
    "total_interpreter_token_bytes",
    "unknown_runtime_format_count",
    "unsupported_shebang_count",
    "validation_mode",
    "worktree_integration_enabled",
}


@unittest.skipUnless(os.name == "posix", "shebang requirements require POSIX")
class RepositoryExecutableShebangRequirementsTests(unittest.TestCase):
    fixture = runtime_test_module.RepositoryExecutableRuntimeManifestTests

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
    def _stage_runtime(
        cls,
        registration: object,
        search_directories: tuple[Path, ...],
        staging_root: Path,
    ) -> tuple[
        RepositoryExecutableStageLease,
        RepositoryExecutableStagingReceipt,
        RepositoryExecutableRuntimeManifestReceipt,
    ]:
        lease, staging = cls.fixture._stage(
            registration,
            search_directories,
            staging_root,
        )
        runtime = inspect_staged_executable_runtime_manifest(
            staging,
            lease=lease,
        )
        return lease, staging, runtime

    @classmethod
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    def _assert_invalid(
        self,
        expected_runtime: object,
        expected_staging: object,
        lease: object,
        *,
        private_marker: str = "private-shebang-requirements-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_shebang_requirements(
                expected_runtime,
                expected_staging=expected_staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_REQUIREMENTS_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    @staticmethod
    def _requirement_by_classification(
        receipt: RepositoryExecutableShebangRequirementsReceipt,
        classification: str,
    ) -> RepositoryExecutableShebangRequirement:
        values = tuple(
            value
            for value in receipt.requirements
            if value.runtime_classification == classification
        )
        if len(values) != 1:
            raise AssertionError(
                f"expected one {classification!r} requirement, got {len(values)}"
            )
        return values[0]

    def test_receipt_correspondence_privacy_and_lease_immutability(self) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        token = b"/usr/bin/env"
        tail = b"python3 -I\tprivate-opaque-tail-marker"
        shebang = b"#!" + token + b"\t\t" + tail + b"\nbody-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=shebang,
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            try:
                receipt = inspect_staged_executable_shebang_requirements(
                    runtime,
                    expected_staging=staging,
                    lease=lease,
                )
                repeated = inspect_staged_executable_shebang_requirements(
                    runtime,
                    expected_staging=staging,
                    lease=lease,
                )
                self.assertEqual(receipt, repeated)
                self.assertEqual(self._lease_snapshot(lease), before)
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangRequirementsReceipt,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_SCHEMA_VERSION,
                    1,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_KIND,
                    "repository_executable_shebang_requirements",
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_EVIDENCE_KIND,
                    "repository_executable_shebang_requirements_validation",
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_KIND,
                    "repository_executable_shebang_requirement",
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENT_BINDING_KIND,
                    "repository_executable_shebang_requirement_binding",
                )
                self.assertEqual(REQUIREMENTS_SOURCE, "controller_inspected")
                self.assertEqual(
                    REQUIREMENTS_SCOPE,
                    "posix_staged_shebang_requirements_v1",
                )

                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), REQUIREMENTS_RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                self.assertEqual(
                    receipt.runtime_manifest_receipt_digest,
                    runtime.receipt_digest,
                )
                self.assertEqual(
                    receipt.staging_receipt_digest,
                    staging.receipt_digest,
                )
                for field in (
                    "registration_digest",
                    "repository_ref",
                    "verification_commands_digest",
                    "resolution_context_digest",
                    "staging_context_digest",
                ):
                    self.assertEqual(
                        getattr(receipt, field),
                        getattr(runtime, field),
                    )
                    self.assertEqual(
                        getattr(receipt, field),
                        getattr(staging, field),
                    )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.posix_shebang_requirement_count, 1)
                self.assertEqual(receipt.argument_tail_requirement_count, 1)
                self.assertEqual(receipt.total_interpreter_token_bytes, len(token))
                self.assertEqual(receipt.total_argument_tail_bytes, len(tail))

                requirement_by_runtime_ref = {}
                for requirement, runtime_file in zip(
                    receipt.requirements,
                    runtime.files,
                    strict=True,
                ):
                    self.assertIsInstance(
                        requirement,
                        RepositoryExecutableShebangRequirement,
                    )
                    self.assertEqual(
                        set(requirement.to_canonical()),
                        REQUIREMENT_KEYS,
                    )
                    self.assertEqual(
                        requirement.staged_file_ref,
                        runtime_file.staged_file_ref,
                    )
                    self.assertEqual(
                        requirement.runtime_file_ref,
                        runtime_file.runtime_file_ref,
                    )
                    self.assertEqual(
                        requirement.runtime_classification,
                        runtime_file.classification,
                    )
                    self.assertEqual(
                        requirement.shebang_directive_ref,
                        runtime_file.shebang_directive_ref,
                    )
                    self.assertRegex(
                        requirement.requirement_ref,
                        r"^sha256:[0-9a-f]{64}$",
                    )
                    requirement_by_runtime_ref[requirement.runtime_file_ref] = (
                        requirement
                    )

                native = self._requirement_by_classification(receipt, "elf")
                self.assertEqual(native.disposition, "native_binary_no_shebang")
                self.assertIsNone(native.shebang_directive_ref)
                self.assertIsNone(native.interpreter_token_ref)
                self.assertEqual(native.interpreter_token_bytes, 0)
                self.assertIsNone(native.argument_separator_kind)
                self.assertIsNone(native.argument_tail_ref)
                self.assertEqual(native.argument_tail_bytes, 0)

                posix = self._requirement_by_classification(
                    receipt,
                    "posix_shebang",
                )
                self.assertEqual(posix.disposition, "absolute_interpreter_token")
                self.assertRegex(
                    posix.interpreter_token_ref,
                    r"^sha256:[0-9a-f]{64}$",
                )
                self.assertEqual(posix.interpreter_token_bytes, len(token))
                self.assertEqual(posix.argument_separator_kind, "horizontal_tab")
                self.assertRegex(
                    posix.argument_tail_ref,
                    r"^sha256:[0-9a-f]{64}$",
                )
                self.assertEqual(posix.argument_tail_bytes, len(tail))

                for binding, runtime_binding in zip(
                    receipt.bindings,
                    runtime.bindings,
                    strict=True,
                ):
                    self.assertIsInstance(
                        binding,
                        RepositoryExecutableShebangRequirementBinding,
                    )
                    self.assertEqual(
                        set(binding.to_canonical()),
                        REQUIREMENT_BINDING_KEYS,
                    )
                    for field in (
                        "command_kind",
                        "command_id",
                        "command_digest",
                        "staged_file_ref",
                        "runtime_file_ref",
                    ):
                        self.assertEqual(
                            getattr(binding, field),
                            getattr(runtime_binding, field),
                        )
                    self.assertEqual(
                        binding.requirement_ref,
                        requirement_by_runtime_ref[
                            binding.runtime_file_ref
                        ].requirement_ref,
                    )

                expected_token_ref = canonical_digest(
                    {
                        "interpreter_token_hex": token.hex(),
                        "kind": (
                            "repository_executable_shebang_"
                            "interpreter_token_ref"
                        ),
                        "runtime_file_ref": posix.runtime_file_ref,
                        "schema_version": 1,
                        "shebang_directive_ref": posix.shebang_directive_ref,
                    }
                )
                self.assertEqual(posix.interpreter_token_ref, expected_token_ref)
                self.assertEqual(
                    posix.argument_tail_ref,
                    canonical_digest(
                        {
                            "argument_separator_kind": "horizontal_tab",
                            "argument_tail_hex": tail.hex(),
                            "interpreter_token_ref": expected_token_ref,
                            "kind": (
                                "repository_executable_shebang_"
                                "argument_tail_ref"
                            ),
                            "runtime_file_ref": posix.runtime_file_ref,
                            "schema_version": 1,
                            "shebang_directive_ref": (
                                posix.shebang_directive_ref
                            ),
                        }
                    ),
                )

                evidence = receipt.to_evidence()
                self.assertEqual(set(evidence), REQUIREMENTS_EVIDENCE_KEYS)
                self.assertEqual(
                    evidence["kind"],
                    REPOSITORY_EXECUTABLE_SHEBANG_REQUIREMENTS_EVIDENCE_KIND,
                )
                self.assertEqual(evidence["effect_class"], 0)
                self.assertEqual(evidence["validation_mode"], "read_only")
                self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
                self.assertEqual(evidence["requirement_count"], 2)
                self.assertEqual(evidence["command_count"], 2)
                self.assertEqual(evidence["native_binary_no_shebang_count"], 1)
                self.assertEqual(evidence["absolute_interpreter_token_count"], 1)
                self.assertEqual(
                    evidence["non_absolute_interpreter_token_count"],
                    0,
                )
                self.assertEqual(evidence["unsupported_shebang_count"], 0)
                self.assertEqual(evidence["unknown_runtime_format_count"], 0)
                for field in (
                    "argument_tail_requirement_count",
                    "posix_shebang_requirement_count",
                    "registration_digest",
                    "repository_ref",
                    "requirement_count",
                    "requirements_scope",
                    "requirements_source",
                    "resolution_context_digest",
                    "runtime_manifest_receipt_digest",
                    "schema_version",
                    "staging_receipt_digest",
                    "total_argument_tail_bytes",
                    "total_interpreter_token_bytes",
                ):
                    self.assertEqual(evidence[field], getattr(receipt, field))
                for true_fact in (
                    "active_lease_verified_at_measurement",
                    "bounded_shebang_requirement_extraction_complete",
                    "interpreter_token_syntax_classification_complete",
                    "staged_byte_correspondence_verified",
                ):
                    self.assertIs(evidence[true_fact], True, true_fact)
                for false_fact in (
                    "action_receipt_issued",
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
                    "effective_invocability_verified",
                    "environment_coverage_verified",
                    "execution_enabled",
                    "future_execution_correspondence_verified",
                    "interpreter_argument_semantics_verified",
                    "interpreter_authenticity_verified",
                    "interpreter_compatibility_verified",
                    "interpreter_identity_verified",
                    "interpreter_resolution_verified",
                    "launcher_semantics_verified",
                    "lease_cleanup_performed",
                    "lease_mutated",
                    "live_execution_eligible",
                    "native_runtime_dependency_coverage_verified",
                    "path_lookup_performed",
                    "proposal_lineage_extended",
                    "receipt_authenticity_verified",
                    "route_eligible",
                    "runtime_manifest_complete",
                    "shared_library_identity_verified",
                    "source_path_reopen_performed",
                    "subprocess_invocation_performed",
                    "toolchain_completeness_verified",
                    "worktree_integration_enabled",
                ):
                    self.assertIs(evidence[false_fact], False, false_fact)

                canonical_json = json.dumps(canonical, sort_keys=True)
                evidence_and_repr = "\n".join(
                    (
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        *(repr(value) for value in receipt.requirements),
                        *(repr(value) for value in receipt.bindings),
                    )
                )
                for private_bytes in (
                    token.decode("ascii"),
                    tail.decode("ascii"),
                    "body-marker",
                ):
                    self.assertNotIn(private_bytes, canonical_json)
                for private_value in (
                    str(root),
                    str(search_one),
                    str(staging_root),
                    "private-bare-command-marker",
                    "private-relative-command-marker",
                    token.decode("ascii"),
                    tail.decode("ascii"),
                    "body-marker",
                    *(value.content_digest for value in runtime.files),
                ):
                    self.assertNotIn(private_value, evidence_and_repr)
                for private_ref in (
                    posix.shebang_directive_ref,
                    posix.interpreter_token_ref,
                    posix.argument_tail_ref,
                    posix.requirement_ref,
                ):
                    self.assertNotIn(private_ref, evidence_and_repr)
                self.assertFalse(hasattr(receipt, "__dict__"))
                self.assertFalse(hasattr(receipt.requirements[0], "__dict__"))
                self.assertFalse(hasattr(receipt.bindings[0], "__dict__"))
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirement_count = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirements[0].disposition = "unknown_runtime_format"
                with self.assertRaises(FrozenInstanceError):
                    receipt.bindings[0].command_kind = "test"
            finally:
                lease.close()

    def test_splitting_boundaries_no_tail_and_non_absolute_token(self) -> None:
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
                "root-token-is-syntactically-absolute",
                b"#!/\n",
                "absolute_interpreter_token",
                None,
                b"/",
                None,
            ),
            (
                "repeated-slash-is-syntactically-absolute",
                b"#!/opt//private-python\n",
                "absolute_interpreter_token",
                None,
                b"/opt//private-python",
                None,
            ),
            (
                "trailing-slash-is-syntactically-absolute",
                b"#!/opt/private-python/\n",
                "absolute_interpreter_token",
                None,
                b"/opt/private-python/",
                None,
            ),
            (
                "dot-component-is-syntactically-absolute",
                b"#!/opt/./private-python\n",
                "absolute_interpreter_token",
                None,
                b"/opt/./private-python",
                None,
            ),
            (
                "dot-dot-component-is-syntactically-absolute",
                b"#!/opt/../private-python\n",
                "absolute_interpreter_token",
                None,
                b"/opt/../private-python",
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
        )
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        for (
            case,
            shebang,
            disposition,
            separator,
            token,
            tail,
        ) in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root, _outside, search_one, search_two, staging_root = (
                    self._workspace(temporary)
                )
                self._set_contents(
                    root,
                    search_one,
                    bare=elf,
                    relative=shebang,
                )
                registration = self._registration(root)
                lease, staging, runtime = self._stage_runtime(
                    registration,
                    (search_one, search_two),
                    staging_root,
                )
                try:
                    receipt = inspect_staged_executable_shebang_requirements(
                        runtime,
                        expected_staging=staging,
                        lease=lease,
                    )
                    requirement = self._requirement_by_classification(
                        receipt,
                        "posix_shebang",
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
                                "repository_executable_shebang_"
                                "interpreter_token_ref"
                            ),
                            "runtime_file_ref": requirement.runtime_file_ref,
                            "schema_version": 1,
                            "shebang_directive_ref": (
                                requirement.shebang_directive_ref
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
                                        "repository_executable_shebang_"
                                        "argument_tail_ref"
                                    ),
                                    "runtime_file_ref": (
                                        requirement.runtime_file_ref
                                    ),
                                    "schema_version": 1,
                                    "shebang_directive_ref": (
                                        requirement.shebang_directive_ref
                                    ),
                                }
                            ),
                        )
                finally:
                    lease.close()

    def test_all_runtime_classifications_have_fixed_dispositions(self) -> None:
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
                "posix_shebang",
                b"#!/bin/sh\n",
                "absolute_interpreter_token",
            ),
            (
                "unsupported_shebang",
                b"#! /bin/sh\n",
                "unsupported_shebang",
            ),
            (
                "unknown",
                b"ordinary private executable bytes\n",
                "unknown_runtime_format",
            ),
        )
        for classification, content, disposition in cases:
            with (
                self.subTest(classification=classification),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root, _outside, search_one, search_two, staging_root = (
                    self._workspace(temporary)
                )
                self._set_contents(root, search_one, bare=content)
                registration = self._registration(root)
                lease, staging, runtime = self._stage_runtime(
                    registration,
                    (search_one, search_two),
                    staging_root,
                )
                try:
                    receipt = inspect_staged_executable_shebang_requirements(
                        runtime,
                        expected_staging=staging,
                        lease=lease,
                    )
                    self.assertEqual(
                        {
                            value.runtime_classification
                            for value in receipt.requirements
                        },
                        {classification},
                    )
                    for requirement in receipt.requirements:
                        self.assertEqual(requirement.disposition, disposition)
                        if classification != "posix_shebang":
                            self.assertIsNone(requirement.interpreter_token_ref)
                            self.assertEqual(requirement.interpreter_token_bytes, 0)
                            self.assertIsNone(requirement.argument_separator_kind)
                            self.assertIsNone(requirement.argument_tail_ref)
                            self.assertEqual(requirement.argument_tail_bytes, 0)
                finally:
                    lease.close()

    def test_shared_runtime_file_is_required_once_and_bound_twice(self) -> None:
        shebang = b"#!/bin/sh -eu\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(root, search_one, bare=shebang)
            registration = self._registration(root, shared=True)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one,),
                staging_root,
            )
            try:
                receipt = inspect_staged_executable_shebang_requirements(
                    runtime,
                    expected_staging=staging,
                    lease=lease,
                )
                self.assertEqual(runtime.file_count, 1)
                self.assertEqual(receipt.requirement_count, 1)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(len(receipt.bindings), 2)
                self.assertEqual(
                    {value.requirement_ref for value in receipt.bindings},
                    {receipt.requirements[0].requirement_ref},
                )
            finally:
                lease.close()

    def test_inactive_closed_cross_pid_and_wrong_typed_inputs_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            inactive = RepositoryExecutableStageLease(staging_root)
            with patch.object(
                requirements_module.os,
                "pread",
                side_effect=AssertionError("descriptor read before validation"),
            ) as pread:
                for bad_runtime, bad_staging, bad_lease in (
                    (object(), staging, lease),
                    (runtime, object(), lease),
                    (runtime, staging, object()),
                    (runtime, staging, inactive),
                ):
                    self._assert_invalid(
                        bad_runtime,
                        bad_staging,
                        bad_lease,
                    )
                with patch.object(
                    requirements_module.os,
                    "getpid",
                    return_value=lease._owner_pid + 1,
                ):
                    self._assert_invalid(runtime, staging, lease)
            pread.assert_not_called()
            lease.close()
            with patch.object(
                requirements_module.os,
                "pread",
                side_effect=AssertionError("closed descriptor read"),
            ) as pread:
                self._assert_invalid(runtime, staging, lease)
            pread.assert_not_called()
            inactive.close()

    def test_forged_reordered_and_transplanted_receipts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            other_root = staging_root.parent / "private-other-stage-marker"
            other_root.mkdir(mode=0o700)
            other_root.chmod(0o700)
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            other_lease, other_staging, other_runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                other_root,
            )
            try:
                valid_reordered = replace(
                    runtime,
                    files=tuple(reversed(runtime.files)),
                )
                self.assertEqual(
                    valid_reordered.receipt_digest,
                    canonical_digest(valid_reordered.to_canonical()),
                )
                forged = replace(
                    runtime,
                    registration_digest="sha256:" + "0" * 64,
                )
                with patch.object(
                    runtime_module.RepositoryExecutableRuntimeManifestReceipt,
                    "to_canonical",
                    return_value=runtime.to_canonical(),
                ):
                    self._assert_invalid(forged, staging, lease)
                for bad_runtime, bad_staging in (
                    (valid_reordered, staging),
                    (other_runtime, staging),
                    (runtime, other_staging),
                    (
                        runtime,
                        replace(
                            staging,
                            staging_context_digest="sha256:" + "1" * 64,
                        ),
                    ),
                ):
                    self._assert_invalid(bad_runtime, bad_staging, lease)
            finally:
                lease.close()
                other_lease.close()

    def test_public_module_monkeypatches_cannot_bypass_fresh_reinspection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!/bin/sh\n",
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            try:
                with (
                    patch.object(
                        runtime_module,
                        "inspect_staged_executable_runtime_manifest",
                        side_effect=AssertionError("patched runtime inspector"),
                    ) as public_inspector,
                    patch.object(
                        runtime_module.RepositoryExecutableRuntimeManifestReceipt,
                        "to_canonical",
                        side_effect=AssertionError("patched canonical method"),
                    ) as public_canonical,
                    patch.object(
                        requirements_module,
                        "canonical_digest",
                        side_effect=AssertionError("patched digest"),
                    ) as public_digest,
                ):
                    receipt = inspect_staged_executable_shebang_requirements(
                        runtime,
                        expected_staging=staging,
                        lease=lease,
                    )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(self._lease_snapshot(lease), before)
                public_inspector.assert_not_called()
                public_canonical.assert_not_called()
                public_digest.assert_not_called()
            finally:
                lease.close()

    def test_upstream_header_digest_forgery_is_independently_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!/bin/sh private-tail-marker\n",
            )
            registration = self._registration(root)
            lease, staging = self.fixture._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            genuine_runtime = inspect_staged_executable_runtime_manifest(
                staging,
                lease=lease,
            )
            before = self._lease_snapshot(lease)
            forged_digest = "sha256:" + "f" * 64
            try:
                with patch.object(
                    runtime_module,
                    "_header_digest",
                    return_value=forged_digest,
                ):
                    self._assert_invalid(genuine_runtime, staging, lease)
                    forged_runtime = (
                        inspect_staged_executable_runtime_manifest(
                            staging,
                            lease=lease,
                        )
                    )
                    self.assertEqual(
                        {value.header_digest for value in forged_runtime.files},
                        {forged_digest},
                    )
                    self.assertEqual(
                        forged_runtime.receipt_digest,
                        canonical_digest(forged_runtime.to_canonical()),
                    )
                    self._assert_invalid(forged_runtime, staging, lease)
                self.assertEqual(self._lease_snapshot(lease), before)
            finally:
                lease.close()

    def test_upstream_shebang_parser_forgery_is_independently_rejected(
        self,
    ) -> None:
        unsupported = b"#! /bin/sh\nprivate-body-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(root, search_one, bare=unsupported)
            registration = self._registration(root)
            lease, staging = self.fixture._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            try:
                with patch.object(
                    runtime_module,
                    "_bounded_shebang_directive",
                    return_value=b"/bin/sh",
                ):
                    forged_runtime = (
                        inspect_staged_executable_runtime_manifest(
                            staging,
                            lease=lease,
                        )
                    )
                    self.assertEqual(
                        {value.classification for value in forged_runtime.files},
                        {"posix_shebang"},
                    )
                    self._assert_invalid(forged_runtime, staging, lease)
                self.assertEqual(self._lease_snapshot(lease), before)
            finally:
                lease.close()

    def test_forged_upstream_runtime_binding_builder_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            forged_binding = replace(
                runtime.bindings[0],
                command_digest="sha256:" + "0" * 64,
            )
            forged_runtime = replace(
                runtime,
                bindings=(forged_binding, *runtime.bindings[1:]),
            )
            self.assertEqual(
                forged_runtime.receipt_digest,
                canonical_digest(forged_runtime.to_canonical()),
            )
            before = self._lease_snapshot(lease)
            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
                    return_value=forged_runtime,
                ) as forged_builder:
                    self._assert_invalid(forged_runtime, staging, lease)
                self.assertGreaterEqual(forged_builder.call_count, 1)
                self.assertEqual(self._lease_snapshot(lease), before)
            finally:
                lease.close()

    def test_patched_staging_projection_cannot_hide_forged_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging = self.fixture._stage(
                registration,
                (search_one, search_two),
                staging_root,
            )
            original_binding = staging.bindings[0]
            forged_binding = replace(
                original_binding,
                command_digest="sha256:" + "0" * 64,
            )
            forged_staging = replace(
                staging,
                bindings=(forged_binding, *staging.bindings[1:]),
            )
            real_projection = staging_module._stage_binding_projection

            def conceal_forgery(binding: object) -> dict[str, object]:
                if binding is forged_binding:
                    return real_projection(original_binding)
                return real_projection(binding)

            before = self._lease_snapshot(lease)
            try:
                with patch.object(
                    staging_module,
                    "_stage_binding_projection",
                    side_effect=conceal_forgery,
                ):
                    forged_runtime = (
                        inspect_staged_executable_runtime_manifest(
                            forged_staging,
                            lease=lease,
                        )
                    )
                    self.assertEqual(
                        forged_runtime.bindings[0].command_digest,
                        forged_binding.command_digest,
                    )
                    self._assert_invalid(
                        forged_runtime,
                        forged_staging,
                        lease,
                    )
                self.assertEqual(self._lease_snapshot(lease), before)
            finally:
                lease.close()

    def test_two_runtime_reproductions_and_independent_remeasurement_occur(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!/bin/sh -eu\n",
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            try:
                with (
                    patch.object(
                        requirements_module,
                        "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
                        wraps=(
                            requirements_module._BUILTIN_INSPECT_RUNTIME_MANIFEST
                        ),
                    ) as reproduce_runtime,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_VERIFY_RETAINED_FILE",
                        wraps=requirements_module._BUILTIN_VERIFY_RETAINED_FILE,
                    ) as remeasure,
                    patch.object(
                        requirements_module,
                        "_BUILTIN_ACTIVE_STAGE_SNAPSHOT",
                        wraps=requirements_module._BUILTIN_ACTIVE_STAGE_SNAPSHOT,
                    ) as stage_snapshot,
                ):
                    receipt = inspect_staged_executable_shebang_requirements(
                        runtime,
                        expected_staging=staging,
                        lease=lease,
                    )
                self.assertEqual(receipt.requirement_count, runtime.file_count)
                self.assertEqual(reproduce_runtime.call_count, 2)
                self.assertEqual(remeasure.call_count, 2 * runtime.file_count)
                self.assertEqual(stage_snapshot.call_count, 4)
                self.assertEqual(self._lease_snapshot(lease), before)
            finally:
                lease.close()

    def test_final_snapshot_tuple_swap_race_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(root, search_one, bare=b"#!/bin/sh\n")
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            original_files = lease._files
            swapped = False
            real_remeasure = requirements_module._BUILTIN_VERIFY_RETAINED_FILE

            def swap_after_measurement(retained: object, anchored: object) -> bytes:
                nonlocal swapped
                header = real_remeasure(retained, anchored)
                if not swapped:
                    swapped = True
                    lease._files = tuple(list(lease._files))
                return header

            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_VERIFY_RETAINED_FILE",
                    side_effect=swap_after_measurement,
                ):
                    self._assert_invalid(runtime, staging, lease)
                self.assertTrue(swapped)
            finally:
                lease._files = original_files
                lease.close()

    def test_forged_requirement_binding_and_receipt_invariants_reject(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!/bin/sh -eu\n",
                relative=b"\x7fELF\x02\x01\x01" + b"\x00" * 25,
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                receipt = inspect_staged_executable_shebang_requirements(
                    runtime,
                    expected_staging=staging,
                    lease=lease,
                )
                posix = self._requirement_by_classification(
                    receipt,
                    "posix_shebang",
                )
                for forged_requirement in (
                    replace(posix, disposition="unknown_runtime_format"),
                    replace(
                        posix,
                        interpreter_token_bytes=(
                            posix.interpreter_token_bytes + 1
                        ),
                    ),
                    replace(posix, argument_separator_kind=None),
                ):
                    with self.assertRaises(ValueError):
                        forged_requirement.to_canonical()

                forged_binding = replace(
                    receipt.bindings[0],
                    requirement_ref="sha256:" + "0" * 64,
                )
                for forged_receipt in (
                    replace(
                        receipt,
                        requirement_count=receipt.requirement_count + 1,
                    ),
                    replace(
                        receipt,
                        requirements=tuple(reversed(receipt.requirements)),
                    ),
                    replace(
                        receipt,
                        bindings=(forged_binding, *receipt.bindings[1:]),
                    ),
                    replace(
                        receipt,
                        total_argument_tail_bytes=(
                            receipt.total_argument_tail_bytes + 1
                        ),
                    ),
                ):
                    with self.assertRaises(ValueError):
                        forged_receipt.to_canonical()
            finally:
                lease.close()

    def test_tampered_lease_anchors_and_descriptor_metadata_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            original_digest = lease._receipt_digest_anchor
            original_refs = lease._receipt_staged_file_refs_anchor
            original_files = lease._files
            original_cleanup_anchor = lease._cleanup_receipt_digest_anchor
            retained = original_files[0]
            original_metadata = retained.metadata
            try:
                with patch.object(
                    requirements_module.os,
                    "pread",
                    side_effect=AssertionError("read before lease validation"),
                ) as pread:
                    lease._receipt_digest_anchor = "sha256:" + "0" * 64
                    self._assert_invalid(runtime, staging, lease)
                    lease._receipt_digest_anchor = original_digest

                    lease._receipt_staged_file_refs_anchor = tuple(
                        reversed(original_refs)
                    )
                    self._assert_invalid(runtime, staging, lease)
                    lease._receipt_staged_file_refs_anchor = original_refs

                    lease._files = tuple(reversed(original_files))
                    self._assert_invalid(runtime, staging, lease)
                    lease._files = original_files

                    lease._cleanup_receipt_digest_anchor = (
                        "sha256:" + "1" * 64
                    )
                    self._assert_invalid(runtime, staging, lease)
                    lease._cleanup_receipt_digest_anchor = original_cleanup_anchor

                    lease._files = (
                        replace(
                            retained,
                            metadata=(
                                *original_metadata[:-1],
                                original_metadata[-1] + 1,
                            ),
                        ),
                        *original_files[1:],
                    )
                    self._assert_invalid(runtime, staging, lease)
                pread.assert_not_called()
            finally:
                lease._receipt_digest_anchor = original_digest
                lease._receipt_staged_file_refs_anchor = original_refs
                lease._files = original_files
                lease._cleanup_receipt_digest_anchor = original_cleanup_anchor
                lease.close()

    def test_descriptor_retarget_and_corrupt_remeasurement_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!/bin/sh private-tail-marker\n",
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            retained = lease._files[0]
            descriptor = retained.descriptor
            backup = os.dup(descriptor)
            foreign = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.dup2(foreign, descriptor, inheritable=False)
                self._assert_invalid(runtime, staging, lease)
                os.dup2(backup, descriptor, inheritable=False)

                real_pread = os.pread
                corrupted = False

                def corrupt_once(fd: int, count: int, offset: int) -> bytes:
                    nonlocal corrupted
                    value = real_pread(fd, count, offset)
                    if fd == descriptor and value and not corrupted:
                        corrupted = True
                        return bytes((value[0] ^ 1,)) + value[1:]
                    return value

                with patch.object(
                    requirements_module.os,
                    "pread",
                    side_effect=corrupt_once,
                ):
                    self._assert_invalid(runtime, staging, lease)
                self.assertTrue(corrupted)
            finally:
                os.dup2(backup, descriptor, inheritable=False)
                os.close(foreign)
                os.close(backup)
                lease.close()

    def test_cleanup_race_fails_closed_and_preserves_verified_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(root, search_one, bare=b"#!/bin/sh\n")
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            real_inspect = requirements_module._BUILTIN_INSPECT_RUNTIME_MANIFEST
            cleaned = False

            def cleanup_after_reinspection(*args: object, **kwargs: object):
                nonlocal cleaned
                value = real_inspect(*args, **kwargs)
                if not cleaned:
                    cleaned = True
                    lease.close()
                return value

            with patch.object(
                requirements_module,
                "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
                side_effect=cleanup_after_reinspection,
            ):
                self._assert_invalid(runtime, staging, lease)
            self.assertTrue(cleaned)
            self.assertEqual(lease.state, "cleaned")
            self.assertTrue(lease.cleanup_receipt.descriptor_release_complete)
            self.assertTrue(
                lease.cleanup_receipt.owned_namespace_absence_verified
            )
            self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_no_path_open_mutation_process_state_or_cleanup_integration(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, outside, search_one, search_two, staging_root = (
                self._workspace(temporary)
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!/bin/sh private-tail-marker\n",
            )
            registration = self._registration(root)
            lease, staging, runtime = self._stage_runtime(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            tree_before = tuple(
                self.fixture.fixture._tree_snapshot(value)
                for value in (root, outside, search_one, search_two)
            )
            with (
                patch.object(
                    builtins,
                    "open",
                    side_effect=AssertionError("path open"),
                ) as builtin_open,
                patch.object(
                    Path,
                    "open",
                    side_effect=AssertionError("path open"),
                ) as path_open,
                patch.object(
                    shutil,
                    "which",
                    side_effect=AssertionError("PATH"),
                ) as which,
                patch.object(
                    os,
                    "getenv",
                    side_effect=AssertionError("environment"),
                ) as getenv,
                patch.object(
                    os,
                    "get_exec_path",
                    side_effect=AssertionError("PATH"),
                ) as get_exec_path,
                patch.object(
                    os,
                    "open",
                    side_effect=AssertionError("path reopen"),
                ) as open_path,
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
                    "close",
                    side_effect=AssertionError("close"),
                ) as close,
                patch.object(
                    os,
                    "dup",
                    side_effect=AssertionError("duplicate descriptor"),
                ) as duplicate,
                patch.object(
                    os,
                    "dup2",
                    side_effect=AssertionError("retarget descriptor"),
                ) as duplicate_to,
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
                patch.object(
                    staging_module,
                    "cleanup_repository_executable_stage",
                    side_effect=AssertionError("cleanup"),
                ) as cleanup,
            ):
                receipt = inspect_staged_executable_shebang_requirements(
                    runtime,
                    expected_staging=staging,
                    lease=lease,
                )
            self.assertEqual(receipt.requirement_count, 2)
            self.assertEqual(self._lease_snapshot(lease), before)
            for observed in (
                builtin_open,
                path_open,
                which,
                getenv,
                get_exec_path,
                open_path,
                write,
                fchmod,
                close,
                duplicate,
                duplicate_to,
                system,
                run,
                popen,
                create_exec,
                create_shell,
                stage_artifact,
                publish_artifact,
                state,
                cleanup,
            ):
                observed.assert_not_called()
            self.assertEqual(
                tuple(
                    self.fixture.fixture._tree_snapshot(value)
                    for value in (root, outside, search_one, search_two)
                ),
                tree_before,
            )
            self.assertEqual(tuple(staging_root.iterdir()), ())
            lease.close()


if __name__ == "__main__":
    unittest.main()
