from __future__ import annotations

import asyncio
import builtins
from dataclasses import FrozenInstanceError, replace
import hashlib
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
import ordomata.repository_executable_shebang_requirements as requirements_module
from ordomata.repository_executable_shebang_requirements import (
    RepositoryExecutableShebangRequirementsReceipt,
    inspect_staged_executable_shebang_requirements,
)
import ordomata.repository_executable_shebang_target_resolution as target_module
from ordomata.repository_executable_shebang_target_resolution import (
    MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_BINDING_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_MEASUREMENT_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_REQUIREMENT_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION,
    RESOLUTION_SCOPE,
    RepositoryExecutableShebangTargetBinding,
    RepositoryExecutableShebangTargetMeasurement,
    RepositoryExecutableShebangTargetRequirement,
    RepositoryExecutableShebangTargetResolutionReceipt,
    inspect_staged_executable_shebang_targets,
)
from ordomata.repository_executable_staging import (
    RepositoryExecutableStageLease,
    RepositoryExecutableStagingReceipt,
    _RetainedStagedFile,
)
from ordomata.repository_executable_runtime_manifest import (
    RepositoryExecutableRuntimeManifestReceipt,
)
import ordomata.state as state_module

if __package__:
    from . import (
        test_repository_executable_shebang_requirements as requirements_test_module,
    )
else:
    import test_repository_executable_shebang_requirements as requirements_test_module


FIXED_TARGET_ERROR = "repository executable shebang target resolution is invalid"


class _DeceptiveString(str):
    """A non-exact string whose comparisons impersonate any fixed literal."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


MEASUREMENT_KEYS = {
    "content_bytes",
    "content_digest",
    "filesystem_identity_ref",
    "kind",
    "measurement_ref",
    "metadata_digest",
    "path_ref",
}
TARGET_REQUIREMENT_KEYS = {
    "argument_tail_ref",
    "disposition",
    "interpreter_token_ref",
    "kind",
    "requirement_ref",
    "runtime_classification",
    "runtime_file_ref",
    "shebang_directive_ref",
    "staged_file_ref",
    "target_measurement_ref",
    "target_requirement_ref",
}
TARGET_BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
}
TARGET_RECEIPT_KEYS = {
    "bindings",
    "command_count",
    "direct_target_requirement_count",
    "kind",
    "measurement_source",
    "measurements",
    "native_not_applicable_count",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "resolution_context_digest",
    "resolution_scope",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shebang_requirements_receipt_digest",
    "staging_context_digest",
    "staging_receipt_digest",
    "target_path_context_digest",
    "total_measured_bytes",
    "unique_target_count",
    "verification_commands_digest",
}


@unittest.skipUnless(os.name == "posix", "shebang target resolution requires POSIX")
class RepositoryExecutableShebangTargetResolutionTests(unittest.TestCase):
    fixture = requirements_test_module.RepositoryExecutableShebangRequirementsTests

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
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableStageLease,
    ) -> tuple[object, ...]:
        return cls.fixture._lease_snapshot(lease)

    @classmethod
    def _tree_snapshot(cls, path: Path) -> tuple[object, ...]:
        return cls.fixture.fixture.fixture._tree_snapshot(path)

    @staticmethod
    def _write_target(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o755)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())

    @classmethod
    def _stage_requirements(
        cls,
        registration: object,
        search_directories: tuple[Path, ...],
        staging_root: Path,
    ) -> tuple[
        RepositoryExecutableStageLease,
        RepositoryExecutableStagingReceipt,
        RepositoryExecutableRuntimeManifestReceipt,
        RepositoryExecutableShebangRequirementsReceipt,
    ]:
        lease, staging, runtime = cls.fixture._stage_runtime(
            registration,
            search_directories,
            staging_root,
        )
        requirements = inspect_staged_executable_shebang_requirements(
            runtime,
            expected_staging=staging,
            lease=lease,
        )
        return lease, staging, runtime, requirements

    @staticmethod
    def _inspect(
        requirements: object,
        runtime: object,
        staging: object,
        lease: object,
        expected_target_paths: object,
    ) -> RepositoryExecutableShebangTargetResolutionReceipt:
        return inspect_staged_executable_shebang_targets(
            requirements,
            expected_runtime=runtime,
            expected_staging=staging,
            lease=lease,
            expected_target_paths=expected_target_paths,
        )

    def _assert_invalid(
        self,
        requirements: object,
        runtime: object,
        staging: object,
        lease: object,
        expected_target_paths: object,
        *,
        private_marker: str = "private-shebang-target-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            self._inspect(
                requirements,
                runtime,
                staging,
                lease,
                expected_target_paths,
            )
        self.assertEqual(str(caught.exception), FIXED_TARGET_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    @staticmethod
    def _descriptor_directory() -> Path | None:
        for candidate in (Path("/dev/fd"), Path("/proc/self/fd")):
            if candidate.is_dir():
                return candidate
        return None

    def test_receipt_correspondence_privacy_and_native_plus_direct_target(
        self,
    ) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        target_content = b"private-target-content-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = (
                Path(temporary).resolve(strict=True)
                / "private-target-directory-marker"
                / "private-interpreter-marker"
            )
            self._write_target(target, target_content)
            shebang = (
                b"#!"
                + os.fsencode(target)
                + b" --opaque private-argument-marker\nbody-marker\n"
            )
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=shebang,
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
            )
            try:
                receipt = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                repeated = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                self.assertEqual(receipt, repeated)
                self.assertEqual(self._lease_snapshot(lease), before)
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

                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangTargetResolutionReceipt,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_SCHEMA_VERSION,
                    1,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_KIND,
                    "repository_executable_shebang_target_resolution",
                )
                self.assertEqual(MEASUREMENT_SOURCE, "controller_measured")
                self.assertEqual(
                    RESOLUTION_SCOPE,
                    "posix_absolute_shebang_target_nofollow_v1",
                )

                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), TARGET_RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                self.assertEqual(
                    receipt.shebang_requirements_receipt_digest,
                    requirements.receipt_digest,
                )
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
                        getattr(requirements, field),
                    )
                self.assertRegex(
                    receipt.target_path_context_digest,
                    r"^sha256:[0-9a-f]{64}$",
                )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.direct_target_requirement_count, 1)
                self.assertEqual(receipt.native_not_applicable_count, 1)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(receipt.total_measured_bytes, len(target_content))

                self.assertEqual(len(receipt.measurements), 1)
                measurement = receipt.measurements[0]
                self.assertIsInstance(
                    measurement,
                    RepositoryExecutableShebangTargetMeasurement,
                )
                self.assertEqual(set(measurement.to_canonical()), MEASUREMENT_KEYS)
                self.assertEqual(measurement.content_bytes, len(target_content))
                self.assertEqual(
                    measurement.content_digest,
                    "sha256:" + hashlib.sha256(target_content).hexdigest(),
                )
                for value in (
                    measurement.path_ref,
                    measurement.filesystem_identity_ref,
                    measurement.metadata_digest,
                    measurement.measurement_ref,
                ):
                    self.assertRegex(value, r"^sha256:[0-9a-f]{64}$")

                self.assertEqual(len(receipt.requirements), 2)
                for target_requirement, upstream_requirement in zip(
                    receipt.requirements,
                    requirements.requirements,
                    strict=True,
                ):
                    self.assertIsInstance(
                        target_requirement,
                        RepositoryExecutableShebangTargetRequirement,
                    )
                    self.assertEqual(
                        set(target_requirement.to_canonical()),
                        TARGET_REQUIREMENT_KEYS,
                    )
                    for field in (
                        "staged_file_ref",
                        "runtime_file_ref",
                        "requirement_ref",
                        "runtime_classification",
                        "shebang_directive_ref",
                        "interpreter_token_ref",
                        "argument_tail_ref",
                    ):
                        self.assertEqual(
                            getattr(target_requirement, field),
                            getattr(upstream_requirement, field),
                        )
                    self.assertRegex(
                        target_requirement.target_requirement_ref,
                        r"^sha256:[0-9a-f]{64}$",
                    )

                native = next(
                    value
                    for value in receipt.requirements
                    if value.disposition == "native_not_applicable"
                )
                direct = next(
                    value
                    for value in receipt.requirements
                    if value.disposition == "direct_absolute_target_measured"
                )
                self.assertIsNone(native.target_measurement_ref)
                self.assertEqual(
                    direct.target_measurement_ref,
                    measurement.measurement_ref,
                )

                self.assertEqual(len(receipt.bindings), 2)
                by_requirement = {
                    value.requirement_ref: value for value in receipt.requirements
                }
                for binding, upstream_binding in zip(
                    receipt.bindings,
                    requirements.bindings,
                    strict=True,
                ):
                    self.assertIsInstance(
                        binding,
                        RepositoryExecutableShebangTargetBinding,
                    )
                    self.assertEqual(
                        set(binding.to_canonical()),
                        TARGET_BINDING_KEYS,
                    )
                    for field in (
                        "command_kind",
                        "command_id",
                        "command_digest",
                        "staged_file_ref",
                        "runtime_file_ref",
                        "requirement_ref",
                    ):
                        self.assertEqual(
                            getattr(binding, field),
                            getattr(upstream_binding, field),
                        )
                    self.assertEqual(
                        binding.target_requirement_ref,
                        by_requirement[
                            binding.requirement_ref
                        ].target_requirement_ref,
                    )

                evidence = receipt.to_evidence()
                self.assertEqual(
                    evidence["kind"],
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RESOLUTION_EVIDENCE_KIND,
                )
                self.assertEqual(evidence["effect_class"], 0)
                self.assertEqual(evidence["validation_mode"], "read_only")
                for true_fact in (
                    "active_lease_verified_at_measurement",
                    "direct_shebang_target_measurement_complete",
                    "exact_target_path_lookup_performed",
                    "exact_target_path_set_verified",
                    "path_lookup_performed",
                    "selected_target_content_measured",
                    "selected_target_namespace_reopen_verified",
                    "staged_byte_correspondence_verified",
                ):
                    self.assertIs(evidence[true_fact], True, true_fact)
                for false_fact in (
                    "action_receipt_issued",
                    "ambient_path_search_performed",
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
                    "effective_invocability_verified",
                    "environment_coverage_verified",
                    "execution_enabled",
                    "external_hardlink_alias_excluded",
                    "external_mount_alias_excluded",
                    "external_writable_descriptor_excluded",
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
                    "proposal_lineage_extended",
                    "receipt_authenticity_verified",
                    "route_eligible",
                    "same_uid_mutation_excluded",
                    "shared_library_identity_verified",
                    "subprocess_invocation_performed",
                    "toolchain_completeness_verified",
                    "worktree_integration_enabled",
                ):
                    self.assertIs(evidence[false_fact], False, false_fact)

                aggregate = "\n".join(
                    (
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        *(repr(value) for value in receipt.measurements),
                        *(repr(value) for value in receipt.requirements),
                        *(repr(value) for value in receipt.bindings),
                    )
                )
                for private_value in (
                    str(root),
                    str(search_one),
                    str(staging_root),
                    str(target),
                    "private-interpreter-marker",
                    "private-target-content-marker",
                    "private-argument-marker",
                    "private-bare-command-marker",
                    "private-relative-command-marker",
                    measurement.content_digest,
                ):
                    self.assertNotIn(private_value, aggregate)
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirement_count = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.measurements[0].content_bytes = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirements[0].disposition = "native_not_applicable"
                with self.assertRaises(FrozenInstanceError):
                    receipt.bindings[0].command_kind = "test"
            finally:
                lease.close()

    def test_shared_direct_target_is_measured_once_and_bound_deterministically(
        self,
    ) -> None:
        target_content = b"one-private-shared-target\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "shared-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                receipt = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.direct_target_requirement_count, 2)
                self.assertEqual(receipt.native_not_applicable_count, 0)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(len(receipt.measurements), 1)
                self.assertEqual(receipt.total_measured_bytes, len(target_content))
                self.assertEqual(
                    {value.target_measurement_ref for value in receipt.requirements},
                    {receipt.measurements[0].measurement_ref},
                )
                self.assertEqual(
                    tuple(value.requirement_ref for value in receipt.requirements),
                    tuple(value.requirement_ref for value in requirements.requirements),
                )
            finally:
                lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "shared-command-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b" -I\n"
            self._set_contents(root, search_one, bare=shebang)
            registration = self._registration(root, shared=True)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one,),
                staging_root,
            )
            try:
                receipt = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                self.assertEqual(receipt.requirement_count, 1)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(len(receipt.bindings), 2)
                self.assertEqual(
                    {value.target_requirement_ref for value in receipt.bindings},
                    {receipt.requirements[0].target_requirement_ref},
                )
            finally:
                lease.close()

    def test_native_only_requires_an_exact_empty_target_path_tuple(self) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            unused = Path(temporary).resolve(strict=True) / "unused-target"
            self._write_target(unused, b"unused\n")
            self._set_contents(root, search_one, bare=elf, relative=elf)
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                receipt = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (),
                )
                self.assertEqual(receipt.direct_target_requirement_count, 0)
                self.assertEqual(receipt.native_not_applicable_count, 2)
                self.assertEqual(receipt.unique_target_count, 0)
                self.assertEqual(receipt.total_measured_bytes, 0)
                self.assertEqual(receipt.measurements, ())
                evidence = receipt.to_evidence()
                for fact in (
                    "exact_target_path_lookup_performed",
                    "namespace_reopen_verified_at_measurement",
                    "path_lookup_performed",
                    "selected_target_content_measured",
                    "selected_target_namespace_reopen_verified",
                ):
                    self.assertIs(evidence[fact], False, fact)
                self._assert_invalid(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (unused,),
                )
            finally:
                lease.close()

    def test_expected_target_paths_are_exact_typed_and_requirement_ordered(
        self,
    ) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "expected-target"
            other = Path(temporary).resolve(strict=True) / "other-target"
            self._write_target(target, b"expected target\n")
            self._write_target(other, b"other target\n")
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=b"#!" + os.fsencode(target) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            concrete_path_type = type(Path())

            class DerivedPath(concrete_path_type):
                pass

            try:
                for case, supplied in (
                    ("list", [target]),
                    ("path-instead-of-tuple", target),
                    ("string-entry", (str(target),)),
                    ("derived-path", (DerivedPath(target),)),
                    ("missing-entry", ()),
                    ("extra-entry", (target, target)),
                    ("wrong-exact-path", (other,)),
                    ("boolean", True),
                ):
                    with self.subTest(case=case):
                        self._assert_invalid(
                            requirements,
                            runtime,
                            staging,
                            lease,
                            supplied,
                        )
                        self.assertEqual(self._lease_snapshot(lease), before)
                receipt = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                self.assertEqual(receipt.direct_target_requirement_count, 1)
            finally:
                lease.close()

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            first = Path(temporary).resolve(strict=True) / "first-target"
            second = Path(temporary).resolve(strict=True) / "second-target"
            self._write_target(first, b"first\n")
            self._write_target(second, b"second\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(first) + b"\n",
                relative=b"#!" + os.fsencode(second) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                self._assert_invalid(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (second, first),
                )
                receipt = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (first, second),
                )
                self.assertEqual(
                    tuple(value.content_bytes for value in receipt.measurements),
                    (len(b"first\n"), len(b"second\n")),
                )
            finally:
                lease.close()

    def test_noncanonical_or_unsupported_requirements_fail_before_target_lookup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as outer:
            base = Path(outer).resolve(strict=True)
            canonical = base / "canonical-target"
            other = base / "other-target"
            self._write_target(canonical, b"canonical\n")
            self._write_target(other, b"other\n")
            cases: tuple[tuple[str, bytes, tuple[Path, ...]], ...] = (
                ("non-absolute", b"private-target", ()),
                ("root", b"/", (Path("/"),)),
                (
                    "repeated-slash",
                    os.fsencode(base) + b"//canonical-target",
                    (canonical,),
                ),
                (
                    "trailing-slash",
                    os.fsencode(canonical) + b"/",
                    (canonical,),
                ),
                (
                    "dot-component",
                    os.fsencode(base) + b"/./canonical-target",
                    (canonical,),
                ),
                (
                    "dot-dot-component",
                    os.fsencode(base) + b"/child/../canonical-target",
                    (canonical,),
                ),
                (
                    "not-exact-expected-path",
                    os.fsencode(canonical),
                    (other,),
                ),
            )
            for case, token, expected_paths in cases:
                with (
                    self.subTest(case=case),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root, _outside, search_one, search_two, staging_root = (
                        self._workspace(temporary)
                    )
                    self._set_contents(
                        root,
                        search_one,
                        bare=b"#!" + token + b"\n",
                    )
                    registration = self._registration(root)
                    lease, staging, runtime, requirements = (
                        self._stage_requirements(
                            registration,
                            (search_one, search_two),
                            staging_root,
                        )
                    )
                    try:
                        self._assert_invalid(
                            requirements,
                            runtime,
                            staging,
                            lease,
                            expected_paths,
                        )
                    finally:
                        lease.close()

            for case, content in (
                ("unsupported-shebang", b"#! /private/target\n"),
                ("unknown-runtime", b"ordinary private executable bytes\n"),
            ):
                with (
                    self.subTest(case=case),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root, _outside, search_one, search_two, staging_root = (
                        self._workspace(temporary)
                    )
                    self._set_contents(root, search_one, bare=content)
                    registration = self._registration(root)
                    lease, staging, runtime, requirements = (
                        self._stage_requirements(
                            registration,
                            (search_one, search_two),
                            staging_root,
                        )
                    )
                    try:
                        self._assert_invalid(
                            requirements,
                            runtime,
                            staging,
                            lease,
                            (),
                        )
                    finally:
                        lease.close()

    def test_distinct_expected_paths_sharing_one_inode_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            base = Path(temporary).resolve(strict=True)
            target = base / "hardlink-target"
            alias = base / "hardlink-alias"
            self._write_target(target, b"shared inode bytes\n")
            os.link(target, alias)
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target) + b"\n",
                relative=b"#!" + os.fsencode(alias) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                self._assert_invalid(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target, alias),
                )
            finally:
                lease.close()

    def test_missing_symlink_nonexecutable_and_nonregular_targets_fail_closed(
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
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root, _outside, search_one, search_two, staging_root = self._workspace(
                    temporary
                )
                base = Path(temporary).resolve(strict=True)
                target = base / "target-directory" / "target-file"
                if case == "missing":
                    target.parent.mkdir()
                elif case == "symlink":
                    actual = base / "actual-target"
                    self._write_target(actual, b"actual\n")
                    target.parent.mkdir()
                    target.symlink_to(actual)
                elif case == "non-executable":
                    self._write_target(target, b"not executable\n")
                    target.chmod(0o644)
                elif case == "directory":
                    target.mkdir(parents=True)
                else:
                    actual_parent = base / "actual-parent"
                    actual = actual_parent / "target-file"
                    self._write_target(actual, b"actual\n")
                    linked_parent = base / "linked-parent"
                    linked_parent.symlink_to(actual_parent, target_is_directory=True)
                    target = linked_parent / "target-file"

                self._set_contents(
                    root,
                    search_one,
                    bare=b"#!" + os.fsencode(target) + b"\n",
                )
                registration = self._registration(root)
                lease, staging, runtime, requirements = self._stage_requirements(
                    registration,
                    (search_one, search_two),
                    staging_root,
                )
                before = self._lease_snapshot(lease)
                try:
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                        private_marker=str(target),
                    )
                    self.assertEqual(self._lease_snapshot(lease), before)
                finally:
                    lease.close()

    def test_wrong_typed_forged_reordered_and_lease_unbound_inputs_reject(
        self,
    ) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        zero_digest = "sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "forgery-target"
            self._write_target(target, b"forgery target\n")
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=b"#!" + os.fsencode(target) + b" -I\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            inactive = RepositoryExecutableStageLease(staging_root)
            before = self._lease_snapshot(lease)
            direct_index = next(
                index
                for index, value in enumerate(requirements.requirements)
                if value.disposition == "absolute_interpreter_token"
            )
            forged_requirement = replace(
                requirements.requirements[direct_index],
                interpreter_token_ref=zero_digest,
            )
            forged_requirements_items = list(requirements.requirements)
            forged_requirements_items[direct_index] = forged_requirement
            forged_inputs = (
                (object(), runtime, staging, lease),
                (requirements, object(), staging, lease),
                (requirements, runtime, object(), lease),
                (requirements, runtime, staging, object()),
                (requirements, runtime, staging, inactive),
                (
                    replace(
                        requirements,
                        staging_receipt_digest=zero_digest,
                    ),
                    runtime,
                    staging,
                    lease,
                ),
                (
                    replace(
                        requirements,
                        requirements=tuple(forged_requirements_items),
                    ),
                    runtime,
                    staging,
                    lease,
                ),
                (
                    replace(
                        requirements,
                        requirements=tuple(reversed(requirements.requirements)),
                    ),
                    runtime,
                    staging,
                    lease,
                ),
                (
                    replace(
                        requirements,
                        bindings=tuple(reversed(requirements.bindings)),
                    ),
                    runtime,
                    staging,
                    lease,
                ),
                (
                    requirements,
                    replace(runtime, staging_receipt_digest=zero_digest),
                    staging,
                    lease,
                ),
                (
                    requirements,
                    runtime,
                    replace(staging, repository_ref=zero_digest),
                    lease,
                ),
            )
            try:
                for case, (
                    candidate_requirements,
                    candidate_runtime,
                    candidate_staging,
                    candidate_lease,
                ) in enumerate(forged_inputs):
                    with self.subTest(case=case):
                        self._assert_invalid(
                            candidate_requirements,
                            candidate_runtime,
                            candidate_staging,
                            candidate_lease,
                            (target,),
                        )
                self.assertEqual(self._lease_snapshot(lease), before)

                original_digest = lease._receipt_digest_anchor
                original_refs = lease._receipt_staged_file_refs_anchor
                original_files = lease._files
                original_cleanup_anchor = lease._cleanup_receipt_digest_anchor
                try:
                    lease._receipt_digest_anchor = zero_digest
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                    lease._receipt_digest_anchor = original_digest

                    lease._receipt_staged_file_refs_anchor = tuple(
                        reversed(original_refs)
                    )
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                    lease._receipt_staged_file_refs_anchor = original_refs

                    lease._files = tuple(reversed(original_files))
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                    lease._files = original_files

                    lease._cleanup_receipt_digest_anchor = zero_digest
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                finally:
                    lease._receipt_digest_anchor = original_digest
                    lease._receipt_staged_file_refs_anchor = original_refs
                    lease._files = original_files
                    lease._cleanup_receipt_digest_anchor = original_cleanup_anchor
            finally:
                lease.close()

            self._assert_invalid(
                requirements,
                runtime,
                staging,
                lease,
                (target,),
            )

    def test_deceptive_string_subclasses_cannot_spoof_exact_chain_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "typed-target"
            self._write_target(target, b"typed target\n")
            directive = b"#!" + os.fsencode(target) + b" -I\n"
            self._set_contents(
                root,
                search_one,
                bare=directive,
                relative=directive,
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            deceptive = _DeceptiveString("closed-or-forged")
            first_requirement = requirements.requirements[0]
            first_binding = requirements.bindings[0]

            def with_requirement(
                replacement: object,
            ) -> RepositoryExecutableShebangRequirementsReceipt:
                items = list(requirements.requirements)
                items[0] = replacement
                return replace(requirements, requirements=tuple(items))

            def with_binding(
                replacement: object,
            ) -> RepositoryExecutableShebangRequirementsReceipt:
                items = list(requirements.bindings)
                items[0] = replacement
                return replace(requirements, bindings=tuple(items))

            forged_receipts = (
                replace(requirements, kind=deceptive),
                replace(requirements, requirements_source=deceptive),
                replace(requirements, requirements_scope=deceptive),
                with_requirement(replace(first_requirement, kind=deceptive)),
                with_requirement(
                    replace(
                        first_requirement,
                        argument_separator_kind=deceptive,
                    )
                ),
                with_binding(replace(first_binding, kind=deceptive)),
            )
            original_state = lease._state
            original_refs = lease._receipt_staged_file_refs_anchor
            original_files = lease._files
            try:
                for candidate in forged_receipts:
                    with self.subTest(field=candidate):
                        self._assert_invalid(
                            candidate,
                            runtime,
                            staging,
                            lease,
                            (target,),
                        )
                lease._state = deceptive
                self._assert_invalid(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                lease._state = original_state
                lease._receipt_staged_file_refs_anchor = tuple(
                    deceptive for _item in original_refs
                )
                self._assert_invalid(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                lease._receipt_staged_file_refs_anchor = original_refs
                forged_staged_file = replace(
                    original_files[0].staged_file,
                    kind=deceptive,
                )
                forged_retained = _RetainedStagedFile(
                    staged_file=forged_staged_file,
                    descriptor=original_files[0].descriptor,
                    metadata=original_files[0].metadata,
                )
                lease._files = (forged_retained, *original_files[1:])
                self._assert_invalid(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
            finally:
                lease._state = original_state
                lease._receipt_staged_file_refs_anchor = original_refs
                lease._files = original_files
                lease.close()

    def test_public_upstream_hooks_cannot_replace_frozen_v1_validation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "frozen-target"
            self._write_target(target, b"frozen target\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                with (
                    patch.object(
                        RepositoryExecutableStagingReceipt,
                        "to_canonical",
                        side_effect=AssertionError("public staging projection"),
                    ) as staging_projection,
                    patch.object(
                        RepositoryExecutableRuntimeManifestReceipt,
                        "to_canonical",
                        side_effect=AssertionError("public runtime projection"),
                    ) as runtime_projection,
                    patch.object(
                        RepositoryExecutableShebangRequirementsReceipt,
                        "to_canonical",
                        side_effect=AssertionError("public requirements projection"),
                    ) as requirements_projection,
                    patch.object(
                        requirements_module,
                        "inspect_staged_executable_shebang_requirements",
                        side_effect=AssertionError("dynamic public inspector"),
                    ) as public_inspector,
                    patch.object(
                        requirements_module,
                        "_receipt_projection",
                        return_value={},
                    ) as public_projection,
                ):
                    receipt = self._inspect(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                self.assertEqual(receipt.direct_target_requirement_count, 2)
                for observed in (
                    staging_projection,
                    runtime_projection,
                    requirements_projection,
                    public_inspector,
                ):
                    observed.assert_not_called()
                self.assertGreater(public_projection.call_count, 0)

                with patch.object(
                    requirements_module,
                    "_split_directive",
                    return_value=(b"/forged/interpreter", None, None),
                ):
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                with patch.object(
                    requirements_module,
                    "_token_ref",
                    return_value="sha256:" + "1" * 64,
                ):
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
            finally:
                lease.close()

    def test_environment_path_process_state_and_controller_effects_are_unused(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "no-effect-target"
            self._write_target(target, b"no effect target\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target) + b" private-tail\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            before = self._lease_snapshot(lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
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
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                self.assertEqual(receipt.direct_target_requirement_count, 2)
                self.assertEqual(self._lease_snapshot(lease), before)
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
                            target.parent,
                        )
                    ),
                    trees_before,
                )
            finally:
                lease.close()

    def test_transient_target_descriptors_close_on_success_and_failure(self) -> None:
        descriptor_directory = self._descriptor_directory()
        if descriptor_directory is None:
            self.skipTest("no process descriptor directory is available")
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            target = Path(temporary).resolve(strict=True) / "descriptor-target"
            moved = Path(temporary).resolve(strict=True) / "moved-target"
            self._write_target(target, b"descriptor target\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            try:
                descriptors_before = frozenset(os.listdir(descriptor_directory))
                receipt = self._inspect(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertEqual(
                    frozenset(os.listdir(descriptor_directory)),
                    descriptors_before,
                )

                target.rename(moved)
                self._assert_invalid(
                    requirements,
                    runtime,
                    staging,
                    lease,
                    (target,),
                )
                self.assertEqual(
                    frozenset(os.listdir(descriptor_directory)),
                    descriptors_before,
                )
            finally:
                if moved.exists():
                    moved.rename(target)
                lease.close()

    def test_target_namespace_swap_between_complete_measurements_rejects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            base = Path(temporary).resolve(strict=True)
            target = base / "raced-target"
            original = base / "original-target"
            replacement = base / "replacement-target"
            self._write_target(target, b"first target identity and content\n")
            self._write_target(
                replacement,
                b"second target identity and content\n",
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            real_measure = target_module._measure_target_set
            measurement_passes = 0

            def swap_after_first_complete_measurement(
                paths: tuple[Path, ...],
            ) -> object:
                nonlocal measurement_passes
                measured = real_measure(paths)
                measurement_passes += 1
                if measurement_passes == 1:
                    target.rename(original)
                    replacement.rename(target)
                return measured

            before = self._lease_snapshot(lease)
            descriptor_directory = self._descriptor_directory()
            descriptors_before = (
                None
                if descriptor_directory is None
                else frozenset(os.listdir(descriptor_directory))
            )
            try:
                with patch.object(
                    target_module,
                    "_measure_target_set",
                    side_effect=swap_after_first_complete_measurement,
                ):
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                self.assertEqual(measurement_passes, 2)
                self.assertEqual(self._lease_snapshot(lease), before)
                if descriptor_directory is not None:
                    self.assertEqual(
                        frozenset(os.listdir(descriptor_directory)),
                        descriptors_before,
                    )
            finally:
                if original.exists():
                    if target.exists():
                        target.rename(replacement)
                    original.rename(target)
                lease.close()

    def test_unrelated_target_parent_sibling_churn_is_not_path_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            base = Path(temporary).resolve(strict=True)
            target = base / "selected-parent" / "selected-target"
            unrelated = target.parent / "unrelated-sibling"
            self._write_target(target, b"stable selected target bytes\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            real_open_target = target_module._open_target_at
            target_opens = 0

            def add_unrelated_sibling_after_first_target_open(
                directory_descriptor: int,
                name: str,
            ) -> object:
                nonlocal target_opens
                opened = real_open_target(directory_descriptor, name)
                target_opens += 1
                if target_opens == 1:
                    unrelated.mkdir()
                return opened

            try:
                with patch.object(
                    target_module,
                    "_open_target_at",
                    side_effect=add_unrelated_sibling_after_first_target_open,
                ):
                    receipt = self._inspect(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                self.assertGreater(target_opens, 1)
                self.assertEqual(receipt.unique_target_count, 1)
                self.assertTrue(unrelated.is_dir())
            finally:
                lease.close()

    def test_final_leaf_and_ancestor_namespace_swaps_reject(self) -> None:
        for race_kind in ("leaf", "ancestor"):
            with (
                self.subTest(race_kind=race_kind),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root, _outside, search_one, search_two, staging_root = self._workspace(
                    temporary
                )
                base = Path(temporary).resolve(strict=True)
                target_parent = base / "selected-parent"
                target = target_parent / "selected-target"
                moved_target = target_parent / "moved-target"
                replacement_target = target_parent / "replacement-target"
                moved_parent = base / "moved-parent"
                replacement_parent = base / "replacement-parent"
                self._write_target(target, b"selected bytes\n")
                if race_kind == "leaf":
                    self._write_target(replacement_target, b"replacement bytes\n")
                else:
                    self._write_target(
                        replacement_parent / target.name,
                        b"replacement subtree bytes\n",
                    )
                self._set_contents(
                    root,
                    search_one,
                    bare=b"#!" + os.fsencode(target) + b"\n",
                )
                registration = self._registration(root)
                lease, staging, runtime, requirements = self._stage_requirements(
                    registration,
                    (search_one, search_two),
                    staging_root,
                )
                real_open_target = target_module._open_target_at
                open_count = 0
                trigger = 4 if race_kind == "leaf" else 7

                def swap_after_target_open(
                    directory_descriptor: int,
                    name: str,
                ) -> object:
                    nonlocal open_count
                    opened = real_open_target(directory_descriptor, name)
                    open_count += 1
                    if open_count == trigger:
                        if race_kind == "leaf":
                            target.rename(moved_target)
                            replacement_target.rename(target)
                        else:
                            target_parent.rename(moved_parent)
                            replacement_parent.rename(target_parent)
                    return opened

                try:
                    with patch.object(
                        target_module,
                        "_open_target_at",
                        side_effect=swap_after_target_open,
                    ):
                        self._assert_invalid(
                            requirements,
                            runtime,
                            staging,
                            lease,
                            (target,),
                        )
                    self.assertGreaterEqual(open_count, trigger)
                finally:
                    if race_kind == "leaf" and moved_target.exists():
                        if target.exists():
                            target.rename(replacement_target)
                        moved_target.rename(target)
                    if race_kind == "ancestor" and moved_parent.exists():
                        if target_parent.exists():
                            target_parent.rename(replacement_parent)
                        moved_parent.rename(target_parent)
                    lease.close()

    def test_final_spelling_collision_after_leaf_open_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two, staging_root = self._workspace(
                temporary
            )
            base = Path(temporary).resolve(strict=True)
            target = base / "selected-parent" / "selected-target"
            self._write_target(target, b"selected target bytes\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target) + b"\n",
            )
            registration = self._registration(root)
            lease, staging, runtime, requirements = self._stage_requirements(
                registration,
                (search_one, search_two),
                staging_root,
            )
            real_open_target = target_module._open_target_at
            real_spelling_state = target_module._entry_spelling_state
            target_opens = 0
            collision_present = False
            collision_checks = 0

            def introduce_collision_after_final_leaf_open(
                directory_descriptor: int,
                name: str,
            ) -> object:
                nonlocal target_opens, collision_present
                opened = real_open_target(directory_descriptor, name)
                target_opens += 1
                if target_opens == 7:
                    collision_present = True
                return opened

            def spelling_state_after_collision(
                directory_descriptor: int,
                name: str,
            ) -> str:
                nonlocal collision_checks
                if collision_present and name == target.name:
                    collision_checks += 1
                    return "ambiguous"
                return real_spelling_state(directory_descriptor, name)

            try:
                with (
                    patch.object(
                        target_module,
                        "_open_target_at",
                        side_effect=introduce_collision_after_final_leaf_open,
                    ),
                    patch.object(
                        target_module,
                        "_entry_spelling_state",
                        side_effect=spelling_state_after_collision,
                    ),
                ):
                    self._assert_invalid(
                        requirements,
                        runtime,
                        staging,
                        lease,
                        (target,),
                    )
                self.assertEqual(target_opens, 7)
                self.assertGreaterEqual(collision_checks, 1)
            finally:
                lease.close()


if __name__ == "__main__":
    unittest.main()
