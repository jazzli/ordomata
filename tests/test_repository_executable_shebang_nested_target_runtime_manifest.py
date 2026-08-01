from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import inspect
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
from ordomata import (
    repository_executable_shebang_nested_target_runtime_manifest
    as runtime_module,
)
from ordomata.repository_executable_shebang_nested_target_runtime_manifest import (
    RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt,
    inspect_staged_executable_shebang_nested_target_runtime_manifest
    as inspect_runtime,
)
from ordomata.repository_executable_shebang_nested_target_staging import (
    RepositoryExecutableShebangNestedTargetStageLease,
    stage_repository_executable_shebang_nested_target_bytes,
)

if __package__:
    from . import (
        test_repository_executable_shebang_nested_target_staging
        as staging_test_module,
    )
else:
    import test_repository_executable_shebang_nested_target_staging as stage_tests

    staging_test_module = stage_tests


FIXED_ERROR = (
    "repository executable shebang nested target runtime manifest is invalid"
)
_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
_MACH_O = b"\xcf\xfa\xed\xfe" + b"\x00" * 28


@unittest.skipUnless(os.name == "posix", "nested target runtime requires POSIX")
class RepositoryExecutableShebangNestedTargetRuntimeManifestTests(
    unittest.TestCase
):
    staging_fixture_type = (
        staging_test_module
        .RepositoryExecutableShebangNestedTargetStagingTests
    )

    def _prepared(
        self,
        temporary: str,
        *,
        content: bytes = b"#!/bin/sh\nexit 0\n",
        include_source_native: bool = False,
    ):
        fixture = self.staging_fixture_type()
        chain, registration, expected, guard, stage_root = fixture._prepared(
            temporary,
            content=content,
            include_source_native=include_source_native,
        )
        lease, staging = fixture._stage(
            chain,
            registration,
            expected,
            guard,
            stage_root,
        )
        return fixture, chain, lease, staging

    def test_receipt_correspondence_privacy_and_lease_immutability(
        self,
    ) -> None:
        marker = b"#!/bin/sh\nprivate-nested-runtime-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(
                temporary,
                content=marker,
                include_source_native=True,
            )
            state = lease.state
            files = lease._files
            receipt_anchor = lease._receipt_object_anchor
            try:
                receipt = (
                    inspect_runtime(
                        staging,
                        lease=lease,
                    )
                )
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt,
                )
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(
                    receipt.known_chain_guard_runtime_inspected_count,
                    1,
                )
                self.assertEqual(
                    receipt.source_native_not_applicable_count,
                    1,
                )
                self.assertEqual(
                    receipt.target_native_not_applicable_count,
                    0,
                )
                runtime_file = receipt.files[0]
                self.assertEqual(runtime_file.classification, "posix_shebang")
                self.assertIsNotNone(runtime_file.shebang_directive_ref)
                self.assertEqual(runtime_file.content_bytes, len(marker))
                self.assertEqual(
                    receipt.nested_target_staging_receipt_digest,
                    staging.receipt_digest,
                )
                canonical = receipt.to_canonical()
                self.assertEqual(
                    receipt.receipt_digest,
                    canonical_digest(canonical),
                )
                self.assertEqual(
                    runtime_file.to_canonical(),
                    canonical["files"][0],
                )
                evidence = receipt.to_evidence()
                self.assertEqual(evidence["effect_class"], 0)
                self.assertTrue(
                    evidence[
                        "exact_nested_target_staging_correspondence_verified"
                    ]
                )
                self.assertFalse(evidence["authority_granted"])
                self.assertFalse(evidence["execution_enabled"])
                self.assertFalse(evidence["subprocess_invocation_performed"])
                self.assertFalse(evidence["model_invocation_performed"])
                self.assertFalse(evidence["network_access_performed"])
                self.assertFalse(evidence["worker_enabled"])
                serialized = json.dumps(
                    {"canonical": canonical, "evidence": evidence},
                    sort_keys=True,
                )
                for private in (
                    str(chain["root"]),
                    str(chain["nested_target"]),
                    str(lease.staging_root),
                    marker.decode("ascii").strip(),
                    "directory_inode",
                    "directory_device",
                ):
                    self.assertNotIn(private, serialized)
                    self.assertNotIn(private, repr(receipt))
                self.assertEqual(lease.state, state)
                self.assertIs(lease._files, files)
                self.assertIs(lease._receipt_object_anchor, receipt_anchor)
                with self.assertRaises(FrozenInstanceError):
                    receipt.file_count = 0
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_fixed_classification_and_bounded_headers(self) -> None:
        cases = (
            ("elf", _ELF, "elf"),
            ("mach-o", _MACH_O, "mach_o"),
            ("shebang", b"#!/usr/bin/python3\nprint(1)\n", "posix_shebang"),
            ("unsupported", b"#! /bin/sh\n", "unsupported_shebang"),
            ("unknown", b"plain executable bytes\n", "unknown"),
        )
        for label, content, expected_classification in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture, chain, lease, staging = self._prepared(
                    temporary,
                    content=content,
                )
                try:
                    receipt = (
                        inspect_runtime(
                            staging,
                            lease=lease,
                        )
                    )
                    self.assertEqual(
                        receipt.files[0].classification,
                        expected_classification,
                    )
                    self.assertEqual(
                        receipt.files[0].header_bytes,
                        min(len(content), 4096),
                    )
                finally:
                    if lease.state == "active":
                        lease.close()
                    fixture.fixture._close_chain(chain)

    def test_tamper_and_remeasurement_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(temporary)
            try:
                forged = replace(
                    staging,
                    guard_summary_ref="sha256:" + "0" * 64,
                )
                with self.assertRaises(ValidationError) as caught:
                    inspect_runtime(
                        forged,
                        lease=lease,
                    )
                self.assertEqual(str(caught.exception), FIXED_ERROR)
                original = runtime_module._BUILTIN_PREAD

                def drift(descriptor: int, size: int, offset: int) -> bytes:
                    value = original(descriptor, size, offset)
                    if offset == 0 and value:
                        return b"X" + value[1:]
                    return value

                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=drift,
                ):
                    with self.assertRaises(ValidationError) as caught:
                        inspect_runtime(
                            staging,
                            lease=lease,
                        )
                self.assertEqual(str(caught.exception), FIXED_ERROR)
                self.assertEqual(lease.state, "active")
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_source_native_zero_file_manifest_performs_no_read(self) -> None:
        guard_fixture = self.staging_fixture_type.fixture
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = guard_fixture._workspace(temporary)
            target_stage_root.rmdir()
            guard_fixture._set_contents(
                root,
                search_one,
                bare=staging_test_module.guard_test_module._ELF,
                relative=staging_test_module.guard_test_module._ELF,
            )
            registration = guard_fixture._registration(root)
            (
                source_lease,
                source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = guard_fixture._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(),
            )
            expected = guard_fixture._nested(
                target_requirements,
                target_runtime,
                target_staging,
                target_lease,
                (),
            )
            guard = guard_fixture._guard(
                expected,
                target_requirements=target_requirements,
                target_runtime=target_runtime,
                target_staging=target_staging,
                target_lease=target_lease,
                source_staging=source_staging,
                source_lease=source_lease,
                paths=(),
            )
            absent_root = Path(temporary) / "absent-nested-runtime-stage"
            nested_lease = RepositoryExecutableShebangNestedTargetStageLease(
                absent_root
            )
            try:
                nested_staging = (
                    stage_repository_executable_shebang_nested_target_bytes(
                        registration,
                        search_directories=(search_one, search_two),
                        expected_chain_guard=guard,
                        expected_nested_resolution=expected,
                        expected_target_requirements=target_requirements,
                        expected_target_runtime=target_runtime,
                        expected_target_staging=target_staging,
                        target_lease=target_lease,
                        expected_source_staging=source_staging,
                        source_lease=source_lease,
                        expected_nested_target_paths=(),
                        lease=nested_lease,
                    )
                )
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("native input read bytes"),
                ):
                    receipt = (
                        inspect_runtime(
                            nested_staging,
                            lease=nested_lease,
                        )
                    )
                self.assertEqual(receipt.files, ())
                self.assertEqual(receipt.file_count, 0)
                self.assertEqual(
                    receipt.source_native_not_applicable_count,
                    2,
                )
                self.assertFalse(absent_root.exists())
            finally:
                if nested_lease.state == "active":
                    nested_lease.close()
                target_lease.close()
                source_lease.close()

    def test_target_native_zero_file_manifest_performs_no_read(self) -> None:
        guard_fixture = self.staging_fixture_type.fixture
        for label, content in (
            ("elf", staging_test_module.guard_test_module._ELF),
            ("mach-o", staging_test_module.guard_test_module._MACH_O),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                chain = guard_fixture._unpack(
                    guard_fixture._one_nested_chain(
                        temporary,
                        first_target_content=content,
                    )
                )
                expected = guard_fixture._nested(
                    chain["target_requirements"],
                    chain["target_runtime"],
                    chain["target_staging"],
                    chain["target_lease"],
                    (),
                )
                guard = guard_fixture._guard(
                    expected,
                    target_requirements=chain["target_requirements"],
                    target_runtime=chain["target_runtime"],
                    target_staging=chain["target_staging"],
                    target_lease=chain["target_lease"],
                    source_staging=chain["source_staging"],
                    source_lease=chain["source_lease"],
                    paths=(),
                )
                registration = guard_fixture._registration(chain["root"])
                absent_root = Path(temporary) / "absent-target-native-runtime"
                nested_lease = (
                    RepositoryExecutableShebangNestedTargetStageLease(
                        absent_root
                    )
                )
                try:
                    nested_staging = (
                        stage_repository_executable_shebang_nested_target_bytes(
                            registration,
                            search_directories=(
                                chain["search_one"],
                                chain["search_two"],
                            ),
                            expected_chain_guard=guard,
                            expected_nested_resolution=expected,
                            expected_target_requirements=(
                                chain["target_requirements"]
                            ),
                            expected_target_runtime=chain["target_runtime"],
                            expected_target_staging=chain["target_staging"],
                            target_lease=chain["target_lease"],
                            expected_source_staging=chain["source_staging"],
                            source_lease=chain["source_lease"],
                            expected_nested_target_paths=(),
                            lease=nested_lease,
                        )
                    )
                    with patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("native input read bytes"),
                    ):
                        receipt = (
                            inspect_runtime(
                                nested_staging,
                                lease=nested_lease,
                            )
                        )
                    self.assertEqual(receipt.files, ())
                    self.assertEqual(
                        receipt.target_native_not_applicable_count,
                        2,
                    )
                    self.assertFalse(absent_root.exists())
                finally:
                    if nested_lease.state == "active":
                        nested_lease.close()
                    guard_fixture._close_chain(chain)

    def test_closed_cross_process_and_forged_lease_state_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(temporary)
            try:
                lease._owner_pid += 1
                with self.assertRaises(ValidationError):
                    inspect_runtime(
                        staging,
                        lease=lease,
                    )
                lease._owner_pid -= 1
                lease.close()
                with self.assertRaises(ValidationError):
                    inspect_runtime(
                        staging,
                        lease=lease,
                    )
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_cleanup_during_header_read_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(temporary)
            original = runtime_module._BUILTIN_READ_EXACT_HEADER

            def cleanup_then_return(
                descriptor: int,
                content_bytes: int,
            ) -> bytes:
                header = original(descriptor, content_bytes)
                lease.close()
                return header

            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_READ_EXACT_HEADER",
                    side_effect=cleanup_then_return,
                ):
                    with self.assertRaises(ValidationError) as caught:
                        inspect_runtime(
                            staging,
                            lease=lease,
                        )
                self.assertEqual(str(caught.exception), FIXED_ERROR)
                self.assertEqual(lease.state, "cleaned")
                self.assertTrue(
                    lease.cleanup_receipt.descriptor_release_complete
                )
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_baseexception_during_header_read_leaves_lease_unchanged(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(temporary)
            files = lease._files
            receipt_anchor = lease._receipt_object_anchor
            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_READ_EXACT_HEADER",
                    side_effect=KeyboardInterrupt,
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        inspect_runtime(
                            staging,
                            lease=lease,
                        )
                self.assertEqual(lease.state, "active")
                self.assertIs(lease._files, files)
                self.assertIs(lease._receipt_object_anchor, receipt_anchor)
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_public_monkeypatches_cannot_replace_frozen_proof_graph(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(temporary)
            try:
                with (
                    patch.object(
                        runtime_module,
                        "_target_staging_receipt_projection",
                        return_value={},
                    ),
                    patch.object(
                        runtime_module,
                        "_classify_header",
                        return_value=("unknown", None),
                    ),
                    patch.object(
                        runtime_module,
                        "_runtime_manifest_projection",
                        side_effect=AssertionError("public projection used"),
                    ),
                ):
                    receipt = (
                        inspect_runtime(
                            staging,
                            lease=lease,
                        )
                    )
                self.assertEqual(receipt.files[0].classification, "posix_shebang")
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_output_projection_rejects_forged_counts_and_lineage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(temporary)
            try:
                receipt = (
                    inspect_runtime(
                        staging,
                        lease=lease,
                    )
                )
                mutations = (
                    replace(
                        receipt,
                        known_chain_guard_runtime_inspected_count=0,
                    ),
                    replace(
                        receipt,
                        files=(
                            replace(
                                receipt.files[0],
                                content_digest="sha256:" + "0" * 64,
                            ),
                        ),
                    ),
                    replace(
                        receipt,
                        requirements=(
                            replace(
                                receipt.requirements[0],
                                target_requirement_ref=(
                                    "sha256:" + "0" * 64
                                ),
                            ),
                        ),
                    ),
                )
                for mutation in mutations:
                    with self.assertRaises(ValueError):
                        mutation.to_canonical()
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_header_reader_is_bounded_and_position_independent(self) -> None:
        content = b"#!/bin/sh\n" + b"x" * 6000
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, _staging = self._prepared(
                temporary,
                content=content,
            )
            descriptor = lease._files[0].descriptor
            calls: list[tuple[int, int]] = []
            original = runtime_module._BUILTIN_PREAD

            def record(value: int, size: int, offset: int) -> bytes:
                calls.append((size, offset))
                return original(value, size, offset)

            try:
                os.lseek(descriptor, 3, os.SEEK_SET)
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=record,
                ):
                    header = runtime_module._read_exact_header(
                        descriptor,
                        len(content),
                    )
                self.assertEqual(header, content[:4096])
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 3)
                self.assertTrue(calls)
                self.assertLessEqual(max(size for size, _ in calls), 4096)
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_no_path_process_or_cleanup_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging = self._prepared(temporary)
            try:
                with (
                    patch("os.open", side_effect=AssertionError("path open")),
                    patch("os.stat", side_effect=AssertionError("path stat")),
                    patch(
                        "os.scandir",
                        side_effect=AssertionError("path scan"),
                    ),
                    patch.object(
                        subprocess,
                        "Popen",
                        side_effect=AssertionError("process launch"),
                    ),
                ):
                    receipt = (
                        inspect_runtime(
                            staging,
                            lease=lease,
                        )
                    )
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(lease.state, "active")
                self.assertIsNone(lease.cleanup_receipt)
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_exports_and_inspector_signature_are_exact(self) -> None:
        self.assertEqual(
            tuple(runtime_module.__all__),
            (
                "MANIFEST_SCOPE",
                "MANIFEST_SOURCE",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_FILE_KIND",
                (
                    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
                    "RUNTIME_MANIFEST_EVIDENCE_KIND"
                ),
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_MANIFEST_KIND",
                (
                    "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
                    "RUNTIME_MANIFEST_SCHEMA_VERSION"
                ),
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND",
                "RepositoryExecutableShebangNestedTargetRuntimeBinding",
                "RepositoryExecutableShebangNestedTargetRuntimeFile",
                "RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt",
                "RepositoryExecutableShebangNestedTargetRuntimeRequirement",
                "inspect_staged_executable_shebang_nested_target_runtime_manifest",
            ),
        )
        self.assertEqual(
            str(inspect.signature(inspect_runtime)),
            (
                "(expected_nested_target_staging: "
                "'RepositoryExecutableShebangNestedTargetStagingReceipt', "
                "*, lease: "
                "'RepositoryExecutableShebangNestedTargetStageLease') -> "
                "'RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt'"
            ),
        )


if __name__ == "__main__":
    unittest.main()
