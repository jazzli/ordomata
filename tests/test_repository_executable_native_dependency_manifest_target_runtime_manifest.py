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

from ordomata import repository_executable_native_dependency_manifest_target_runtime_manifest as runtime_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_manifest_target_runtime_manifest import (
    RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt,
    inspect_staged_executable_native_dependency_manifest_target_runtime_manifest,
)
from ordomata.repository_executable_native_dependency_manifest_target_staging import (
    RepositoryExecutableNativeDependencyManifestTargetStageLease,
    stage_repository_executable_native_dependency_manifest_target_bytes,
)

if __package__:
    from . import test_repository_executable_native_dependency_manifest_target_staging as stage_test
else:
    import test_repository_executable_native_dependency_manifest_target_staging as stage_test


FIXED_ERROR = "repository executable native dependency manifest target runtime manifest is invalid"


@unittest.skipUnless(os.name == "posix", "manifest target runtime inspection requires POSIX")
class RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestTests(unittest.TestCase):
    def _prepare(self, *, terminal: bool = False) -> tuple[object, ...]:
        source = stage_test.RepositoryExecutableNativeDependencyManifestTargetStagingTests("runTest")
        self.addCleanup(source.doCleanups)
        values = source._prepare(source_mode="terminal" if terminal else "mixed")
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, private = values
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "runtime-stage-root"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        lease = RepositoryExecutableNativeDependencyManifestTargetStageLease(root)
        staging = stage_repository_executable_native_dependency_manifest_target_bytes(
            targets,
            expected_manifest=manifest_receipt,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=source_staging,
            executable_lease=executable_lease,
            expected_non_absolute_dependency_manifest=manifest,
            lease=lease,
        )
        self.addCleanup(lease.close)
        return staging, lease, root, private

    @staticmethod
    def _lease_snapshot(lease: object) -> tuple[object, ...]:
        return (
            lease.state,
            lease.receipt,
            lease.cleanup_receipt,
            lease._receipt_anchor,
            lease._receipt_digest_anchor,
            lease._files_anchor,
            lease._files,
            lease._root_descriptor,
            lease._root_metadata,
        )

    def _assert_invalid(self, staging: object, lease: object, *, marker: str = "private-runtime-marker") -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(staging, lease=lease)
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_remeasures_detached_descriptors_and_keeps_lineage_private(self) -> None:
        staging, lease, root, private = self._prepare()
        before = self._lease_snapshot(lease)
        receipt = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(staging, lease=lease)
        self.assertIsInstance(receipt, RepositoryExecutableNativeDependencyManifestTargetRuntimeManifestReceipt)
        self.assertEqual(receipt.file_count, 2)
        self.assertEqual(receipt.total_content_bytes, staging.total_staged_bytes)
        self.assertEqual(receipt.target_staging_receipt_digest, staging.receipt_digest)
        self.assertEqual(self._lease_snapshot(lease), before)
        self.assertEqual([item.classification for item in receipt.files], ["unknown", "unknown"])
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(evidence["staged_descriptor_full_remeasurement_complete"])
        self.assertFalse(evidence["execution_enabled"])
        self.assertFalse(evidence["path_open_performed"])
        aggregate = "\n".join((json.dumps(receipt.to_canonical(), sort_keys=True), json.dumps(evidence, sort_keys=True), repr(receipt)))
        for value in (*private, os.fspath(root)):
            self.assertNotIn(value, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.file_count = 0

    def test_terminal_stage_performs_no_descriptor_reads_or_root_mutation(self) -> None:
        staging, lease, root, _private = self._prepare(terminal=True)
        marker = root / "caller-root-remains-untouched"
        marker.write_text("marker", encoding="utf-8")
        with patch.object(runtime_module, "_BUILTIN_PREAD", side_effect=AssertionError("private-unexpected-pread")) as pread:
            receipt = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(staging, lease=lease)
        self.assertEqual(receipt.file_count, 0)
        self.assertEqual(receipt.total_content_bytes, 0)
        self.assertEqual(receipt.total_header_bytes, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "marker")
        pread.assert_not_called()

    def test_fixed_header_classifier_accepts_only_bounded_byte_level_forms(self) -> None:
        ref = "sha256:" + "0" * 64
        cases = (
            (b"\x7fELF\x02\x01\x01" + b"\x00" * 24, "elf", False),
            (b"\xcf\xfa\xed\xfe" + b"\x00" * 28, "mach_o", False),
            (b"#!/usr/bin/python3 -I\nbody\n", "posix_shebang", True),
            (b"#! /bad-leading-space\n", "unsupported_shebang", False),
            (b"private-unknown", "unknown", False),
        )
        for header, classification, has_directive in cases:
            with self.subTest(classification=classification):
                observed, directive = runtime_module._classify_header(ref, header)
                self.assertEqual(observed, classification)
                self.assertEqual(directive is not None, has_directive)

    def test_staging_receipt_lease_or_descriptor_drift_fails_closed(self) -> None:
        staging, lease, _root, _private = self._prepare()
        for forged in (
            None,
            replace(staging, repository_ref="sha256:" + "0" * 64),
            replace(staging, unique_target_count=0),
            replace(staging, staged_files=()),
        ):
            with self.subTest(forged=repr(forged)):
                self._assert_invalid(forged, lease)
        original = lease._files
        lease._files = tuple(reversed(original))
        self._assert_invalid(staging, lease)
        lease._files = original
        real = runtime_module._BUILTIN_READ_AND_VERIFY
        with patch.object(runtime_module, "_BUILTIN_READ_AND_VERIFY", side_effect=lambda *args: real(*args) + b"private-header-drift"):
            self._assert_invalid(staging, lease, marker="private-header-drift")

    def test_reads_no_path_and_performs_no_network_process_or_lease_effect(self) -> None:
        staging, lease, _root, _private = self._prepare()
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(os, "open", side_effect=poison) as os_opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(staging, lease=lease)
        self.assertEqual(receipt.file_count, 2)
        self.assertEqual(self._lease_snapshot(lease), before)
        opened.assert_not_called()
        os_opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_public_helpers_cannot_replace_the_frozen_proof_graph(self) -> None:
        staging, lease, _root, _private = self._prepare()
        poison = AssertionError("private-public-monkeypatch")
        with (
            patch.object(runtime_module, "_runtime_file_projection", side_effect=poison),
            patch.object(runtime_module, "_runtime_manifest_projection", side_effect=poison),
            patch.object(runtime_module, "_active_stage_snapshot", side_effect=poison),
            patch.object(runtime_module, "_read_and_verify", side_effect=poison),
            patch.object(runtime_module, "_build_runtime_file", side_effect=poison),
            patch.object(runtime_module, "_classify_header", side_effect=poison),
        ):
            receipt = inspect_staged_executable_native_dependency_manifest_target_runtime_manifest(staging, lease=lease)
        self.assertEqual(receipt.file_count, 2)


if __name__ == "__main__":
    unittest.main()
