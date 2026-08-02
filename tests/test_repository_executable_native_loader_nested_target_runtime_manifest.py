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
import unittest
from unittest.mock import patch

from ordomata.errors import ValidationError
import ordomata.repository_executable_native_loader_nested_target_runtime_manifest \
    as runtime_module
from ordomata.repository_executable_native_loader_nested_target_runtime_manifest import (
    RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt,
    inspect_staged_executable_native_loader_nested_target_runtime_manifest,
)
from ordomata.repository_executable_native_loader_nested_target_staging import (
    RepositoryExecutableNativeLoaderNestedTargetStageLease,
)

if __package__:
    from . import (
        test_repository_executable_native_loader_nested_target_staging
        as staging_test_module,
    )
    from . import (
        test_repository_executable_native_loader_requirements as native_module,
    )
else:
    import test_repository_executable_native_loader_nested_target_staging \
        as staging_test_module
    import test_repository_executable_native_loader_requirements as native_module


FIXED_ERROR = (
    "repository executable native loader nested target runtime manifest is invalid"
)


@unittest.skipUnless(os.name == "posix", "nested runtime inspection requires POSIX")
class RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestTests(
    unittest.TestCase
):
    staging_fixture = (
        staging_test_module.RepositoryExecutableNativeLoaderNestedTargetStagingTests
    )
    guard_fixture = staging_fixture.guard_fixture
    nested_fixture = guard_fixture.nested_fixture
    fixture = guard_fixture.fixture
    _searches = staticmethod(staging_fixture._searches)

    @staticmethod
    def _lease_snapshot(lease: object) -> tuple[object, ...]:
        return (
            lease.state,
            lease.receipt,
            lease.cleanup_receipt,
            lease._receipt_digest_anchor,
            lease._receipt_object_anchor,
            lease._receipt_file_refs_anchor,
            lease._files_object_anchor,
            lease._state,
            lease._owner_pid,
            lease._files,
            lease._root_descriptor,
            lease._root_metadata,
            lease._pending_name,
            lease._pending_identity,
            lease._pending_descriptors,
            lease._descriptor_release_unverifiable,
        )

    def _chain(
        self,
        *,
        first_content: bytes = b"\x7fELF\x02\x01\x01" + b"\x00" * 25,
        second_content: bytes | None = None,
        same_target: bool = False,
        no_targets: bool = False,
        non_target_kind: str | None = None,
    ):
        if no_targets:
            chain = self.guard_fixture._chain(self, no_first_targets=True)
        elif non_target_kind is not None:
            chain = self.guard_fixture._chain(
                self,
                same_first_target=True,
                first_content_kind=non_target_kind,
            )
        else:
            chain = self.guard_fixture._chain(
                self,
                same_nested_target=same_target,
            )
            nested_paths = tuple(Path(item) for item in chain["nested_paths"])
            nested_paths[0].write_bytes(first_content)
            nested_paths[0].chmod(0o755)
            for nested_path in nested_paths[1:]:
                nested_path.write_bytes(
                    first_content if second_content is None else second_content
                )
                nested_path.chmod(0o755)

        nested = self.guard_fixture._nested(self, chain)
        guard = self.guard_fixture._guard(self, chain, nested)
        stage_root = chain["root"].parent / "private-runtime-depth-two-stage-root"
        if no_targets or non_target_kind is not None:
            if stage_root.exists():
                stage_root.rmdir()
        else:
            stage_root.mkdir(mode=0o700)
            stage_root.chmod(0o700)
        lease = RepositoryExecutableNativeLoaderNestedTargetStageLease(stage_root)
        lease, staging = self.staging_fixture._stage(
            self,
            chain,
            nested,
            guard,
            stage_root,
            lease=lease,
        )
        self.addCleanup(lease.close)
        return lease, staging, chain, stage_root

    def _assert_invalid(
        self,
        staging: object,
        lease: object,
        *,
        marker: str = "private-runtime-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_loader_nested_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_fixed_runtime_classifications_and_bounded_headers(self) -> None:
        cases = (
            ("elf", b"\x7fELF\x02\x01\x01" + b"\x00" * 25, None),
            ("mach_o", native_module._mach64(b"/private/dyld"), None),
            ("posix_shebang", b"#!/usr/bin/python3 -I\nbody\n", True),
            ("unsupported_shebang", b"#! /bad-leading-space\n", None),
            ("unknown", b"private-unknown-nested-loader-bytes\n", None),
        )
        for classification, content, directive_expected in cases:
            with self.subTest(classification=classification):
                lease, staging, _chain, _root = self._chain(
                    first_content=content,
                    same_target=True,
                )
                receipt = inspect_staged_executable_native_loader_nested_target_runtime_manifest(
                    staging,
                    lease=lease,
                )
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.lineage_count, 2)
                self.assertEqual(receipt.files[0].classification, classification)
                self.assertEqual(
                    receipt.files[0].shebang_directive_ref is not None,
                    directive_expected is True,
                )
                self.assertLessEqual(receipt.files[0].header_bytes, 4_096)
                self.assertEqual(
                    receipt.to_evidence()[f"{classification}_file_count"],
                    1,
                )

    def test_exports_and_inspector_signature_are_exact(self) -> None:
        self.assertEqual(
            runtime_module.__all__,
            [
                "MANIFEST_SCOPE",
                "MANIFEST_SOURCE",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_FILE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_LINEAGE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RUNTIME_REQUIREMENT_KIND",
                "RepositoryExecutableNativeLoaderNestedTargetRuntimeBinding",
                "RepositoryExecutableNativeLoaderNestedTargetRuntimeFile",
                "RepositoryExecutableNativeLoaderNestedTargetRuntimeLineage",
                "RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt",
                "RepositoryExecutableNativeLoaderNestedTargetRuntimeRequirement",
                "inspect_staged_executable_native_loader_nested_target_runtime_manifest",
            ],
        )
        parameters = tuple(
            inspect.signature(
                inspect_staged_executable_native_loader_nested_target_runtime_manifest
            ).parameters.values()
        )
        self.assertEqual(
            tuple(item.name for item in parameters),
            ("expected_nested_target_staging", "lease"),
        )
        self.assertEqual(
            parameters[0].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertEqual(parameters[1].kind, inspect.Parameter.KEYWORD_ONLY)

    def test_receipt_lineage_privacy_and_lease_immutability(self) -> None:
        private_content = b"private-nested-runtime-content-marker\n"
        lease, staging, chain, stage_root = self._chain(
            first_content=private_content,
            same_target=True,
        )
        before = self._lease_snapshot(lease)
        receipt = inspect_staged_executable_native_loader_nested_target_runtime_manifest(
            staging,
            lease=lease,
        )
        self.assertIsInstance(
            receipt,
            RepositoryExecutableNativeLoaderNestedTargetRuntimeManifestReceipt,
        )
        self.assertEqual(self._lease_snapshot(lease), before)
        self.assertEqual(receipt.file_count, 1)
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.lineage_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(
            receipt.nested_target_staging_receipt_digest,
            staging.receipt_digest,
        )
        self.assertEqual(
            {item.disposition for item in receipt.lineages},
            {"runtime_requirement_bound"},
        )
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
        self.assertEqual(evidence["effect_class"], 0)
        self.assertEqual(evidence["validation_mode"], "read_only")
        self.assertTrue(evidence["staged_descriptor_full_remeasurement_complete"])
        self.assertFalse(evidence["authority_granted"])
        self.assertFalse(evidence["execution_enabled"])
        aggregate = "\n".join(
            (
                json.dumps(receipt.to_canonical(), sort_keys=True),
                json.dumps(evidence, sort_keys=True),
                repr(receipt),
            )
        )
        for private in (
            private_content.decode().strip(),
            str(chain["nested_one"]),
            str(stage_root),
        ):
            self.assertNotIn(private, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.file_count = 0

    def test_empty_outcomes_preserve_lineage_without_descriptor_reads(self) -> None:
        cases = (
            (None, 0, 0),
            ("elf_absent", 1, 2),
            ("unsupported", 1, 2),
            ("non_native", 1, 2),
        )
        for kind, requirement_count, bound_lineage_count in cases:
            with self.subTest(kind=kind):
                lease, staging, _chain, stage_root = self._chain(
                    no_targets=kind is None,
                    non_target_kind=kind,
                )
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("private-unexpected-read-marker"),
                ) as pread:
                    receipt = inspect_staged_executable_native_loader_nested_target_runtime_manifest(
                        staging,
                        lease=lease,
                    )
                self.assertEqual(receipt.file_count, 0)
                self.assertEqual(receipt.requirement_count, requirement_count)
                self.assertEqual(receipt.lineage_count, 2)
                self.assertEqual(
                    sum(
                        item.disposition == "runtime_requirement_bound"
                        for item in receipt.lineages
                    ),
                    bound_lineage_count,
                )
                self.assertFalse(stage_root.exists())
                pread.assert_not_called()

    def test_header_read_is_bounded_and_position_independent(self) -> None:
        content = b"\x7fELF\x02\x01\x01" + b"x" * 10_000
        lease, staging, _chain, _root = self._chain(
            first_content=content,
            same_target=True,
        )
        descriptor = lease._files[0].descriptor
        before_position = os.lseek(descriptor, 0, os.SEEK_CUR)
        real = runtime_module._BUILTIN_READ_EXACT_HEADER
        observations: list[tuple[int, int]] = []

        def observe(fd: int, content_bytes: int) -> bytes:
            header = real(fd, content_bytes)
            observations.append((content_bytes, len(header)))
            return header

        with patch.object(
            runtime_module,
            "_BUILTIN_READ_EXACT_HEADER",
            side_effect=observe,
        ):
            receipt = inspect_staged_executable_native_loader_nested_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(observations, [(len(content), 4_096)])
        self.assertEqual(receipt.total_header_bytes, 4_096)
        self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), before_position)

    def test_tampered_staging_receipt_and_lease_fail_closed(self) -> None:
        lease, staging, _chain, _root = self._chain(same_target=True)
        for forged in (
            None,
            replace(staging, repository_ref="sha256:" + "0" * 64),
            replace(staging, unique_nested_target_count=0),
            replace(staging, staged_files=()),
        ):
            with self.subTest(forged=repr(forged)):
                self._assert_invalid(forged, lease)
        original_files = lease._files
        lease._files = tuple(reversed(original_files))
        self._assert_invalid(staging, lease)
        lease._files = original_files
        lease.close()
        self._assert_invalid(staging, lease)

    def test_remeasurement_drift_and_header_mismatch_fail_closed(self) -> None:
        lease, staging, _chain, _root = self._chain(same_target=True)
        real = runtime_module._BUILTIN_VERIFY_RETAINED_TARGET
        calls = 0

        def mismatch(*args, **kwargs):
            nonlocal calls
            calls += 1
            header = real(*args, **kwargs)
            if calls == 1:
                return header + b"private-drift-marker"
            return header

        with patch.object(
            runtime_module,
            "_BUILTIN_VERIFY_RETAINED_TARGET",
            side_effect=mismatch,
        ):
            self._assert_invalid(
                staging,
                lease,
                marker="private-drift-marker",
            )
        self.assertEqual(lease.state, "active")

    def test_output_projection_rejects_forged_counts_and_lineage(self) -> None:
        lease, staging, _chain, _root = self._chain(same_target=True)
        receipt = inspect_staged_executable_native_loader_nested_target_runtime_manifest(
            staging,
            lease=lease,
        )
        for forged in (
            replace(receipt, file_count=0),
            replace(receipt, total_header_bytes=0),
            replace(receipt, known_chain_guard_runtime_inspected_count=1),
            replace(receipt, files=()),
            replace(receipt, lineages=()),
        ):
            with self.subTest(forged=repr(forged)):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

    def test_public_helper_monkeypatches_do_not_replace_proof_graph(self) -> None:
        lease, staging, _chain, _root = self._chain(same_target=True)
        poison = AssertionError("private-public-monkeypatch-marker")
        names = (
            "_is_digest",
            "_runtime_file_projection",
            "_runtime_requirement_projection",
            "_runtime_lineage_projection",
            "_runtime_binding_projection",
            "_runtime_manifest_projection",
            "_read_exact_header",
            "_build_runtime_file",
            "_build_runtime_requirement",
            "_active_nested_target_stage_snapshot",
            "_verify_anchored_retained_nested_target",
        )
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(
                    patch.object(runtime_module, name, side_effect=poison)
                )
            receipt = inspect_staged_executable_native_loader_nested_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(receipt.file_count, 1)

    def test_no_path_process_network_cleanup_or_lease_effects(self) -> None:
        lease, staging, _chain, _root = self._chain(same_target=True)
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(os, "open", side_effect=poison) as os_opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_loader_nested_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(receipt.file_count, 1)
        self.assertEqual(self._lease_snapshot(lease), before)
        opened.assert_not_called()
        os_opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_interrupts_preserved_and_failures_fixed_redacted(self) -> None:
        lease, staging, _chain, _root = self._chain(same_target=True)
        marker = "private-runtime-baseexception-marker"
        with patch.object(
            runtime_module,
            "_BUILTIN_ACTIVE_STAGE_SNAPSHOT",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(staging, lease, marker=marker)
        for interruption in (KeyboardInterrupt(), SystemExit(7)):
            with (
                self.subTest(interruption=type(interruption).__name__),
                patch.object(
                    runtime_module,
                    "_BUILTIN_ACTIVE_STAGE_SNAPSHOT",
                    side_effect=interruption,
                ),
                self.assertRaises(type(interruption)),
            ):
                inspect_staged_executable_native_loader_nested_target_runtime_manifest(
                    staging,
                    lease=lease,
                )


if __name__ == "__main__":
    unittest.main()
