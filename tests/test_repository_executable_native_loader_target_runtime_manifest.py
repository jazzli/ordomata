from __future__ import annotations

import builtins
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.errors import ValidationError
from ordomata import (
    repository_executable_native_loader_target_runtime_manifest
    as runtime_module,
)
from ordomata.repository_executable_native_loader_target_runtime_manifest import (
    RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt,
    inspect_staged_executable_native_loader_target_runtime_manifest,
)
from ordomata.repository_executable_native_loader_target_resolution import (
    inspect_staged_executable_native_loader_targets,
)
from ordomata.repository_executable_native_loader_target_staging import (
    RepositoryExecutableNativeLoaderTargetStageLease,
    stage_repository_executable_native_loader_target_bytes,
)

if __package__:
    from . import (
        test_repository_executable_native_loader_requirements as native_module,
    )
    from . import (
        test_repository_executable_native_loader_target_resolution as target_module,
    )
else:
    import test_repository_executable_native_loader_requirements as native_module
    import test_repository_executable_native_loader_target_resolution as target_module


FIXED_ERROR = (
    "repository executable native loader target runtime manifest is invalid"
)


@unittest.skipUnless(os.name == "posix", "loader runtime inspection requires POSIX")
class RepositoryExecutableNativeLoaderTargetRuntimeManifestTests(
    unittest.TestCase
):
    fixture = target_module.RepositoryExecutableNativeLoaderTargetResolutionTests

    @staticmethod
    def _write_target(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o755)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())

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
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, _outside, search_one, search_two, source_stage_root = (
            self.fixture._workspace(temporary.name)
        )
        target_stage_root = (
            Path(temporary.name).resolve(strict=True)
            / "private-loader-runtime-stage-root"
        )
        target_stage_root.mkdir(mode=0o700)
        target_stage_root.chmod(0o700)
        target_one = root.parent / "private-runtime-loader-target-one"
        target_two = (
            target_one
            if same_target
            else root.parent / "private-runtime-loader-target-two"
        )
        if no_targets:
            bare = native_module._elf64(None)
            relative = b"#!/usr/bin/python3\nprivate-non-native-source\n"
            paths: tuple[Path, ...] = ()
        else:
            self._write_target(target_one, first_content)
            if target_two != target_one:
                self._write_target(
                    target_two,
                    first_content
                    if second_content is None
                    else second_content,
                )
            bare = native_module._elf64(os.fsencode(target_one))
            relative = native_module._mach64(os.fsencode(target_two))
            paths = (target_one,) if same_target else (target_one, target_two)
        self.fixture._set_contents(
            root,
            search_one,
            bare=bare,
            relative=relative,
        )
        registration = self.fixture._registration(root)
        executable_lease, source_staging, source_runtime, requirements = (
            self.fixture._stage_chain(
                registration,
                (search_one, search_two),
                source_stage_root,
            )
        )
        self.addCleanup(executable_lease.close)
        resolution = inspect_staged_executable_native_loader_targets(
            requirements,
            expected_runtime=source_runtime,
            expected_staging=source_staging,
            lease=executable_lease,
            expected_loader_paths=paths,
        )
        target_lease = RepositoryExecutableNativeLoaderTargetStageLease(
            target_stage_root
        )
        target_staging = stage_repository_executable_native_loader_target_bytes(
            registration,
            search_directories=(search_one, search_two),
            expected_target_resolution=resolution,
            expected_requirements=requirements,
            expected_runtime=source_runtime,
            expected_staging=source_staging,
            executable_lease=executable_lease,
            expected_loader_paths=paths,
            lease=target_lease,
        )
        self.addCleanup(target_lease.close)
        return target_lease, target_staging, paths, target_stage_root

    def _assert_invalid(
        self,
        staging: object,
        lease: object,
        *,
        marker: str = "private-runtime-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_loader_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_fixed_runtime_classifications_and_bounded_headers(self) -> None:
        cases = (
            (
                "elf",
                b"\x7fELF\x02\x01\x01" + b"\x00" * 25,
                None,
            ),
            ("mach_o", native_module._mach64(b"/private/dyld"), None),
            ("posix_shebang", b"#!/usr/bin/python3 -I\nbody\n", True),
            ("unsupported_shebang", b"#! /bad-leading-space\n", None),
            ("unknown", b"private-unknown-loader-bytes\n", None),
        )
        for classification, content, directive_expected in cases:
            with self.subTest(classification=classification):
                lease, staging, _paths, _root = self._chain(
                    first_content=content,
                    same_target=True,
                )
                receipt = (
                    inspect_staged_executable_native_loader_target_runtime_manifest(
                        staging,
                        lease=lease,
                    )
                )
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(
                    receipt.files[0].classification,
                    classification,
                )
                self.assertEqual(
                    receipt.files[0].shebang_directive_ref is not None,
                    directive_expected is True,
                )
                self.assertLessEqual(receipt.files[0].header_bytes, 4_096)
                self.assertEqual(
                    receipt.to_evidence()[f"{classification}_file_count"],
                    1,
                )

    def test_receipt_lineage_privacy_and_lease_immutability(self) -> None:
        private_content = b"private-loader-runtime-content-marker\n"
        lease, staging, paths, stage_root = self._chain(
            first_content=private_content,
            same_target=True,
        )
        before = self._lease_snapshot(lease)
        receipt = inspect_staged_executable_native_loader_target_runtime_manifest(
            staging,
            lease=lease,
        )
        self.assertIsInstance(
            receipt,
            RepositoryExecutableNativeLoaderTargetRuntimeManifestReceipt,
        )
        self.assertEqual(self._lease_snapshot(lease), before)
        self.assertEqual(receipt.file_count, 1)
        self.assertEqual(receipt.declared_target_requirement_count, 2)
        self.assertEqual(receipt.no_target_requirement_count, 0)
        self.assertEqual(
            receipt.target_staging_receipt_digest,
            staging.receipt_digest,
        )
        evidence = receipt.to_evidence()
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
            *(os.fspath(path) for path in paths),
            os.fspath(stage_root),
        ):
            self.assertNotIn(private, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.file_count = 0

    def test_no_target_manifest_performs_no_descriptor_read(self) -> None:
        lease, staging, _paths, stage_root = self._chain(no_targets=True)
        marker = stage_root / "private-no-target-root-marker"
        marker.write_text("untouched", encoding="utf-8")
        with patch.object(
            runtime_module,
            "_BUILTIN_PREAD",
            side_effect=AssertionError("private-unexpected-read-marker"),
        ) as pread:
            receipt = inspect_staged_executable_native_loader_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(receipt.file_count, 0)
        self.assertEqual(receipt.declared_target_requirement_count, 0)
        self.assertEqual(receipt.no_target_requirement_count, 2)
        self.assertEqual(receipt.total_content_bytes, 0)
        self.assertEqual(receipt.total_header_bytes, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "untouched")
        pread.assert_not_called()

    def test_header_read_is_bounded_and_position_independent(self) -> None:
        content = b"\x7fELF\x02\x01\x01" + b"x" * 10_000
        lease, staging, _paths, _root = self._chain(
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
            receipt = inspect_staged_executable_native_loader_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(observations, [(len(content), 4_096)])
        self.assertEqual(receipt.total_header_bytes, 4_096)
        self.assertEqual(
            os.lseek(descriptor, 0, os.SEEK_CUR),
            before_position,
        )

    def test_tampered_staging_receipt_and_lease_fail_closed(self) -> None:
        lease, staging, _paths, _root = self._chain(same_target=True)
        for forged in (
            None,
            replace(staging, repository_ref="sha256:" + "0" * 64),
            replace(staging, unique_target_count=0),
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
        lease, staging, _paths, _root = self._chain(same_target=True)
        real = runtime_module._BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET
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
            "_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET",
            side_effect=mismatch,
        ):
            self._assert_invalid(
                staging,
                lease,
                marker="private-drift-marker",
            )
        self.assertEqual(lease.state, "active")

    def test_output_projection_rejects_forged_counts_and_lineage(self) -> None:
        lease, staging, _paths, _root = self._chain(same_target=True)
        receipt = inspect_staged_executable_native_loader_target_runtime_manifest(
            staging,
            lease=lease,
        )
        for forged in (
            replace(receipt, file_count=0),
            replace(receipt, total_header_bytes=0),
            replace(receipt, no_target_requirement_count=1),
            replace(receipt, files=()),
        ):
            with self.subTest(forged=repr(forged)):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

    def test_public_helper_monkeypatches_do_not_replace_proof_graph(self) -> None:
        lease, staging, _paths, _root = self._chain(same_target=True)
        poison = AssertionError("private-public-monkeypatch-marker")
        names = (
            "_runtime_file_projection",
            "_runtime_requirement_projection",
            "_runtime_binding_projection",
            "_target_staging_receipt_projection",
            "_runtime_manifest_projection",
            "_read_exact_header",
            "_build_runtime_file",
            "_build_runtime_requirement",
            "_active_target_stage_snapshot",
            "_verify_anchored_retained_target",
        )
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(
                    patch.object(runtime_module, name, side_effect=poison)
                )
            receipt = inspect_staged_executable_native_loader_target_runtime_manifest(
                staging,
                lease=lease,
            )
        self.assertEqual(receipt.file_count, 1)

    def test_no_path_process_network_cleanup_or_lease_effects(self) -> None:
        lease, staging, _paths, _root = self._chain(same_target=True)
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(os, "open", side_effect=poison) as os_opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = inspect_staged_executable_native_loader_target_runtime_manifest(
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
        lease, staging, _paths, _root = self._chain(same_target=True)
        marker = "private-runtime-baseexception-marker"
        with patch.object(
            runtime_module,
            "_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(staging, lease, marker=marker)
        for interruption in (KeyboardInterrupt(), SystemExit(7)):
            with (
                self.subTest(interruption=type(interruption).__name__),
                patch.object(
                    runtime_module,
                    "_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT",
                    side_effect=interruption,
                ),
                self.assertRaises(type(interruption)),
            ):
                inspect_staged_executable_native_loader_target_runtime_manifest(
                    staging,
                    lease=lease,
                )


if __name__ == "__main__":
    unittest.main()
