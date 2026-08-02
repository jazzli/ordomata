from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ordomata import repository_executable_native_dependency_manifest_target_staging as staging_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_dependency_manifest_target_staging import (
    RepositoryExecutableNativeDependencyManifestTargetStageLease,
    RepositoryExecutableNativeDependencyManifestTargetStagingReceipt,
    cleanup_repository_executable_native_dependency_manifest_target_stage,
    stage_repository_executable_native_dependency_manifest_target_bytes,
)

if __package__:
    from . import test_repository_executable_native_dependency_manifest_targets as targets_test
else:
    import test_repository_executable_native_dependency_manifest_targets as targets_test


FIXED_ERROR = "repository executable native dependency manifest target staging is invalid"


@unittest.skipUnless(os.name == "posix", "manifest-target staging requires POSIX")
class RepositoryExecutableNativeDependencyManifestTargetStagingTests(unittest.TestCase):
    def _prepare(self, *, source_mode: str = "mixed") -> tuple[object, ...]:
        # Reuse the exact Class 0 fixture so the Class 1 test cannot quietly
        # construct a looser source chain.
        source = targets_test.RepositoryExecutableNativeDependencyManifestTargetsTests(
            "runTest"
        )
        self.addCleanup(source.doCleanups)
        return source._prepare(source_mode=source_mode)

    def _root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "caller-owned-stage-root"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        return root

    @staticmethod
    def _stage(
        targets: object,
        manifest_receipt: object,
        requirements: object,
        runtime: object,
        source_staging: object,
        executable_lease: object,
        manifest: object,
        root: Path,
    ) -> tuple[object, RepositoryExecutableNativeDependencyManifestTargetStageLease]:
        lease = RepositoryExecutableNativeDependencyManifestTargetStageLease(root)
        receipt = stage_repository_executable_native_dependency_manifest_target_bytes(
            targets,
            expected_manifest=manifest_receipt,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=source_staging,
            executable_lease=executable_lease,
            expected_non_absolute_dependency_manifest=manifest,
            lease=lease,
        )
        return receipt, lease

    def _assert_invalid(self, values: tuple[object, ...], root: Path) -> None:
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, _private = values
        with self.assertRaises(ValidationError) as caught:
            self._stage(
                targets,
                manifest_receipt,
                requirements,
                runtime,
                source_staging,
                executable_lease,
                manifest,
                root,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertIsNone(caught.exception.__cause__)

    def test_stages_only_pinned_manifest_target_bytes_and_retains_no_names(self) -> None:
        values = self._prepare()
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, private_values = values
        root = self._root()
        receipt, lease = self._stage(
            targets,
            manifest_receipt,
            requirements,
            runtime,
            source_staging,
            executable_lease,
            manifest,
            root,
        )
        self.addCleanup(lease.close)
        self.assertIsInstance(receipt, RepositoryExecutableNativeDependencyManifestTargetStagingReceipt)
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertEqual(receipt.total_staged_bytes, targets.total_measured_bytes)
        self.assertTrue(receipt.staging_root_used)
        self.assertEqual(lease.state, "active")
        self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(len(lease._files), 2)
        for retained, expected in zip(lease._files, targets.measurements, strict=True):
            metadata = os.fstat(retained.descriptor)
            self.assertEqual(metadata.st_nlink, 0)
            self.assertEqual(metadata.st_size, expected.content_bytes)
            copied = os.pread(retained.descriptor, expected.content_bytes, 0)
            self.assertEqual(
                "sha256:" + hashlib.sha256(copied).hexdigest(),
                expected.content_digest,
            )
        aggregate = "\n".join(
            (
                json.dumps(receipt.to_canonical(), sort_keys=True),
                json.dumps(receipt.to_evidence(), sort_keys=True),
                repr(receipt),
            )
        )
        for private in private_values:
            self.assertNotIn(private, aggregate)
        self.assertEqual(receipt.to_evidence()["effect_class"], 1)
        self.assertFalse(receipt.to_evidence()["execution_enabled"])
        cleanup = cleanup_repository_executable_native_dependency_manifest_target_stage(lease)
        self.assertEqual(cleanup.outcome, "released")
        self.assertTrue(cleanup.descriptor_release_complete)
        self.assertEqual(lease.state, "cleaned")
        self.assertEqual(lease.close(), cleanup)

    def test_terminal_manifest_never_opens_or_requires_the_caller_root(self) -> None:
        values = self._prepare(source_mode="terminal")
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, _private = values
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        absent_root = Path(temporary.name) / "absent-caller-root"
        receipt, lease = self._stage(
            targets,
            manifest_receipt,
            requirements,
            runtime,
            source_staging,
            executable_lease,
            manifest,
            absent_root,
        )
        self.addCleanup(lease.close)
        self.assertEqual(receipt.unique_target_count, 0)
        self.assertEqual(receipt.total_staged_bytes, 0)
        self.assertFalse(receipt.staging_root_used)
        self.assertEqual(lease.state, "active")

    def test_root_must_be_empty_owner_only_real_directory_outside_targets(self) -> None:
        values = self._prepare()
        nonempty = self._root()
        (nonempty / "untrusted-existing-entry").write_bytes(b"marker")
        self._assert_invalid(values, nonempty)

        wrong_mode = self._root()
        wrong_mode.chmod(0o755)
        self._assert_invalid(values, wrong_mode)

        targets, _manifest_receipt, _requirements, _runtime, _source_staging, _executable_lease, manifest, _private = values
        self.assertEqual(targets.unique_target_count, 2)
        self._assert_invalid(values, manifest[0].target_path.parent)

    def test_symlink_root_is_rejected_and_source_is_not_staged(self) -> None:
        values = self._prepare()
        target = self._root()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        link = Path(temporary.name) / "stage-link"
        os.symlink(target, link)
        self._assert_invalid(values, link)
        self.assertEqual(list(target.iterdir()), [])

    def test_tampering_or_reuse_of_the_one_shot_lease_is_rejected(self) -> None:
        values = self._prepare()
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, _private = values
        root = self._root()
        receipt, lease = self._stage(
            targets,
            manifest_receipt,
            requirements,
            runtime,
            source_staging,
            executable_lease,
            manifest,
            root,
        )
        self.addCleanup(lease.close)
        with self.assertRaises(ValidationError) as caught:
            stage_repository_executable_native_dependency_manifest_target_bytes(
                targets,
                expected_manifest=manifest_receipt,
                expected_requirements=requirements,
                expected_runtime=runtime,
                expected_staging=source_staging,
                executable_lease=executable_lease,
                expected_non_absolute_dependency_manifest=manifest,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        with self.assertRaises(FrozenInstanceError):
            receipt.unique_target_count = 0
        self.assertEqual(lease.close().outcome, "released")

    def test_post_stage_source_drift_rejects_and_releases_every_staged_copy(self) -> None:
        values = self._prepare()
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, _private = values
        root = self._root()
        lease = RepositoryExecutableNativeDependencyManifestTargetStageLease(root)
        real_measure = staging_module._BUILTIN_MEASURE_WITH_CONSUMER

        def measure_then_drift(paths: tuple[Path, ...], consumer: object) -> object:
            measured = real_measure(paths, consumer)
            manifest[0].target_path.write_bytes(b"post-stage-drift")
            manifest[0].target_path.chmod(0o755)
            return measured

        with patch.object(
            staging_module,
            "_BUILTIN_MEASURE_WITH_CONSUMER",
            side_effect=measure_then_drift,
        ):
            with self.assertRaises(ValidationError) as caught:
                stage_repository_executable_native_dependency_manifest_target_bytes(
                    targets,
                    expected_manifest=manifest_receipt,
                    expected_requirements=requirements,
                    expected_runtime=runtime,
                    expected_staging=source_staging,
                    executable_lease=executable_lease,
                    expected_non_absolute_dependency_manifest=manifest,
                    lease=lease,
                )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(lease._files, ())

    def test_public_surface_has_exact_fixed_errors_and_no_subprocess_route(self) -> None:
        signature = inspect.signature(stage_repository_executable_native_dependency_manifest_target_bytes)
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_targets",
                "expected_manifest",
                "expected_requirements",
                "expected_runtime",
                "expected_staging",
                "executable_lease",
                "expected_non_absolute_dependency_manifest",
                "lease",
            ),
        )
        self.assertNotIn("subprocess", staging_module.__dict__)
        self.assertNotIn("socket", staging_module.__dict__)
        self.assertNotIn("urllib", staging_module.__dict__)
        values = self._prepare()
        targets, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, _private = values
        tampered = replace(targets, total_measured_bytes=targets.total_measured_bytes + 1)
        self._assert_invalid((tampered, manifest_receipt, requirements, runtime, source_staging, executable_lease, manifest, ()), self._root())


if __name__ == "__main__":
    unittest.main()
