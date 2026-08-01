from __future__ import annotations

from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pickle
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
from ordomata import (
    repository_executable_native_loader_target_resolution
    as target_resolution_module,
)
from ordomata.repository_executable_native_loader_target_resolution import (
    inspect_staged_executable_native_loader_targets,
)
import ordomata.repository_executable_native_loader_target_staging as staging_module
from ordomata.repository_executable_native_loader_target_staging import (
    RepositoryExecutableNativeLoaderTargetStageLease,
    cleanup_repository_executable_native_loader_target_stage,
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


FIXED_STAGING_ERROR = (
    "repository executable native loader target staging is invalid"
)
FIXED_CLEANUP_ERROR = (
    "repository executable native loader target staging cleanup is uncertain"
)


@unittest.skipUnless(os.name == "posix", "loader target staging requires POSIX")
class RepositoryExecutableNativeLoaderTargetStagingTests(unittest.TestCase):
    fixture = target_module.RepositoryExecutableNativeLoaderTargetResolutionTests

    @staticmethod
    def _target_stage_root(temporary: str) -> Path:
        path = Path(temporary).resolve(strict=True) / "private-loader-stage-root"
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        return path

    def _chain(
        self,
        *,
        same_target: bool = False,
        no_targets: bool = False,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, _outside, search_one, search_two, source_stage_root = (
            self.fixture._workspace(temporary.name)
        )
        target_stage_root = self._target_stage_root(temporary.name)
        target_one = root.parent / "private-native-loader-target-one"
        target_two = (
            target_one
            if same_target
            else root.parent / "private-native-loader-target-two"
        )
        if no_targets:
            bare = native_module._elf64(None)
            relative = b"#!/usr/bin/python3\nprivate-non-native-bytes\n"
            paths: tuple[Path, ...] = ()
        else:
            self.fixture._write_target(
                target_one,
                b"private-native-loader-target-one-bytes\n",
            )
            if target_two != target_one:
                self.fixture._write_target(
                    target_two,
                    b"private-native-loader-target-two-bytes\n",
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
        executable_lease, source_staging, runtime, requirements = (
            self.fixture._stage_chain(
                registration,
                (search_one, search_two),
                source_stage_root,
            )
        )
        self.addCleanup(executable_lease.close)
        resolution = inspect_staged_executable_native_loader_targets(
            requirements,
            expected_runtime=runtime,
            expected_staging=source_staging,
            lease=executable_lease,
            expected_loader_paths=paths,
        )
        target_lease = RepositoryExecutableNativeLoaderTargetStageLease(
            target_stage_root
        )
        self.addCleanup(
            lambda: target_lease.close()
            if target_lease.state in {"new", "active"}
            else None
        )
        return (
            temporary,
            registration,
            (search_one, search_two),
            executable_lease,
            source_staging,
            runtime,
            requirements,
            resolution,
            paths,
            target_lease,
            target_stage_root,
        )

    @staticmethod
    def _stage(
        registration: object,
        searches: object,
        executable_lease: object,
        source_staging: object,
        runtime: object,
        requirements: object,
        resolution: object,
        paths: object,
        target_lease: object,
    ):
        return stage_repository_executable_native_loader_target_bytes(
            registration,
            search_directories=searches,
            expected_target_resolution=resolution,
            expected_requirements=requirements,
            expected_runtime=runtime,
            expected_staging=source_staging,
            executable_lease=executable_lease,
            expected_loader_paths=paths,
            lease=target_lease,
        )

    def _assert_invalid(self, *args: object, marker: str = "private-marker"):
        with self.assertRaises(ValidationError) as caught:
            self._stage(*args)
        self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_receipt_evidence_privacy_descriptors_and_source_lease(self) -> None:
        (
            _temporary,
            registration,
            searches,
            executable_lease,
            source_staging,
            runtime,
            requirements,
            resolution,
            paths,
            target_lease,
            target_stage_root,
        ) = self._chain()
        before_source = self.fixture._lease_snapshot(executable_lease)
        receipt = self._stage(
            registration,
            searches,
            executable_lease,
            source_staging,
            runtime,
            requirements,
            resolution,
            paths,
            target_lease,
        )
        self.assertEqual(target_lease.state, "active")
        self.assertIs(receipt, target_lease.receipt)
        self.assertEqual(receipt.declared_target_requirement_count, 2)
        self.assertEqual(receipt.no_target_requirement_count, 0)
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertTrue(receipt.staging_root_used)
        self.assertEqual(list(target_stage_root.iterdir()), [])
        self.assertEqual(
            self.fixture._lease_snapshot(executable_lease), before_source
        )
        canonical = receipt.to_canonical()
        evidence = receipt.to_evidence()
        self.assertEqual(canonical["loader_path_context_digest"], (
            resolution.loader_path_context_digest
        ))
        self.assertEqual(evidence["effect_class"], 1)
        self.assertEqual(evidence["validation_mode"], "local_staging")
        self.assertTrue(evidence["staged_byte_correspondence_verified"])
        self.assertFalse(evidence["authority_granted"])
        self.assertFalse(evidence["execution_enabled"])
        self.assertFalse(evidence["dynamic_loader_identity_verified"])
        self.assertEqual(
            receipt.expected_target_resolution_receipt_digest,
            canonical_digest(resolution.to_canonical()),
        )
        aggregate = "\n".join(
            (
                json.dumps(canonical, sort_keys=True),
                json.dumps(evidence, sort_keys=True),
                repr(receipt),
            )
        )
        for private in (
            *(os.fspath(path) for path in paths),
            os.fspath(target_stage_root),
            "private-native-loader-target-one-bytes",
            "private-native-loader-target-two-bytes",
        ):
            self.assertNotIn(private, aggregate)
        expected_content = {
            b"private-native-loader-target-one-bytes\n",
            b"private-native-loader-target-two-bytes\n",
        }
        observed_content: set[bytes] = set()
        for retained in target_lease._files:
            metadata = os.fstat(retained.descriptor)
            flags = fcntl.fcntl(retained.descriptor, fcntl.F_GETFL)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
            self.assertEqual(metadata.st_nlink, 0)
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertFalse(os.get_inheritable(retained.descriptor))
            observed_content.add(
                os.pread(retained.descriptor, metadata.st_size, 0)
            )
        self.assertEqual(observed_content, expected_content)
        with self.assertRaises(FrozenInstanceError):
            receipt.unique_target_count = 0

    def test_shared_loader_is_copied_once_and_bound_twice(self) -> None:
        chain = self._chain(same_target=True)
        receipt = self._stage(*chain[1:10])
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.declared_target_requirement_count, 2)
        self.assertEqual(receipt.unique_target_count, 1)
        self.assertEqual(len(target_lease_files := chain[9]._files), 1)
        self.assertEqual(
            {item.target_staged_file_ref for item in receipt.requirements},
            {target_lease_files[0].staged_file.target_staged_file_ref},
        )

    def test_staged_bytes_survive_source_replacement(self) -> None:
        chain = self._chain()
        paths = chain[8]
        target_lease = chain[9]
        self._stage(*chain[1:10])
        retained_by_digest = {
            item.staged_file.content_digest: item for item in target_lease._files
        }
        for path in paths:
            path.write_bytes(b"private-replacement-bytes\n")
            path.chmod(0o755)
        observed = {
            "sha256:"
            + hashlib.sha256(
                os.pread(
                    item.descriptor,
                    item.staged_file.content_bytes,
                    0,
                )
            ).hexdigest()
            for item in retained_by_digest.values()
        }
        self.assertEqual(observed, set(retained_by_digest))

    def test_no_target_chain_creates_active_empty_lease_without_root_use(self) -> None:
        chain = self._chain(no_targets=True)
        target_stage_root = chain[10]
        marker = target_stage_root / "private-root-untouched-marker"
        marker.write_text("untouched", encoding="utf-8")
        receipt = self._stage(*chain[1:10])
        self.assertEqual(receipt.declared_target_requirement_count, 0)
        self.assertEqual(receipt.no_target_requirement_count, 2)
        self.assertEqual(receipt.unique_target_count, 0)
        self.assertFalse(receipt.staging_root_used)
        self.assertEqual(chain[9].state, "active")
        self.assertEqual(chain[9]._files, ())
        self.assertEqual(marker.read_text(encoding="utf-8"), "untouched")

    def test_cleanup_is_idempotent_and_lease_is_not_copyable(self) -> None:
        chain = self._chain()
        target_lease = chain[9]
        receipt = self._stage(*chain[1:10])
        digest = receipt.receipt_digest
        cleanup = cleanup_repository_executable_native_loader_target_stage(
            target_lease
        )
        self.assertEqual(cleanup.outcome, "already_absent_verified")
        self.assertEqual(cleanup.target_staging_receipt_digest, digest)
        self.assertTrue(cleanup.owned_namespace_absence_verified)
        self.assertTrue(cleanup.descriptor_release_complete)
        self.assertFalse(cleanup.secure_erasure_verified)
        self.assertEqual(target_lease.state, "cleaned")
        self.assertIs(
            cleanup_repository_executable_native_loader_target_stage(target_lease),
            cleanup,
        )
        for operation in (copy, deepcopy, pickle.dumps):
            with self.assertRaises(TypeError):
                operation(target_lease)

    def test_wrong_lineage_paths_and_leases_fail_before_target_root_mutation(
        self,
    ) -> None:
        chain = self._chain()
        (
            _temporary,
            registration,
            searches,
            executable_lease,
            source_staging,
            runtime,
            requirements,
            resolution,
            paths,
            target_lease,
            target_stage_root,
        ) = chain
        marker = target_stage_root / "private-root-marker"
        marker.write_text("unchanged", encoding="utf-8")
        cases = (
            (
                None,
                searches,
                executable_lease,
                source_staging,
                runtime,
                requirements,
                resolution,
                paths,
            ),
            (
                registration,
                list(searches),
                executable_lease,
                source_staging,
                runtime,
                requirements,
                resolution,
                paths,
            ),
            (
                registration,
                searches,
                executable_lease,
                source_staging,
                runtime,
                requirements,
                replace(
                    resolution,
                    repository_ref="sha256:" + "0" * 64,
                ),
                paths,
            ),
            (
                registration,
                searches,
                executable_lease,
                source_staging,
                runtime,
                requirements,
                resolution,
                tuple(reversed(paths)),
            ),
        )
        for case in cases:
            with self.subTest(case=repr(case[:2])):
                fresh = RepositoryExecutableNativeLoaderTargetStageLease(
                    target_stage_root
                )
                self._assert_invalid(*case, fresh)
                self.assertEqual(fresh.state, "new")
                self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")
        self.assertEqual(target_lease.state, "new")

    def test_staging_root_shape_mode_content_and_overlap_fail_closed(self) -> None:
        for mutation in ("mode", "content", "overlap"):
            chain = self._chain()
            target_stage_root = chain[10]
            lease = chain[9]
            if mutation == "mode":
                target_stage_root.chmod(0o755)
            elif mutation == "content":
                (target_stage_root / "private-content").write_text(
                    "content", encoding="utf-8"
                )
            else:
                lease = RepositoryExecutableNativeLoaderTargetStageLease(
                    chain[8][0].parent
                )
            self._assert_invalid(*chain[1:9], lease)
            self.assertIn(lease.state, {"new", "cleaned"})

    def test_source_drift_during_action_capture_fails_without_staged_bytes(
        self,
    ) -> None:
        chain = self._chain()
        target = chain[8][0]
        real = target_resolution_module._BUILTIN_MEASURE_TARGET_SET_WITH_CONSUMER

        def mutate_after_capture(paths, consumer):
            measured = real(paths, consumer)
            target.write_bytes(b"private-mutated-loader-bytes\n")
            target.chmod(0o755)
            return measured

        with patch.object(
            target_resolution_module,
            "_BUILTIN_MEASURE_TARGET_SET_WITH_CONSUMER",
            side_effect=mutate_after_capture,
        ):
            self._assert_invalid(*chain[1:10])
        self.assertEqual(chain[9].state, "new")
        self.assertEqual(list(chain[10].iterdir()), [])

    def test_post_stage_correspondence_drift_aborts_and_releases_descriptors(
        self,
    ) -> None:
        chain = self._chain()
        real = staging_module._BUILTIN_INSPECT_TARGETS
        calls = 0

        def drift_on_post(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real(*args, **kwargs)
            if calls == 2:
                return replace(result, repository_ref="sha256:" + "1" * 64)
            return result

        with patch.object(
            staging_module,
            "_BUILTIN_INSPECT_TARGETS",
            side_effect=drift_on_post,
        ):
            self._assert_invalid(*chain[1:10])
        self.assertEqual(chain[9].state, "cleaned")
        self.assertEqual(chain[9]._files, ())
        self.assertEqual(list(chain[10].iterdir()), [])

    def test_copy_failure_aborts_owned_names_and_descriptors(self) -> None:
        chain = self._chain()
        with patch.object(
            staging_module,
            "_write_all",
            side_effect=OSError("private-copy-failure-marker"),
        ):
            self._assert_invalid(
                *chain[1:10],
                marker="private-copy-failure-marker",
            )
        self.assertEqual(chain[9].state, "cleaned")
        self.assertEqual(chain[9]._files, ())
        self.assertEqual(list(chain[10].iterdir()), [])

    def test_no_process_network_or_environment_effects(self) -> None:
        chain = self._chain()
        before_environment = dict(os.environ)
        marker = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(subprocess, "run", side_effect=marker) as run,
            patch.object(subprocess, "Popen", side_effect=marker) as popen,
            patch.object(socket, "socket", side_effect=marker) as network,
        ):
            receipt = self._stage(*chain[1:10])
        self.assertEqual(receipt.unique_target_count, 2)
        self.assertEqual(dict(os.environ), before_environment)
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()

    def test_cleanup_uncertainty_is_fixed_redacted_and_fail_closed(self) -> None:
        chain = self._chain()
        target_lease = chain[9]
        self._stage(*chain[1:10])
        marker = "private-cleanup-error-marker"
        with patch.object(
            staging_module,
            "_release_retained_targets",
            return_value=False,
        ):
            with self.assertRaises(ConfigurationError) as caught:
                cleanup_repository_executable_native_loader_target_stage(
                    target_lease
                )
        self.assertEqual(str(caught.exception), FIXED_CLEANUP_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertEqual(target_lease.state, "cleanup_unverifiable")


if __name__ == "__main__":
    unittest.main()
