from __future__ import annotations

from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
import fcntl
import json
import os
from pathlib import Path
import pickle
import stat
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
import ordomata.repository_executable_shebang_nested_target_staging as staging_module
from ordomata.repository_executable_shebang_nested_target_staging import (
    RepositoryExecutableShebangNestedTargetStageLease,
    cleanup_repository_executable_shebang_nested_target_stage,
    stage_repository_executable_shebang_nested_target_bytes,
)

if __package__:
    from . import (
        test_repository_executable_shebang_nested_target_chain_guard
        as guard_test_module,
    )
else:
    import test_repository_executable_shebang_nested_target_chain_guard as guard_test_module


FIXED_STAGING_ERROR = (
    "repository executable shebang nested target staging is invalid"
)
FIXED_COPY_ERROR = (
    "repository executable shebang nested target staging lease cannot be copied"
)


@unittest.skipUnless(os.name == "posix", "nested target staging requires POSIX")
class RepositoryExecutableShebangNestedTargetStagingTests(unittest.TestCase):
    fixture = (
        guard_test_module
        .RepositoryExecutableShebangNestedTargetChainGuardTests
    )

    def _prepared(
        self,
        temporary: str,
        *,
        content: bytes = b"private-nested-staging-content\n",
        include_source_native: bool = False,
    ) -> tuple[dict[str, object], object, object, object, Path]:
        chain = self.fixture._unpack(
            self.fixture._one_nested_chain(
                temporary,
                nested_target_content=content,
                include_source_native=include_source_native,
            )
        )
        paths = (chain["nested_target"],)
        expected, guard = self.fixture()._expected_and_guard(chain, paths)
        registration = self.fixture._registration(chain["root"])
        stage_root = (
            Path(temporary).resolve(strict=True)
            / "private-nested-target-stage-root"
        )
        stage_root.mkdir(mode=0o700)
        stage_root.chmod(0o700)
        return chain, registration, expected, guard, stage_root

    @staticmethod
    def _stage(
        chain: dict[str, object],
        registration: object,
        expected: object,
        guard: object,
        stage_root: Path,
        *,
        lease: RepositoryExecutableShebangNestedTargetStageLease | None = None,
    ):
        lease = lease or RepositoryExecutableShebangNestedTargetStageLease(
            stage_root
        )
        receipt = stage_repository_executable_shebang_nested_target_bytes(
            registration,
            search_directories=(
                chain["search_one"],
                chain["search_two"],
            ),
            expected_chain_guard=guard,
            expected_nested_resolution=expected,
            expected_target_requirements=chain["target_requirements"],
            expected_target_runtime=chain["target_runtime"],
            expected_target_staging=chain["target_staging"],
            target_lease=chain["target_lease"],
            expected_source_staging=chain["source_staging"],
            source_lease=chain["source_lease"],
            expected_nested_target_paths=(chain["nested_target"],),
            lease=lease,
        )
        return lease, receipt

    def test_guarded_bytes_are_staged_once_with_private_exact_receipt(
        self,
    ) -> None:
        marker = b"private-nested-staging-content-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            chain, registration, expected, guard, stage_root = self._prepared(
                temporary,
                content=marker,
                include_source_native=True,
            )
            lease = None
            try:
                lease, receipt = self._stage(
                    chain,
                    registration,
                    expected,
                    guard,
                    stage_root,
                )
                self.assertEqual(lease.state, "active")
                self.assertIs(lease.receipt, receipt)
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(receipt.total_staged_bytes, len(marker))
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.known_chain_guard_staged_count, 1)
                self.assertEqual(
                    receipt.source_native_not_applicable_count,
                    1,
                )
                self.assertEqual(
                    receipt.expected_chain_guard_receipt_digest,
                    guard.receipt_digest,
                )
                self.assertEqual(
                    receipt.action_chain_guard_receipt_digest,
                    guard.receipt_digest,
                )
                self.assertEqual(
                    receipt.post_stage_chain_guard_receipt_digest,
                    guard.receipt_digest,
                )
                self.assertEqual(list(stage_root.iterdir()), [])
                retained = lease._files[0]
                metadata = os.fstat(retained.descriptor)
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
                self.assertEqual(metadata.st_nlink, 0)
                self.assertEqual(
                    fcntl.fcntl(retained.descriptor, fcntl.F_GETFL)
                    & os.O_ACCMODE,
                    os.O_RDONLY,
                )
                self.assertFalse(os.get_inheritable(retained.descriptor))
                self.assertEqual(
                    os.pread(retained.descriptor, len(marker), 0),
                    marker,
                )
                canonical = receipt.to_canonical()
                self.assertEqual(
                    receipt.receipt_digest,
                    canonical_digest(canonical),
                )
                self.assertEqual(
                    receipt.staged_files[0].to_canonical(),
                    canonical["staged_files"][0],
                )
                self.assertEqual(
                    receipt.requirements[0].to_canonical(),
                    canonical["requirements"][0],
                )
                self.assertEqual(
                    receipt.bindings[0].to_canonical(),
                    canonical["bindings"][0],
                )
                evidence = receipt.to_evidence()
                self.assertEqual(evidence["effect_class"], 1)
                self.assertTrue(
                    evidence["read_only_descriptor_lease_established"]
                )
                self.assertFalse(evidence["authority_granted"])
                self.assertFalse(evidence["authorization_verified"])
                self.assertFalse(evidence["execution_enabled"])
                self.assertFalse(
                    evidence["subprocess_invocation_performed"]
                )
                self.assertFalse(
                    evidence["harness_invocation_performed"]
                )
                serialized = json.dumps(
                    {"canonical": canonical, "evidence": evidence},
                    sort_keys=True,
                )
                for private in (
                    str(chain["root"]),
                    str(chain["nested_target"]),
                    str(stage_root),
                    marker.decode("ascii").strip(),
                    "directory_inode",
                    "directory_device",
                ):
                    self.assertNotIn(private, serialized)
                    self.assertNotIn(private, repr(receipt))
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirement_count = 0
            finally:
                if lease is not None and lease.state == "active":
                    lease.close()
                self.fixture._close_chain(chain)

    def test_shared_nested_target_stages_one_file_with_two_bindings(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain, registration, expected, guard, stage_root = self._prepared(
                temporary
            )
            lease = None
            try:
                lease, receipt = self._stage(
                    chain,
                    registration,
                    expected,
                    guard,
                    stage_root,
                )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.known_chain_guard_staged_count, 2)
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(
                    {
                        item.nested_target_staged_file_ref
                        for item in receipt.requirements
                    },
                    {receipt.staged_files[0].nested_target_staged_file_ref},
                )
            finally:
                if lease is not None and lease.state == "active":
                    lease.close()
                self.fixture._close_chain(chain)

    def test_staged_bytes_survive_original_namespace_change_and_cleanup(
        self,
    ) -> None:
        marker = b"private-stable-detached-nested-target\n"
        with tempfile.TemporaryDirectory() as temporary:
            chain, registration, expected, guard, stage_root = self._prepared(
                temporary,
                content=marker,
            )
            lease = None
            descriptor = None
            try:
                lease, _receipt = self._stage(
                    chain,
                    registration,
                    expected,
                    guard,
                    stage_root,
                )
                descriptor = lease._files[0].descriptor
                Path(chain["nested_target"]).write_bytes(b"changed\n")
                self.assertEqual(
                    os.pread(descriptor, len(marker), 0),
                    marker,
                )
                first = lease.close()
                second = lease.close()
                self.assertIs(first, second)
                self.assertEqual(first.outcome, "already_absent_verified")
                self.assertTrue(first.owned_namespace_absence_verified)
                self.assertTrue(first.descriptor_release_complete)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            finally:
                if lease is not None and lease.state == "active":
                    lease.close()
                self.fixture._close_chain(chain)

    def test_lease_is_same_pid_noncopyable_and_nonserializable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True) / "unused-stage-root"
            lease = RepositoryExecutableShebangNestedTargetStageLease(root)
            for operation in (
                lambda: copy(lease),
                lambda: deepcopy(lease),
                lambda: pickle.dumps(lease),
            ):
                with self.assertRaises(TypeError) as caught:
                    operation()
                self.assertEqual(str(caught.exception), FIXED_COPY_ERROR)
            lease._owner_pid += 1
            with self.assertRaises(ValidationError) as caught:
                cleanup_repository_executable_shebang_nested_target_stage(
                    lease
                )
            self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)

    def test_tampered_guard_and_overlapping_root_fail_before_retention(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain, registration, expected, guard, stage_root = self._prepared(
                temporary
            )
            try:
                forged = replace(
                    guard,
                    guard_summary_ref="sha256:" + "0" * 64,
                )
                lease = RepositoryExecutableShebangNestedTargetStageLease(
                    stage_root
                )
                with self.assertRaises(ValidationError) as caught:
                    self._stage(
                        chain,
                        registration,
                        expected,
                        forged,
                        stage_root,
                        lease=lease,
                    )
                self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
                self.assertEqual(lease._files, ())
                self.assertEqual(list(stage_root.iterdir()), [])

                overlap = Path(chain["root"]) / "private-overlap-stage"
                overlap.mkdir(mode=0o700)
                overlap.chmod(0o700)
                lease = RepositoryExecutableShebangNestedTargetStageLease(
                    overlap
                )
                with self.assertRaises(ValidationError) as caught:
                    self._stage(
                        chain,
                        registration,
                        expected,
                        guard,
                        overlap,
                        lease=lease,
                    )
                self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
                self.assertEqual(lease._files, ())
                self.assertEqual(list(overlap.iterdir()), [])
            finally:
                self.fixture._close_chain(chain)

    def test_post_stage_guard_drift_fails_closed_and_cleans_stage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain, registration, expected, guard, stage_root = self._prepared(
                temporary
            )
            lease = RepositoryExecutableShebangNestedTargetStageLease(
                stage_root
            )
            original = staging_module._BUILTIN_INSPECT_CHAIN_GUARD
            calls = 0

            def drift(*args: object, **kwargs: object):
                nonlocal calls
                calls += 1
                result = original(*args, **kwargs)
                if calls == 1:
                    Path(chain["nested_target"]).write_bytes(b"drifted\n")
                return result

            try:
                with patch.object(
                    staging_module,
                    "_BUILTIN_INSPECT_CHAIN_GUARD",
                    side_effect=drift,
                ):
                    with self.assertRaises(ValidationError) as caught:
                        self._stage(
                            chain,
                            registration,
                            expected,
                            guard,
                            stage_root,
                            lease=lease,
                        )
                self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
                self.assertEqual(lease.state, "cleaned")
                self.assertEqual(lease._files, ())
                self.assertEqual(list(stage_root.iterdir()), [])
            finally:
                if lease.state == "active":
                    lease.close()
                self.fixture._close_chain(chain)

    def test_source_native_returns_active_empty_lease_without_stage_root(
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
            ) = self.fixture._workspace(temporary)
            target_stage_root.rmdir()
            self.fixture._set_contents(
                root,
                search_one,
                bare=guard_test_module._ELF,
                relative=guard_test_module._ELF,
            )
            registration = self.fixture._registration(root)
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
            ) = self.fixture._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(),
            )
            expected = self.fixture._nested(
                target_requirements,
                target_runtime,
                target_staging,
                target_lease,
                (),
            )
            guard = self.fixture._guard(
                expected,
                target_requirements=target_requirements,
                target_runtime=target_runtime,
                target_staging=target_staging,
                target_lease=target_lease,
                source_staging=source_staging,
                source_lease=source_lease,
                paths=(),
            )
            absent_stage_root = (
                Path(temporary).resolve(strict=True)
                / "must-remain-absent-nested-stage-root"
            )
            lease = RepositoryExecutableShebangNestedTargetStageLease(
                absent_stage_root
            )
            try:
                receipt = (
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
                        lease=lease,
                    )
                )
                self.assertEqual(lease.state, "active")
                self.assertEqual(lease._files, ())
                self.assertFalse(receipt.staging_root_used)
                self.assertEqual(receipt.unique_nested_target_count, 0)
                self.assertEqual(receipt.total_staged_bytes, 0)
                self.assertEqual(
                    receipt.source_native_not_applicable_count,
                    2,
                )
                self.assertFalse(absent_stage_root.exists())
                self.assertFalse(target_stage_root.exists())
                cleanup = lease.close()
                self.assertEqual(
                    cleanup.outcome,
                    "already_absent_verified",
                )
            finally:
                if lease.state == "active":
                    lease.close()
                target_lease.close()
                source_lease.close()

    def test_target_native_returns_active_empty_lease_without_stage_root(
        self,
    ) -> None:
        for label, content in (
            ("elf", guard_test_module._ELF),
            ("mach-o", guard_test_module._MACH_O),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                chain = self.fixture._unpack(
                    self.fixture._one_nested_chain(
                        temporary,
                        first_target_content=content,
                    )
                )
                expected = self.fixture._nested(
                    chain["target_requirements"],
                    chain["target_runtime"],
                    chain["target_staging"],
                    chain["target_lease"],
                    (),
                )
                guard = self.fixture._guard(
                    expected,
                    target_requirements=chain["target_requirements"],
                    target_runtime=chain["target_runtime"],
                    target_staging=chain["target_staging"],
                    target_lease=chain["target_lease"],
                    source_staging=chain["source_staging"],
                    source_lease=chain["source_lease"],
                    paths=(),
                )
                registration = self.fixture._registration(chain["root"])
                absent_stage_root = (
                    Path(temporary).resolve(strict=True)
                    / "must-remain-absent-target-native-stage-root"
                )
                lease = RepositoryExecutableShebangNestedTargetStageLease(
                    absent_stage_root
                )
                try:
                    receipt = (
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
                            lease=lease,
                        )
                    )
                    self.assertEqual(lease.state, "active")
                    self.assertFalse(receipt.staging_root_used)
                    self.assertEqual(receipt.unique_nested_target_count, 0)
                    self.assertEqual(receipt.total_staged_bytes, 0)
                    self.assertEqual(
                        receipt.target_native_not_applicable_count,
                        2,
                    )
                    self.assertFalse(absent_stage_root.exists())
                    lease.close()
                finally:
                    if lease.state == "active":
                        lease.close()
                    self.fixture._close_chain(chain)

    def test_cleanup_uncertainty_remains_explicit_on_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain, registration, expected, guard, stage_root = self._prepared(
                temporary
            )
            lease = None
            try:
                lease, _receipt = self._stage(
                    chain,
                    registration,
                    expected,
                    guard,
                    stage_root,
                )
                descriptor = lease._files[0].descriptor
                original_close = staging_module._close_descriptor

                def uncertain_close(value: int) -> bool:
                    if value == descriptor:
                        return False
                    return original_close(value)

                with patch.object(
                    staging_module,
                    "_close_descriptor",
                    side_effect=uncertain_close,
                ):
                    with self.assertRaises(ConfigurationError):
                        lease.close()
                self.assertEqual(lease.state, "cleanup_unverifiable")
                self.assertEqual(
                    lease.cleanup_receipt.outcome,
                    "unverifiable",
                )
                retry = lease.close()
                self.assertEqual(retry.outcome, "unverifiable")
                self.assertFalse(retry.descriptor_release_complete)
                self.assertFalse(
                    retry.owned_namespace_absence_verified
                )
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            finally:
                if lease is not None and lease.state == "active":
                    lease.close()
                self.fixture._close_chain(chain)


if __name__ == "__main__":
    unittest.main()
