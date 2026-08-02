from __future__ import annotations

from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
import fcntl
import inspect
import json
import os
from pathlib import Path
import pickle
import socket
import stat
import subprocess
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
import ordomata.repository_executable_native_loader_nested_target_staging \
    as staging_module
from ordomata.repository_executable_native_loader_nested_target_staging import (
    RepositoryExecutableNativeLoaderNestedTargetStageLease,
    cleanup_repository_executable_native_loader_nested_target_stage,
    stage_repository_executable_native_loader_nested_target_bytes,
)

if __package__:
    from . import (
        test_repository_executable_native_loader_nested_target_chain_guard
        as guard_test_module,
    )
else:
    import test_repository_executable_native_loader_nested_target_chain_guard \
        as guard_test_module


FIXED_STAGING_ERROR = (
    "repository executable native loader nested target staging is invalid"
)
FIXED_COPY_ERROR = (
    "repository executable native loader nested target staging lease cannot be copied"
)


@unittest.skipUnless(os.name == "posix", "native-loader staging requires POSIX")
class RepositoryExecutableNativeLoaderNestedTargetStagingTests(
    unittest.TestCase
):
    guard_fixture = (
        guard_test_module
        .RepositoryExecutableNativeLoaderNestedTargetChainGuardTests
    )
    nested_fixture = guard_fixture.nested_fixture
    fixture = guard_fixture.fixture

    def _prepared(self, **kwargs: object):
        chain = self.guard_fixture._chain(self, **kwargs)
        nested = self.guard_fixture._nested(self, chain)
        guard = self.guard_fixture._guard(self, chain, nested)
        stage_root = chain["root"].parent / "private-depth-two-stage-root"
        stage_root.mkdir(mode=0o700)
        stage_root.chmod(0o700)
        return chain, nested, guard, stage_root

    @staticmethod
    def _searches(chain: dict[str, object]) -> tuple[Path, Path]:
        base = chain["root"].parent
        return (
            base / "private-staging-search-one-marker",
            base / "private-staging-search-two-marker",
        )

    def _stage(
        self,
        chain: dict[str, object],
        nested: object,
        guard: object,
        stage_root: Path,
        *,
        lease: RepositoryExecutableNativeLoaderNestedTargetStageLease | None = None,
        **overrides: object,
    ):
        lease = lease or RepositoryExecutableNativeLoaderNestedTargetStageLease(
            stage_root
        )
        arguments = {
            "search_directories": self._searches(chain),
            "expected_chain_guard": guard,
            "expected_nested_resolution": nested,
            "expected_target_requirements": chain["target_requirements"],
            "expected_target_runtime": chain["target_runtime"],
            "expected_target_staging": chain["target_staging"],
            "expected_target_resolution": chain["first_resolution"],
            "target_lease": chain["target_lease"],
            "expected_source_staging": chain["source_staging"],
            "source_lease": chain["source_lease"],
            "expected_loader_paths": chain["first_paths"],
            "expected_nested_loader_paths": chain["nested_paths"],
            "lease": lease,
        }
        arguments.update(overrides)
        receipt = stage_repository_executable_native_loader_nested_target_bytes(
            chain["registration"],
            **arguments,
        )
        return lease, receipt

    def _assert_invalid(
        self,
        chain: dict[str, object],
        nested: object,
        guard: object,
        stage_root: Path,
        **overrides: object,
    ) -> None:
        lease = RepositoryExecutableNativeLoaderNestedTargetStageLease(stage_root)
        with self.assertRaises(ValidationError) as caught:
            self._stage(
                chain,
                nested,
                guard,
                stage_root,
                lease=lease,
                **overrides,
            )
        self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(lease._files, ())

    def test_guarded_bytes_are_staged_with_private_exact_receipt(self) -> None:
        chain, nested, guard, stage_root = self._prepared()
        lease, receipt = self._stage(chain, nested, guard, stage_root)
        try:
            self.assertEqual(lease.state, "active")
            self.assertIs(lease.receipt, receipt)
            self.assertEqual(receipt.unique_nested_target_count, 2)
            self.assertEqual(receipt.requirement_count, 2)
            self.assertEqual(receipt.lineage_count, 2)
            self.assertEqual(receipt.command_count, 2)
            self.assertEqual(receipt.known_chain_guard_staged_count, 2)
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
            for retained in lease._files:
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
            canonical = receipt.to_canonical()
            evidence = receipt.to_evidence()
            self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
            self.assertEqual(
                receipt.lineages[0].to_canonical(), canonical["lineages"][0]
            )
            self.assertEqual(evidence["effect_class"], 1)
            self.assertTrue(evidence["read_only_descriptor_lease_established"])
            self.assertFalse(evidence["authority_granted"])
            self.assertFalse(evidence["execution_enabled"])
            serialized = json.dumps(
                {"canonical": canonical, "evidence": evidence},
                sort_keys=True,
            )
            for private in (
                str(chain["root"]),
                str(chain["nested_one"]),
                str(stage_root),
                "private-nested-loader-one-bytes",
                "directory_inode",
                "directory_device",
            ):
                self.assertNotIn(private, serialized)
                self.assertNotIn(private, repr(receipt))
            with self.assertRaises(FrozenInstanceError):
                receipt.requirement_count = 0
        finally:
            lease.close()

    def test_shared_nested_target_is_staged_once_for_two_lineages(self) -> None:
        chain, nested, guard, stage_root = self._prepared(
            same_nested_target=True
        )
        lease, receipt = self._stage(chain, nested, guard, stage_root)
        try:
            self.assertEqual(receipt.unique_nested_target_count, 1)
            self.assertEqual(receipt.requirement_count, 2)
            self.assertEqual(receipt.lineage_count, 2)
            self.assertEqual(receipt.command_count, 2)
            self.assertEqual(
                {
                    item.nested_target_staged_file_ref
                    for item in receipt.requirements
                },
                {receipt.staged_files[0].nested_target_staged_file_ref},
            )
        finally:
            lease.close()

    def test_detached_bytes_survive_namespace_change_and_cleanup(self) -> None:
        chain, nested, guard, stage_root = self._prepared(
            same_first_target=True,
            same_nested_target=True,
        )
        original = Path(chain["nested_one"]).read_bytes()
        lease, _receipt = self._stage(chain, nested, guard, stage_root)
        descriptor = lease._files[0].descriptor
        Path(chain["nested_one"]).write_bytes(b"changed-after-stage\n")
        self.assertEqual(os.pread(descriptor, len(original), 0), original)
        first = lease.close()
        second = lease.close()
        self.assertIs(first, second)
        self.assertEqual(first.outcome, "already_absent_verified")
        self.assertTrue(first.owned_namespace_absence_verified)
        self.assertTrue(first.descriptor_release_complete)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_lease_is_same_pid_noncopyable_and_nonserializable(self) -> None:
        chain, _nested, _guard, stage_root = self._prepared()
        lease = RepositoryExecutableNativeLoaderNestedTargetStageLease(stage_root)
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
            cleanup_repository_executable_native_loader_nested_target_stage(
                lease
            )
        self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
        self.assertIsNotNone(chain)

    def test_tampered_guard_and_overlapping_root_fail_before_retention(self) -> None:
        chain, nested, guard, stage_root = self._prepared()
        forged = replace(guard, guard_summary_ref="sha256:" + "0" * 64)
        self._assert_invalid(chain, nested, forged, stage_root)
        overlap = chain["root"] / "private-overlap-stage"
        overlap.mkdir(mode=0o700)
        overlap.chmod(0o700)
        self._assert_invalid(chain, nested, guard, overlap)
        self.assertEqual(list(overlap.iterdir()), [])

    def test_receipt_projection_rejects_lineage_and_binding_forgery(self) -> None:
        chain, nested, guard, stage_root = self._prepared()
        lease, receipt = self._stage(chain, nested, guard, stage_root)
        try:
            with self.assertRaises(ValueError):
                replace(receipt, lineage_count=0).to_canonical()
            first = receipt.bindings[0]
            second = receipt.bindings[1]
            duplicate = replace(
                second,
                staged_file_ref=first.staged_file_ref,
                runtime_file_ref=first.runtime_file_ref,
                requirement_ref=first.requirement_ref,
                target_requirement_ref=first.target_requirement_ref,
                target_stage_requirement_ref=first.target_stage_requirement_ref,
                target_runtime_requirement_ref=(
                    first.target_runtime_requirement_ref
                ),
                target_loader_lineage_ref=first.target_loader_lineage_ref,
                nested_target_lineage_ref=first.nested_target_lineage_ref,
                chain_guard_lineage_ref=first.chain_guard_lineage_ref,
                nested_target_stage_lineage_ref=(
                    first.nested_target_stage_lineage_ref
                ),
            )
            with self.assertRaises(ValueError):
                replace(
                    receipt,
                    bindings=(first, duplicate),
                ).to_canonical()
        finally:
            lease.close()

    def test_guard_replays_twice_and_capture_is_action_only(self) -> None:
        chain, nested, guard, stage_root = self._prepared(
            same_first_target=True,
            same_nested_target=True,
        )
        original = staging_module._BUILTIN_INSPECT_CHAIN_GUARD
        consumers: list[object | None] = []

        def observed(*args: object, **kwargs: object):
            consumers.append(kwargs.get("unique_nested_target_consumer"))
            return original(*args, **kwargs)

        with patch.object(
            staging_module,
            "_BUILTIN_INSPECT_CHAIN_GUARD",
            side_effect=observed,
        ):
            lease, receipt = self._stage(chain, nested, guard, stage_root)
        try:
            self.assertEqual(len(consumers), 2)
            self.assertIsNotNone(consumers[0])
            self.assertIsNone(consumers[1])
            self.assertEqual(
                receipt.action_chain_guard_receipt_digest,
                receipt.post_stage_chain_guard_receipt_digest,
            )
        finally:
            lease.close()

    def test_post_stage_guard_drift_fails_closed_and_cleans(self) -> None:
        chain, nested, guard, stage_root = self._prepared(
            same_first_target=True,
            same_nested_target=True,
        )
        lease = RepositoryExecutableNativeLoaderNestedTargetStageLease(stage_root)
        original = staging_module._BUILTIN_INSPECT_CHAIN_GUARD
        calls = 0

        def drift(*args: object, **kwargs: object):
            nonlocal calls
            calls += 1
            result = original(*args, **kwargs)
            if calls == 1:
                Path(chain["nested_one"]).write_bytes(b"drifted\n")
            return result

        with patch.object(
            staging_module,
            "_BUILTIN_INSPECT_CHAIN_GUARD",
            side_effect=drift,
        ):
            with self.assertRaises(ValidationError) as caught:
                self._stage(
                    chain,
                    nested,
                    guard,
                    stage_root,
                    lease=lease,
                )
        self.assertEqual(str(caught.exception), FIXED_STAGING_ERROR)
        self.assertEqual(lease.state, "cleaned")
        self.assertEqual(lease._files, ())
        self.assertEqual(list(stage_root.iterdir()), [])

    def test_no_target_preserves_command_lineage_without_staging_root(self) -> None:
        chain = self.guard_fixture._chain(self, no_first_targets=True)
        nested = self.guard_fixture._nested(self, chain)
        guard = self.guard_fixture._guard(self, chain, nested)
        absent = chain["root"].parent / "must-remain-absent-stage-root"
        lease = RepositoryExecutableNativeLoaderNestedTargetStageLease(absent)
        receipt = self._stage(
            chain, nested, guard, absent, lease=lease
        )[1]
        try:
            self.assertFalse(receipt.staging_root_used)
            self.assertEqual(receipt.requirement_count, 0)
            self.assertEqual(receipt.lineage_count, 2)
            self.assertEqual(receipt.command_count, 2)
            self.assertEqual(receipt.unique_nested_target_count, 0)
            self.assertEqual(receipt.total_staged_bytes, 0)
            self.assertTrue(
                all(
                    item.disposition != "stage_requirement_bound"
                    for item in receipt.lineages
                )
            )
            self.assertFalse(absent.exists())
        finally:
            lease.close()

    def test_non_target_dispositions_return_active_empty_lease(self) -> None:
        cases = (
            ("elf_absent", "loader_declaration_absent"),
            ("mach_absent", "loader_declaration_absent"),
            ("unsupported", "unsupported_native_layout"),
            ("non_native", "non_native_not_applicable"),
        )
        for content_kind, disposition in cases:
            with self.subTest(content_kind=content_kind):
                chain, nested, guard, stage_root = self._prepared(
                    same_first_target=True,
                    first_content_kind=content_kind,
                )
                stage_root.rmdir()
                lease = RepositoryExecutableNativeLoaderNestedTargetStageLease(
                    stage_root
                )
                receipt = self._stage(
                    chain, nested, guard, stage_root, lease=lease
                )[1]
                try:
                    self.assertFalse(receipt.staging_root_used)
                    self.assertEqual(receipt.unique_nested_target_count, 0)
                    self.assertEqual(receipt.requirements[0].disposition, disposition)
                    self.assertEqual(
                        receipt.lineages[0].disposition,
                        "stage_requirement_bound",
                    )
                    self.assertFalse(stage_root.exists())
                finally:
                    lease.close()

    def test_cleanup_uncertainty_remains_explicit_on_retry(self) -> None:
        chain, nested, guard, stage_root = self._prepared(
            same_first_target=True,
            same_nested_target=True,
        )
        lease, _receipt = self._stage(chain, nested, guard, stage_root)
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
        retry = lease.close()
        self.assertEqual(retry.outcome, "unverifiable")
        self.assertFalse(retry.descriptor_release_complete)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_frozen_proof_graph_and_public_surface_are_exact(self) -> None:
        chain, nested, guard, stage_root = self._prepared(
            same_first_target=True,
            same_nested_target=True,
        )
        with patch.object(
            staging_module,
            "_chain_guard_projection_v1",
            side_effect=AssertionError("public projection"),
        ), patch.object(
            staging_module,
            "_inspect_staged_executable_native_loader_nested_target_chain_guard",
            side_effect=AssertionError("public guard"),
        ):
            lease, receipt = self._stage(chain, nested, guard, stage_root)
        lease.close()
        self.assertEqual(receipt.command_count, 2)
        signature = inspect.signature(
            stage_repository_executable_native_loader_nested_target_bytes
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "registration",
                "search_directories",
                "expected_chain_guard",
                "expected_nested_resolution",
                "expected_target_requirements",
                "expected_target_runtime",
                "expected_target_staging",
                "expected_target_resolution",
                "target_lease",
                "expected_source_staging",
                "source_lease",
                "expected_loader_paths",
                "expected_nested_loader_paths",
                "lease",
            ),
        )
        self.assertEqual(
            staging_module.__all__,
            [
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_STAGED_FILE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_STAGE_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_STAGE_CLEANUP_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_STAGE_LINEAGE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_"
                "STAGE_REQUIREMENT_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_"
                "STAGING_EVIDENCE_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_STAGING_KIND",
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_"
                "STAGING_SCHEMA_VERSION",
                "STAGING_SCOPE",
                "STAGING_SOURCE",
                "RepositoryExecutableNativeLoaderNestedTargetStagedFile",
                "RepositoryExecutableNativeLoaderNestedTargetStageBinding",
                "RepositoryExecutableNativeLoaderNestedTargetStageCleanupReceipt",
                "RepositoryExecutableNativeLoaderNestedTargetStageLease",
                "RepositoryExecutableNativeLoaderNestedTargetStageLineage",
                "RepositoryExecutableNativeLoaderNestedTargetStageRequirement",
                "RepositoryExecutableNativeLoaderNestedTargetStagingReceipt",
                "cleanup_repository_executable_native_loader_nested_target_stage",
                "stage_repository_executable_native_loader_nested_target_bytes",
            ],
        )

    def test_no_process_network_model_or_persistence_effects(self) -> None:
        chain, nested, guard, stage_root = self._prepared(
            same_first_target=True,
            same_nested_target=True,
        )
        before = (
            chain["source_lease"]._files,
            chain["target_lease"]._files,
        )
        with patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("subprocess"),
        ), patch.object(
            socket,
            "socket",
            side_effect=AssertionError("network"),
        ):
            lease, receipt = self._stage(chain, nested, guard, stage_root)
        try:
            self.assertIs(chain["source_lease"]._files, before[0])
            self.assertIs(chain["target_lease"]._files, before[1])
            evidence = receipt.to_evidence()
            self.assertFalse(evidence["model_invocation_performed"])
            self.assertFalse(evidence["durable_control_plane_persistence_enabled"])
        finally:
            lease.close()

    def test_interrupts_are_preserved(self) -> None:
        chain, nested, guard, stage_root = self._prepared()
        for exception in (KeyboardInterrupt(), SystemExit()):
            with self.subTest(exception=type(exception).__name__), patch.object(
                staging_module,
                "_BUILTIN_CHAIN_GUARD_PROJECTION",
                side_effect=exception,
            ):
                with self.assertRaises(type(exception)):
                    self._stage(chain, nested, guard, stage_root)


if __name__ == "__main__":
    unittest.main()
