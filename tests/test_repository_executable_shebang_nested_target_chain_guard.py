from __future__ import annotations

import asyncio
import builtins
from dataclasses import FrozenInstanceError, replace
import inspect
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ordomata.artifact_filesystem as artifact_filesystem_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
import ordomata.repository_executable_shebang_nested_target_chain_guard as guard_module
import ordomata.repository_executable_shebang_nested_target_resolution as nested_module
import ordomata.state as state_module

if __package__:
    from . import (
        test_repository_executable_shebang_nested_target_resolution
        as nested_test_module,
    )
else:
    import test_repository_executable_shebang_nested_target_resolution \
        as nested_test_module


FIXED_GUARD_ERROR = (
    "repository executable shebang nested target chain guard is invalid"
)
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
_MACH_O = b"\xcf\xfa\xed\xfe" + b"\x00" * 28

GUARDED_MEASUREMENT_KEYS = {
    "guarded_measurement_ref",
    "kind",
    "known_source_identity_set_digest",
    "known_target_identity_set_digest",
    "nested_target_measurement_ref",
    "protected_staging_root_identity_set_digest",
}
GUARD_REQUIREMENT_KEYS = {
    "chain_guard_requirement_ref",
    "disposition",
    "guarded_measurement_ref",
    "kind",
    "nested_target_measurement_ref",
    "nested_target_requirement_ref",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
    "target_runtime_requirement_ref",
    "target_shebang_requirement_ref",
    "target_stage_requirement_ref",
}
GUARD_BINDING_KEYS = {
    "chain_guard_requirement_ref",
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "nested_target_requirement_ref",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
    "target_runtime_requirement_ref",
    "target_shebang_requirement_ref",
    "target_stage_requirement_ref",
}
GUARD_RECEIPT_KEYS = {
    "bindings",
    "command_count",
    "guard_scope",
    "guard_summary_ref",
    "guarded_measurement_count",
    "guarded_measurements",
    "inspection_source",
    "kind",
    "known_chain_guard_verified_count",
    "known_source_identity_count",
    "known_source_identity_set_digest",
    "known_target_identity_count",
    "known_target_identity_set_digest",
    "maximum_resolution_depth",
    "nested_target_path_context_digest",
    "nested_target_resolution_receipt_digest",
    "protected_staging_root_identity_count",
    "protected_staging_root_identity_set_digest",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "resolution_context_digest",
    "resolution_depth",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shebang_requirements_receipt_digest",
    "source_native_not_applicable_count",
    "source_staging_context_digest",
    "source_staging_receipt_digest",
    "target_native_not_applicable_count",
    "target_path_context_digest",
    "target_resolution_receipt_digest",
    "target_runtime_manifest_receipt_digest",
    "target_shebang_requirements_receipt_digest",
    "target_staging_context_digest",
    "target_staging_receipt_digest",
    "total_guarded_bytes",
    "verification_commands_digest",
}
GUARD_EVIDENCE_KEYS = {
    "active_source_stage_lease_anchor_verified",
    "active_target_stage_lease_verified",
    "authority_granted",
    "authorization_decision",
    "authorization_verified",
    "broader_protected_root_exclusion_verified",
    "candidate_bytes_exposed",
    "closing_namespace_guard_verified",
    "command_count",
    "current_freshness_verified",
    "dependency_closure_verified",
    "descriptor_numbers_exposed",
    "effect_class",
    "execution_enabled",
    "generic_cycle_exclusion_verified",
    "guard_scope",
    "guarded_measurement_count",
    "harness_invoked",
    "inspection_source",
    "kind",
    "known_chain_identity_reentry_exclusion_verified",
    "known_source_identity_count",
    "known_source_identity_reentry_exclusion_verified",
    "known_source_original_identity_reentry_excluded",
    "known_source_staged_identity_reentry_excluded",
    "known_target_identity_count",
    "known_target_identity_reentry_exclusion_verified",
    "known_target_original_identity_reentry_excluded",
    "known_target_staged_identity_reentry_excluded",
    "maximum_resolution_depth",
    "model_invoked",
    "nested_resolution_reproduced",
    "nested_target_paths_exposed",
    "path_lookup_performed",
    "protected_staging_root_identity_count",
    "protected_staging_root_identity_exclusion_verified",
    "receipt_authenticity_verified",
    "receipt_digest",
    "requirement_count",
    "resolution_depth",
    "schema_version",
    "source_path_reentry_exclusion_verified",
    "source_staging_root_identity_ancestor_excluded",
    "source_staging_root_identity_exclusion_verified",
    "source_staging_root_path_reentry_exclusion_verified",
    "source_staging_root_path_reopen_performed",
    "staging_enabled",
    "subprocess_invoked",
    "target_staging_root_identity_ancestor_excluded",
    "target_staging_root_identity_exclusion_verified",
    "target_staging_root_path_reentry_exclusion_verified",
    "target_staging_root_path_reopen_performed",
    "temporary_names_exposed",
    "total_guarded_bytes",
    "two_pass_guard_measurement_verified",
    "validation_mode",
}


@unittest.skipUnless(os.name == "posix", "nested target guard requires POSIX")
class RepositoryExecutableShebangNestedTargetChainGuardTests(
    unittest.TestCase
):
    fixture = (
        nested_test_module
        .RepositoryExecutableShebangNestedTargetResolutionTests
    )

    @classmethod
    def _workspace(
        cls,
        temporary: str,
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
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
    def _write_target(cls, path: Path, content: bytes) -> None:
        cls.fixture._write_target(path, content)

    @classmethod
    def _stage_target_requirements(
        cls,
        registration: object,
        *,
        search_directories: tuple[Path, ...],
        executable_stage_root: Path,
        target_stage_root: Path,
        target_paths: tuple[Path, ...],
    ) -> tuple[object, ...]:
        return cls.fixture._stage_target_requirements(
            registration,
            search_directories=search_directories,
            executable_stage_root=executable_stage_root,
            target_stage_root=target_stage_root,
            target_paths=target_paths,
        )

    @classmethod
    def _one_nested_chain(
        cls,
        temporary: str,
        **kwargs: object,
    ) -> tuple[object, ...]:
        return cls.fixture._one_nested_chain(temporary, **kwargs)

    @staticmethod
    def _nested(
        target_requirements: object,
        target_runtime: object,
        target_staging: object,
        target_lease: object,
        paths: object,
    ):
        return nested_module.inspect_staged_executable_shebang_nested_targets(
            target_requirements,
            expected_target_runtime=target_runtime,
            expected_target_staging=target_staging,
            lease=target_lease,
            expected_nested_target_paths=paths,
        )

    @staticmethod
    def _guard(
        expected_nested_resolution: object,
        *,
        target_requirements: object,
        target_runtime: object,
        target_staging: object,
        target_lease: object,
        source_staging: object,
        source_lease: object,
        paths: object,
    ):
        return (
            guard_module
            .inspect_staged_executable_shebang_nested_target_chain_guard(
                expected_nested_resolution,
                expected_target_requirements=target_requirements,
                expected_target_runtime=target_runtime,
                expected_target_staging=target_staging,
                target_lease=target_lease,
                expected_source_staging=source_staging,
                source_lease=source_lease,
                expected_nested_target_paths=paths,
            )
        )

    def _assert_invalid(
        self,
        expected_nested_resolution: object,
        *,
        target_requirements: object,
        target_runtime: object,
        target_staging: object,
        target_lease: object,
        source_staging: object,
        source_lease: object,
        paths: object,
        private_marker: str = "private-chain-guard-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            self._guard(
                expected_nested_resolution,
                target_requirements=target_requirements,
                target_runtime=target_runtime,
                target_staging=target_staging,
                target_lease=target_lease,
                source_staging=source_staging,
                source_lease=source_lease,
                paths=paths,
            )
        self.assertEqual(str(caught.exception), FIXED_GUARD_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    @staticmethod
    def _lease_snapshot(lease: object) -> tuple[object, ...]:
        return (
            lease._state,
            lease._owner_pid,
            lease._receipt,
            lease._cleanup_receipt,
            lease._receipt_digest_anchor,
            lease._files,
            lease._root_descriptor,
            lease._root_metadata,
            lease._pending_name,
            lease._pending_identity,
            lease._pending_descriptors,
            lease._descriptor_release_unverifiable,
        )

    @classmethod
    def _custom_chain(
        cls,
        temporary: str,
        *,
        nested_path: Path,
        nested_content: bytes | None,
        source_content: bytes | None = None,
    ) -> tuple[object, ...]:
        (
            root,
            outside,
            search_one,
            search_two,
            executable_stage_root,
            target_stage_root,
        ) = cls._workspace(temporary)
        base = Path(temporary).resolve(strict=True)
        first_target = base / "private-depth-one-chain-guard-target"
        cls._write_target(
            first_target,
            b"#!" + os.fsencode(nested_path) + b"\nprivate-first-body\n",
        )
        source_shebang = b"#!" + os.fsencode(first_target) + b"\n"
        cls._set_contents(
            root,
            search_one,
            bare=source_shebang if source_content is None else source_content,
            relative=source_shebang,
        )
        if nested_content is not None:
            cls._write_target(nested_path, nested_content)
        registration = cls._registration(root)
        chain = cls._stage_target_requirements(
            registration,
            search_directories=(search_one, search_two),
            executable_stage_root=executable_stage_root,
            target_stage_root=target_stage_root,
            target_paths=(first_target,),
        )
        return (
            root,
            outside,
            search_one,
            search_two,
            executable_stage_root,
            target_stage_root,
            first_target,
            nested_path,
            *chain,
        )

    @staticmethod
    def _unpack(values: tuple[object, ...]) -> dict[str, object]:
        (
            root,
            outside,
            search_one,
            search_two,
            executable_stage_root,
            target_stage_root,
            first_target,
            nested_target,
            source_lease,
            source_staging,
            source_runtime,
            source_requirements,
            target_resolution,
            target_lease,
            target_staging,
            target_runtime,
            target_requirements,
        ) = values
        return {
            "root": root,
            "outside": outside,
            "search_one": search_one,
            "search_two": search_two,
            "executable_stage_root": executable_stage_root,
            "target_stage_root": target_stage_root,
            "first_target": first_target,
            "nested_target": nested_target,
            "source_lease": source_lease,
            "source_staging": source_staging,
            "source_runtime": source_runtime,
            "source_requirements": source_requirements,
            "target_resolution": target_resolution,
            "target_lease": target_lease,
            "target_staging": target_staging,
            "target_runtime": target_runtime,
            "target_requirements": target_requirements,
        }

    def _expected_and_guard(self, chain: dict[str, object], paths: tuple[Path, ...]):
        expected = self._nested(
            chain["target_requirements"],
            chain["target_runtime"],
            chain["target_staging"],
            chain["target_lease"],
            paths,
        )
        guarded = self._guard(
            expected,
            target_requirements=chain["target_requirements"],
            target_runtime=chain["target_runtime"],
            target_staging=chain["target_staging"],
            target_lease=chain["target_lease"],
            source_staging=chain["source_staging"],
            source_lease=chain["source_lease"],
            paths=paths,
        )
        return expected, guarded

    @staticmethod
    def _close_chain(chain: dict[str, object]) -> None:
        chain["target_lease"].close()
        chain["source_lease"].close()

    def test_happy_shared_correspondence_privacy_and_immutability(self) -> None:
        marker = b"private-chain-guard-nested-content-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(
                self._one_nested_chain(
                    temporary,
                    nested_target_content=marker,
                    include_source_native=True,
                )
            )
            target_before = self._lease_snapshot(chain["target_lease"])
            source_before = self._lease_snapshot(chain["source_lease"])
            try:
                expected, receipt = self._expected_and_guard(
                    chain,
                    (chain["nested_target"],),
                )
                repeated = self._guard(
                    expected,
                    target_requirements=chain["target_requirements"],
                    target_runtime=chain["target_runtime"],
                    target_staging=chain["target_staging"],
                    target_lease=chain["target_lease"],
                    source_staging=chain["source_staging"],
                    source_lease=chain["source_lease"],
                    paths=(chain["nested_target"],),
                )
                self.assertEqual(receipt, repeated)
                self.assertEqual(
                    receipt.nested_target_resolution_receipt_digest,
                    expected.receipt_digest,
                )
                self.assertEqual(
                    receipt.source_staging_receipt_digest,
                    chain["source_staging"].receipt_digest,
                )
                self.assertEqual(
                    receipt.target_staging_receipt_digest,
                    chain["target_staging"].receipt_digest,
                )
                self.assertEqual(receipt.resolution_depth, 2)
                self.assertEqual(receipt.maximum_resolution_depth, 2)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.known_chain_guard_verified_count, 1)
                self.assertEqual(receipt.source_native_not_applicable_count, 1)
                self.assertEqual(receipt.target_native_not_applicable_count, 0)
                self.assertEqual(receipt.guarded_measurement_count, 1)
                self.assertEqual(receipt.total_guarded_bytes, len(marker))
                self.assertEqual(len(receipt.guarded_measurements), 1)
                self.assertEqual(
                    set(receipt.guarded_measurements[0].to_canonical()),
                    GUARDED_MEASUREMENT_KEYS,
                )
                for value in receipt.requirements:
                    self.assertEqual(
                        set(value.to_canonical()),
                        GUARD_REQUIREMENT_KEYS,
                    )
                for value in receipt.bindings:
                    self.assertEqual(
                        set(value.to_canonical()),
                        GUARD_BINDING_KEYS,
                    )
                self.assertEqual(
                    sorted(
                        value.disposition for value in receipt.requirements
                    ),
                    [
                        "known_chain_guard_verified",
                        "source_native_not_applicable",
                    ],
                )
                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), GUARD_RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                evidence = receipt.to_evidence()
                self.assertEqual(set(evidence), GUARD_EVIDENCE_KEYS)
                self.assertEqual(evidence["effect_class"], 0)
                self.assertEqual(evidence["validation_mode"], "read_only")
                self.assertTrue(evidence["nested_resolution_reproduced"])
                self.assertTrue(
                    evidence["known_source_original_identity_reentry_excluded"]
                )
                self.assertTrue(
                    evidence["source_staging_root_identity_ancestor_excluded"]
                )
                self.assertFalse(
                    evidence["source_staging_root_path_reentry_exclusion_verified"]
                )
                self.assertFalse(
                    evidence["target_staging_root_path_reentry_exclusion_verified"]
                )
                self.assertFalse(evidence["receipt_authenticity_verified"])
                self.assertFalse(evidence["generic_cycle_exclusion_verified"])
                self.assertFalse(
                    evidence["broader_protected_root_exclusion_verified"]
                )
                self.assertFalse(evidence["authority_granted"])
                self.assertFalse(evidence["authorization_verified"])
                self.assertFalse(evidence["execution_enabled"])
                serialized = json.dumps(
                    {"canonical": canonical, "evidence": evidence},
                    sort_keys=True,
                )
                for private in (
                    str(chain["root"]),
                    str(chain["nested_target"]),
                    str(chain["executable_stage_root"]),
                    str(chain["target_stage_root"]),
                    marker.decode("ascii").strip(),
                    "directory_inode",
                    "directory_device",
                ):
                    self.assertNotIn(private, serialized)
                    self.assertNotIn(private, repr(receipt))
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirement_count = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirements[0].disposition = "forged"
                self.assertEqual(
                    self._lease_snapshot(chain["target_lease"]),
                    target_before,
                )
                self.assertEqual(
                    self._lease_snapshot(chain["source_lease"]),
                    source_before,
                )
            finally:
                self._close_chain(chain)

    def test_shared_nested_target_has_one_guarded_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            try:
                _expected, receipt = self._expected_and_guard(
                    chain,
                    (chain["nested_target"],),
                )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.known_chain_guard_verified_count, 2)
                self.assertEqual(receipt.guarded_measurement_count, 1)
                refs = {
                    item.guarded_measurement_ref
                    for item in receipt.requirements
                }
                self.assertEqual(len(refs), 1)
                self.assertEqual(
                    refs,
                    {
                        receipt.guarded_measurements[0]
                        .guarded_measurement_ref
                    },
                )
            finally:
                self._close_chain(chain)

    def test_source_native_zero_nested_and_root_path_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target_stage_root.rmdir()
            self._set_contents(root, search_one, bare=_ELF, relative=_ELF)
            registration = self._registration(root)
            values = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(),
            )
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
            ) = values
            expected = self._nested(
                target_requirements,
                target_runtime,
                target_staging,
                target_lease,
                (),
            )
            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_MEASURE_NESTED_TARGET_PATH",
                    side_effect=AssertionError("candidate path read"),
                ) as measure:
                    receipt = self._guard(
                        expected,
                        target_requirements=target_requirements,
                        target_runtime=target_runtime,
                        target_staging=target_staging,
                        target_lease=target_lease,
                        source_staging=source_staging,
                        source_lease=source_lease,
                        paths=(),
                    )
                measure.assert_not_called()
                self.assertEqual(receipt.known_chain_guard_verified_count, 0)
                self.assertEqual(receipt.guarded_measurement_count, 0)
                self.assertEqual(receipt.total_guarded_bytes, 0)
                self.assertEqual(receipt.guarded_measurements, ())
                self.assertEqual(receipt.source_native_not_applicable_count, 2)
                evidence = receipt.to_evidence()
                self.assertFalse(evidence["path_lookup_performed"])
                self.assertFalse(
                    evidence["target_staging_root_identity_exclusion_verified"]
                )
                self.assertFalse(
                    evidence["target_staging_root_identity_ancestor_excluded"]
                )
                self.assertFalse(
                    evidence["target_staging_root_path_reentry_exclusion_verified"]
                )
                self.assertFalse(evidence["receipt_authenticity_verified"])
                self.assertFalse(target_stage_root.exists())
            finally:
                target_lease.close()
                source_lease.close()

    def test_target_native_zero_nested_path_reads(self) -> None:
        for label, content in (("elf", _ELF), ("mach-o", _MACH_O)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                chain = self._unpack(
                    self._one_nested_chain(
                        temporary,
                        first_target_content=content,
                    )
                )
                expected = self._nested(
                    chain["target_requirements"],
                    chain["target_runtime"],
                    chain["target_staging"],
                    chain["target_lease"],
                    (),
                )
                try:
                    with patch.object(
                        nested_module,
                        "_BUILTIN_MEASURE_NESTED_TARGET_PATH",
                        side_effect=AssertionError("candidate path read"),
                    ) as measure:
                        receipt = self._guard(
                            expected,
                            target_requirements=chain["target_requirements"],
                            target_runtime=chain["target_runtime"],
                            target_staging=chain["target_staging"],
                            target_lease=chain["target_lease"],
                            source_staging=chain["source_staging"],
                            source_lease=chain["source_lease"],
                            paths=(),
                        )
                    measure.assert_not_called()
                    self.assertEqual(
                        receipt.known_chain_guard_verified_count,
                        0,
                    )
                    self.assertEqual(
                        receipt.target_native_not_applicable_count,
                        2,
                    )
                    self.assertFalse(
                        receipt.to_evidence()["path_lookup_performed"]
                    )
                finally:
                    self._close_chain(chain)

    def test_original_source_identity_and_hardlink_alias_fail_before_read(self) -> None:
        for label, use_alias in (("exact", False), ("hardlink", True)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                (
                    root,
                    outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                source_path = search_one / "private-bare-tool-marker"
                alias = Path(temporary).resolve(strict=True) / "source-hardlink-alias"
                nested_path = alias if use_alias else source_path
                first_target = (
                    Path(temporary).resolve(strict=True)
                    / "private-depth-one-source-cycle"
                )
                self._write_target(
                    first_target,
                    b"#!" + os.fsencode(nested_path) + b"\n",
                )
                source_shebang = b"#!" + os.fsencode(first_target) + b"\n"
                self._set_contents(
                    root,
                    search_one,
                    bare=source_shebang,
                    relative=source_shebang,
                )
                if use_alias:
                    os.link(source_path, alias)
                registration = self._registration(root)
                values = self._stage_target_requirements(
                    registration,
                    search_directories=(search_one, search_two),
                    executable_stage_root=executable_stage_root,
                    target_stage_root=target_stage_root,
                    target_paths=(first_target,),
                )
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
                ) = values
                expected = self._nested(
                    target_requirements,
                    target_runtime,
                    target_staging,
                    target_lease,
                    (nested_path,),
                )
                try:
                    with patch.object(
                        nested_module,
                        "_BUILTIN_READ",
                        side_effect=AssertionError("leaf bytes read"),
                    ) as read:
                        self._assert_invalid(
                            expected,
                            target_requirements=target_requirements,
                            target_runtime=target_runtime,
                            target_staging=target_staging,
                            target_lease=target_lease,
                            source_staging=source_staging,
                            source_lease=source_lease,
                            paths=(nested_path,),
                        )
                    read.assert_not_called()
                finally:
                    target_lease.close()
                    source_lease.close()

    def test_source_staging_root_identity_fails_before_leaf_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve(strict=True)
            executable_stage_root = base / "private-staging-root-marker"
            nested_path = executable_stage_root / "late-private-target"
            chain = self._unpack(
                self._custom_chain(
                    temporary,
                    nested_path=nested_path,
                    nested_content=None,
                )
            )
            self._write_target(nested_path, b"private-late-root-target\n")
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (nested_path,),
            )
            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_READ",
                    side_effect=AssertionError("leaf bytes read"),
                ) as read:
                    self._assert_invalid(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(nested_path,),
                    )
                read.assert_not_called()
            finally:
                nested_path.unlink()
                self._close_chain(chain)

    def test_inherited_depth_one_and_target_root_exclusions_block_expected_receipt(
        self,
    ) -> None:
        cases = ("depth-one-exact", "depth-one-hardlink", "target-root")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                (
                    root,
                    _outside,
                    search_one,
                    search_two,
                    executable_stage_root,
                    target_stage_root,
                ) = self._workspace(temporary)
                base = Path(temporary).resolve(strict=True)
                first_target = base / "private-depth-one-inherited-guard"
                hardlink = base / "private-depth-one-inherited-hardlink"
                target_root_leaf = target_stage_root / "late-target-root-leaf"
                if case == "depth-one-exact":
                    selected = first_target
                elif case == "depth-one-hardlink":
                    selected = hardlink
                else:
                    selected = target_root_leaf
                self._write_target(
                    first_target,
                    b"#!" + os.fsencode(selected) + b"\n",
                )
                if case == "depth-one-hardlink":
                    os.link(first_target, hardlink)
                source_shebang = b"#!" + os.fsencode(first_target) + b"\n"
                self._set_contents(
                    root,
                    search_one,
                    bare=source_shebang,
                    relative=source_shebang,
                )
                registration = self._registration(root)
                values = self._stage_target_requirements(
                    registration,
                    search_directories=(search_one, search_two),
                    executable_stage_root=executable_stage_root,
                    target_stage_root=target_stage_root,
                    target_paths=(first_target,),
                )
                (
                    source_lease,
                    _source_staging,
                    _source_runtime,
                    _source_requirements,
                    _target_resolution,
                    target_lease,
                    target_staging,
                    target_runtime,
                    target_requirements,
                ) = values
                if case == "target-root":
                    self._write_target(target_root_leaf, b"late root bytes\n")
                try:
                    with self.assertRaisesRegex(
                        ValidationError,
                        "repository executable shebang nested target resolution is invalid",
                    ):
                        self._nested(
                            target_requirements,
                            target_runtime,
                            target_staging,
                            target_lease,
                            (selected,),
                        )
                finally:
                    if target_root_leaf.exists():
                        target_root_leaf.unlink()
                    target_lease.close()
                    source_lease.close()

    def test_candidate_hardlink_alias_cannot_form_guard_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            base = Path(temporary).resolve(strict=True)
            first_one = base / "guard-alias-first-one"
            first_two = base / "guard-alias-first-two"
            nested_one = base / "guard-alias-nested-one"
            nested_two = base / "guard-alias-nested-two"
            self._write_target(nested_one, b"shared candidate inode\n")
            os.link(nested_one, nested_two)
            self._write_target(
                first_one,
                b"#!" + os.fsencode(nested_one) + b"\n",
            )
            self._write_target(
                first_two,
                b"#!" + os.fsencode(nested_two) + b"\n",
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(first_one) + b"\n",
                relative=b"#!" + os.fsencode(first_two) + b"\n",
            )
            registration = self._registration(root)
            values = self._stage_target_requirements(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(first_one, first_two),
            )
            (
                source_lease,
                _source_staging,
                _source_runtime,
                _source_requirements,
                _target_resolution,
                target_lease,
                target_staging,
                target_runtime,
                target_requirements,
            ) = values
            try:
                with self.assertRaisesRegex(
                    ValidationError,
                    "repository executable shebang nested target resolution is invalid",
                ):
                    self._nested(
                        target_requirements,
                        target_runtime,
                        target_staging,
                        target_lease,
                        (nested_one, nested_two),
                    )
            finally:
                target_lease.close()
                source_lease.close()

    def test_exact_input_types_and_path_set_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            path = chain["nested_target"]
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (path,),
            )
            other = Path(temporary).resolve(strict=True) / "unexpected-guard-path"
            self._write_target(other, b"unexpected bytes\n")
            cases = (
                ("nested-dict", {"kind": "forged"}, (path,)),
                ("wrong-requirements", expected, (path,)),
                ("list-paths", expected, [path]),
                ("string-path", expected, (str(path),)),
                ("missing-path", expected, ()),
                ("extra-path", expected, (path, other)),
                ("duplicate-path", expected, (path, path)),
            )
            try:
                for label, nested_value, paths in cases:
                    with self.subTest(label=label):
                        target_requirements = chain["target_requirements"]
                        if label == "wrong-requirements":
                            target_requirements = expected
                        self._assert_invalid(
                            nested_value,
                            target_requirements=target_requirements,
                            target_runtime=chain["target_runtime"],
                            target_staging=chain["target_staging"],
                            target_lease=chain["target_lease"],
                            source_staging=chain["source_staging"],
                            source_lease=chain["source_lease"],
                            paths=paths,
                        )
            finally:
                self._close_chain(chain)

    def test_receipt_projection_rejects_count_set_and_binding_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            try:
                _expected, receipt = self._expected_and_guard(
                    chain,
                    (chain["nested_target"],),
                )
                forged_digest = "sha256:" + "a" * 64
                forged_binding = replace(
                    receipt.bindings[0],
                    chain_guard_requirement_ref=forged_digest,
                )
                for label, forged in (
                    (
                        "verified-count",
                        replace(
                            receipt,
                            known_chain_guard_verified_count=1,
                        ),
                    ),
                    (
                        "measurement-count",
                        replace(receipt, guarded_measurement_count=0),
                    ),
                    (
                        "known-source-count",
                        replace(
                            receipt,
                            known_source_identity_count=(
                                receipt.known_source_identity_count + 1
                            ),
                        ),
                    ),
                    (
                        "known-target-count",
                        replace(
                            receipt,
                            known_target_identity_count=(
                                receipt.known_target_identity_count + 1
                            ),
                        ),
                    ),
                    (
                        "protected-root-count",
                        replace(
                            receipt,
                            protected_staging_root_identity_count=(
                                1
                                if receipt.protected_staging_root_identity_count
                                == 2
                                else 2
                            ),
                        ),
                    ),
                    (
                        "byte-total",
                        replace(
                            receipt,
                            total_guarded_bytes=(
                                receipt.total_guarded_bytes + 1
                            ),
                        ),
                    ),
                    (
                        "summary-ref",
                        replace(receipt, guard_summary_ref=forged_digest),
                    ),
                    (
                        "set-digest",
                        replace(
                            receipt,
                            known_source_identity_set_digest=forged_digest,
                        ),
                    ),
                    (
                        "binding-lineage",
                        replace(
                            receipt,
                            bindings=(forged_binding, *receipt.bindings[1:]),
                        ),
                    ),
                ):
                    with self.subTest(label=label), self.assertRaises(ValueError):
                        forged.to_canonical()
            finally:
                self._close_chain(chain)

    def test_source_receipt_transplant_and_root_context_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            chain_one = self._unpack(self._one_nested_chain(first))
            chain_two = self._unpack(self._one_nested_chain(second))
            expected = self._nested(
                chain_one["target_requirements"],
                chain_one["target_runtime"],
                chain_one["target_staging"],
                chain_one["target_lease"],
                (chain_one["nested_target"],),
            )
            try:
                self._assert_invalid(
                    expected,
                    target_requirements=chain_one["target_requirements"],
                    target_runtime=chain_one["target_runtime"],
                    target_staging=chain_one["target_staging"],
                    target_lease=chain_one["target_lease"],
                    source_staging=chain_two["source_staging"],
                    source_lease=chain_two["source_lease"],
                    paths=(chain_one["nested_target"],),
                )

                metadata = chain_one["source_lease"]._root_metadata
                self.assertIsNotNone(metadata)
                chain_one["source_lease"]._root_metadata = (
                    metadata[0],
                    metadata[1] + 1,
                    *metadata[2:],
                )
                try:
                    self._assert_invalid(
                        expected,
                        target_requirements=chain_one["target_requirements"],
                        target_runtime=chain_one["target_runtime"],
                        target_staging=chain_one["target_staging"],
                        target_lease=chain_one["target_lease"],
                        source_staging=chain_one["source_staging"],
                        source_lease=chain_one["source_lease"],
                        paths=(chain_one["nested_target"],),
                    )
                finally:
                    chain_one["source_lease"]._root_metadata = metadata
            finally:
                self._close_chain(chain_two)
                self._close_chain(chain_one)

    def test_stale_nested_receipt_and_source_lease_state_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (chain["nested_target"],),
            )
            chain["nested_target"].write_bytes(b"changed after expected receipt\n")
            chain["nested_target"].chmod(0o755)
            try:
                self._assert_invalid(
                    expected,
                    target_requirements=chain["target_requirements"],
                    target_runtime=chain["target_runtime"],
                    target_staging=chain["target_staging"],
                    target_lease=chain["target_lease"],
                    source_staging=chain["source_staging"],
                    source_lease=chain["source_lease"],
                    paths=(chain["nested_target"],),
                )

                chain["source_lease"]._state = "cleaned"
                try:
                    self._assert_invalid(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(chain["nested_target"],),
                    )
                finally:
                    chain["source_lease"]._state = "active"
            finally:
                self._close_chain(chain)

    def test_guarded_pass_content_race_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            path = chain["nested_target"]
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (path,),
            )
            original = path.read_bytes()
            real_measure = nested_module._BUILTIN_MEASURE_GUARDED_TARGET_SET
            calls = 0

            def race(*args: object, **kwargs: object):
                nonlocal calls
                result = real_measure(*args, **kwargs)
                calls += 1
                if calls == 1:
                    path.write_bytes(b"raced private bytes with same length"[: len(original)])
                    path.chmod(0o755)
                return result

            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_MEASURE_GUARDED_TARGET_SET",
                    side_effect=race,
                ):
                    self._assert_invalid(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(path,),
                    )
                self.assertGreaterEqual(calls, 1)
            finally:
                path.write_bytes(original)
                path.chmod(0o755)
                self._close_chain(chain)

    def test_post_output_namespace_swap_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            path = chain["nested_target"]
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (path,),
            )
            original = path.read_bytes()
            displaced = path.with_name(path.name + "-displaced")
            real_projection = guard_module._BUILTIN_RECEIPT_PROJECTION
            swapped = False

            def swap_after_projection(value: object):
                nonlocal swapped
                result = real_projection(value)
                if not swapped:
                    path.rename(displaced)
                    self._write_target(path, b"replacement after output\n")
                    swapped = True
                return result

            try:
                with patch.object(
                    guard_module,
                    "_BUILTIN_RECEIPT_PROJECTION",
                    side_effect=swap_after_projection,
                ):
                    self._assert_invalid(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(path,),
                    )
                self.assertTrue(swapped)
            finally:
                if displaced.exists():
                    if path.exists():
                        path.unlink()
                    displaced.rename(path)
                elif path.exists():
                    path.write_bytes(original)
                    path.chmod(0o755)
                self._close_chain(chain)

    def test_final_closing_nested_projection_namespace_swap_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            path = chain["nested_target"]
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (path,),
            )
            displaced = path.with_name(path.name + "-closing-displaced")
            real_projection = nested_module._BUILTIN_RECEIPT_PROJECTION
            projection_calls = 0
            swapped = False

            def swap_during_closing_projection(value: object):
                nonlocal projection_calls, swapped
                result = real_projection(value)
                projection_calls += 1
                if projection_calls == 2:
                    path.rename(displaced)
                    self._write_target(
                        path,
                        b"replacement during final nested projection\n",
                    )
                    swapped = True
                return result

            try:
                with patch.object(
                    nested_module,
                    "_BUILTIN_RECEIPT_PROJECTION",
                    side_effect=swap_during_closing_projection,
                ):
                    self._assert_invalid(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(path,),
                    )
                self.assertTrue(swapped)
                self.assertEqual(projection_calls, 2)
            finally:
                if displaced.exists():
                    if path.exists():
                        path.unlink()
                    displaced.rename(path)
                self._close_chain(chain)

    def test_exact_two_guarded_reproductions_and_closing_expected_anchor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (chain["nested_target"],),
            )
            calls: list[dict[str, object]] = []
            real_inspect = guard_module._BUILTIN_INSPECT_NESTED_TARGETS

            def observe(*args: object, **kwargs: object):
                calls.append(dict(kwargs))
                return real_inspect(*args, **kwargs)

            try:
                with patch.object(
                    guard_module,
                    "_BUILTIN_INSPECT_NESTED_TARGETS",
                    side_effect=observe,
                ):
                    receipt = self._guard(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(chain["nested_target"],),
                    )
                self.assertEqual(len(calls), 2)
                self.assertIsNotNone(calls[0]["guard_context"])
                self.assertIsNotNone(calls[1]["guard_context"])
                self.assertNotIn("expected_receipt_canonical", calls[0])
                self.assertNotIn("closing_guard_anchor", calls[0])
                self.assertEqual(
                    calls[1]["expected_receipt_canonical"],
                    expected.to_canonical(),
                )
                self.assertTrue(
                    inspect.isfunction(calls[1]["closing_guard_anchor"])
                )
                self.assertTrue(
                    receipt.to_evidence()["closing_namespace_guard_verified"]
                )
            finally:
                self._close_chain(chain)

    def test_source_cleanup_during_final_guarded_reproduction_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (chain["nested_target"],),
            )
            real_inspect = guard_module._BUILTIN_INSPECT_NESTED_TARGETS
            calls = 0

            def close_source_before_final(*args: object, **kwargs: object):
                nonlocal calls
                calls += 1
                if calls == 2:
                    chain["source_lease"].close()
                return real_inspect(*args, **kwargs)

            try:
                with patch.object(
                    guard_module,
                    "_BUILTIN_INSPECT_NESTED_TARGETS",
                    side_effect=close_source_before_final,
                ):
                    self._assert_invalid(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(chain["nested_target"],),
                    )
                self.assertEqual(calls, 2)
                self.assertEqual(chain["source_lease"].state, "cleaned")
                self.assertIsNotNone(chain["source_lease"].cleanup_receipt)
            finally:
                chain["target_lease"].close()
                if chain["source_lease"].state == "active":
                    chain["source_lease"].close()

    def test_final_source_anchor_namespace_swap_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            path = chain["nested_target"]
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (path,),
            )
            displaced = path.with_name(path.name + "-source-anchor-displaced")
            real_snapshot = (
                guard_module._BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT
            )
            snapshot_calls = 0
            swapped = False

            def swap_after_final_source_anchor(
                *args: object,
                **kwargs: object,
            ):
                nonlocal snapshot_calls, swapped
                result = real_snapshot(*args, **kwargs)
                snapshot_calls += 1
                if snapshot_calls == 4:
                    path.rename(displaced)
                    self._write_target(
                        path,
                        b"replacement after final source anchor\n",
                    )
                    swapped = True
                return result

            try:
                with patch.object(
                    guard_module,
                    "_BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT",
                    side_effect=swap_after_final_source_anchor,
                ):
                    self._assert_invalid(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(path,),
                    )
                self.assertTrue(swapped)
                self.assertEqual(snapshot_calls, 4)
            finally:
                if displaced.exists():
                    if path.exists():
                        path.unlink()
                    displaced.rename(path)
                self._close_chain(chain)

    def test_private_staged_identity_domains_reject_before_leaf_read(self) -> None:
        domains = (
            ("source-staged", "repository_executable_staged_file_identity"),
            (
                "target-staged",
                "repository_executable_shebang_target_staged_file_identity",
            ),
        )
        for label, identity_kind in domains:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                chain = self._unpack(self._one_nested_chain(temporary))
                path = chain["nested_target"]
                metadata = path.stat(follow_symlinks=False)
                identity_ref = nested_module._identity_ref_in_domain(
                    metadata,
                    kind=identity_kind,
                )
                context = nested_module._NestedTargetGuardContext(
                    protected_root_identities=frozenset(),
                    known_source_identity_refs=(
                        frozenset({identity_ref})
                        if label == "source-staged"
                        else frozenset()
                    ),
                    known_target_identity_refs=(
                        frozenset({identity_ref})
                        if label == "target-staged"
                        else frozenset()
                    ),
                )
                try:
                    with patch.object(
                        nested_module,
                        "_BUILTIN_READ",
                        side_effect=AssertionError("leaf bytes read"),
                    ) as read:
                        with self.assertRaisesRegex(
                            ValidationError,
                            "repository executable shebang nested target resolution is invalid",
                        ):
                            nested_module._inspect_staged_executable_shebang_nested_targets(
                                chain["target_requirements"],
                                expected_target_runtime=chain["target_runtime"],
                                expected_target_staging=chain["target_staging"],
                                lease=chain["target_lease"],
                                expected_nested_target_paths=(path,),
                                guard_context=context,
                            )
                    read.assert_not_called()
                finally:
                    self._close_chain(chain)

    def test_frozen_proof_graph_ignores_public_monkeypatches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (chain["nested_target"],),
            )
            requirement_type = (
                guard_module
                .RepositoryExecutableShebangNestedTargetChainGuardRequirement
            )
            try:
                with (
                    patch.object(
                        guard_module,
                        "INSPECTION_SOURCE",
                        "forged-inspection-source",
                    ),
                    patch.object(
                        guard_module,
                        "GUARD_SCOPE",
                        "forged-guard-scope",
                    ),
                    patch.object(
                        guard_module,
                        "canonical_json",
                        side_effect=AssertionError("live canonical json"),
                    ) as live_json,
                    patch.object(
                        guard_module,
                        "_active_source_stage_snapshot",
                        side_effect=AssertionError("live source snapshot"),
                    ) as live_source,
                    patch.object(
                        guard_module,
                        "_receipt_projection",
                        side_effect=AssertionError("live receipt projection"),
                    ) as live_projection,
                    patch.object(
                        guard_module,
                        "RepositoryExecutableShebangNestedTargetChainGuardedMeasurement",
                        object,
                    ),
                    patch.object(
                        guard_module,
                        "RepositoryExecutableShebangNestedTargetChainGuardRequirement",
                        object,
                    ),
                    patch.object(
                        guard_module,
                        "RepositoryExecutableShebangNestedTargetChainGuardBinding",
                        object,
                    ),
                    patch.object(
                        guard_module,
                        "RepositoryExecutableShebangNestedTargetChainGuardReceipt",
                        object,
                    ),
                    patch.object(
                        nested_module,
                        "_identity_ref_in_domain",
                        side_effect=AssertionError("live identity helper"),
                    ) as live_identity,
                    patch.object(
                        requirement_type,
                        "__eq__",
                        side_effect=AssertionError("dataclass equality"),
                    ) as equality,
                ):
                    receipt = self._guard(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(chain["nested_target"],),
                    )
                self.assertEqual(receipt.inspection_source, "controller_inspected")
                self.assertEqual(
                    receipt.guard_scope,
                    "known_source_chain_identity_and_staging_root_identity_v1",
                )
                live_json.assert_not_called()
                live_source.assert_not_called()
                live_projection.assert_not_called()
                live_identity.assert_not_called()
                equality.assert_not_called()
            finally:
                self._close_chain(chain)

    def test_no_state_write_process_artifact_or_cleanup_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._unpack(self._one_nested_chain(temporary))
            expected = self._nested(
                chain["target_requirements"],
                chain["target_runtime"],
                chain["target_staging"],
                chain["target_lease"],
                (chain["nested_target"],),
            )
            source_before = self._lease_snapshot(chain["source_lease"])
            target_before = self._lease_snapshot(chain["target_lease"])
            try:
                with (
                    patch.object(
                        builtins,
                        "open",
                        side_effect=AssertionError("builtin write surface"),
                    ) as builtin_open,
                    patch.object(os, "write", side_effect=AssertionError("write")) as write,
                    patch.object(os, "chmod", side_effect=AssertionError("chmod")) as chmod,
                    patch.object(os, "link", side_effect=AssertionError("link")) as link,
                    patch.object(os, "unlink", side_effect=AssertionError("unlink")) as unlink,
                    patch.object(os, "rename", side_effect=AssertionError("rename")) as rename,
                    patch.object(os, "mkdir", side_effect=AssertionError("mkdir")) as mkdir,
                    patch.object(os, "system", side_effect=AssertionError("shell")) as system,
                    patch.object(subprocess, "run", side_effect=AssertionError("process")) as run,
                    patch.object(subprocess, "Popen", side_effect=AssertionError("process")) as popen,
                    patch.object(
                        asyncio,
                        "create_subprocess_exec",
                        side_effect=AssertionError("process"),
                    ) as create_exec,
                    patch.object(
                        artifact_filesystem_module,
                        "stage_artifact",
                        side_effect=AssertionError("artifact"),
                    ) as stage_artifact,
                    patch.object(
                        state_module.SQLiteStateStore,
                        "__init__",
                        side_effect=AssertionError("state"),
                    ) as state,
                ):
                    receipt = self._guard(
                        expected,
                        target_requirements=chain["target_requirements"],
                        target_runtime=chain["target_runtime"],
                        target_staging=chain["target_staging"],
                        target_lease=chain["target_lease"],
                        source_staging=chain["source_staging"],
                        source_lease=chain["source_lease"],
                        paths=(chain["nested_target"],),
                    )
                self.assertEqual(receipt.known_chain_guard_verified_count, 2)
                for observed in (
                    builtin_open,
                    write,
                    chmod,
                    link,
                    unlink,
                    rename,
                    mkdir,
                    system,
                    run,
                    popen,
                    create_exec,
                    stage_artifact,
                    state,
                ):
                    observed.assert_not_called()
                self.assertEqual(
                    self._lease_snapshot(chain["source_lease"]),
                    source_before,
                )
                self.assertEqual(
                    self._lease_snapshot(chain["target_lease"]),
                    target_before,
                )
            finally:
                self._close_chain(chain)

    def test_exports_signature_and_fixed_public_surface_are_exact(self) -> None:
        self.assertEqual(
            set(guard_module.__all__),
            {
                "GUARD_SCOPE",
                "INSPECTION_SOURCE",
                "MAXIMUM_RESOLUTION_DEPTH",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARDED_MEASUREMENT_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_EVIDENCE_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_REQUIREMENT_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION",
                "RESOLUTION_DEPTH",
                "RepositoryExecutableShebangNestedTargetChainGuardBinding",
                "RepositoryExecutableShebangNestedTargetChainGuardReceipt",
                "RepositoryExecutableShebangNestedTargetChainGuardRequirement",
                "RepositoryExecutableShebangNestedTargetChainGuardedMeasurement",
                "inspect_staged_executable_shebang_nested_target_chain_guard",
            },
        )
        signature = inspect.signature(
            guard_module
            .inspect_staged_executable_shebang_nested_target_chain_guard
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_nested_resolution",
                "expected_target_requirements",
                "expected_target_runtime",
                "expected_target_staging",
                "target_lease",
                "expected_source_staging",
                "source_lease",
                "expected_nested_target_paths",
            ),
        )
        self.assertEqual(
            signature.parameters["expected_nested_resolution"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(signature.parameters)[1:]:
            self.assertEqual(
                signature.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        self.assertEqual(guard_module.INSPECTION_SOURCE, "controller_inspected")
        self.assertEqual(
            guard_module.GUARD_SCOPE,
            "known_source_chain_identity_and_staging_root_identity_v1",
        )
        self.assertEqual(guard_module.RESOLUTION_DEPTH, 2)
        self.assertEqual(guard_module.MAXIMUM_RESOLUTION_DEPTH, 2)
        self.assertNotIn("registration", signature.parameters)
        self.assertNotIn("authority", signature.parameters)
        self.assertNotIn("depth", signature.parameters)
