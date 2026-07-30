from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, replace
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch

import ordomata.artifact_filesystem as artifact_filesystem_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
import ordomata.repository_executable_shebang_target_runtime_manifest as runtime_module
from ordomata.repository_executable_shebang_target_runtime_manifest import (
    MANIFEST_SCOPE,
    MANIFEST_SOURCE,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_BINDING_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_FILE_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_KIND,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION,
    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_REQUIREMENT_KIND,
    RepositoryExecutableShebangTargetRuntimeBinding,
    RepositoryExecutableShebangTargetRuntimeFile,
    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
    RepositoryExecutableShebangTargetRuntimeRequirement,
    inspect_staged_executable_shebang_target_runtime_manifest,
)
import ordomata.repository_executable_shebang_target_staging as target_staging_module
from ordomata.repository_executable_shebang_target_staging import (
    RepositoryExecutableShebangTargetStageLease,
    RepositoryExecutableShebangTargetStagingReceipt,
)
import ordomata.state as state_module

if __package__:
    from . import (
        test_repository_executable_shebang_target_staging
        as target_staging_test_module,
    )
else:
    import test_repository_executable_shebang_target_staging as target_staging_test_module


FIXED_RUNTIME_ERROR = (
    "repository executable shebang target runtime manifest is invalid"
)
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"

RUNTIME_FILE_KEYS = {
    "classification",
    "content_bytes",
    "content_digest",
    "header_bytes",
    "header_digest",
    "kind",
    "shebang_directive_ref",
    "staged_filesystem_identity_ref",
    "target_runtime_file_ref",
    "target_staged_file_ref",
}
RUNTIME_BINDING_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "kind",
    "requirement_ref",
    "runtime_file_ref",
    "staged_file_ref",
    "target_requirement_ref",
    "target_runtime_requirement_ref",
    "target_stage_requirement_ref",
}
RUNTIME_RECEIPT_KEYS = {
    "bindings",
    "command_count",
    "direct_target_requirement_count",
    "file_count",
    "files",
    "kind",
    "manifest_scope",
    "manifest_source",
    "native_not_applicable_count",
    "registration_digest",
    "repository_ref",
    "requirement_count",
    "requirements",
    "resolution_context_digest",
    "runtime_manifest_receipt_digest",
    "schema_version",
    "shebang_requirements_receipt_digest",
    "source_staging_context_digest",
    "staging_receipt_digest",
    "target_path_context_digest",
    "target_resolution_receipt_digest",
    "target_staging_context_digest",
    "target_staging_receipt_digest",
    "total_content_bytes",
    "total_header_bytes",
    "verification_commands_digest",
}


@unittest.skipUnless(os.name == "posix", "target runtime manifests require POSIX")
class RepositoryExecutableShebangTargetRuntimeManifestTests(unittest.TestCase):
    fixture = (
        target_staging_test_module
        .RepositoryExecutableShebangTargetStagingTests
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
    def _tree_snapshot(cls, path: Path) -> tuple[object, ...]:
        return cls.fixture._tree_snapshot(path)

    @classmethod
    def _stage_chain(
        cls,
        registration: object,
        *,
        search_directories: tuple[Path, ...],
        executable_stage_root: Path,
        target_stage_root: Path,
        target_paths: tuple[Path, ...],
    ) -> tuple[object, object, object, object, object, object, object]:
        (
            executable_lease,
            staging,
            executable_runtime,
            requirements,
            target_resolution,
        ) = cls.fixture._resolution_chain(
            registration,
            search_directories,
            executable_stage_root,
            target_paths,
        )
        target_lease = RepositoryExecutableShebangTargetStageLease(
            target_stage_root
        )
        target_staging = cls.fixture._stage(
            registration,
            search_directories=search_directories,
            target_resolution=target_resolution,
            requirements=requirements,
            runtime=executable_runtime,
            staging=staging,
            executable_lease=executable_lease,
            target_paths=target_paths,
            target_lease=target_lease,
        )
        return (
            executable_lease,
            staging,
            executable_runtime,
            requirements,
            target_resolution,
            target_lease,
            target_staging,
        )

    @classmethod
    def _one_direct_stage(
        cls,
        temporary: str,
        *,
        target_content: bytes = b"#!/bin/sh\n",
    ) -> tuple[object, RepositoryExecutableShebangTargetStageLease, object]:
        (
            root,
            _outside,
            search_one,
            search_two,
            executable_stage_root,
            target_stage_root,
        ) = cls._workspace(temporary)
        target = Path(temporary).resolve(strict=True) / "compact-runtime-target"
        cls._write_target(target, target_content)
        shebang = b"#!" + os.fsencode(target) + b"\n"
        cls._set_contents(root, search_one, bare=shebang, relative=shebang)
        registration = cls._registration(root)
        (
            executable_lease,
            _staging,
            _executable_runtime,
            _requirements,
            _target_resolution,
            target_lease,
            target_staging,
        ) = cls._stage_chain(
            registration,
            search_directories=(search_one, search_two),
            executable_stage_root=executable_stage_root,
            target_stage_root=target_stage_root,
            target_paths=(target,),
        )
        return executable_lease, target_lease, target_staging

    @staticmethod
    def _descriptor_facts(descriptor: int) -> tuple[object, ...]:
        metadata = os.fstat(descriptor)
        return (
            descriptor,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            os.get_inheritable(descriptor),
            fcntl.fcntl(descriptor, fcntl.F_GETFL),
            os.lseek(descriptor, 0, os.SEEK_CUR),
        )

    @classmethod
    def _lease_snapshot(
        cls,
        lease: RepositoryExecutableShebangTargetStageLease,
    ) -> tuple[object, ...]:
        return (
            lease.state,
            lease.receipt,
            lease.cleanup_receipt,
            lease._receipt_digest_anchor,
            id(lease._receipt_object_anchor),
            lease._receipt_file_refs_anchor,
            id(lease._files_object_anchor),
            lease._cleanup_receipt_digest_anchor,
            id(lease._cleanup_receipt_object_anchor),
            lease._owner_pid,
            id(lease._files),
            tuple(
                (
                    id(value),
                    value.staged_file,
                    value.metadata,
                    cls._descriptor_facts(value.descriptor),
                )
                for value in lease._files
            ),
            lease._root_descriptor,
            lease._root_metadata,
            lease._pending_name,
            lease._pending_identity,
            lease._pending_descriptors,
            lease._descriptor_release_unverifiable,
        )

    def _assert_invalid(
        self,
        expected_target_staging: object,
        lease: object,
        *,
        private_marker: str = "private-target-runtime-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_shebang_target_runtime_manifest(
                expected_target_staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_RUNTIME_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_receipt_correspondence_privacy_and_lease_immutability(self) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        target_content = (
            b"#!/usr/bin/env python3\nprivate-target-header-marker\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = (
                Path(temporary).resolve(strict=True)
                / "private-target-runtime-source-marker"
            )
            self._write_target(target, target_content)
            self._set_contents(
                root,
                search_one,
                bare=elf,
                relative=b"#!" + os.fsencode(target) + b" -I\nbody\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                executable_runtime,
                requirements,
                target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            before = self._lease_snapshot(target_lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
            )
            try:
                receipt = (
                    inspect_staged_executable_shebang_target_runtime_manifest(
                        target_staging,
                        lease=target_lease,
                    )
                )
                repeated = (
                    inspect_staged_executable_shebang_target_runtime_manifest(
                        target_staging,
                        lease=target_lease,
                    )
                )
                self.assertEqual(receipt, repeated)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangTargetRuntimeManifestReceipt,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION,
                    1,
                )
                self.assertEqual(
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_KIND,
                    "repository_executable_shebang_target_runtime_manifest",
                )
                self.assertEqual(MANIFEST_SOURCE, "controller_inspected")
                self.assertEqual(
                    MANIFEST_SCOPE,
                    "posix_staged_shebang_target_runtime_header_v1",
                )
                canonical = receipt.to_canonical()
                self.assertEqual(set(canonical), RUNTIME_RECEIPT_KEYS)
                self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
                self.assertEqual(
                    receipt.target_staging_receipt_digest,
                    target_staging.receipt_digest,
                )
                self.assertEqual(
                    receipt.target_resolution_receipt_digest,
                    target_resolution.receipt_digest,
                )
                for field, upstream in (
                    ("shebang_requirements_receipt_digest", requirements),
                    ("runtime_manifest_receipt_digest", executable_runtime),
                    ("staging_receipt_digest", staging),
                ):
                    self.assertEqual(getattr(receipt, field), upstream.receipt_digest)
                for field in (
                    "registration_digest",
                    "repository_ref",
                    "verification_commands_digest",
                    "resolution_context_digest",
                    "target_path_context_digest",
                    "target_staging_context_digest",
                ):
                    self.assertEqual(
                        getattr(receipt, field),
                        getattr(target_staging, field),
                    )
                self.assertEqual(
                    receipt.source_staging_context_digest,
                    target_staging.source_staging_context_digest,
                )
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.direct_target_requirement_count, 1)
                self.assertEqual(receipt.native_not_applicable_count, 1)
                self.assertEqual(receipt.total_content_bytes, len(target_content))
                self.assertEqual(receipt.total_header_bytes, len(target_content))

                runtime_file = receipt.files[0]
                staged_target = target_staging.staged_files[0]
                self.assertIsInstance(
                    runtime_file,
                    RepositoryExecutableShebangTargetRuntimeFile,
                )
                self.assertEqual(
                    runtime_file.kind,
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_FILE_KIND,
                )
                self.assertEqual(set(runtime_file.to_canonical()), RUNTIME_FILE_KEYS)
                self.assertEqual(runtime_file.classification, "posix_shebang")
                self.assertIsNotNone(runtime_file.shebang_directive_ref)
                self.assertEqual(
                    runtime_file.target_staged_file_ref,
                    staged_target.target_staged_file_ref,
                )
                self.assertEqual(
                    runtime_file.staged_filesystem_identity_ref,
                    staged_target.staged_filesystem_identity_ref,
                )
                self.assertEqual(
                    runtime_file.content_digest,
                    staged_target.content_digest,
                )
                self.assertEqual(
                    runtime_file.header_digest,
                    "sha256:"
                    + hashlib.sha256(
                        staged_target.target_staged_file_ref.encode("ascii")
                        + b"\x00"
                        + target_content
                    ).hexdigest(),
                )

                runtime_file_by_stage_ref = {
                    value.target_staged_file_ref: value
                    for value in receipt.files
                }
                runtime_requirement_by_ref = {
                    value.target_runtime_requirement_ref: value
                    for value in receipt.requirements
                }
                for value, upstream in zip(
                    receipt.requirements,
                    target_staging.requirements,
                    strict=True,
                ):
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangTargetRuntimeRequirement,
                    )
                    self.assertEqual(
                        value.kind,
                        REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_REQUIREMENT_KIND,
                    )
                    for field in (
                        "staged_file_ref",
                        "runtime_file_ref",
                        "requirement_ref",
                        "target_requirement_ref",
                        "target_stage_requirement_ref",
                        "runtime_classification",
                        "target_measurement_ref",
                        "target_staged_file_ref",
                    ):
                        self.assertEqual(
                            getattr(value, field),
                            getattr(upstream, field),
                        )
                    if upstream.disposition == "native_not_applicable":
                        self.assertEqual(value.disposition, "native_not_applicable")
                        self.assertIsNone(value.target_runtime_file_ref)
                    else:
                        self.assertEqual(
                            value.disposition,
                            "direct_absolute_target_runtime_inspected",
                        )
                        self.assertEqual(
                            value.target_runtime_file_ref,
                            runtime_file_by_stage_ref[
                                upstream.target_staged_file_ref
                            ].target_runtime_file_ref,
                        )
                    self.assertRegex(
                        value.target_runtime_requirement_ref,
                        _DIGEST_PATTERN,
                    )

                for value, upstream in zip(
                    receipt.bindings,
                    target_staging.bindings,
                    strict=True,
                ):
                    self.assertIsInstance(
                        value,
                        RepositoryExecutableShebangTargetRuntimeBinding,
                    )
                    self.assertEqual(
                        value.kind,
                        REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_BINDING_KIND,
                    )
                    self.assertEqual(set(value.to_canonical()), RUNTIME_BINDING_KEYS)
                    for field in (
                        "command_kind",
                        "command_id",
                        "command_digest",
                        "staged_file_ref",
                        "runtime_file_ref",
                        "requirement_ref",
                        "target_requirement_ref",
                        "target_stage_requirement_ref",
                    ):
                        self.assertEqual(
                            getattr(value, field),
                            getattr(upstream, field),
                        )
                    self.assertIn(
                        value.target_runtime_requirement_ref,
                        runtime_requirement_by_ref,
                    )

                evidence = receipt.to_evidence()
                self.assertEqual(
                    evidence["kind"],
                    REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND,
                )
                self.assertEqual(evidence["effect_class"], 0)
                self.assertEqual(evidence["validation_mode"], "read_only")
                self.assertEqual(evidence["file_count"], 1)
                self.assertEqual(evidence["posix_shebang_file_count"], 1)
                for fact in (
                    "active_target_stage_lease_verified_at_measurement",
                    "bounded_header_measurement_complete",
                    "bounded_shebang_syntax_classification_complete",
                    "staged_byte_correspondence_verified",
                    "staged_descriptor_full_remeasurement_complete",
                ):
                    self.assertIs(evidence[fact], True, fact)
                for fact in (
                    "authority_granted",
                    "authorization_verified",
                    "dispatch_enabled",
                    "execution_enabled",
                    "interpreter_identity_verified",
                    "route_eligible",
                    "toolchain_completeness_verified",
                ):
                    self.assertIs(evidence[fact], False, fact)

                aggregate = "\n".join(
                    (
                        json.dumps(evidence, sort_keys=True),
                        repr(receipt),
                        repr(target_lease),
                        *(repr(value) for value in receipt.files),
                        *(repr(value) for value in receipt.requirements),
                        *(repr(value) for value in receipt.bindings),
                    )
                )
                for private_value in (
                    str(root),
                    str(search_one),
                    str(target_stage_root),
                    str(target),
                    "private-target-header-marker",
                    "/usr/bin/env python3",
                    runtime_file.content_digest,
                ):
                    self.assertNotIn(private_value, aggregate)
                with self.assertRaises(FrozenInstanceError):
                    receipt.file_count = 0
                with self.assertRaises(FrozenInstanceError):
                    receipt.files[0].classification = "unknown"
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirements[0].disposition = "native_not_applicable"
                with self.assertRaises(FrozenInstanceError):
                    receipt.bindings[0].command_kind = "test"
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
                target_lease.close()
                executable_lease.close()

    def test_fixed_binary_classification_and_minimum_headers(self) -> None:
        target_staged_file_ref = "sha256:" + "a" * 64
        cases = [
            ("elf-32-le", b"\x7fELF\x01\x01\x01" + b"\x00" * 9, "elf"),
            ("elf-64-be", b"\x7fELF\x02\x02\x01" + b"\x00" * 9, "elf"),
            ("elf-bad-class", b"\x7fELF\x03\x01\x01" + b"\x00" * 9, "unknown"),
            ("elf-bad-data", b"\x7fELF\x02\x03\x01" + b"\x00" * 9, "unknown"),
            ("elf-bad-version", b"\x7fELF\x02\x01\x02" + b"\x00" * 9, "unknown"),
            ("elf-short", b"\x7fELF\x02\x01\x01" + b"\x00" * 8, "unknown"),
        ]
        mach_o_minimums = (
            (b"\xfe\xed\xfa\xce", 28),
            (b"\xce\xfa\xed\xfe", 28),
            (b"\xfe\xed\xfa\xcf", 32),
            (b"\xcf\xfa\xed\xfe", 32),
            (b"\xca\xfe\xba\xbe", 28),
            (b"\xbe\xba\xfe\xca", 28),
            (b"\xca\xfe\xba\xbf", 40),
            (b"\xbf\xba\xfe\xca", 40),
        )
        for index, (magic, minimum) in enumerate(mach_o_minimums):
            cases.append(
                (f"mach-o-{index}-minimum", magic + b"\x00" * (minimum - 4), "mach_o")
            )
            cases.append(
                (f"mach-o-{index}-short", magic + b"\x00" * (minimum - 5), "unknown")
            )
        cases.extend(
            (
                ("ordinary", b"ordinary target bytes\n", "unknown"),
                ("empty", b"", "unknown"),
            )
        )
        for case, header, expected in cases:
            with self.subTest(case=case):
                classification, directive_ref = runtime_module._classify_header(
                    target_staged_file_ref,
                    header,
                )
                self.assertEqual(classification, expected)
                self.assertIsNone(directive_ref)

    def test_shebang_grammar_and_header_boundaries(self) -> None:
        target_staged_file_ref = "sha256:" + "b" * 64
        cases = (
            ("valid", b"#!/usr/bin/python3\n", "posix_shebang"),
            ("valid-env", b"#!/usr/bin/env python3\n", "posix_shebang"),
            ("valid-interior-tab", b"#!/usr/bin/env\tpython3\n", "posix_shebang"),
            ("valid-max", b"#!" + b"a" * 255 + b"\n", "posix_shebang"),
            ("empty", b"#!\n", "unsupported_shebang"),
            ("leading-space", b"#! /usr/bin/python3\n", "unsupported_shebang"),
            ("leading-tab", b"#!\t/usr/bin/python3\n", "unsupported_shebang"),
            ("trailing-space", b"#!/usr/bin/python3 \n", "unsupported_shebang"),
            ("trailing-tab", b"#!/usr/bin/python3\t\n", "unsupported_shebang"),
            ("all-whitespace", b"#! \t \n", "unsupported_shebang"),
            ("nul", b"#!/usr/bin/py\x00thon\n", "unsupported_shebang"),
            ("control", b"#!/usr/bin/py\x1fthon\n", "unsupported_shebang"),
            ("del", b"#!/usr/bin/py\x7fthon\n", "unsupported_shebang"),
            ("non-ascii", b"#!/usr/bin/py\xc3\xa9\n", "unsupported_shebang"),
            ("crlf", b"#!/usr/bin/python3\r\n", "unsupported_shebang"),
            ("overlong", b"#!" + b"a" * 256 + b"\n", "unsupported_shebang"),
            ("no-newline", b"#!/usr/bin/python3", "unsupported_shebang"),
            (
                "newline-past-header",
                (b"#!" + b"a" * 4_095 + b"\n")[:4_096],
                "unsupported_shebang",
            ),
        )
        for case, header, expected in cases:
            with self.subTest(case=case):
                classification, directive_ref = runtime_module._classify_header(
                    target_staged_file_ref,
                    header,
                )
                self.assertEqual(classification, expected)
                self.assertEqual(
                    directive_ref is not None,
                    expected == "posix_shebang",
                )
                if directive_ref is not None:
                    self.assertRegex(directive_ref, _DIGEST_PATTERN)

    def test_read_exact_header_is_bounded_and_position_independent(self) -> None:
        with tempfile.TemporaryFile() as stream:
            for size in (0, 1, 4_095, 4_096, 4_097):
                with self.subTest(size=size):
                    stream.seek(0)
                    stream.truncate()
                    stream.write(b"x" * size)
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.seek(min(size, 1))
                    offset_before = stream.tell()
                    with patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        wraps=runtime_module._BUILTIN_PREAD,
                    ) as pread:
                        header = runtime_module._read_exact_header(
                            stream.fileno(),
                            size,
                        )
                    self.assertEqual(header, b"x" * min(size, 4_096))
                    self.assertEqual(stream.tell(), offset_before)
                    self.assertIn(
                        call(stream.fileno(), 1, min(size, 4_096)),
                        pread.call_args_list,
                    )
                    self.assertLessEqual(
                        max(item.args[1] for item in pread.call_args_list),
                        4_096,
                    )

        for size in (4_096, 4_097):
            with self.subTest(wrong_boundary=size):
                with tempfile.TemporaryFile() as stream:
                    stream.write(b"x" * size)
                    stream.flush()
                    os.fsync(stream.fileno())
                    real_pread = runtime_module._BUILTIN_PREAD

                    def wrong_boundary(
                        descriptor: int,
                        count: int,
                        offset: int,
                    ) -> bytes:
                        if count == 1 and offset == min(size, 4_096):
                            return b"x" if size == 4_096 else b""
                        return real_pread(descriptor, count, offset)

                    with patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        side_effect=wrong_boundary,
                    ):
                        with self.assertRaises(ValueError):
                            runtime_module._read_exact_header(
                                stream.fileno(),
                                size,
                            )

    def test_shared_target_is_manifested_once_and_bound_deterministically(self) -> None:
        target_content = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "shared-runtime-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            try:
                receipt = (
                    inspect_staged_executable_shebang_target_runtime_manifest(
                        target_staging,
                        lease=target_lease,
                    )
                )
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(receipt.files[0].classification, "elf")
                self.assertEqual(
                    {
                        value.target_runtime_file_ref
                        for value in receipt.requirements
                    },
                    {receipt.files[0].target_runtime_file_ref},
                )
                self.assertEqual(
                    tuple(value.command_id for value in receipt.bindings),
                    tuple(value.command_id for value in target_staging.bindings),
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_two_targets_preserve_first_use_file_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target_one = Path(temporary).resolve(strict=True) / "runtime-target-one"
            target_two = Path(temporary).resolve(strict=True) / "runtime-target-two"
            self._write_target(target_one, b"#!/bin/one\n")
            self._write_target(
                target_two,
                b"\xfe\xed\xfa\xce" + b"\x00" * 24,
            )
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target_one) + b"\n",
                relative=b"#!" + os.fsencode(target_two) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target_one, target_two),
            )
            try:
                receipt = (
                    inspect_staged_executable_shebang_target_runtime_manifest(
                        target_staging,
                        lease=target_lease,
                    )
                )
                self.assertEqual(
                    tuple(value.target_staged_file_ref for value in receipt.files),
                    tuple(
                        value.target_staged_file_ref
                        for value in target_staging.staged_files
                    ),
                )
                self.assertEqual(
                    tuple(value.classification for value in receipt.files),
                    ("posix_shebang", "mach_o"),
                )
                direct_runtime_refs = tuple(
                    value.target_runtime_file_ref
                    for value in receipt.requirements
                    if value.target_runtime_file_ref is not None
                )
                self.assertEqual(
                    direct_runtime_refs,
                    tuple(value.target_runtime_file_ref for value in receipt.files),
                )
            finally:
                target_lease.close()
                executable_lease.close()

    def test_native_only_empty_lease_succeeds_without_read_or_root_touch(self) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 25
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
            self._set_contents(root, search_one, bare=elf, relative=elf)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(),
            )
            before = self._lease_snapshot(target_lease)
            try:
                with (
                    patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("descriptor read"),
                    ) as pread,
                    patch.object(
                        runtime_module.os,
                        "open",
                        side_effect=AssertionError("root/path open"),
                    ) as open_path,
                ):
                    receipt = (
                        inspect_staged_executable_shebang_target_runtime_manifest(
                            target_staging,
                            lease=target_lease,
                        )
                    )
                pread.assert_not_called()
                open_path.assert_not_called()
                self.assertEqual(self._lease_snapshot(target_lease), before)
                self.assertEqual(receipt.files, ())
                self.assertEqual(receipt.file_count, 0)
                self.assertEqual(receipt.total_content_bytes, 0)
                self.assertEqual(receipt.total_header_bytes, 0)
                self.assertEqual(receipt.direct_target_requirement_count, 0)
                self.assertEqual(receipt.native_not_applicable_count, 2)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertTrue(
                    all(
                        value.disposition == "native_not_applicable"
                        and value.target_measurement_ref is None
                        and value.target_staged_file_ref is None
                        and value.target_runtime_file_ref is None
                        for value in receipt.requirements
                    )
                )
                self.assertFalse(target_stage_root.exists())
            finally:
                target_lease.close()
                executable_lease.close()

    def test_zero_length_staged_target_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "zero-runtime-target"
            self._write_target(target, b"")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            try:
                receipt = (
                    inspect_staged_executable_shebang_target_runtime_manifest(
                        target_staging,
                        lease=target_lease,
                    )
                )
                self.assertEqual(receipt.file_count, 1)
                runtime_file = receipt.files[0]
                self.assertEqual(runtime_file.classification, "unknown")
                self.assertEqual(runtime_file.content_bytes, 0)
                self.assertEqual(runtime_file.header_bytes, 0)
                self.assertEqual(
                    runtime_file.content_digest,
                    "sha256:" + hashlib.sha256(b"").hexdigest(),
                )
                self.assertIsNone(runtime_file.shebang_directive_ref)
                self.assertEqual(receipt.total_content_bytes, 0)
                self.assertEqual(receipt.total_header_bytes, 0)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_new_closed_and_cross_process_leases_reject_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "lease-runtime-target"
            self._write_target(target, b"#!/bin/sh\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            unused_root = target_stage_root.parent / "unused-runtime-stage-root"
            unused_root.mkdir(mode=0o700)
            unused = RepositoryExecutableShebangTargetStageLease(unused_root)
            original_pid = target_lease._owner_pid
            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("read before lease validation"),
                ) as pread:
                    self._assert_invalid(target_staging, unused)

                    target_lease._owner_pid = original_pid + 1
                    self._assert_invalid(target_staging, target_lease)
                    target_lease._owner_pid = original_pid
                pread.assert_not_called()

                target_lease.close()
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("read from closed lease"),
                ) as pread:
                    self._assert_invalid(target_staging, target_lease)
                pread.assert_not_called()
            finally:
                target_lease._owner_pid = original_pid
                target_lease.close()
                unused.close()
                executable_lease.close()

    def test_expected_receipt_requires_exact_anchored_object_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "identity-runtime-target"
            self._write_target(target, b"#!/bin/sh\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            equal_but_distinct = replace(target_staging)
            self.assertEqual(equal_but_distinct, target_staging)
            self.assertIsNot(equal_but_distinct, target_staging)
            tampered = replace(
                target_staging,
                total_staged_bytes=target_staging.total_staged_bytes + 1,
            )
            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("read before receipt validation"),
                ) as pread:
                    for case, expected in (
                        ("wrong-type", object()),
                        ("equal-distinct", equal_but_distinct),
                        ("tampered", tampered),
                    ):
                        with self.subTest(case=case):
                            self._assert_invalid(expected, target_lease)
                pread.assert_not_called()
            finally:
                target_lease.close()
                executable_lease.close()

    def test_stronger_lease_anchors_and_root_context_reject_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "anchor-runtime-target"
            self._write_target(target, b"#!/bin/sh\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            original = {
                name: getattr(target_lease, name)
                for name in (
                    "_receipt",
                    "_receipt_object_anchor",
                    "_receipt_digest_anchor",
                    "_receipt_file_refs_anchor",
                    "_files",
                    "_files_object_anchor",
                    "_cleanup_receipt_digest_anchor",
                    "_cleanup_receipt_object_anchor",
                    "_root_descriptor",
                    "_root_metadata",
                    "_pending_name",
                    "_descriptor_release_unverifiable",
                )
            }

            def check(attribute: str, bad_value: object) -> None:
                setattr(target_lease, attribute, bad_value)
                try:
                    self._assert_invalid(target_staging, target_lease)
                finally:
                    setattr(target_lease, attribute, original[attribute])

            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("read before anchor validation"),
                ) as pread:
                    check("_receipt", replace(target_staging))
                    check("_receipt_object_anchor", replace(target_staging))
                    check("_receipt_digest_anchor", "sha256:" + "0" * 64)
                    check(
                        "_receipt_file_refs_anchor",
                        target_lease._receipt_file_refs_anchor
                        + ("sha256:" + "1" * 64,),
                    )
                    distinct_files = (*target_lease._files,)
                    self.assertIsNot(distinct_files, target_lease._files)
                    check("_files", distinct_files)
                    check("_files_object_anchor", distinct_files)
                    check("_cleanup_receipt_digest_anchor", "sha256:" + "2" * 64)
                    check("_cleanup_receipt_object_anchor", object())
                    check("_root_descriptor", -1)
                    check("_root_metadata", None)
                    check("_pending_name", "private-pending-name-marker")
                    check("_descriptor_release_unverifiable", True)
                pread.assert_not_called()
                self.assertEqual(target_lease._receipt, target_staging)
                self.assertIs(
                    target_lease._receipt,
                    target_lease._receipt_object_anchor,
                )
                self.assertIs(target_lease._files, target_lease._files_object_anchor)
            finally:
                for name, value in original.items():
                    setattr(target_lease, name, value)
                target_lease.close()
                executable_lease.close()

    def test_descriptor_retarget_metadata_and_other_inode_fail_closed(self) -> None:
        target_content = b"#!/bin/sh\nprivate-descriptor-runtime-marker\n"
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "descriptor-runtime-target"
            self._write_target(target, target_content)
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                staging,
                executable_runtime,
                requirements,
                target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            second_root = target_stage_root.parent / "second-target-runtime-stage"
            second_root.mkdir(mode=0o700)
            second_lease = RepositoryExecutableShebangTargetStageLease(second_root)
            second_staging = self.fixture._stage(
                registration,
                search_directories=(search_one, search_two),
                target_resolution=target_resolution,
                requirements=requirements,
                runtime=executable_runtime,
                staging=staging,
                executable_lease=executable_lease,
                target_paths=(target,),
                target_lease=second_lease,
            )
            self.assertEqual(
                second_staging.staged_files[0].content_digest,
                target_staging.staged_files[0].content_digest,
            )
            retained = target_lease._files[0]
            original_files = target_lease._files
            original_files_anchor = target_lease._files_object_anchor
            descriptor = retained.descriptor
            backup = os.dup(descriptor)
            foreign = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.dup2(foreign, descriptor, inheritable=False)
                self._assert_invalid(target_staging, target_lease)
                os.dup2(backup, descriptor, inheritable=False)

                forged_metadata = replace(
                    retained,
                    metadata=(
                        *retained.metadata[:-1],
                        retained.metadata[-1] + 1,
                    ),
                )
                forged_files = (forged_metadata,)
                target_lease._files = forged_files
                target_lease._files_object_anchor = forged_files
                self._assert_invalid(target_staging, target_lease)

                other = second_lease._files[0]
                forged_other_inode = target_staging_module._RetainedStagedTarget(
                    staged_file=target_staging.staged_files[0],
                    descriptor=other.descriptor,
                    metadata=other.metadata,
                )
                forged_files = (forged_other_inode,)
                target_lease._files = forged_files
                target_lease._files_object_anchor = forged_files
                self._assert_invalid(target_staging, target_lease)
            finally:
                os.dup2(backup, descriptor, inheritable=False)
                target_lease._files = original_files
                target_lease._files_object_anchor = original_files_anchor
                os.close(foreign)
                os.close(backup)
                target_lease.close()
                second_lease.close()
                executable_lease.close()

    def test_header_read_and_final_remeasurement_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "race-runtime-target"
            self._write_target(target, b"#!/bin/sh\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            before = self._lease_snapshot(target_lease)
            real_read = runtime_module._BUILTIN_READ_EXACT_HEADER
            corrupted = False

            def corrupt_header(descriptor: int, content_bytes: int) -> bytes:
                nonlocal corrupted
                header = real_read(descriptor, content_bytes)
                if not corrupted and header:
                    corrupted = True
                    return bytes((header[0] ^ 1,)) + header[1:]
                return header

            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_READ_EXACT_HEADER",
                    side_effect=corrupt_header,
                ):
                    self._assert_invalid(target_staging, target_lease)
                self.assertTrue(corrupted)
                self.assertEqual(self._lease_snapshot(target_lease), before)

                real_verify = (
                    runtime_module._BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET
                )
                verify_calls = 0

                def fail_final_remeasurement(*args: object, **kwargs: object) -> bytes:
                    nonlocal verify_calls
                    verify_calls += 1
                    header = real_verify(*args, **kwargs)
                    if verify_calls > target_staging.unique_target_count:
                        raise ValueError("private-final-remeasurement-marker")
                    return header

                with patch.object(
                    runtime_module,
                    "_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET",
                    side_effect=fail_final_remeasurement,
                ):
                    self._assert_invalid(
                        target_staging,
                        target_lease,
                        private_marker="private-final-remeasurement-marker",
                    )
                self.assertGreaterEqual(verify_calls, 2)
                self.assertEqual(self._lease_snapshot(target_lease), before)
            finally:
                target_lease.close()
                executable_lease.close()

    def test_cleanup_after_header_read_fails_closed_but_remains_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "cleanup-runtime-target"
            self._write_target(target, b"#!/bin/sh\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            real_read = runtime_module._BUILTIN_READ_EXACT_HEADER
            cleaned = False

            def cleanup_after_read(descriptor: int, content_bytes: int) -> bytes:
                nonlocal cleaned
                header = real_read(descriptor, content_bytes)
                if not cleaned:
                    cleaned = True
                    target_lease.close()
                return header

            with patch.object(
                runtime_module,
                "_BUILTIN_READ_EXACT_HEADER",
                side_effect=cleanup_after_read,
            ):
                self._assert_invalid(target_staging, target_lease)
            self.assertTrue(cleaned)
            self.assertEqual(target_lease.state, "cleaned")
            self.assertTrue(target_lease.cleanup_receipt.descriptor_release_complete)
            self.assertTrue(
                target_lease.cleanup_receipt.owned_namespace_absence_verified
            )
            self.assertEqual(tuple(target_stage_root.iterdir()), ())
            executable_lease.close()

    def test_baseexception_during_header_read_leaves_lease_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "interrupt-runtime-target"
            self._write_target(target, b"#!/bin/sh\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            before = self._lease_snapshot(target_lease)
            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_READ_EXACT_HEADER",
                    side_effect=KeyboardInterrupt("private-interrupt-marker"),
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        inspect_staged_executable_shebang_target_runtime_manifest(
                            target_staging,
                            lease=target_lease,
                        )
                self.assertEqual(self._lease_snapshot(target_lease), before)
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
            finally:
                target_lease.close()
                executable_lease.close()

    def test_captured_proof_seams_ignore_public_helper_and_library_patches(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable_lease, target_lease, target_staging = (
                self._one_direct_stage(temporary)
            )
            baseline = (
                inspect_staged_executable_shebang_target_runtime_manifest(
                    target_staging,
                    lease=target_lease,
                )
            )
            captured_pread = runtime_module._BUILTIN_PREAD
            captured_verify = (
                runtime_module._BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET
            )
            try:
                with (
                    patch.object(
                        runtime_module,
                        "_BUILTIN_PREAD",
                        wraps=captured_pread,
                    ) as shipped_pread,
                    patch.object(
                        runtime_module,
                        "_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET",
                        wraps=captured_verify,
                    ) as shipped_verify,
                    patch.object(
                        runtime_module,
                        "_active_target_stage_snapshot",
                        return_value=({}, ()),
                    ) as public_snapshot,
                    patch.object(
                        runtime_module,
                        "_verify_anchored_retained_target",
                        return_value=b"forged-public-verification",
                    ) as public_verify,
                    patch.object(
                        runtime_module,
                        "_read_exact_header",
                        return_value=b"forged-public-header",
                    ) as public_read,
                    patch.object(
                        runtime_module,
                        "_build_runtime_file",
                        return_value=object(),
                    ) as public_build_file,
                    patch.object(
                        runtime_module,
                        "_build_runtime_requirement",
                        return_value=object(),
                    ) as public_build_requirement,
                    patch.object(
                        runtime_module,
                        "_classify_header",
                        return_value=("unknown", None),
                    ) as public_classify,
                    patch.object(
                        runtime_module,
                        "_runtime_manifest_projection",
                        return_value={"forged": True},
                    ) as public_manifest_projection,
                    patch.object(
                        runtime_module,
                        "_target_staging_receipt_projection",
                        return_value={"forged": True},
                    ) as public_staging_projection,
                    patch.object(
                        runtime_module,
                        "canonical_digest",
                        return_value="sha256:" + "0" * 64,
                    ) as public_digest,
                    patch.object(
                        runtime_module.os,
                        "pread",
                        return_value=b"forged-public-pread",
                    ) as public_pread,
                    patch.object(
                        runtime_module.os,
                        "fstat",
                        side_effect=AssertionError("public fstat bypass"),
                    ) as public_fstat,
                    patch.object(
                        runtime_module.hashlib,
                        "sha256",
                        side_effect=AssertionError("public sha256 bypass"),
                    ) as public_sha256,
                ):
                    observed = (
                        inspect_staged_executable_shebang_target_runtime_manifest(
                            target_staging,
                            lease=target_lease,
                        )
                    )
                self.assertEqual(observed, baseline)
                self.assertGreater(shipped_pread.call_count, 0)
                self.assertEqual(
                    shipped_verify.call_count,
                    2 * target_staging.unique_target_count,
                )
                for bypass in (
                    public_snapshot,
                    public_verify,
                    public_read,
                    public_build_file,
                    public_build_requirement,
                    public_classify,
                    public_manifest_projection,
                    public_staging_projection,
                    public_digest,
                    public_pread,
                    public_fstat,
                    public_sha256,
                ):
                    bypass.assert_not_called()
            finally:
                target_lease.close()
                executable_lease.close()

    def test_deceptive_string_subclasses_reject_upstream_and_output_projections(
        self,
    ) -> None:
        class DeceptiveString(str):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            executable_lease, target_lease, target_staging = (
                self._one_direct_stage(temporary)
            )
            receipt = (
                inspect_staged_executable_shebang_target_runtime_manifest(
                    target_staging,
                    lease=target_lease,
                )
            )
            original_kind = target_staging.kind
            try:
                object.__setattr__(
                    target_staging,
                    "kind",
                    DeceptiveString(original_kind),
                )
                with patch.object(
                    runtime_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("read deceptive upstream"),
                ) as pread:
                    self._assert_invalid(target_staging, target_lease)
                pread.assert_not_called()
                object.__setattr__(target_staging, "kind", original_kind)

                forged_values = (
                    replace(
                        receipt,
                        kind=DeceptiveString(receipt.kind),
                    ),
                    replace(
                        receipt.files[0],
                        classification=DeceptiveString(
                            receipt.files[0].classification
                        ),
                    ),
                    replace(
                        receipt.files[0],
                        content_digest=DeceptiveString(
                            receipt.files[0].content_digest
                        ),
                    ),
                    replace(
                        receipt.requirements[0],
                        disposition=DeceptiveString(
                            receipt.requirements[0].disposition
                        ),
                    ),
                    replace(
                        receipt.bindings[0],
                        command_kind=DeceptiveString(
                            receipt.bindings[0].command_kind
                        ),
                    ),
                )
                for forged in forged_values:
                    with self.subTest(type=type(forged).__name__):
                        with self.assertRaises(ValueError):
                            forged.to_canonical()
            finally:
                object.__setattr__(target_staging, "kind", original_kind)
                target_lease.close()
                executable_lease.close()

    def test_valid_receipt_structural_replacements_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                _outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target_one = Path(temporary).resolve(strict=True) / "shape-target-one"
            target_two = Path(temporary).resolve(strict=True) / "shape-target-two"
            self._write_target(target_one, b"x")
            self._write_target(target_two, b"ordinary-two\n")
            self._set_contents(
                root,
                search_one,
                bare=b"#!" + os.fsencode(target_one) + b"\n",
                relative=b"#!" + os.fsencode(target_two) + b"\n",
            )
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target_one, target_two),
            )
            try:
                receipt = (
                    inspect_staged_executable_shebang_target_runtime_manifest(
                        target_staging,
                        lease=target_lease,
                    )
                )
                first_file = receipt.files[0]
                first_requirement = receipt.requirements[0]
                first_binding = receipt.bindings[0]
                unit_receipt = replace(
                    receipt,
                    files=(first_file,),
                    requirements=(first_requirement,),
                    bindings=(first_binding,),
                    file_count=1,
                    requirement_count=1,
                    command_count=1,
                    direct_target_requirement_count=1,
                    native_not_applicable_count=0,
                    total_content_bytes=1,
                    total_header_bytes=1,
                )
                self.assertEqual(
                    unit_receipt.to_canonical()["file_count"],
                    1,
                )
                bool_as_int_cases = {
                    "schema_version": True,
                    "file_count": True,
                    "requirement_count": True,
                    "command_count": True,
                    "direct_target_requirement_count": True,
                    "native_not_applicable_count": False,
                    "total_content_bytes": True,
                    "total_header_bytes": True,
                }
                for field, deceptive_bool in bool_as_int_cases.items():
                    with self.subTest(bool_as_int=field):
                        self.assertEqual(
                            getattr(unit_receipt, field),
                            int(deceptive_bool),
                        )
                        forged = replace(
                            unit_receipt,
                            **{field: deceptive_bool},
                        )
                        with self.assertRaises(ValueError):
                            forged.to_canonical()

                structural_cases = {
                    "reordered-files": replace(
                        receipt,
                        files=tuple(reversed(receipt.files)),
                    ),
                    "reordered-requirements": replace(
                        receipt,
                        requirements=tuple(reversed(receipt.requirements)),
                    ),
                    "reordered-bindings": replace(
                        receipt,
                        bindings=tuple(reversed(receipt.bindings)),
                    ),
                    "empty-files-with-direct-requirements": replace(
                        receipt,
                        files=(),
                        file_count=0,
                        total_content_bytes=0,
                        total_header_bytes=0,
                    ),
                    "empty-requirements": replace(
                        receipt,
                        requirements=(),
                        requirement_count=0,
                    ),
                    "empty-bindings": replace(
                        receipt,
                        bindings=(),
                        command_count=0,
                    ),
                    "duplicate-file": replace(
                        receipt,
                        files=(first_file, first_file),
                    ),
                    "altered-content-total": replace(
                        receipt,
                        total_content_bytes=receipt.total_content_bytes + 1,
                    ),
                    "altered-header-total": replace(
                        receipt,
                        total_header_bytes=receipt.total_header_bytes + 1,
                    ),
                    "minimum-header-forged-elf": replace(
                        receipt,
                        files=(
                            replace(first_file, classification="elf"),
                            *receipt.files[1:],
                        ),
                    ),
                    "file-ref-correspondence": replace(
                        receipt,
                        files=(
                            replace(
                                first_file,
                                target_runtime_file_ref=(
                                    "sha256:" + "3" * 64
                                ),
                            ),
                            *receipt.files[1:],
                        ),
                    ),
                    "requirement-ref-correspondence": replace(
                        receipt,
                        requirements=(
                            replace(
                                first_requirement,
                                target_runtime_file_ref=(
                                    "sha256:" + "4" * 64
                                ),
                            ),
                            *receipt.requirements[1:],
                        ),
                    ),
                    "binding-ref-correspondence": replace(
                        receipt,
                        bindings=(
                            replace(
                                first_binding,
                                target_runtime_requirement_ref=(
                                    "sha256:" + "5" * 64
                                ),
                            ),
                            *receipt.bindings[1:],
                        ),
                    ),
                }
                for case, forged in structural_cases.items():
                    with self.subTest(case=case):
                        with self.assertRaises(ValueError):
                            forged.to_canonical()
            finally:
                target_lease.close()
                executable_lease.close()

    def test_post_final_snapshot_lineage_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable_lease, target_lease, target_staging = (
                self._one_direct_stage(temporary)
            )
            before = self._lease_snapshot(target_lease)
            original_registration_digest = target_staging.registration_digest
            real_verify = (
                runtime_module._BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET
            )
            verify_calls = 0
            mutated = False

            def mutate_after_final_snapshot(
                *args: object,
                **kwargs: object,
            ) -> bytes:
                nonlocal verify_calls, mutated
                header = real_verify(*args, **kwargs)
                verify_calls += 1
                if verify_calls == 2:
                    object.__setattr__(
                        target_staging,
                        "registration_digest",
                        "sha256:" + "6" * 64,
                    )
                    mutated = True
                return header

            try:
                with patch.object(
                    runtime_module,
                    "_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET",
                    side_effect=mutate_after_final_snapshot,
                ):
                    self._assert_invalid(target_staging, target_lease)
                self.assertTrue(mutated)
            finally:
                object.__setattr__(
                    target_staging,
                    "registration_digest",
                    original_registration_digest,
                )
                self.assertEqual(self._lease_snapshot(target_lease), before)
                target_lease.close()
                executable_lease.close()

    def test_transient_live_binding_collection_race_never_leaks_forged_lineage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable_lease, target_lease, target_staging = (
                self._one_direct_stage(temporary)
            )
            original_bindings = target_staging.bindings
            original_digests = tuple(
                value.command_digest for value in original_bindings
            )
            forged_bindings = tuple(
                replace(
                    value,
                    command_digest="sha256:" + f"{index + 7:064x}",
                )
                for index, value in enumerate(original_bindings)
            )
            forged_digests = tuple(
                value.command_digest for value in forged_bindings
            )
            self.assertNotEqual(forged_digests, original_digests)
            before = self._lease_snapshot(target_lease)
            real_snapshot = runtime_module._BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT
            real_verify = (
                runtime_module._BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET
            )
            snapshot_calls = 0
            verification_calls = 0
            mutated = False
            restored = False

            def mutate_after_initial_snapshot(
                *args: object,
                **kwargs: object,
            ) -> object:
                nonlocal snapshot_calls, mutated
                result = real_snapshot(*args, **kwargs)
                snapshot_calls += 1
                if snapshot_calls == 1:
                    object.__setattr__(
                        target_staging,
                        "bindings",
                        forged_bindings,
                    )
                    mutated = True
                return result

            def restore_after_initial_verification(
                *args: object,
                **kwargs: object,
            ) -> bytes:
                nonlocal verification_calls, restored
                header = real_verify(*args, **kwargs)
                verification_calls += 1
                if verification_calls == 1:
                    object.__setattr__(
                        target_staging,
                        "bindings",
                        original_bindings,
                    )
                    restored = True
                return header

            observed = None
            rejected = None
            try:
                with (
                    patch.object(
                        runtime_module,
                        "_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT",
                        side_effect=mutate_after_initial_snapshot,
                    ),
                    patch.object(
                        runtime_module,
                        "_BUILTIN_VERIFY_ANCHORED_RETAINED_TARGET",
                        side_effect=restore_after_initial_verification,
                    ),
                ):
                    try:
                        observed = (
                            inspect_staged_executable_shebang_target_runtime_manifest(
                                target_staging,
                                lease=target_lease,
                            )
                        )
                    except ValidationError as exc:
                        rejected = exc
                self.assertTrue(mutated)
                self.assertTrue(restored)
                self.assertGreaterEqual(snapshot_calls, 1)
                self.assertGreaterEqual(verification_calls, 1)
                if rejected is not None:
                    self.assertEqual(str(rejected), FIXED_RUNTIME_ERROR)
                    self.assertIsNone(rejected.__cause__)
                    self.assertIsNone(observed)
                else:
                    self.assertIsNotNone(observed)
                    assert observed is not None
                    self.assertEqual(
                        tuple(
                            value.command_digest
                            for value in observed.bindings
                        ),
                        original_digests,
                    )
                    self.assertTrue(
                        set(forged_digests).isdisjoint(
                            value.command_digest
                            for value in observed.bindings
                        )
                    )
                    self.assertEqual(
                        observed.target_staging_receipt_digest,
                        target_staging.receipt_digest,
                    )
                    requirement_by_ref = {
                        value.target_runtime_requirement_ref: value
                        for value in observed.requirements
                    }
                    for value, anchored in zip(
                        observed.bindings,
                        original_bindings,
                        strict=True,
                    ):
                        for field in (
                            "command_kind",
                            "command_id",
                            "command_digest",
                            "staged_file_ref",
                            "runtime_file_ref",
                            "requirement_ref",
                            "target_requirement_ref",
                            "target_stage_requirement_ref",
                        ):
                            self.assertEqual(
                                getattr(value, field),
                                getattr(anchored, field),
                            )
                        requirement = requirement_by_ref[
                            value.target_runtime_requirement_ref
                        ]
                        self.assertEqual(
                            value.target_stage_requirement_ref,
                            requirement.target_stage_requirement_ref,
                        )
            finally:
                object.__setattr__(
                    target_staging,
                    "bindings",
                    original_bindings,
                )
                self.assertEqual(self._lease_snapshot(target_lease), before)
                target_lease.close()
                executable_lease.close()

    def test_exports_and_inspector_signature_are_exact(self) -> None:
        self.assertEqual(
            runtime_module.__all__,
            [
                "MANIFEST_SCOPE",
                "MANIFEST_SOURCE",
                "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_BINDING_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_FILE_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_EVIDENCE_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_KIND",
                "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_MANIFEST_SCHEMA_VERSION",
                "REPOSITORY_EXECUTABLE_SHEBANG_TARGET_RUNTIME_REQUIREMENT_KIND",
                "RepositoryExecutableShebangTargetRuntimeBinding",
                "RepositoryExecutableShebangTargetRuntimeFile",
                "RepositoryExecutableShebangTargetRuntimeManifestReceipt",
                "RepositoryExecutableShebangTargetRuntimeRequirement",
                "inspect_staged_executable_shebang_target_runtime_manifest",
            ],
        )
        signature = inspect.signature(
            inspect_staged_executable_shebang_target_runtime_manifest
        )
        self.assertEqual(
            tuple(signature.parameters),
            ("expected_target_staging", "lease"),
        )
        expected_parameter = signature.parameters["expected_target_staging"]
        lease_parameter = signature.parameters["lease"]
        self.assertIs(
            expected_parameter.kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(expected_parameter.default, inspect.Parameter.empty)
        self.assertIs(lease_parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(lease_parameter.default, inspect.Parameter.empty)

    def test_no_environment_process_state_path_write_or_cleanup_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                root,
                outside,
                search_one,
                search_two,
                executable_stage_root,
                target_stage_root,
            ) = self._workspace(temporary)
            target = Path(temporary).resolve(strict=True) / "no-effect-runtime-target"
            self._write_target(target, b"#!/bin/sh\n")
            shebang = b"#!" + os.fsencode(target) + b"\n"
            self._set_contents(root, search_one, bare=shebang, relative=shebang)
            registration = self._registration(root)
            (
                executable_lease,
                _staging,
                _executable_runtime,
                _requirements,
                _target_resolution,
                target_lease,
                target_staging,
            ) = self._stage_chain(
                registration,
                search_directories=(search_one, search_two),
                executable_stage_root=executable_stage_root,
                target_stage_root=target_stage_root,
                target_paths=(target,),
            )
            before = self._lease_snapshot(target_lease)
            trees_before = tuple(
                self._tree_snapshot(path)
                for path in (root, outside, search_one, search_two, target.parent)
            )
            try:
                with (
                    patch.object(shutil, "which", side_effect=AssertionError("PATH")) as which,
                    patch.object(os, "getenv", side_effect=AssertionError("environment")) as getenv,
                    patch.object(os, "get_exec_path", side_effect=AssertionError("PATH")) as get_exec_path,
                    patch.object(os, "open", side_effect=AssertionError("path reopen")) as open_path,
                    patch.object(os, "write", side_effect=AssertionError("write")) as write,
                    patch.object(os, "fchmod", side_effect=AssertionError("chmod")) as fchmod,
                    patch.object(os, "close", side_effect=AssertionError("close")) as close,
                    patch.object(os, "dup", side_effect=AssertionError("dup")) as duplicate,
                    patch.object(os, "dup2", side_effect=AssertionError("dup2")) as duplicate_to,
                    patch.object(os, "lseek", side_effect=AssertionError("seek")) as seek,
                    patch.object(os, "system", side_effect=AssertionError("shell")) as system,
                    patch.object(subprocess, "run", side_effect=AssertionError("process")) as run,
                    patch.object(subprocess, "Popen", side_effect=AssertionError("process")) as popen,
                    patch.object(asyncio, "create_subprocess_exec", side_effect=AssertionError("process")) as create_exec,
                    patch.object(asyncio, "create_subprocess_shell", side_effect=AssertionError("process")) as create_shell,
                    patch.object(artifact_filesystem_module, "stage_artifact", side_effect=AssertionError("artifact")) as stage_artifact,
                    patch.object(artifact_filesystem_module, "publish_staged_artifact", side_effect=AssertionError("artifact")) as publish_artifact,
                    patch.object(state_module.SQLiteStateStore, "__init__", side_effect=AssertionError("state")) as state,
                    patch.object(target_staging_module, "cleanup_repository_executable_shebang_target_stage", side_effect=AssertionError("cleanup")) as cleanup,
                ):
                    receipt = (
                        inspect_staged_executable_shebang_target_runtime_manifest(
                            target_staging,
                            lease=target_lease,
                        )
                    )
                self.assertEqual(receipt.file_count, 1)
                self.assertEqual(self._lease_snapshot(target_lease), before)
                for observed in (
                    which,
                    getenv,
                    get_exec_path,
                    open_path,
                    write,
                    fchmod,
                    close,
                    duplicate,
                    duplicate_to,
                    seek,
                    system,
                    run,
                    popen,
                    create_exec,
                    create_shell,
                    stage_artifact,
                    publish_artifact,
                    state,
                    cleanup,
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
                self.assertEqual(tuple(target_stage_root.iterdir()), ())
            finally:
                target_lease.close()
                executable_lease.close()


if __name__ == "__main__":
    unittest.main()
