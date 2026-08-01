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
    repository_executable_shebang_nested_target_requirements
    as requirements_module,
)
from ordomata import (
    repository_executable_shebang_nested_target_runtime_manifest
    as runtime_module,
)
from ordomata.repository_executable_shebang_nested_target_requirements import (
    RepositoryExecutableShebangNestedTargetRequirementsReceipt,
    inspect_staged_executable_shebang_nested_target_requirements
    as inspect_requirements,
)
from ordomata.repository_executable_shebang_nested_target_runtime_manifest import (
    inspect_staged_executable_shebang_nested_target_runtime_manifest
    as inspect_runtime,
)
from ordomata.repository_executable_shebang_nested_target_staging import (
    RepositoryExecutableShebangNestedTargetStageLease,
    stage_repository_executable_shebang_nested_target_bytes,
)

if __package__:
    from . import (
        test_repository_executable_shebang_nested_target_runtime_manifest
        as runtime_test_module,
    )
    from . import (
        test_repository_executable_shebang_nested_target_staging
        as staging_test_module,
    )
else:
    import test_repository_executable_shebang_nested_target_runtime_manifest \
        as runtime_test_module
    import test_repository_executable_shebang_nested_target_staging \
        as staging_test_module


FIXED_ERROR = (
    "repository executable shebang nested target requirements are invalid"
)
_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
_MACH_O = b"\xcf\xfa\xed\xfe" + b"\x00" * 28


@unittest.skipUnless(os.name == "posix", "nested requirements require POSIX")
class RepositoryExecutableShebangNestedTargetRequirementsTests(
    unittest.TestCase
):
    runtime_fixture_type = (
        runtime_test_module
        .RepositoryExecutableShebangNestedTargetRuntimeManifestTests
    )

    def _prepared(
        self,
        temporary: str,
        *,
        content: bytes = b"#!/usr/bin/env python3 -I\nprint(1)\n",
        include_source_native: bool = False,
    ):
        fixture = self.runtime_fixture_type()
        staging_fixture, chain, lease, staging = fixture._prepared(
            temporary,
            content=content,
            include_source_native=include_source_native,
        )
        runtime = inspect_runtime(staging, lease=lease)
        return staging_fixture, chain, lease, staging, runtime

    @staticmethod
    def _inspect(runtime, staging, lease):
        return inspect_requirements(
            runtime,
            expected_nested_target_staging=staging,
            lease=lease,
        )

    def test_receipt_correspondence_privacy_and_lease_immutability(
        self,
    ) -> None:
        marker = b"#!/usr/bin/env private-nested-token -I\nprint(1)\n"
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(
                temporary,
                content=marker,
                include_source_native=True,
            )
            state = lease.state
            files = lease._files
            receipt_anchor = lease._receipt_object_anchor
            try:
                receipt = self._inspect(runtime, staging, lease)
                self.assertIsInstance(
                    receipt,
                    RepositoryExecutableShebangNestedTargetRequirementsReceipt,
                )
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(
                    receipt.known_chain_guard_requirement_count,
                    1,
                )
                self.assertEqual(
                    receipt.source_native_not_applicable_count,
                    1,
                )
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(
                    receipt.nested_target_posix_shebang_requirement_count,
                    1,
                )
                inspected = next(
                    item
                    for item in receipt.requirements
                    if item.runtime_disposition
                    == "known_chain_guard_runtime_inspected"
                )
                self.assertEqual(
                    inspected.disposition,
                    "absolute_interpreter_token",
                )
                self.assertTrue(inspected.interpreter_token_absolute)
                self.assertEqual(
                    inspected.interpreter_token_bytes,
                    len(b"/usr/bin/env"),
                )
                self.assertEqual(inspected.argument_separator_kind, "space")
                self.assertEqual(
                    inspected.argument_tail_bytes,
                    len(b"private-nested-token -I"),
                )
                self.assertIsNotNone(inspected.interpreter_token_ref)
                self.assertIsNotNone(inspected.argument_tail_ref)
                canonical = receipt.to_canonical()
                self.assertEqual(
                    receipt.receipt_digest,
                    canonical_digest(canonical),
                )
                self.assertEqual(
                    receipt.nested_target_runtime_manifest_receipt_digest,
                    runtime.receipt_digest,
                )
                evidence = receipt.to_evidence()
                self.assertEqual(evidence["effect_class"], 0)
                self.assertTrue(
                    evidence[
                        "exact_nested_target_runtime_manifest_"
                        "correspondence_verified"
                    ]
                )
                for field in (
                    "authority_granted",
                    "authorization_verified",
                    "execution_enabled",
                    "network_access_performed",
                    "model_invocation_performed",
                    "subprocess_invocation_performed",
                    "worker_enabled",
                ):
                    self.assertFalse(evidence[field])
                serialized = json.dumps(
                    {"canonical": canonical, "evidence": evidence},
                    sort_keys=True,
                )
                for private in (
                    str(chain["root"]),
                    str(chain["nested_target"]),
                    str(lease.staging_root),
                    marker.decode("ascii").strip(),
                    "private-nested-token",
                    "directory_inode",
                    "directory_device",
                ):
                    self.assertNotIn(private, serialized)
                    self.assertNotIn(private, repr(receipt))
                self.assertEqual(lease.state, state)
                self.assertIs(lease._files, files)
                self.assertIs(lease._receipt_object_anchor, receipt_anchor)
                with self.assertRaises(FrozenInstanceError):
                    receipt.requirement_count = 0
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_fixed_classification_and_parser_dispositions(self) -> None:
        cases = (
            ("elf", _ELF, "native_binary_no_shebang", None, 0),
            ("mach-o", _MACH_O, "native_binary_no_shebang", None, 0),
            (
                "absolute",
                b"#!/bin/sh\nexit 0\n",
                "absolute_interpreter_token",
                True,
                0,
            ),
            (
                "relative",
                b"#!python3 -I\nprint(1)\n",
                "non_absolute_interpreter_token",
                False,
                2,
            ),
            (
                "tab",
                b"#!/bin/sh\t-e\nexit 0\n",
                "absolute_interpreter_token",
                True,
                2,
            ),
            (
                "unsupported",
                b"#! /bin/sh\n",
                "unsupported_shebang",
                None,
                0,
            ),
            (
                "unknown",
                b"plain executable bytes\n",
                "unknown_runtime_format",
                None,
                0,
            ),
        )
        for label, content, disposition, absolute, tail_bytes in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                fixture, chain, lease, staging, runtime = self._prepared(
                    tmp,
                    content=content,
                )
                try:
                    receipt = self._inspect(runtime, staging, lease)
                    requirement = receipt.requirements[0]
                    self.assertEqual(requirement.disposition, disposition)
                    self.assertEqual(
                        requirement.interpreter_token_absolute,
                        absolute,
                    )
                    self.assertEqual(
                        requirement.argument_tail_bytes,
                        tail_bytes,
                    )
                finally:
                    if lease.state == "active":
                        lease.close()
                    fixture.fixture._close_chain(chain)

    def test_shared_nested_target_is_extracted_once_and_bound_twice(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            try:
                receipt = self._inspect(runtime, staging, lease)
                self.assertEqual(receipt.requirement_count, 2)
                self.assertEqual(receipt.command_count, 2)
                self.assertEqual(
                    receipt.known_chain_guard_requirement_count,
                    2,
                )
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(
                    {
                        item.nested_target_runtime_file_ref
                        for item in receipt.requirements
                    },
                    {runtime.files[0].nested_target_runtime_file_ref},
                )
                self.assertEqual(
                    len(
                        {
                            item.nested_target_shebang_requirement_ref
                            for item in receipt.requirements
                        }
                    ),
                    2,
                )
                self.assertEqual(
                    {
                        item.interpreter_token_ref
                        for item in receipt.requirements
                    },
                    {receipt.requirements[0].interpreter_token_ref},
                )
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_baseexception_during_remeasurement_is_redacted_and_nonmutating(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            state = lease.state
            files = lease._files
            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_PREAD",
                    side_effect=BaseException("private read failure"),
                ):
                    with self.assertRaises(ValidationError) as caught:
                        self._inspect(runtime, staging, lease)
                self.assertEqual(str(caught.exception), FIXED_ERROR)
                self.assertNotIn("private read failure", str(caught.exception))
                self.assertEqual(lease.state, state)
                self.assertIs(lease._files, files)
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_forged_runtime_staging_and_output_lineage_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            try:
                forged_runtime = replace(
                    runtime,
                    guard_summary_ref="sha256:" + "0" * 64,
                )
                for candidate_runtime, candidate_staging in (
                    (forged_runtime, staging),
                    (
                        runtime,
                        replace(
                            staging,
                            guard_summary_ref="sha256:" + "1" * 64,
                        ),
                    ),
                ):
                    with self.assertRaises(ValidationError) as caught:
                        self._inspect(
                            candidate_runtime,
                            candidate_staging,
                            lease,
                        )
                    self.assertEqual(str(caught.exception), FIXED_ERROR)
                receipt = self._inspect(runtime, staging, lease)
                forged_requirement = replace(
                    receipt.requirements[0],
                    nested_target_requirement_ref="sha256:" + "2" * 64,
                )
                forged_receipt = replace(
                    receipt,
                    requirements=(
                        forged_requirement,
                        *receipt.requirements[1:],
                    ),
                )
                with self.assertRaises(Exception):
                    forged_receipt.to_canonical()
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_closed_cross_process_and_wrong_types_reject_before_read(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("invalid input read bytes"),
                ):
                    for candidate in (None, object(), staging):
                        with self.assertRaises(ValidationError):
                            self._inspect(candidate, staging, lease)
                    lease._owner_pid += 1
                    with self.assertRaises(ValidationError):
                        self._inspect(runtime, staging, lease)
                    lease._owner_pid -= 1
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)
            with self.assertRaises(ValidationError):
                self._inspect(runtime, staging, lease)

    def test_two_reproductions_two_remeasurements_and_closing_anchor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            counts = {"runtime": 0, "measure": 0, "close": 0}
            original_runtime = requirements_module._BUILTIN_INSPECT_RUNTIME_MANIFEST
            original_measure = requirements_module._BUILTIN_DESCRIPTOR_REMEASUREMENT
            original_close = requirements_module._BUILTIN_CLOSING_DESCRIPTOR_ANCHOR

            def counted_runtime(*args, **kwargs):
                counts["runtime"] += 1
                return original_runtime(*args, **kwargs)

            def counted_measure(*args, **kwargs):
                counts["measure"] += 1
                return original_measure(*args, **kwargs)

            def counted_close(*args, **kwargs):
                counts["close"] += 1
                return original_close(*args, **kwargs)

            try:
                with (
                    patch.object(
                        requirements_module,
                        "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
                        side_effect=counted_runtime,
                    ),
                    patch.object(
                        requirements_module,
                        "_BUILTIN_DESCRIPTOR_REMEASUREMENT",
                        side_effect=counted_measure,
                    ),
                    patch.object(
                        requirements_module,
                        "_BUILTIN_CLOSING_DESCRIPTOR_ANCHOR",
                        side_effect=counted_close,
                    ),
                ):
                    self._inspect(runtime, staging, lease)
                self.assertEqual(counts, {"runtime": 2, "measure": 2, "close": 1})
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_descriptor_tamper_and_remeasurement_drift_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            original = requirements_module._BUILTIN_PREAD
            reads = 0

            def drift(descriptor: int, count: int, offset: int) -> bytes:
                nonlocal reads
                reads += 1
                result = original(descriptor, count, offset)
                if reads > 2 and result:
                    return bytes([result[0] ^ 1]) + result[1:]
                return result

            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_PREAD",
                    side_effect=drift,
                ):
                    with self.assertRaises(ValidationError) as caught:
                        self._inspect(runtime, staging, lease)
                self.assertEqual(str(caught.exception), FIXED_ERROR)
                self.assertEqual(lease.state, "active")
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_cleanup_during_runtime_reproduction_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            original = requirements_module._BUILTIN_INSPECT_RUNTIME_MANIFEST
            called = False

            def close_after(*args, **kwargs):
                nonlocal called
                result = original(*args, **kwargs)
                if not called:
                    called = True
                    lease.close()
                return result

            try:
                with patch.object(
                    requirements_module,
                    "_BUILTIN_INSPECT_RUNTIME_MANIFEST",
                    side_effect=close_after,
                ):
                    with self.assertRaises(ValidationError) as caught:
                        self._inspect(runtime, staging, lease)
                self.assertEqual(str(caught.exception), FIXED_ERROR)
                self.assertEqual(lease.state, "cleaned")
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_public_monkeypatches_cannot_replace_frozen_proof_graph(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            try:
                expected = self._inspect(runtime, staging, lease)
                with (
                    patch.object(
                        requirements_module,
                        "_requirement_projection",
                        return_value={"forged": "requirement"},
                    ),
                    patch.object(
                        requirements_module,
                        "_receipt_projection",
                        return_value={"forged": "receipt"},
                    ),
                    patch.object(
                        requirements_module,
                        "_classify_header",
                        return_value=("unknown", None, None),
                    ),
                    patch.object(
                        requirements_module,
                        "_split_directive",
                        return_value=(b"forged", None, None),
                    ),
                    patch.object(
                        requirements_module,
                        "_runtime_manifest_projection",
                        return_value={"forged": "runtime"},
                    ),
                    patch.object(
                        requirements_module,
                        "_target_staging_receipt_projection",
                        return_value={"forged": "staging"},
                    ),
                    patch.object(
                        requirements_module,
                        "_staged_file_projection",
                        return_value={"forged": "file"},
                    ),
                    patch.object(
                        requirements_module.hashlib,
                        "sha256",
                        side_effect=AssertionError("public hash called"),
                    ),
                    patch.object(
                        requirements_module.os,
                        "pread",
                        side_effect=AssertionError("public pread called"),
                    ),
                    patch.object(
                        runtime_module,
                        "inspect_staged_executable_shebang_nested_target_"
                        "runtime_manifest",
                        side_effect=AssertionError("public runtime called"),
                    ),
                    patch.object(
                        runtime_module
                        .RepositoryExecutableShebangNestedTargetRuntimeManifestReceipt,
                        "to_canonical",
                        side_effect=AssertionError("public canonical called"),
                    ),
                ):
                    actual = self._inspect(runtime, staging, lease)
                self.assertEqual(actual, expected)
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_no_path_environment_process_write_or_cleanup_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, chain, lease, staging, runtime = self._prepared(temporary)
            forbidden = AssertionError("forbidden effect")
            try:
                with (
                    patch("builtins.open", side_effect=forbidden),
                    patch.object(os, "open", side_effect=forbidden),
                    patch.object(os, "chdir", side_effect=forbidden),
                    patch.object(os, "putenv", side_effect=forbidden),
                    patch.object(os, "system", side_effect=forbidden),
                    patch.object(subprocess, "run", side_effect=forbidden),
                    patch.object(subprocess, "Popen", side_effect=forbidden),
                    patch.object(
                        RepositoryExecutableShebangNestedTargetStageLease,
                        "close",
                        side_effect=forbidden,
                    ),
                ):
                    receipt = self._inspect(runtime, staging, lease)
                self.assertEqual(receipt.unique_nested_target_count, 1)
                self.assertEqual(lease.state, "active")
            finally:
                if lease.state == "active":
                    lease.close()
                fixture.fixture._close_chain(chain)

    def test_exports_and_inspector_signature_are_exact(self) -> None:
        expected = {
            "REQUIREMENTS_SCOPE",
            "REQUIREMENTS_SOURCE",
            (
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
                "REQUIREMENTS_EVIDENCE_KIND"
            ),
            "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_REQUIREMENTS_KIND",
            (
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
                "REQUIREMENTS_SCHEMA_VERSION"
            ),
            (
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
                "SHEBANG_REQUIREMENT_BINDING_KIND"
            ),
            (
                "REPOSITORY_EXECUTABLE_SHEBANG_NESTED_TARGET_"
                "SHEBANG_REQUIREMENT_KIND"
            ),
            "RepositoryExecutableShebangNestedTargetRequirementsReceipt",
            "RepositoryExecutableShebangNestedTargetShebangRequirement",
            (
                "RepositoryExecutableShebangNestedTarget"
                "ShebangRequirementBinding"
            ),
            "inspect_staged_executable_shebang_nested_target_requirements",
        }
        self.assertEqual(set(requirements_module.__all__), expected)
        signature = inspect.signature(inspect_requirements)
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_nested_target_runtime",
                "expected_nested_target_staging",
                "lease",
            ),
        )
        self.assertEqual(
            signature.parameters[
                "expected_nested_target_staging"
            ].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            signature.parameters["lease"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )

    def test_source_native_zero_file_receipt_performs_no_read(self) -> None:
        guard_fixture = staging_test_module \
            .RepositoryExecutableShebangNestedTargetStagingTests.fixture
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
            absent_root = Path(temporary) / "absent-nested-requirements-stage"
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
                nested_runtime = inspect_runtime(
                    nested_staging,
                    lease=nested_lease,
                )
                with patch.object(
                    requirements_module,
                    "_BUILTIN_PREAD",
                    side_effect=AssertionError("native input read bytes"),
                ):
                    receipt = self._inspect(
                        nested_runtime,
                        nested_staging,
                        nested_lease,
                    )
                self.assertEqual(receipt.unique_nested_target_count, 0)
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

    def test_target_native_zero_file_receipt_performs_no_read(self) -> None:
        guard_fixture = staging_test_module \
            .RepositoryExecutableShebangNestedTargetStagingTests.fixture
        for label, content in (
            ("elf", staging_test_module.guard_test_module._ELF),
            ("mach-o", staging_test_module.guard_test_module._MACH_O),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                chain = guard_fixture._unpack(
                    guard_fixture._one_nested_chain(
                        tmp,
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
                absent_root = Path(tmp) / "absent-target-native-requirements"
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
                    nested_runtime = inspect_runtime(
                        nested_staging,
                        lease=nested_lease,
                    )
                    with patch.object(
                        requirements_module,
                        "_BUILTIN_PREAD",
                        side_effect=AssertionError("native input read bytes"),
                    ):
                        receipt = self._inspect(
                            nested_runtime,
                            nested_staging,
                            nested_lease,
                        )
                    self.assertEqual(receipt.unique_nested_target_count, 0)
                    self.assertEqual(
                        receipt.target_native_not_applicable_count,
                        2,
                    )
                    self.assertFalse(absent_root.exists())
                finally:
                    if nested_lease.state == "active":
                        nested_lease.close()
                    guard_fixture._close_chain(chain)
