from __future__ import annotations

import builtins
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import importlib
import inspect
import json
import os
import socket
import subprocess
import unittest
from unittest.mock import patch

from ordomata import (
    repository_executable_native_loader_target_loader_requirements
    as loader_module,
)
from ordomata import (
    repository_executable_native_loader_target_runtime_manifest
    as runtime_module,
)
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_loader_target_loader_requirements import (
    RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt,
    inspect_staged_executable_native_loader_target_loader_requirements,
)
from ordomata.repository_executable_native_loader_target_runtime_manifest import (
    inspect_staged_executable_native_loader_target_runtime_manifest,
)

if __package__:
    from . import (
        test_repository_executable_native_loader_requirements as native_fixture,
    )
    from . import (
        test_repository_executable_native_loader_target_runtime_manifest
        as runtime_fixture,
    )
else:
    import test_repository_executable_native_loader_requirements as native_fixture
    runtime_fixture = importlib.import_module(
        "test_repository_executable_native_loader_target_runtime_manifest"
    )


FIXED_ERROR = (
    "repository executable native loader target loader requirements are invalid"
)


@unittest.skipUnless(os.name == "posix", "loader syntax inspection requires POSIX")
class RepositoryExecutableNativeLoaderTargetLoaderRequirementsTests(
    unittest.TestCase
):
    runtime_test_type = (
        runtime_fixture.RepositoryExecutableNativeLoaderTargetRuntimeManifestTests
    )
    fixture = runtime_test_type.fixture
    _write_target = staticmethod(
        runtime_test_type._write_target
    )
    _lease_snapshot = staticmethod(
        runtime_test_type._lease_snapshot
    )
    _chain = runtime_test_type._chain

    def _inspect(self, *, content: bytes, same_target: bool = True):
        lease, staging, paths, stage_root = self._chain(
            first_content=content,
            same_target=same_target,
        )
        runtime = inspect_staged_executable_native_loader_target_runtime_manifest(
            staging,
            lease=lease,
        )
        receipt = (
            inspect_staged_executable_native_loader_target_loader_requirements(
                runtime,
                expected_target_staging=staging,
                lease=lease,
            )
        )
        return receipt, runtime, staging, lease, paths, stage_root

    def _assert_invalid(
        self,
        runtime: object,
        staging: object,
        lease: object,
        *,
        marker: str = "private-target-loader-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_loader_target_loader_requirements(
                runtime,
                expected_target_staging=staging,
                lease=lease,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_fixed_loader_of_loader_dispositions(self) -> None:
        cases = (
            (
                "elf_interpreter_absent",
                native_fixture._elf64(None),
                "elf64",
                0,
            ),
            (
                "elf_interpreter_declared",
                native_fixture._elf64(b"/private/nested-elf-loader"),
                "elf64",
                len(b"/private/nested-elf-loader"),
            ),
            (
                "mach_o_dylinker_absent",
                native_fixture._mach64(None),
                "mach_o64",
                0,
            ),
            (
                "mach_o_dylinker_declared",
                native_fixture._mach64(b"/private/nested-mach-loader"),
                "mach_o64",
                len(b"/private/nested-mach-loader"),
            ),
            (
                "unsupported_native_layout",
                native_fixture._fat_mach64(),
                "mach_o_fat64",
                0,
            ),
            (
                "non_native_not_applicable",
                b"#!/usr/bin/python3 -I\nprivate-loader-script\n",
                None,
                0,
            ),
        )
        for disposition, content, format_class, path_bytes in cases:
            with self.subTest(disposition=disposition):
                receipt, *_unused = self._inspect(content=content)
                self.assertEqual(receipt.requirement_count, 1)
                self.assertEqual(receipt.lineage_count, 2)
                self.assertEqual(
                    receipt.requirements[0].disposition,
                    disposition,
                )
                self.assertEqual(
                    receipt.requirements[0].format_class,
                    format_class,
                )
                self.assertEqual(
                    receipt.requirements[0].loader_path_bytes,
                    path_bytes,
                )
                self.assertEqual(
                    receipt.nested_loader_declared_count,
                    int(disposition.endswith("_declared")),
                )
                evidence = receipt.to_evidence()
                self.assertEqual(
                    evidence[f"{disposition}_count"],
                    1,
                )

    def test_shared_target_deduplicates_syntax_but_preserves_lineage(self) -> None:
        receipt, runtime, staging, *_unused = self._inspect(
            content=native_fixture._elf64(None),
        )
        self.assertEqual(runtime.file_count, 1)
        self.assertEqual(receipt.requirement_count, 1)
        self.assertEqual(receipt.lineage_count, staging.requirement_count)
        self.assertEqual(receipt.command_count, staging.command_count)
        self.assertEqual(receipt.target_required_lineage_count, 2)
        requirement_ref = receipt.requirements[0].target_loader_requirement_ref
        self.assertEqual(
            {item.target_loader_requirement_ref for item in receipt.lineages},
            {requirement_ref},
        )

    def test_no_target_receipt_performs_no_descriptor_read(self) -> None:
        lease, staging, _paths, stage_root = self._chain(no_targets=True)
        runtime = inspect_staged_executable_native_loader_target_runtime_manifest(
            staging,
            lease=lease,
        )
        marker = stage_root / "private-no-target-loader-marker"
        marker.write_text("untouched", encoding="utf-8")
        with patch.object(
            runtime_module,
            "_BUILTIN_PREAD",
            side_effect=AssertionError("private-unexpected-read-marker"),
        ) as pread:
            receipt = (
                inspect_staged_executable_native_loader_target_loader_requirements(
                    runtime,
                    expected_target_staging=staging,
                    lease=lease,
                )
            )
        self.assertEqual(receipt.requirement_count, 0)
        self.assertEqual(receipt.target_required_lineage_count, 0)
        self.assertEqual(receipt.no_target_lineage_count, 2)
        self.assertEqual(receipt.total_loader_path_bytes, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "untouched")
        pread.assert_not_called()

    def test_receipt_privacy_lineage_and_lease_immutability(self) -> None:
        private_path = b"/private/loader-of-loader-secret-marker"
        private_content = native_fixture._elf64(private_path)
        receipt, runtime, staging, lease, paths, stage_root = self._inspect(
            content=private_content,
        )
        before = self._lease_snapshot(lease)
        repeated = (
            inspect_staged_executable_native_loader_target_loader_requirements(
                runtime,
                expected_target_staging=staging,
                lease=lease,
            )
        )
        self.assertEqual(repeated, receipt)
        self.assertEqual(self._lease_snapshot(lease), before)
        self.assertIsInstance(
            receipt,
            RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt,
        )
        self.assertEqual(
            receipt.target_runtime_manifest_receipt_digest,
            runtime.receipt_digest,
        )
        self.assertEqual(
            receipt.target_staging_receipt_digest,
            staging.receipt_digest,
        )
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertEqual(evidence["validation_mode"], "read_only")
        self.assertTrue(
            evidence["bounded_loader_of_loader_syntax_inspection_complete"]
        )
        self.assertFalse(evidence["authority_granted"])
        self.assertFalse(evidence["execution_enabled"])
        self.assertFalse(evidence["recursive_native_loader_resolution_verified"])
        aggregate = "\n".join(
            (
                json.dumps(receipt.to_canonical(), sort_keys=True),
                json.dumps(evidence, sort_keys=True),
                repr(receipt),
            )
        )
        for private in (
            private_path.decode(),
            private_content.hex(),
            *(os.fspath(path) for path in paths),
            os.fspath(stage_root),
        ):
            self.assertNotIn(private, aggregate)
        with self.assertRaises(FrozenInstanceError):
            receipt.requirement_count = 0

    def test_tampered_inputs_and_inactive_lease_fail_closed(self) -> None:
        _receipt, runtime, staging, lease, *_unused = self._inspect(
            content=native_fixture._elf64(None),
        )
        for forged_runtime, forged_staging in (
            (None, staging),
            (runtime, None),
            (
                replace(
                    runtime,
                    target_staging_receipt_digest="sha256:" + "0" * 64,
                ),
                staging,
            ),
            (
                runtime,
                replace(staging, repository_ref="sha256:" + "0" * 64),
            ),
        ):
            with self.subTest(
                runtime=repr(forged_runtime),
                staging=repr(forged_staging),
            ):
                self._assert_invalid(forged_runtime, forged_staging, lease)
        lease.close()
        self._assert_invalid(runtime, staging, lease)

    def test_exports_signature_interrupts_and_fixed_errors_are_exact(self) -> None:
        expected_exports = {
            "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_BINDING_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_LINEAGE_KIND",
            "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_REQUIREMENT_KIND",
            (
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_"
                "REQUIREMENTS_EVIDENCE_KIND"
            ),
            (
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_"
                "REQUIREMENTS_KIND"
            ),
            (
                "REPOSITORY_EXECUTABLE_NATIVE_LOADER_TARGET_LOADER_"
                "REQUIREMENTS_SCHEMA_VERSION"
            ),
            "REQUIREMENTS_SCOPE",
            "REQUIREMENTS_SOURCE",
            "RepositoryExecutableNativeLoaderTargetLoaderBinding",
            "RepositoryExecutableNativeLoaderTargetLoaderLineage",
            "RepositoryExecutableNativeLoaderTargetLoaderRequirement",
            "RepositoryExecutableNativeLoaderTargetLoaderRequirementsReceipt",
            (
                "inspect_staged_executable_native_loader_target_"
                "loader_requirements"
            ),
        }
        self.assertEqual(set(loader_module.__all__), expected_exports)
        signature = inspect.signature(
            inspect_staged_executable_native_loader_target_loader_requirements
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_target_runtime",
                "expected_target_staging",
                "lease",
            ),
        )
        self.assertEqual(
            signature.parameters["expected_target_staging"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            signature.parameters["lease"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )

        _receipt, runtime, staging, lease, *_unused = self._inspect(
            content=native_fixture._elf64(None),
        )
        with patch.object(
            loader_module,
            "_BUILTIN_REMEASURE_REQUIREMENTS",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                inspect_staged_executable_native_loader_target_loader_requirements(
                    runtime,
                    expected_target_staging=staging,
                    lease=lease,
                )
        marker = "private-parser-failure-marker"
        with patch.object(
            loader_module,
            "_BUILTIN_REMEASURE_REQUIREMENTS",
            side_effect=RuntimeError(marker),
        ):
            self._assert_invalid(runtime, staging, lease, marker=marker)

    def test_fresh_runtime_and_remeasurement_drift_fail_closed(self) -> None:
        _receipt, runtime, staging, lease, *_unused = self._inspect(
            content=native_fixture._elf64(None),
        )
        real_runtime = loader_module._BUILTIN_INSPECT_TARGET_RUNTIME
        calls = 0

        def drift(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_runtime(*args, **kwargs)
            if calls == 2:
                return replace(result, total_header_bytes=0)
            return result

        with patch.object(
            loader_module,
            "_BUILTIN_INSPECT_TARGET_RUNTIME",
            side_effect=drift,
        ):
            self._assert_invalid(runtime, staging, lease)

        real_remeasure = loader_module._BUILTIN_REMEASURE_REQUIREMENTS
        remeasure_calls = 0

        def changed(*args, **kwargs):
            nonlocal remeasure_calls
            remeasure_calls += 1
            result = real_remeasure(*args, **kwargs)
            if remeasure_calls == 2:
                return (
                    replace(
                        result[0],
                        disposition="unsupported_native_layout",
                        image_kind=None,
                        layout_supported=False,
                    ),
                )
            return result

        with patch.object(
            loader_module,
            "_BUILTIN_REMEASURE_REQUIREMENTS",
            side_effect=changed,
        ):
            self._assert_invalid(runtime, staging, lease)

    def test_projection_rejects_forged_counts_and_lineage(self) -> None:
        receipt, *_unused = self._inspect(
            content=native_fixture._elf64(None),
        )
        for forged in (
            replace(receipt, requirement_count=0),
            replace(receipt, lineage_count=0),
            replace(receipt, nested_loader_declared_count=1),
            replace(receipt, total_loader_path_bytes=1),
            replace(receipt, requirements=()),
            replace(receipt, lineages=()),
        ):
            with self.subTest(forged=repr(forged)):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

    def test_public_helper_monkeypatches_do_not_replace_proof_graph(self) -> None:
        _receipt, runtime, staging, lease, *_unused = self._inspect(
            content=native_fixture._elf64(None),
        )
        poison = AssertionError("private-public-monkeypatch-marker")
        names = (
            "_requirement_ref_projection",
            "_requirement_projection",
            "_lineage_ref_projection",
            "_lineage_projection",
            "_binding_projection",
            "_receipt_projection",
            "_evidence_projection",
            "_build_requirement",
            "_build_lineage",
            "_remeasure_requirements",
            "_validate_runtime_stage_correspondence",
        )
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(
                    patch.object(loader_module, name, side_effect=poison)
                )
            receipt = (
                inspect_staged_executable_native_loader_target_loader_requirements(
                    runtime,
                    expected_target_staging=staging,
                    lease=lease,
                )
            )
        self.assertEqual(receipt.requirement_count, 1)

    def test_no_path_process_network_cleanup_or_lease_effects(self) -> None:
        lease, staging, _paths, _stage_root = self._chain(
            first_content=native_fixture._elf64(None),
            same_target=True,
        )
        runtime = inspect_staged_executable_native_loader_target_runtime_manifest(
            staging,
            lease=lease,
        )
        before = self._lease_snapshot(lease)
        poison = AssertionError("private-prohibited-effect-marker")
        with (
            patch.object(builtins, "open", side_effect=poison) as opened,
            patch.object(os, "open", side_effect=poison) as os_opened,
            patch.object(subprocess, "run", side_effect=poison) as run,
            patch.object(subprocess, "Popen", side_effect=poison) as popen,
            patch.object(socket, "socket", side_effect=poison) as network,
        ):
            receipt = (
                inspect_staged_executable_native_loader_target_loader_requirements(
                    runtime,
                    expected_target_staging=staging,
                    lease=lease,
                )
            )
        self.assertEqual(receipt.requirement_count, 1)
        self.assertEqual(self._lease_snapshot(lease), before)
        opened.assert_not_called()
        os_opened.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
