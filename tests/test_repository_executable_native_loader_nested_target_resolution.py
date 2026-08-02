from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata import (
    repository_executable_native_loader_nested_target_resolution
    as nested_module,
)
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_loader_nested_target_resolution import (
    CYCLE_SCOPE,
    MAXIMUM_RESOLUTION_DEPTH,
    MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION,
    RESOLUTION_DEPTH,
    RESOLUTION_SCOPE,
    RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt,
    inspect_staged_executable_native_loader_nested_targets,
)
from ordomata.repository_executable_native_loader_target_loader_requirements import (
    inspect_staged_executable_native_loader_target_loader_requirements,
)
from ordomata.repository_executable_native_loader_target_resolution import (
    inspect_staged_executable_native_loader_targets,
)
from ordomata.repository_executable_native_loader_target_runtime_manifest import (
    inspect_staged_executable_native_loader_target_runtime_manifest,
)
from ordomata.repository_executable_native_loader_target_staging import (
    RepositoryExecutableNativeLoaderTargetStageLease,
    stage_repository_executable_native_loader_target_bytes,
)

if __package__:
    from . import (
        test_repository_executable_native_loader_requirements
        as native_fixture,
    )
    from . import (
        test_repository_executable_native_loader_target_resolution
        as target_fixture,
    )
else:
    import test_repository_executable_native_loader_requirements as native_fixture
    import test_repository_executable_native_loader_target_resolution as target_fixture


FIXED_ERROR = (
    "repository executable native loader nested target resolution is invalid"
)


@unittest.skipUnless(os.name == "posix", "nested loader measurement requires POSIX")
class RepositoryExecutableNativeLoaderNestedTargetResolutionTests(
    unittest.TestCase
):
    fixture = target_fixture.RepositoryExecutableNativeLoaderTargetResolutionTests

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
        same_first_target: bool = False,
        same_nested_target: bool = False,
        no_first_targets: bool = False,
        first_content_kind: str = "elf_declared",
        nested_reentry: bool = False,
        nested_hardlink_alias: bool = False,
        nested_under_stage_root: bool = False,
        nested_source_reentry: bool = False,
        nested_source_hardlink_alias: bool = False,
        nested_under_source_stage_root: bool = False,
    ) -> dict[str, object]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root, _outside, search_one, search_two, source_stage_root = (
            self.fixture._workspace(temporary.name)
        )
        target_stage_root = (
            Path(temporary.name).resolve(strict=True)
            / "private-nested-loader-stage-root"
        )
        target_stage_root.mkdir(mode=0o700)
        target_stage_root.chmod(0o700)
        first_one = root.parent / "private-first-loader-one"
        first_two = (
            first_one
            if same_first_target
            else root.parent / "private-first-loader-two"
        )
        nested_one = root.parent / "private-nested-loader-one"
        nested_two = (
            nested_one
            if same_nested_target
            else root.parent / "private-nested-loader-two"
        )
        source_bare_path = search_one / "private-bare-tool-marker"
        source_relative_path = (
            root
            / "private-source-path-marker"
            / "private-relative-tool-marker"
        )
        if nested_source_reentry:
            nested_one = source_bare_path
            nested_two = (
                source_bare_path
                if same_first_target
                else source_relative_path
            )
        elif nested_source_hardlink_alias:
            nested_one = root.parent / "private-source-hardlink-alias"
            nested_two = nested_one
        elif nested_under_source_stage_root:
            nested_one = source_stage_root / "private-late-nested-loader"
            nested_two = nested_one
        elif nested_reentry:
            nested_one = first_one
            nested_two = first_two
        elif nested_hardlink_alias:
            nested_one = root.parent / "private-first-loader-hardlink"
            nested_two = nested_one
        elif nested_under_stage_root:
            nested_one = target_stage_root / "private-late-nested-loader"
            nested_two = nested_one

        if no_first_targets:
            source_bare = native_fixture._elf64(None)
            source_relative = b"#!/usr/bin/python3\nprivate-non-native-source\n"
            first_paths: tuple[Path, ...] = ()
            nested_paths: tuple[Path, ...] = ()
        else:
            if first_content_kind == "elf_declared":
                first_content = native_fixture._elf64(os.fsencode(nested_one))
            elif first_content_kind == "elf_absent":
                first_content = native_fixture._elf64(None)
            elif first_content_kind == "mach_absent":
                first_content = native_fixture._mach64(None)
            elif first_content_kind == "unsupported":
                first_content = native_fixture._fat_mach64()
            elif first_content_kind == "non_native":
                first_content = b"#!/usr/bin/python3 -I\nprivate-loader-script\n"
            else:
                raise AssertionError("unknown test content kind")
            second_content = native_fixture._mach64(os.fsencode(nested_two))
            self.fixture._write_target(first_one, first_content)
            if first_two != first_one:
                self.fixture._write_target(first_two, second_content)
            if nested_hardlink_alias:
                os.link(first_one, nested_one)
            elif not any(
                (
                    nested_reentry,
                    nested_under_stage_root,
                    nested_source_reentry,
                    nested_source_hardlink_alias,
                    nested_under_source_stage_root,
                )
            ):
                self.fixture._write_target(
                    nested_one,
                    b"private-nested-loader-one-bytes\n",
                )
                if nested_two != nested_one:
                    self.fixture._write_target(
                        nested_two,
                        b"private-nested-loader-two-bytes\n",
                    )
            source_bare = native_fixture._elf64(os.fsencode(first_one))
            source_relative = native_fixture._mach64(os.fsencode(first_two))
            first_paths = (
                (first_one,)
                if same_first_target
                else (first_one, first_two)
            )
            if first_content_kind in {
                "elf_absent",
                "mach_absent",
                "unsupported",
                "non_native",
            } and same_first_target:
                nested_paths = ()
            else:
                nested_paths = (
                    (nested_one,)
                    if same_first_target or nested_two == nested_one
                    else (nested_one, nested_two)
                )

        self.fixture._set_contents(
            root,
            search_one,
            bare=source_bare,
            relative=source_relative,
        )
        if nested_source_hardlink_alias:
            os.link(source_bare_path, nested_one)
        registration = self.fixture._registration(root)
        source_lease, source_staging, source_runtime, source_requirements = (
            self.fixture._stage_chain(
                registration,
                (search_one, search_two),
                source_stage_root,
            )
        )
        self.addCleanup(source_lease.close)
        if nested_under_source_stage_root:
            self.fixture._write_target(
                nested_one,
                b"private-source-stage-root-nested-loader\n",
            )
        first_resolution = inspect_staged_executable_native_loader_targets(
            source_requirements,
            expected_runtime=source_runtime,
            expected_staging=source_staging,
            lease=source_lease,
            expected_loader_paths=first_paths,
        )
        target_lease = RepositoryExecutableNativeLoaderTargetStageLease(
            target_stage_root
        )
        target_staging = stage_repository_executable_native_loader_target_bytes(
            registration,
            search_directories=(search_one, search_two),
            expected_target_resolution=first_resolution,
            expected_requirements=source_requirements,
            expected_runtime=source_runtime,
            expected_staging=source_staging,
            executable_lease=source_lease,
            expected_loader_paths=first_paths,
            lease=target_lease,
        )
        self.addCleanup(target_lease.close)
        target_runtime = (
            inspect_staged_executable_native_loader_target_runtime_manifest(
                target_staging,
                lease=target_lease,
            )
        )
        target_requirements = (
            inspect_staged_executable_native_loader_target_loader_requirements(
                target_runtime,
                expected_target_staging=target_staging,
                lease=target_lease,
            )
        )
        return {
            "first_paths": first_paths,
            "first_resolution": first_resolution,
            "nested_paths": nested_paths,
            "nested_one": nested_one,
            "registration": registration,
            "root": root,
            "source_lease": source_lease,
            "source_staging": source_staging,
            "target_lease": target_lease,
            "target_requirements": target_requirements,
            "target_runtime": target_runtime,
            "target_stage_root": target_stage_root,
            "target_staging": target_staging,
        }

    def _inspect(self, chain: dict[str, object]):
        return inspect_staged_executable_native_loader_nested_targets(
            chain["target_requirements"],
            expected_target_runtime=chain["target_runtime"],
            expected_target_staging=chain["target_staging"],
            expected_target_resolution=chain["first_resolution"],
            lease=chain["target_lease"],
            expected_loader_paths=chain["first_paths"],
            expected_nested_loader_paths=chain["nested_paths"],
        )

    def _assert_invalid(
        self,
        chain: dict[str, object],
        *,
        marker: str = "private-nested-loader-error-marker",
        **overrides: object,
    ) -> None:
        arguments = {
            "expected_target_runtime": chain["target_runtime"],
            "expected_target_staging": chain["target_staging"],
            "expected_target_resolution": chain["first_resolution"],
            "lease": chain["target_lease"],
            "expected_loader_paths": chain["first_paths"],
            "expected_nested_loader_paths": chain["nested_paths"],
        }
        arguments.update(overrides)
        with self.assertRaises(ValidationError) as caught:
            inspect_staged_executable_native_loader_nested_targets(
                chain["target_requirements"],
                **arguments,
            )
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertNotIn(marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_declared_elf_and_mach_targets_are_measured_once(self) -> None:
        chain = self._chain()
        before = self._lease_snapshot(chain["target_lease"])
        receipt = self._inspect(chain)
        repeated = self._inspect(chain)

        self.assertEqual(receipt, repeated)
        self.assertEqual(before, self._lease_snapshot(chain["target_lease"]))
        self.assertIsInstance(
            receipt,
            RepositoryExecutableNativeLoaderNestedTargetResolutionReceipt,
        )
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.lineage_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.unique_nested_target_count, 2)
        self.assertEqual(receipt.declared_nested_target_requirement_count, 2)
        self.assertEqual(receipt.no_nested_target_requirement_count, 0)
        self.assertEqual(receipt.resolution_depth, 2)
        self.assertEqual(receipt.maximum_resolution_depth, 2)
        self.assertEqual(
            {item.nested_target_disposition for item in receipt.requirements},
            {"declared_nested_loader_target_measured"},
        )
        self.assertEqual(
            receipt.target_loader_requirements_receipt_digest,
            chain["target_requirements"].receipt_digest,
        )
        self.assertEqual(
            receipt.target_resolution_receipt_digest,
            chain["first_resolution"].receipt_digest,
        )

        canonical_text = json.dumps(receipt.to_canonical(), sort_keys=True)
        evidence_text = json.dumps(receipt.to_evidence(), sort_keys=True)
        for private_path in (
            str(chain["root"]),
            str(chain["nested_one"]),
            str(chain["target_stage_root"]),
        ):
            self.assertNotIn(private_path, canonical_text)
            self.assertNotIn(private_path, evidence_text)
            self.assertNotIn(private_path, repr(receipt))
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(evidence["immediate_target_identity_reentry_excluded"])
        self.assertTrue(evidence["target_staging_root_reentry_excluded"])
        self.assertFalse(evidence["execution_enabled"])
        self.assertFalse(evidence["model_invocation_performed"])
        self.assertFalse(evidence["network_access_performed"])

    def test_shared_nested_target_deduplicates_measurement(self) -> None:
        chain = self._chain(same_nested_target=True)
        receipt = self._inspect(chain)

        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.unique_nested_target_count, 1)
        self.assertEqual(
            len(
                {
                    item.nested_target_measurement_ref
                    for item in receipt.requirements
                }
            ),
            1,
        )

    def test_fixed_non_declared_dispositions_do_not_read_targets(self) -> None:
        cases = (
            ("elf_absent", "loader_declaration_absent"),
            ("mach_absent", "loader_declaration_absent"),
            ("unsupported", "unsupported_native_layout"),
            ("non_native", "non_native_not_applicable"),
        )
        for content_kind, expected in cases:
            with self.subTest(content_kind=content_kind):
                chain = self._chain(
                    same_first_target=True,
                    first_content_kind=content_kind,
                )
                with patch(
                    "ordomata.repository_executable_shebang_nested_target_"
                    "resolution._BUILTIN_READ",
                    side_effect=AssertionError("unexpected leaf read"),
                ):
                    receipt = self._inspect(chain)
                self.assertEqual(receipt.requirement_count, 1)
                self.assertEqual(receipt.unique_nested_target_count, 0)
                self.assertEqual(
                    receipt.requirements[0].nested_target_disposition,
                    expected,
                )

    def test_no_first_targets_preserves_lineage_without_lookup(self) -> None:
        chain = self._chain(no_first_targets=True)
        with patch(
            "ordomata.repository_executable_shebang_nested_target_"
            "resolution._BUILTIN_READ",
            side_effect=AssertionError("unexpected leaf read"),
        ):
            receipt = self._inspect(chain)

        self.assertEqual(receipt.requirement_count, 0)
        self.assertEqual(receipt.unique_nested_target_count, 0)
        self.assertEqual(receipt.target_loader_lineage_count, 0)
        self.assertEqual(receipt.no_target_lineage_count, receipt.lineage_count)
        self.assertGreater(receipt.lineage_count, 0)
        self.assertEqual(receipt.command_count, receipt.lineage_count)

    def test_exact_ordered_path_expectations_fail_before_leaf_read(self) -> None:
        chain = self._chain()
        first_paths = chain["first_paths"]
        nested_paths = chain["nested_paths"]
        cases = (
            {"expected_loader_paths": list(first_paths)},
            {"expected_loader_paths": tuple(reversed(first_paths))},
            {"expected_nested_loader_paths": list(nested_paths)},
            {"expected_nested_loader_paths": tuple(reversed(nested_paths))},
            {"expected_nested_loader_paths": nested_paths[:1]},
            {"expected_nested_loader_paths": nested_paths + nested_paths[:1]},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with patch(
                    "ordomata.repository_executable_shebang_nested_target_"
                    "resolution._BUILTIN_READ",
                    side_effect=AssertionError("unexpected leaf read"),
                ):
                    self._assert_invalid(chain, **overrides)

    def test_exact_first_target_path_reentry_fails_before_leaf_read(self) -> None:
        chain = self._chain(
            same_first_target=True,
            nested_reentry=True,
        )
        with patch(
            "ordomata.repository_executable_shebang_nested_target_"
            "resolution._BUILTIN_READ",
            side_effect=AssertionError("unexpected leaf read"),
        ):
            self._assert_invalid(chain)

    def test_first_target_hardlink_reentry_fails_before_leaf_read(self) -> None:
        chain = self._chain(
            same_first_target=True,
            nested_hardlink_alias=True,
        )
        with patch(
            "ordomata.repository_executable_shebang_nested_target_"
            "resolution._BUILTIN_READ",
            side_effect=AssertionError("unexpected leaf read"),
        ):
            self._assert_invalid(chain)

    def test_target_staging_root_reentry_fails_before_leaf_read(self) -> None:
        chain = self._chain(
            same_first_target=True,
            nested_under_stage_root=True,
        )
        with patch(
            "ordomata.repository_executable_shebang_nested_target_"
            "resolution._BUILTIN_READ",
            side_effect=AssertionError("unexpected leaf read"),
        ):
            self._assert_invalid(chain)

    def test_forged_chain_and_closed_lease_fail_with_fixed_error(self) -> None:
        chain = self._chain(same_first_target=True)
        for key in (
            "target_requirements",
            "target_runtime",
            "target_staging",
            "first_resolution",
        ):
            with self.subTest(key=key):
                forged_chain = dict(chain)
                forged_chain[key] = replace(
                    chain[key],
                    registration_digest="sha256:" + "0" * 64,
                )
                self._assert_invalid(forged_chain)

        chain["target_lease"].close()
        self._assert_invalid(chain)

    def test_three_chain_reproductions_two_measurements_and_closing_anchor(
        self,
    ) -> None:
        chain = self._chain(same_first_target=True)
        inspect_requirements = (
            nested_module._BUILTIN_INSPECT_LOADER_REQUIREMENTS
        )
        snapshot = nested_module._BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT
        measure = nested_module._BUILTIN_MEASURE_GUARDED_TARGET_SET
        with patch.object(
            nested_module,
            "_BUILTIN_INSPECT_LOADER_REQUIREMENTS",
            wraps=inspect_requirements,
        ) as inspect_mock, patch.object(
            nested_module,
            "_BUILTIN_ACTIVE_TARGET_STAGE_SNAPSHOT",
            wraps=snapshot,
        ) as snapshot_mock, patch.object(
            nested_module,
            "_BUILTIN_MEASURE_GUARDED_TARGET_SET",
            wraps=measure,
        ) as measure_mock:
            self._inspect(chain)

        self.assertEqual(inspect_mock.call_count, 3)
        self.assertEqual(snapshot_mock.call_count, 4)
        self.assertEqual(measure_mock.call_count, 2)

    def test_two_pass_measurement_detects_nested_target_drift(self) -> None:
        chain = self._chain(same_first_target=True)
        nested_path = chain["nested_one"]
        real_measure = nested_module._BUILTIN_MEASURE_GUARDED_TARGET_SET
        calls = 0

        def drifting_measure(*args: object, **kwargs: object):
            nonlocal calls
            result = real_measure(*args, **kwargs)
            calls += 1
            if calls == 1:
                nested_path.write_bytes(b"private-drifted-loader-bytes\n")
                nested_path.chmod(0o755)
            return result

        with patch.object(
            nested_module,
            "_BUILTIN_MEASURE_GUARDED_TARGET_SET",
            side_effect=drifting_measure,
        ):
            self._assert_invalid(chain)
        self.assertEqual(calls, 2)

    def test_receipt_projection_rejects_forgery_and_is_immutable(self) -> None:
        receipt = self._inspect(self._chain(same_first_target=True))
        with self.assertRaises(FrozenInstanceError):
            receipt.requirement_count = 999
        for forged in (
            replace(receipt, requirement_count=999),
            replace(receipt, unique_nested_target_count=999),
            replace(receipt, total_measured_bytes=999),
            replace(receipt, resolution_depth=3),
        ):
            with self.assertRaises(ValueError):
                forged.to_canonical()

    def test_contract_exports_signature_and_captured_helpers(self) -> None:
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_KIND,
            "repository_executable_native_loader_nested_target_resolution",
        )
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_RESOLUTION_SCHEMA_VERSION,
            1,
        )
        self.assertEqual(MEASUREMENT_SOURCE, "controller_measured")
        self.assertEqual(
            RESOLUTION_SCOPE,
            "native_loader_nested_declared_absolute_target_nofollow_v1",
        )
        self.assertEqual(RESOLUTION_DEPTH, 2)
        self.assertEqual(MAXIMUM_RESOLUTION_DEPTH, 2)
        self.assertEqual(
            CYCLE_SCOPE,
            "immediate_native_loader_target_reentry_v1",
        )
        signature = inspect.signature(
            inspect_staged_executable_native_loader_nested_targets
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_loader_requirements",
                "expected_target_runtime",
                "expected_target_staging",
                "expected_target_resolution",
                "lease",
                "expected_loader_paths",
                "expected_nested_loader_paths",
            ),
        )
        self.assertEqual(
            nested_module.__all__[-1],
            "inspect_staged_executable_native_loader_nested_targets",
        )

        chain = self._chain(same_first_target=True)
        with patch.object(
            nested_module,
            "_validated_chain_snapshot",
            side_effect=AssertionError("uncaptured helper used"),
        ):
            self.assertEqual(self._inspect(chain), self._inspect(chain))

    def test_no_subprocess_network_model_or_lease_mutation(self) -> None:
        chain = self._chain(same_first_target=True)
        before = self._lease_snapshot(chain["target_lease"])
        with patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("subprocess invoked"),
        ), patch.object(
            socket,
            "socket",
            side_effect=AssertionError("network invoked"),
        ), patch.object(
            os,
            "system",
            side_effect=AssertionError("shell invoked"),
        ):
            receipt = self._inspect(chain)
        self.assertEqual(receipt.to_evidence()["effect_class"], 0)
        self.assertEqual(before, self._lease_snapshot(chain["target_lease"]))

    def test_keyboard_interrupt_and_system_exit_are_preserved(self) -> None:
        chain = self._chain(same_first_target=True)
        for signal in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(signal=type(signal).__name__):
                with patch.object(
                    nested_module,
                    "_BUILTIN_VALIDATED_CHAIN_SNAPSHOT",
                    side_effect=signal,
                ):
                    with self.assertRaises(type(signal)):
                        self._inspect(chain)


if __name__ == "__main__":
    unittest.main()
