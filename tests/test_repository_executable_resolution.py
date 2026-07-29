from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
import ordomata.repository_executable_resolution as resolution_module
import ordomata.repository_registration as registration_module
from ordomata.repository_executable_resolution import (
    MEASUREMENT_SOURCE,
    REPOSITORY_EXECUTABLE_RESOLUTION_EVIDENCE_KIND,
    REPOSITORY_EXECUTABLE_RESOLUTION_KIND,
    REPOSITORY_EXECUTABLE_RESOLUTION_SCHEMA_VERSION,
    RESOLUTION_SCOPE,
    RepositoryExecutableResolutionReceipt,
    ResolvedExecutableMeasurement,
    fresh_repository_executable_resolution_evidence,
    resolve_repository_executables,
)
from ordomata.repository_registration import (
    BaselineCommandResults,
    ExecutableToolchainIdentities,
    RepositoryRegistration,
    validate_repository_registration,
)


FIXED_RESOLUTION_ERROR = "repository executable resolution is invalid"
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
MEASUREMENT_KEYS = {
    "command_digest",
    "command_id",
    "command_kind",
    "content_bytes",
    "content_digest",
    "declared_executable_kind",
    "declared_executable_ref",
    "filesystem_identity_ref",
    "kind",
    "metadata_digest",
    "resolution_method",
    "resolution_root_ref",
    "resolved_executable_ref",
    "search_directory_index",
}
RECEIPT_KEYS = {
    "baseline_command_results_digest",
    "executable_toolchain_identities_digest",
    "kind",
    "measurement_source",
    "measurements",
    "registration_digest",
    "repository_ref",
    "resolution_context_digest",
    "resolution_scope",
    "schema_version",
    "total_measured_bytes",
    "unique_file_count",
    "verification_commands_digest",
}
EVIDENCE_KEYS = {
    "action_time_revalidation_required",
    "action_receipt_issued",
    "authority_granted",
    "atomic_snapshot_verified",
    "baseline_execution_correspondence_verified",
    "billing_eligible",
    "capacity_eligible",
    "configuration_coverage_verified",
    "current_freshness_verified",
    "dependency_environment_coverage_verified",
    "dispatch_enabled",
    "dynamic_loader_identity_verified",
    "effective_invocability_verified",
    "environment_coverage_verified",
    "executable_authenticity_verified",
    "executable_provenance_verified",
    "future_execution_correspondence_verified",
    "interpreter_identity_verified",
    "kind",
    "launcher_identity_verified",
    "live_execution_eligible",
    "measurement_count",
    "measurement_source",
    "module_identity_verified",
    "package_identity_verified",
    "persistence_enabled",
    "plugin_identity_verified",
    "receipt_authenticity_verified",
    "receipt_digest",
    "registration_digest",
    "repository_ref",
    "resolution_context_digest",
    "resolution_scope",
    "repository_snapshot_correspondence_verified",
    "route_eligible",
    "schema_version",
    "selected_file_content_measurement_complete",
    "sequential_resolution_measurement_complete",
    "shared_library_identity_verified",
    "shebang_identity_verified",
    "toolchain_completeness_verified",
    "total_measured_bytes",
    "unique_file_count",
    "v4_identity_claim_correspondence_verified",
    "validation_mode",
}


@unittest.skipUnless(os.name == "posix", "the v1 resolver is POSIX-only")
class RepositoryExecutableResolutionTests(unittest.TestCase):
    @staticmethod
    def _write_executable(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o755)

    @classmethod
    def _workspace(
        cls,
        temporary: str,
    ) -> tuple[Path, Path, Path, Path]:
        base = Path(temporary).resolve(strict=True)
        root = base / "private-resolution-repository-marker"
        outside = base / "private-resolution-outside-marker"
        search_one = base / "private-search-one-marker"
        search_two = base / "private-search-two-marker"
        for directory in (root, outside, search_one, search_two):
            directory.mkdir()
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n",
            encoding="utf-8",
        )
        for name in (
            "private-source-path-marker",
            "private-test-path-marker",
            "private-docs-path-marker",
        ):
            (root / name).mkdir()
        (root / "private-protected-path-marker.txt").write_text(
            "controller-owned\n",
            encoding="utf-8",
        )
        cls._write_executable(
            search_one / "private-bare-tool-marker",
            b"first-controller-tool\n",
        )
        cls._write_executable(
            search_two / "private-bare-tool-marker",
            b"second-controller-tool\n",
        )
        cls._write_executable(
            root
            / "private-source-path-marker"
            / "private-relative-tool-marker",
            b"repository-relative-tool\n",
        )
        (outside / "sentinel.txt").write_text(
            "outside-unchanged\n",
            encoding="utf-8",
        )
        return root, outside, search_one, search_two

    @staticmethod
    def _payload() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "repository_registration",
            "registration_id": "private-resolution-registration-marker",
            "registration_version": "1.0.0",
            "repository": {
                "repository_id": "private-resolution-repository-id-marker",
                "vcs": "git",
                "root": ".",
            },
            "verification_commands": {
                "format": [
                    {
                        "command_id": "private-bare-command-marker",
                        "argv": ["private-bare-tool-marker", "--check"],
                        "cwd": ".",
                    }
                ],
                "lint": [],
                "type_check": [],
                "test": [
                    {
                        "command_id": "private-relative-command-marker",
                        "argv": [
                            "private-source-path-marker/"
                            "private-relative-tool-marker",
                            "--test",
                        ],
                        "cwd": ".",
                    }
                ],
                "build": [],
            },
            "path_policy": {
                "allowed_paths": [
                    "private-docs-path-marker",
                    "private-source-path-marker",
                    "private-test-path-marker",
                ],
                "protected_paths": [
                    ".agentops",
                    ".git",
                    ".ordomata",
                    "private-protected-path-marker.txt",
                ],
            },
            "resource_limits": {
                "cpu_count": 2,
                "cpu_seconds": 300,
                "memory_bytes": 1_073_741_824,
                "process_count": 64,
                "workspace_bytes": 1_073_741_824,
                "output_bytes": 4_194_304,
                "artifact_count": 64,
                "artifact_bytes": 16_777_216,
                "wall_seconds": 600,
                "idle_seconds": 120,
            },
            "isolation_requirements": {
                "backend": "local_container",
                "network_mode": "disabled",
                "non_root": True,
                "read_only_base_repository": True,
                "read_only_root_filesystem": True,
                "explicit_mounts_only": True,
                "git_metadata_hidden": True,
                "credential_paths_denied": True,
                "control_sockets_denied": True,
                "fresh_cell_per_attempt": True,
            },
            "review_policy": {
                "output": "patch_only",
                "branch_creation": False,
                "commit": False,
                "push": False,
                "pull_request": False,
                "promotion": False,
            },
        }

    @staticmethod
    def _command_digest(kind: str, command: dict[str, object]) -> str:
        return canonical_digest(
            {
                "command": {
                    "argv": list(command["argv"]),
                    "command_id": command["command_id"],
                    "cwd": command["cwd"],
                    "kind": kind,
                },
                "kind": "repository_verification_command",
                "schema_version": 1,
            }
        )

    @classmethod
    def _baseline(cls, payload: dict[str, object]) -> dict[str, object]:
        results: list[dict[str, object]] = []
        ordinal = 0
        for kind in ("format", "lint", "type_check", "test", "build"):
            for command in payload["verification_commands"][kind]:
                started_at = 1_000 + ordinal * 2_000
                results.append(
                    {
                        "kind": kind,
                        "command_id": command["command_id"],
                        "command_digest": cls._command_digest(kind, command),
                        "started_at_unix_ms": started_at,
                        "completed_at_unix_ms": started_at + 1_000,
                        "termination": {"kind": "exited", "exit_code": 0},
                    }
                )
                ordinal += 1
        return {
            "kind": "repository_baseline_command_results",
            "attestation_source": "controller_supplied",
            "snapshot_digest": "sha256:" + "b" * 64,
            "results": results,
        }

    @classmethod
    def _identities(cls, payload: dict[str, object]) -> dict[str, object]:
        identities: list[dict[str, object]] = []
        for kind in ("format", "lint", "type_check", "test", "build"):
            for command in payload["verification_commands"][kind]:
                command_id = command["command_id"]
                identities.append(
                    {
                        "kind": kind,
                        "command_id": command_id,
                        "command_digest": cls._command_digest(kind, command),
                        "executable_identity_digest": canonical_digest(
                            {"opaque_executable_claim": f"{kind}:{command_id}"}
                        ),
                        "toolchain_identity_digest": canonical_digest(
                            {"opaque_toolchain_claim": f"{kind}:{command_id}"}
                        ),
                    }
                )
        return {
            "kind": "repository_executable_toolchain_identities",
            "attestation_source": "controller_supplied",
            "identities": identities,
        }

    @classmethod
    def _versioned_payload(cls, schema_version: int) -> dict[str, object]:
        payload = cls._payload()
        if schema_version >= 2:
            payload["schema_version"] = schema_version
            payload["path_policy"]["generated_paths"] = []
            payload["path_policy"]["vendor_paths"] = []
        if schema_version >= 3:
            payload["baseline_command_results"] = cls._baseline(payload)
        if schema_version >= 4:
            payload["executable_toolchain_identities"] = cls._identities(
                payload
            )
        return payload

    @classmethod
    def _registration(
        cls,
        root: Path,
        *,
        payload: dict[str, object] | None = None,
        schema_version: int = 4,
    ) -> RepositoryRegistration:
        return validate_repository_registration(
            payload or cls._versioned_payload(schema_version),
            repository_root=root,
        )

    @staticmethod
    def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
        entries: list[tuple[object, ...]] = []
        for directory, directory_names, file_names in os.walk(
            root,
            followlinks=False,
        ):
            parent = Path(directory)
            for name in sorted((*directory_names, *file_names)):
                path = parent / name
                relative = path.relative_to(root).as_posix()
                metadata = path.lstat()
                mode = stat.S_IMODE(metadata.st_mode)
                if path.is_symlink():
                    entries.append((relative, "symlink", mode, os.readlink(path)))
                elif path.is_dir():
                    entries.append((relative, "directory", mode))
                else:
                    entries.append(
                        (
                            relative,
                            "file",
                            mode,
                            hashlib.sha256(path.read_bytes()).hexdigest(),
                        )
                    )
        return tuple(sorted(entries))

    def _assert_resolution_invalid(
        self,
        registration: RepositoryRegistration,
        search_directories: object,
        *,
        private_marker: str = "private-resolution-error-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            resolve_repository_executables(
                registration,
                search_directories=search_directories,
            )
        self.assertEqual(str(caught.exception), FIXED_RESOLUTION_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_receipt_is_command_linked_deterministic_and_aggregate_private(
        self,
    ) -> None:
        self.assertEqual(
            REPOSITORY_EXECUTABLE_RESOLUTION_KIND,
            "repository_executable_resolution",
        )
        self.assertEqual(REPOSITORY_EXECUTABLE_RESOLUTION_SCHEMA_VERSION, 1)
        self.assertEqual(
            REPOSITORY_EXECUTABLE_RESOLUTION_EVIDENCE_KIND,
            "repository_executable_resolution_validation",
        )
        self.assertEqual(MEASUREMENT_SOURCE, "controller_measured")
        self.assertEqual(RESOLUTION_SCOPE, "posix_nofollow_v1")
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            receipt = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            repeated = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )

            self.assertIsInstance(
                receipt,
                RepositoryExecutableResolutionReceipt,
            )
            self.assertEqual(receipt, repeated)
            canonical = receipt.to_canonical()
            self.assertEqual(set(canonical), RECEIPT_KEYS)
            self.assertEqual(canonical["kind"], REPOSITORY_EXECUTABLE_RESOLUTION_KIND)
            self.assertEqual(canonical["schema_version"], 1)
            self.assertEqual(canonical["measurement_source"], MEASUREMENT_SOURCE)
            self.assertEqual(canonical["resolution_scope"], RESOLUTION_SCOPE)
            self.assertEqual(
                canonical["registration_digest"],
                registration.registration_digest,
            )
            self.assertEqual(receipt.receipt_digest, canonical_digest(canonical))
            self.assertEqual(len(canonical["measurements"]), 2)
            self.assertEqual(canonical["unique_file_count"], 2)
            self.assertEqual(
                canonical["total_measured_bytes"],
                len(b"first-controller-tool\n")
                + len(b"repository-relative-tool\n"),
            )

            bare, relative = canonical["measurements"]
            for measurement in (bare, relative):
                self.assertEqual(set(measurement), MEASUREMENT_KEYS)
                self.assertEqual(
                    measurement["kind"],
                    "repository_executable_measurement",
                )
                for field in (
                    "command_digest",
                    "declared_executable_ref",
                    "filesystem_identity_ref",
                    "metadata_digest",
                    "resolution_root_ref",
                    "resolved_executable_ref",
                    "content_digest",
                ):
                    self.assertRegex(
                        measurement[field],
                        r"^sha256:[0-9a-f]{64}$",
                    )
            self.assertEqual(bare["command_kind"], "format")
            self.assertEqual(bare["search_directory_index"], 0)
            self.assertEqual(bare["declared_executable_kind"], "path_search")
            self.assertEqual(
                bare["content_digest"],
                "sha256:"
                + hashlib.sha256(b"first-controller-tool\n").hexdigest(),
            )
            self.assertEqual(relative["command_kind"], "test")
            self.assertIsNone(relative["search_directory_index"])
            self.assertEqual(
                relative["declared_executable_kind"],
                "repository_relative",
            )
            self.assertEqual(
                relative["content_digest"],
                "sha256:"
                + hashlib.sha256(b"repository-relative-tool\n").hexdigest(),
            )

            evidence = receipt.to_evidence()
            self.assertEqual(
                fresh_repository_executable_resolution_evidence(
                    registration,
                    search_directories=(search_one, search_two),
                ),
                evidence,
            )
            self.assertEqual(set(evidence), EVIDENCE_KEYS)
            self.assertEqual(
                evidence["kind"],
                REPOSITORY_EXECUTABLE_RESOLUTION_EVIDENCE_KIND,
            )
            self.assertEqual(evidence["validation_mode"], "read_only")
            self.assertEqual(evidence["measurement_count"], 2)
            self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
            self.assertIs(evidence["action_time_revalidation_required"], True)
            self.assertIs(
                evidence["sequential_resolution_measurement_complete"],
                True,
            )
            self.assertIs(
                evidence["selected_file_content_measurement_complete"],
                True,
            )
            for false_fact in (
                "authority_granted",
                "atomic_snapshot_verified",
                "baseline_execution_correspondence_verified",
                "action_receipt_issued",
                "billing_eligible",
                "capacity_eligible",
                "configuration_coverage_verified",
                "current_freshness_verified",
                "dependency_environment_coverage_verified",
                "dispatch_enabled",
                "dynamic_loader_identity_verified",
                "effective_invocability_verified",
                "environment_coverage_verified",
                "executable_authenticity_verified",
                "executable_provenance_verified",
                "future_execution_correspondence_verified",
                "interpreter_identity_verified",
                "launcher_identity_verified",
                "live_execution_eligible",
                "module_identity_verified",
                "package_identity_verified",
                "persistence_enabled",
                "plugin_identity_verified",
                "receipt_authenticity_verified",
                "repository_snapshot_correspondence_verified",
                "route_eligible",
                "shared_library_identity_verified",
                "shebang_identity_verified",
                "toolchain_completeness_verified",
                "v4_identity_claim_correspondence_verified",
            ):
                self.assertIs(evidence[false_fact], False)

            public_projection = json.dumps(evidence, sort_keys=True)
            private_values = (
                str(root),
                str(search_one),
                str(search_two),
                "private-bare-command-marker",
                "private-relative-command-marker",
                "private-bare-tool-marker",
                "private-relative-tool-marker",
                bare["content_digest"],
                relative["content_digest"],
            )
            for private_value in private_values:
                self.assertNotIn(private_value, public_projection)
                self.assertNotIn(private_value, repr(receipt))
            self.assertIsInstance(
                receipt.measurements[0],
                ResolvedExecutableMeasurement,
            )
            with self.assertRaises(FrozenInstanceError):
                receipt.total_measured_bytes = 0

    def test_search_precedence_content_changes_and_opaque_claims_are_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            first = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            second = resolve_repository_executables(
                registration,
                search_directories=(search_two, search_one),
            )
            self.assertNotEqual(
                first.resolution_context_digest,
                second.resolution_context_digest,
            )
            self.assertNotEqual(first.receipt_digest, second.receipt_digest)
            self.assertNotEqual(
                first.to_canonical()["measurements"][0]["content_digest"],
                second.to_canonical()["measurements"][0]["content_digest"],
            )

            original_registration_digest = registration.registration_digest
            self._write_executable(
                search_one / "private-bare-tool-marker",
                b"changed-controller-tool\n",
            )
            changed_content = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            self.assertEqual(
                registration.registration_digest,
                original_registration_digest,
            )
            self.assertNotEqual(first.receipt_digest, changed_content.receipt_digest)

            changed_claim_payload = self._versioned_payload(4)
            changed_claim_payload["executable_toolchain_identities"][
                "identities"
            ][0]["executable_identity_digest"] = "sha256:" + "c" * 64
            changed_claim_registration = self._registration(
                root,
                payload=changed_claim_payload,
            )
            changed_claim = resolve_repository_executables(
                changed_claim_registration,
                search_directories=(search_one, search_two),
            )
            self.assertNotEqual(
                changed_content.executable_toolchain_identities_digest,
                changed_claim.executable_toolchain_identities_digest,
            )
            self.assertNotEqual(
                changed_content.receipt_digest,
                changed_claim.receipt_digest,
            )
            self.assertEqual(
                changed_content.to_canonical()["measurements"][0][
                    "content_digest"
                ],
                changed_claim.to_canonical()["measurements"][0][
                    "content_digest"
                ],
            )
            self.assertIs(
                changed_claim.to_evidence()[
                    "v4_identity_claim_correspondence_verified"
                ],
                False,
            )

    def test_relative_only_commands_need_no_search_path_and_files_are_deduplicated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two = self._workspace(temporary)
            relative_only = self._versioned_payload(4)
            relative_only["verification_commands"]["format"] = []
            relative_only["baseline_command_results"] = self._baseline(
                relative_only
            )
            relative_only["executable_toolchain_identities"] = self._identities(
                relative_only
            )
            relative_registration = self._registration(
                root,
                payload=relative_only,
            )
            relative_receipt = resolve_repository_executables(
                relative_registration,
                search_directories=(),
            )
            self.assertEqual(len(relative_receipt.measurements), 1)
            self.assertEqual(relative_receipt.unique_file_count, 1)

            shared = self._versioned_payload(4)
            shared["verification_commands"]["test"][0]["argv"][0] = (
                "private-bare-tool-marker"
            )
            shared["baseline_command_results"] = self._baseline(shared)
            shared["executable_toolchain_identities"] = self._identities(
                shared
            )
            shared_registration = self._registration(root, payload=shared)
            shared_receipt = resolve_repository_executables(
                shared_registration,
                search_directories=(search_one,),
            )
            self.assertEqual(len(shared_receipt.measurements), 2)
            self.assertEqual(shared_receipt.unique_file_count, 1)
            self.assertEqual(
                shared_receipt.total_measured_bytes,
                len(b"first-controller-tool\n"),
            )
            self.assertEqual(
                {
                    measurement.content_digest
                    for measurement in shared_receipt.measurements
                },
                {
                    "sha256:"
                    + hashlib.sha256(b"first-controller-tool\n").hexdigest()
                },
            )

    def test_patchable_registration_hooks_cannot_poison_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            with (
                patch.object(
                    registration_module,
                    "revalidate_repository_registration",
                    side_effect=AssertionError("public revalidator"),
                ) as revalidate,
                patch.object(
                    RepositoryRegistration,
                    "to_canonical",
                    side_effect=AssertionError("public canonical hook"),
                ) as registration_canonical,
                patch.object(
                    RepositoryRegistration,
                    "to_evidence",
                    side_effect=AssertionError("public evidence hook"),
                ) as registration_evidence,
                patch.object(
                    BaselineCommandResults,
                    "to_canonical",
                    side_effect=AssertionError("public baseline hook"),
                ) as baseline_canonical,
                patch.object(
                    ExecutableToolchainIdentities,
                    "to_canonical",
                    side_effect=AssertionError("public identity hook"),
                ) as identity_canonical,
            ):
                receipt = resolve_repository_executables(
                    registration,
                    search_directories=(search_one, search_two),
                )
            self.assertEqual(len(receipt.measurements), 2)
            for observed in (
                revalidate,
                registration_canonical,
                registration_evidence,
                baseline_canonical,
                identity_canonical,
            ):
                observed.assert_not_called()

            identities = registration.executable_toolchain_identities
            self.assertIsNotNone(identities)
            forged = replace(
                registration,
                executable_toolchain_identities=replace(
                    identities,
                    repository_ref="sha256:" + "0" * 64,
                ),
            )
            self._assert_resolution_invalid(
                forged,
                (search_one, search_two),
            )

    def test_v1_through_v3_reject_before_any_resolution_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two = self._workspace(temporary)
            registrations = tuple(
                self._registration(root, schema_version=version)
                for version in (1, 2, 3)
            )
            with (
                patch.object(
                    resolution_module.os,
                    "open",
                    side_effect=AssertionError("must not open"),
                ) as open_file,
                patch.object(
                    resolution_module.os,
                    "scandir",
                    side_effect=AssertionError("must not scan"),
                ) as scandir,
                patch.object(
                    resolution_module.os,
                    "stat",
                    side_effect=AssertionError("must not stat"),
                ) as stat_path,
                patch.object(
                    resolution_module.os,
                    "lstat",
                    side_effect=AssertionError("must not lstat"),
                ) as lstat_path,
            ):
                for registration in registrations:
                    with self.subTest(schema_version=registration.schema_version):
                        self._assert_resolution_invalid(
                            registration,
                            (search_one,),
                        )
            for observed in (open_file, scandir, stat_path, lstat_path):
                observed.assert_not_called()

    def test_repository_relative_cwd_ambiguity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two = self._workspace(temporary)
            payload = self._versioned_payload(4)
            payload["verification_commands"]["test"][0]["cwd"] = (
                "private-test-path-marker"
            )
            payload["baseline_command_results"] = self._baseline(payload)
            payload["executable_toolchain_identities"] = self._identities(
                payload
            )
            registration = self._registration(root, payload=payload)
            self._assert_resolution_invalid(registration, (search_one,))

    def test_search_directory_shape_and_bounds_fail_closed(self) -> None:
        private_marker = "private-search-shape-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, _search_two = self._workspace(temporary)
            registration = self._registration(root)
            missing = Path(temporary) / private_marker
            ordinary_file = Path(temporary) / f"{private_marker}-file"
            ordinary_file.write_text("not a directory\n", encoding="utf-8")
            symlink = Path(temporary) / f"{private_marker}-symlink"
            symlink.symlink_to(search_one, target_is_directory=True)
            relative = Path(private_marker)
            duplicates = (search_one, search_one)
            too_many: list[Path] = []
            for index in range(33):
                directory = Path(temporary) / f"bounded-search-{index:02d}"
                directory.mkdir()
                too_many.append(directory)
            cases: tuple[tuple[str, object], ...] = (
                ("list", [search_one]),
                ("string-entry", (str(search_one),)),
                ("empty", ()),
                ("relative", (relative,)),
                ("missing", (missing,)),
                ("ordinary-file", (ordinary_file,)),
                ("symlink", (symlink,)),
                ("duplicate", duplicates),
                ("too-many", tuple(too_many)),
                ("boolean", True),
            )
            for case, search_directories in cases:
                with self.subTest(case=case):
                    self._assert_resolution_invalid(
                        registration,
                        search_directories,
                        private_marker=private_marker,
                    )

    def test_invalid_higher_precedence_candidates_are_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            selected = search_one / "private-bare-tool-marker"

            selected.unlink()
            receipt = resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            self.assertEqual(
                receipt.to_canonical()["measurements"][0][
                    "search_directory_index"
                ],
                1,
            )

            invalid_cases = ("non-executable", "directory", "symlink", "fifo")
            for case in invalid_cases:
                with self.subTest(case=case):
                    if selected.exists() or selected.is_symlink():
                        if selected.is_dir() and not selected.is_symlink():
                            selected.rmdir()
                        else:
                            selected.unlink()
                    if case == "non-executable":
                        selected.write_bytes(b"not executable\n")
                        selected.chmod(0o644)
                    elif case == "directory":
                        selected.mkdir()
                    elif case == "symlink":
                        selected.symlink_to(
                            search_two / "private-bare-tool-marker"
                        )
                    else:
                        os.mkfifo(selected)
                    self._assert_resolution_invalid(
                        registration,
                        (search_one, search_two),
                    )

    def test_case_alias_and_earlier_candidate_appearance_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            selected = search_one / "private-bare-tool-marker"
            selected.rename(search_one / "Private-Bare-Tool-Marker")
            self._assert_resolution_invalid(
                registration,
                (search_one, search_two),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            earlier = search_one / "private-bare-tool-marker"
            earlier.unlink()
            real_read = resolution_module.os.read
            appeared = False

            def add_earlier_candidate(
                file_descriptor: int,
                count: int,
            ) -> bytes:
                nonlocal appeared
                data = real_read(file_descriptor, count)
                if not appeared and data:
                    appeared = True
                    self._write_executable(
                        earlier,
                        b"late-higher-precedence-tool\n",
                    )
                return data

            with patch.object(
                resolution_module.os,
                "read",
                side_effect=add_earlier_candidate,
            ):
                self._assert_resolution_invalid(
                    registration,
                    (search_one, search_two),
                )
            self.assertTrue(appeared)

    def test_repository_relative_symlink_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            relative = (
                root
                / "private-source-path-marker"
                / "private-relative-tool-marker"
            )
            relative.unlink()
            relative.symlink_to(search_two / "private-bare-tool-marker")
            self._assert_resolution_invalid(
                registration,
                (search_one, search_two),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            source = root / "private-source-path-marker"
            moved = root / "private-source-real-marker"
            source.rename(moved)
            source.symlink_to(moved, target_is_directory=True)
            self._assert_resolution_invalid(
                registration,
                (search_one, search_two),
            )

    def test_oversized_executable_and_candidate_swap_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            selected = search_one / "private-bare-tool-marker"
            with selected.open("wb") as oversized:
                oversized.seek(MAX_EXECUTABLE_BYTES)
                oversized.write(b"x")
            selected.chmod(0o755)
            self._assert_resolution_invalid(
                registration,
                (search_one, search_two),
            )

            with selected.open("wb") as sparse:
                sparse.seek(1024 * 1024)
                sparse.write(b"x")
            selected.chmod(0o755)
            sparse_metadata = selected.stat()
            if (
                hasattr(sparse_metadata, "st_blocks")
                and sparse_metadata.st_blocks * 512 < sparse_metadata.st_size
            ):
                self._assert_resolution_invalid(
                    registration,
                    (search_one, search_two),
                )

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            selected = search_one / "private-bare-tool-marker"
            original = search_one / "private-original-tool-marker"
            replacement = search_one / "private-replacement-tool-marker"
            self._write_executable(replacement, b"replacement-controller-tool\n")
            real_read = resolution_module.os.read
            swapped = False

            def swap_after_read(file_descriptor: int, count: int) -> bytes:
                nonlocal swapped
                data = real_read(file_descriptor, count)
                if not swapped and data:
                    swapped = True
                    selected.rename(original)
                    replacement.rename(selected)
                return data

            with patch.object(
                resolution_module.os,
                "read",
                side_effect=swap_after_read,
            ):
                self._assert_resolution_invalid(
                    registration,
                    (search_one, search_two),
                )
            self.assertTrue(swapped)

    def test_file_descriptors_close_on_success_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            descriptor_directory = Path("/dev/fd")
            if not descriptor_directory.is_dir():
                descriptor_directory = Path("/proc/self/fd")
            if not descriptor_directory.is_dir():
                self.skipTest("no process descriptor directory is available")

            descriptors_before = frozenset(os.listdir(descriptor_directory))
            resolve_repository_executables(
                registration,
                search_directories=(search_one, search_two),
            )
            self.assertEqual(
                frozenset(os.listdir(descriptor_directory)),
                descriptors_before,
            )

            selected = search_one / "private-bare-tool-marker"
            selected.chmod(0o644)
            self._assert_resolution_invalid(
                registration,
                (search_one, search_two),
            )
            self.assertEqual(
                frozenset(os.listdir(descriptor_directory)),
                descriptors_before,
            )

    def test_resolution_uses_no_environment_process_or_write_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, outside, search_one, search_two = self._workspace(temporary)
            registration = self._registration(root)
            repository_before = self._tree_snapshot(root)
            outside_before = self._tree_snapshot(outside)
            search_one_before = self._tree_snapshot(search_one)
            search_two_before = self._tree_snapshot(search_two)

            with (
                patch.object(
                    shutil,
                    "which",
                    side_effect=AssertionError("ambient resolution"),
                ) as which,
                patch.object(
                    os,
                    "getenv",
                    side_effect=AssertionError("environment lookup"),
                ) as getenv,
                patch.object(
                    os,
                    "get_exec_path",
                    side_effect=AssertionError("PATH lookup"),
                ) as get_exec_path,
                patch.object(
                    subprocess,
                    "run",
                    side_effect=AssertionError("command execution"),
                ) as run,
                patch.object(
                    subprocess,
                    "Popen",
                    side_effect=AssertionError("process creation"),
                ) as popen,
                patch.object(
                    subprocess,
                    "call",
                    side_effect=AssertionError("process call"),
                ) as call,
                patch.object(
                    subprocess,
                    "check_call",
                    side_effect=AssertionError("checked process call"),
                ) as check_call,
                patch.object(
                    subprocess,
                    "check_output",
                    side_effect=AssertionError("process output"),
                ) as check_output,
                patch.object(
                    asyncio,
                    "create_subprocess_exec",
                    side_effect=AssertionError("worker creation"),
                ) as create_subprocess,
                patch.object(
                    asyncio,
                    "create_subprocess_shell",
                    side_effect=AssertionError("shell worker creation"),
                ) as create_subprocess_shell,
                patch.object(
                    os,
                    "system",
                    side_effect=AssertionError("shell execution"),
                ) as system,
                patch.object(
                    Path,
                    "mkdir",
                    side_effect=AssertionError("directory write"),
                ) as mkdir,
                patch.object(
                    Path,
                    "write_text",
                    side_effect=AssertionError("text write"),
                ) as write_text,
                patch.object(
                    Path,
                    "write_bytes",
                    side_effect=AssertionError("byte write"),
                ) as write_bytes,
                patch.object(
                    Path,
                    "touch",
                    side_effect=AssertionError("file write"),
                ) as touch,
                patch.object(
                    Path,
                    "unlink",
                    side_effect=AssertionError("file removal"),
                ) as unlink,
                patch.object(
                    Path,
                    "rename",
                    side_effect=AssertionError("file rename"),
                ) as rename,
                patch.object(
                    Path,
                    "replace",
                    side_effect=AssertionError("file replace"),
                ) as replace,
            ):
                receipt = resolve_repository_executables(
                    registration,
                    search_directories=(search_one, search_two),
                )
                evidence = receipt.to_evidence()
            self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
            for observed in (
                which,
                getenv,
                get_exec_path,
                run,
                popen,
                call,
                check_call,
                check_output,
                create_subprocess,
                create_subprocess_shell,
                system,
                mkdir,
                write_text,
                write_bytes,
                touch,
                unlink,
                rename,
                replace,
            ):
                observed.assert_not_called()
            self.assertEqual(self._tree_snapshot(root), repository_before)
            self.assertEqual(self._tree_snapshot(outside), outside_before)
            self.assertEqual(self._tree_snapshot(search_one), search_one_before)
            self.assertEqual(self._tree_snapshot(search_two), search_two_before)
            self.assertFalse((root / ".ordomata").exists())
            self.assertFalse((root / ".git" / "worktrees").exists())


if __name__ == "__main__":
    unittest.main()
