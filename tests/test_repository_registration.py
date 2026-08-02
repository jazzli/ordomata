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
from ordomata.errors import ConfigurationError, ValidationError
from ordomata.repository_registration import (
    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_SCHEMA_VERSION,
    REPOSITORY_REGISTRATION_KIND,
    REPOSITORY_REGISTRATION_SCHEMA_VERSION,
    REPOSITORY_REGISTRATION_SUPPORTED_SCHEMA_VERSIONS,
    ExecutableToolchainIdentities,
    ExecutableToolchainIdentity,
    fresh_repository_registration_evidence,
    load_repository_registration,
    revalidate_repository_registration,
    validate_repository_registration,
)
from ordomata.schema import validate_instance


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
REGISTRATION_SCHEMA = (
    REPOSITORY_ROOT / "schemas" / "repository-registration.schema.json"
)
REGISTRATION_SCHEMA_V2 = (
    REPOSITORY_ROOT / "schemas" / "repository-registration-v2.schema.json"
)
REGISTRATION_SCHEMA_V3 = (
    REPOSITORY_ROOT / "schemas" / "repository-registration-v3.schema.json"
)
REGISTRATION_SCHEMA_V4 = (
    REPOSITORY_ROOT / "schemas" / "repository-registration-v4.schema.json"
)
FIXED_VALIDATION_ERROR = "repository registration is invalid"
FIXED_LOAD_ERROR = "repository registration could not be loaded"
FIXED_SCHEMA_LOAD_ERROR = "repository registration schema could not be loaded"
MAX_REGISTRATION_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_SCHEMA_DOCUMENT_BYTES = 1024 * 1024
MAX_DIRECT_SNAPSHOT_BYTES = 4 * 1024 * 1024
FROZEN_REGISTRATION_SCHEMA_SHA256 = (
    "9e778e6329d3ecd35c6a13bcfe9351c153c8d102db629b9cbe8000ea1e55afcc"
)
FROZEN_REGISTRATION_SCHEMA_V2_SHA256 = (
    "8d93b0757779275927c2149541dad7e50799ea109994c6ca09847edff592cb10"
)
FROZEN_REGISTRATION_SCHEMA_V3_SHA256 = (
    "9b9f8175de30eb56086526fbf7e885c2616088f470f73b8e8872e073ea48f1cb"
)
FROZEN_REGISTRATION_SCHEMA_V4_SHA256 = (
    "b341b4b0a8d0144ee6537f84fc5c78242b156058654ea0c8fa555e0b9c4b6123"
)
LEGACY_REGISTRATION_CANONICAL_KEYS = {
    "isolation_requirements",
    "kind",
    "path_policy",
    "registration_ref",
    "registration_version",
    "repository",
    "resource_limits",
    "review_policy",
    "schema_version",
    "verification_commands",
}
LEGACY_REGISTRATION_EVIDENCE_KEYS = {
    "authority_granted",
    "dispatch_enabled",
    "filesystem_identity_ref",
    "isolation_requirements_digest",
    "kind",
    "path_policy_digest",
    "registration_digest",
    "registration_ref",
    "registration_version",
    "repository_ref",
    "resource_limits_digest",
    "review_policy_digest",
    "schema_version",
    "validation_mode",
    "verification_commands_digest",
}
V3_BASELINE_EVIDENCE_KEYS = {
    "baseline_attestation_source",
    "baseline_authenticity_verified",
    "baseline_command_results_digest",
    "baseline_freshness_verified",
    "baseline_result_count",
}
V4_EXECUTABLE_TOOLCHAIN_EVIDENCE_KEYS = {
    "executable_toolchain_attestation_source",
    "executable_toolchain_authenticity_verified",
    "executable_toolchain_content_verified",
    "executable_toolchain_execution_correspondence_verified",
    "executable_toolchain_freshness_verified",
    "executable_toolchain_identities_digest",
    "executable_toolchain_identity_count",
    "executable_toolchain_resolution_verified",
    "toolchain_completeness_verified",
}


class RepositoryRegistrationTests(unittest.TestCase):
    @staticmethod
    def _repository(temporary: str) -> tuple[Path, Path]:
        base = Path(temporary)
        root = base / "private-repository-root-marker"
        outside = base / "private-outside-marker"
        root.mkdir()
        outside.mkdir()
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n",
            encoding="utf-8",
        )
        (root / ".git" / "refs" / "heads").mkdir(parents=True)
        (root / ".git" / "refs" / "heads" / "main").write_text(
            "0" * 40 + "\n",
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
        (outside / "sentinel.txt").write_text(
            "outside-unchanged\n",
            encoding="utf-8",
        )
        return root, outside

    @staticmethod
    def _payload() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "repository_registration",
            "registration_id": "private-registration-id-marker",
            "registration_version": "1.0.0",
            "repository": {
                "repository_id": "private-repository-id-marker",
                "vcs": "git",
                "root": ".",
            },
            "verification_commands": {
                "format": [
                    {
                        "command_id": "format-check",
                        "argv": [
                            "python3",
                            "-m",
                            "compileall",
                            "-q",
                            "private-source-path-marker",
                        ],
                        "cwd": ".",
                    }
                ],
                "lint": [],
                "type_check": [],
                "test": [
                    {
                        "command_id": "unit-tests",
                        "argv": [
                            "python3",
                            "-m",
                            "unittest",
                            "discover",
                            "-s",
                            "private-test-path-marker",
                        ],
                        "cwd": ".",
                    }
                ],
                "build": [],
            },
            "path_policy": {
                "allowed_paths": [
                    "private-test-path-marker",
                    "private-source-path-marker",
                    "private-docs-path-marker",
                ],
                "protected_paths": [
                    "private-protected-path-marker.txt",
                    ".ordomata",
                    ".git",
                    ".agentops",
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

    @classmethod
    def _v2_payload(cls) -> dict[str, object]:
        payload = cls._payload()
        payload["schema_version"] = 2
        payload["path_policy"]["generated_paths"] = [
            "private-source-path-marker/generated",
        ]
        payload["path_policy"]["vendor_paths"] = [
            "private-test-path-marker/vendor",
        ]
        return payload

    @staticmethod
    def _command_attestation_digest(
        kind: str,
        command: dict[str, object],
    ) -> str:
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
    def _baseline_for_payload(
        cls,
        payload: dict[str, object],
    ) -> dict[str, object]:
        results: list[dict[str, object]] = []
        sequence = 0
        for kind in ("format", "lint", "type_check", "test", "build"):
            for command in payload["verification_commands"][kind]:
                started_at = 1_000 + sequence * 2_000
                results.append(
                    {
                        "kind": kind,
                        "command_id": command["command_id"],
                        "command_digest": cls._command_attestation_digest(
                            kind,
                            command,
                        ),
                        "started_at_unix_ms": started_at,
                        "completed_at_unix_ms": started_at + 1_000,
                        "termination": {
                            "kind": "exited",
                            "exit_code": 0,
                        },
                    }
                )
                sequence += 1
        return {
            "kind": "repository_baseline_command_results",
            "attestation_source": "controller_supplied",
            "snapshot_digest": "sha256:" + "b" * 64,
            "results": results,
        }

    @classmethod
    def _v3_payload(cls) -> dict[str, object]:
        payload = cls._v2_payload()
        payload["schema_version"] = 3
        payload["baseline_command_results"] = cls._baseline_for_payload(
            payload
        )
        return payload

    @staticmethod
    def _declared_executable_ref(
        *,
        command_digest: str,
        declared_executable: str,
    ) -> str:
        return canonical_digest(
            {
                "command_digest": command_digest,
                "declared_executable": declared_executable,
                "kind": "repository_declared_executable",
                "schema_version": 1,
            }
        )

    @classmethod
    def _executable_toolchain_identities_for_payload(
        cls,
        payload: dict[str, object],
    ) -> dict[str, object]:
        identities: list[dict[str, object]] = []
        for kind in ("format", "lint", "type_check", "test", "build"):
            for command in payload["verification_commands"][kind]:
                command_id = command["command_id"]
                identities.append(
                    {
                        "kind": kind,
                        "command_id": command_id,
                        "command_digest": cls._command_attestation_digest(
                            kind,
                            command,
                        ),
                        "executable_identity_digest": canonical_digest(
                            {
                                "claimed_executable_identity": (
                                    f"{kind}:{command_id}"
                                )
                            }
                        ),
                        "toolchain_identity_digest": canonical_digest(
                            {
                                "claimed_toolchain_identity": (
                                    f"{kind}:{command_id}"
                                )
                            }
                        ),
                    }
                )
        return {
            "kind": "repository_executable_toolchain_identities",
            "attestation_source": "controller_supplied",
            "identities": identities,
        }

    @classmethod
    def _v4_payload(cls) -> dict[str, object]:
        payload = cls._v3_payload()
        payload["schema_version"] = 4
        payload["executable_toolchain_identities"] = (
            cls._executable_toolchain_identities_for_payload(payload)
        )
        return payload

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
                    entries.append(
                        (relative, "symlink", mode, os.readlink(path))
                    )
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

    def _assert_invalid(
        self,
        root: Path,
        payload: object,
        *,
        private_marker: str = "private-invalid-registration-marker",
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            validate_repository_registration(payload, repository_root=root)
        self.assertEqual(str(caught.exception), FIXED_VALIDATION_ERROR)
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertNotIn(str(root), str(caught.exception))

    def test_valid_registration_is_canonical_frozen_and_privacy_bounded(
        self,
    ) -> None:
        self.assertEqual(REPOSITORY_REGISTRATION_SCHEMA_VERSION, 4)
        self.assertEqual(
            REPOSITORY_REGISTRATION_SUPPORTED_SCHEMA_VERSIONS,
            frozenset({1, 2, 3, 4}),
        )
        self.assertEqual(
            REPOSITORY_REGISTRATION_KIND,
            "repository_registration",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            payload = self._payload()
            registration = validate_repository_registration(
                payload,
                repository_root=root,
            )
            canonical = registration.to_canonical()
            original_canonical = deepcopy(canonical)

            self.assertRegex(
                registration.registration_digest,
                r"^sha256:[0-9a-f]{64}$",
            )
            self.assertEqual(
                registration.registration_digest,
                canonical_digest(canonical),
            )
            for attribute in (
                "repository",
                "verification_commands",
                "path_policy",
                "resource_limits",
                "isolation_requirements",
                "review_policy",
            ):
                self.assertIsNotNone(getattr(registration, attribute))
            for kind, commands in payload["verification_commands"].items():
                self.assertEqual(
                    [
                        {
                            "argv": command["argv"],
                            "command_id": command["command_id"],
                            "cwd": command["cwd"],
                            "kind": kind,
                        }
                        for command in commands
                    ],
                    canonical["verification_commands"][kind],
                )
            self.assertEqual(
                canonical["path_policy"]["allowed_paths"],
                sorted(payload["path_policy"]["allowed_paths"]),
            )
            self.assertEqual(
                canonical["path_policy"]["protected_paths"],
                sorted(payload["path_policy"]["protected_paths"]),
            )
            original_digest = registration.registration_digest
            # Python 3.12 reports inherited frozen-slot assignment as
            # TypeError; newer interpreters report FrozenInstanceError.
            with self.assertRaises((FrozenInstanceError, TypeError)):
                registration.registration_digest = "sha256:" + "0" * 64
            self.assertEqual(registration.registration_digest, original_digest)

            payload["repository"]["repository_id"] = "mutated"
            payload["verification_commands"]["test"][0]["argv"].append(
                "mutated"
            )
            payload["path_policy"]["allowed_paths"].append("mutated")
            self.assertEqual(registration.to_canonical(), original_canonical)

            evidence = registration.to_evidence()
            self.assertEqual(evidence["validation_mode"], "read_only")
            self.assertFalse(evidence["dispatch_enabled"])
            self.assertFalse(evidence["authority_granted"])
            self.assertEqual(
                evidence["registration_digest"],
                registration.registration_digest,
            )
            projection = json.dumps(evidence, sort_keys=True)
            for private_value in (
                str(root),
                "private-source-path-marker",
                "private-test-path-marker",
                "private-docs-path-marker",
                "private-protected-path-marker.txt",
                "unit-tests",
                "compileall",
            ):
                self.assertNotIn(private_value, projection)

    def test_frozen_schemas_and_versioned_shapes_remain_disjoint(
        self,
    ) -> None:
        self.assertEqual(
            hashlib.sha256(REGISTRATION_SCHEMA.read_bytes()).hexdigest(),
            FROZEN_REGISTRATION_SCHEMA_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(REGISTRATION_SCHEMA_V2.read_bytes()).hexdigest(),
            FROZEN_REGISTRATION_SCHEMA_V2_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(REGISTRATION_SCHEMA_V3.read_bytes()).hexdigest(),
            FROZEN_REGISTRATION_SCHEMA_V3_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(REGISTRATION_SCHEMA_V4.read_bytes()).hexdigest(),
            FROZEN_REGISTRATION_SCHEMA_V4_SHA256,
        )
        schema_v1 = json.loads(REGISTRATION_SCHEMA.read_text(encoding="utf-8"))
        schema_v2 = json.loads(
            REGISTRATION_SCHEMA_V2.read_text(encoding="utf-8")
        )
        schema_v3 = json.loads(
            REGISTRATION_SCHEMA_V3.read_text(encoding="utf-8")
        )
        schema_v4 = json.loads(
            REGISTRATION_SCHEMA_V4.read_text(encoding="utf-8")
        )
        payload_v1 = self._payload()
        payload_v2 = self._v2_payload()
        payload_v3 = self._v3_payload()
        payload_v4 = self._v4_payload()

        schemas = (schema_v1, schema_v2, schema_v3, schema_v4)
        payloads = (payload_v1, payload_v2, payload_v3, payload_v4)
        for payload_index, payload in enumerate(payloads):
            for schema_index, schema in enumerate(schemas):
                with self.subTest(
                    payload_version=payload_index + 1,
                    schema_version=schema_index + 1,
                ):
                    self.assertEqual(
                        validate_instance(payload, schema).valid,
                        payload_index == schema_index,
                    )

        incomplete_v2_payloads = []
        for version, baseline in (
            (2, payload_v2),
            (3, payload_v3),
            (4, payload_v4),
        ):
            for missing in ("generated_paths", "vendor_paths"):
                with self.subTest(version=version, missing=missing):
                    incomplete = deepcopy(baseline)
                    del incomplete["path_policy"][missing]
                    incomplete_v2_payloads.append(incomplete)
                    self.assertFalse(
                        validate_instance(incomplete, schemas[version - 1]).valid
                    )

        incomplete_v3 = deepcopy(payload_v3)
        del incomplete_v3["baseline_command_results"]
        self.assertFalse(validate_instance(incomplete_v3, schema_v3).valid)

        incomplete_v4_baseline = deepcopy(payload_v4)
        del incomplete_v4_baseline["baseline_command_results"]
        self.assertFalse(
            validate_instance(incomplete_v4_baseline, schema_v4).valid
        )
        incomplete_v4_identities = deepcopy(payload_v4)
        del incomplete_v4_identities["executable_toolchain_identities"]
        self.assertFalse(
            validate_instance(incomplete_v4_identities, schema_v4).valid
        )

        widened_v1 = deepcopy(payload_v1)
        widened_v1["path_policy"]["generated_paths"] = []
        widened_v1["path_policy"]["vendor_paths"] = []
        self.assertFalse(validate_instance(widened_v1, schema_v1).valid)

        for version, payload, schema in (
            (1, payload_v1, schema_v1),
            (2, payload_v2, schema_v2),
        ):
            widened = deepcopy(payload)
            widened["baseline_command_results"] = deepcopy(
                payload_v3["baseline_command_results"]
            )
            with self.subTest(version=version, field="baseline"):
                self.assertFalse(validate_instance(widened, schema).valid)

        widened_identity_payloads = []
        for version, payload, schema in (
            (1, payload_v1, schema_v1),
            (2, payload_v2, schema_v2),
            (3, payload_v3, schema_v3),
        ):
            widened = deepcopy(payload)
            widened["executable_toolchain_identities"] = deepcopy(
                payload_v4["executable_toolchain_identities"]
            )
            widened_identity_payloads.append(widened)
            with self.subTest(version=version, field="toolchain-identities"):
                self.assertFalse(validate_instance(widened, schema).valid)

        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            self._assert_invalid(root, widened_v1)
            for incomplete in incomplete_v2_payloads:
                self._assert_invalid(root, incomplete)
            self._assert_invalid(root, incomplete_v3)
            self._assert_invalid(root, incomplete_v4_baseline)
            self._assert_invalid(root, incomplete_v4_identities)
            for widened in widened_identity_payloads:
                self._assert_invalid(root, widened)

    def test_v2_exclusions_are_canonical_digest_bound_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            payload = self._v2_payload()
            payload["path_policy"]["generated_paths"].append(
                "private-docs-path-marker/generated"
            )
            registration = validate_repository_registration(
                payload,
                repository_root=root,
            )

            self.assertEqual(registration.schema_version, 2)
            self.assertEqual(
                registration.path_policy.generated_paths,
                (
                    "private-docs-path-marker/generated",
                    "private-source-path-marker/generated",
                ),
            )
            self.assertEqual(
                registration.path_policy.vendor_paths,
                ("private-test-path-marker/vendor",),
            )
            canonical = registration.to_canonical()
            self.assertEqual(
                canonical["path_policy"]["generated_paths"],
                list(registration.path_policy.generated_paths),
            )
            self.assertEqual(
                canonical["path_policy"]["vendor_paths"],
                list(registration.path_policy.vendor_paths),
            )
            evidence = fresh_repository_registration_evidence(registration)
            self.assertEqual(evidence["schema_version"], 2)
            self.assertEqual(
                evidence["path_policy_digest"],
                canonical_digest(canonical["path_policy"]),
            )
            projection = json.dumps(evidence, sort_keys=True)
            self.assertNotIn("private-source-path-marker", projection)
            self.assertNotIn("private-test-path-marker", projection)
            self.assertNotIn("private-docs-path-marker", projection)
            self.assertNotIn(
                "private-source-path-marker",
                repr(registration.path_policy),
            )

            reordered_payload = deepcopy(payload)
            reordered_payload["path_policy"]["generated_paths"].reverse()
            reordered = validate_repository_registration(
                reordered_payload,
                repository_root=root,
            )
            self.assertEqual(
                registration.registration_digest,
                reordered.registration_digest,
            )

            swapped_payload = deepcopy(payload)
            generated = swapped_payload["path_policy"]["generated_paths"]
            vendor = swapped_payload["path_policy"]["vendor_paths"]
            generated[0], vendor[0] = vendor[0], generated[0]
            swapped = validate_repository_registration(
                swapped_payload,
                repository_root=root,
            )
            self.assertNotEqual(
                registration.path_policy.digest,
                swapped.path_policy.digest,
            )
            self.assertNotEqual(
                registration.registration_digest,
                swapped.registration_digest,
            )

    def test_v1_digest_semantics_and_v2_empty_exclusions_are_stable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            registration_v1 = validate_repository_registration(
                self._payload(),
                repository_root=root,
            )
            self.assertEqual(
                set(registration_v1.to_canonical()),
                LEGACY_REGISTRATION_CANONICAL_KEYS,
            )
            self.assertEqual(
                set(registration_v1.to_evidence()),
                LEGACY_REGISTRATION_EVIDENCE_KEYS,
            )
            path_policy_v1 = {
                "allowed_paths": list(
                    registration_v1.path_policy.allowed_paths
                ),
                "protected_paths": list(
                    registration_v1.path_policy.protected_paths
                ),
            }
            self.assertEqual(
                registration_v1.path_policy.to_canonical(),
                path_policy_v1,
            )
            self.assertEqual(
                registration_v1.to_evidence()["path_policy_digest"],
                canonical_digest(path_policy_v1),
            )

            payload_v2 = self._v2_payload()
            payload_v2["path_policy"]["generated_paths"] = []
            payload_v2["path_policy"]["vendor_paths"] = []
            registration_v2 = validate_repository_registration(
                payload_v2,
                repository_root=root,
            )
            self.assertEqual(
                set(registration_v2.to_canonical()),
                LEGACY_REGISTRATION_CANONICAL_KEYS,
            )
            self.assertEqual(
                set(registration_v2.to_evidence()),
                LEGACY_REGISTRATION_EVIDENCE_KEYS,
            )
            self.assertEqual(
                registration_v2.path_policy.to_canonical(),
                path_policy_v1,
            )
            self.assertEqual(
                registration_v2.path_policy.digest,
                registration_v1.path_policy.digest,
            )
            self.assertNotEqual(
                registration_v2.registration_digest,
                registration_v1.registration_digest,
            )
            self.assertEqual(
                revalidate_repository_registration(registration_v2),
                registration_v2,
            )

    def test_v3_baseline_is_canonical_digest_bound_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            payload = self._v3_payload()
            payload["baseline_command_results"]["results"].reverse()
            registration = validate_repository_registration(
                payload,
                repository_root=root,
            )
            canonical = registration.to_canonical()
            baseline = canonical["baseline_command_results"]

            self.assertEqual(registration.schema_version, 3)
            self.assertEqual(
                set(canonical),
                LEGACY_REGISTRATION_CANONICAL_KEYS
                | {"baseline_command_results"},
            )
            self.assertEqual(
                set(baseline),
                {
                    "attestation_source",
                    "kind",
                    "repository_ref",
                    "results",
                    "schema_version",
                    "snapshot_digest",
                    "verification_commands_digest",
                },
            )
            self.assertEqual(
                baseline["kind"],
                "repository_baseline_command_results",
            )
            self.assertEqual(baseline["schema_version"], 1)
            self.assertEqual(
                baseline["attestation_source"],
                "controller_supplied",
            )
            self.assertEqual(
                baseline["repository_ref"],
                registration.repository.repository_ref,
            )
            self.assertEqual(
                baseline["verification_commands_digest"],
                registration.verification_commands.digest,
            )
            self.assertEqual(
                [result["command_id"] for result in baseline["results"]],
                ["format-check", "unit-tests"],
            )

            evidence = registration.to_evidence()
            self.assertEqual(
                set(evidence),
                LEGACY_REGISTRATION_EVIDENCE_KEYS
                | V3_BASELINE_EVIDENCE_KEYS,
            )
            self.assertEqual(
                evidence["baseline_command_results_digest"],
                canonical_digest(baseline),
            )
            self.assertEqual(evidence["baseline_result_count"], 2)
            self.assertEqual(
                evidence["baseline_attestation_source"],
                "controller_supplied",
            )
            self.assertIs(evidence["baseline_authenticity_verified"], False)
            self.assertIs(evidence["baseline_freshness_verified"], False)
            self.assertFalse(evidence["dispatch_enabled"])
            self.assertFalse(evidence["authority_granted"])
            projection = json.dumps(evidence, sort_keys=True)
            for private_value in (
                payload["baseline_command_results"]["snapshot_digest"],
                "format-check",
                "unit-tests",
                "private-source-path-marker",
                "private-test-path-marker",
            ):
                self.assertNotIn(private_value, projection)
                self.assertNotIn(private_value, repr(registration))

            reordered = self._v3_payload()
            reordered_registration = validate_repository_registration(
                reordered,
                repository_root=root,
            )
            self.assertEqual(
                registration.registration_digest,
                reordered_registration.registration_digest,
            )

            changed_snapshot = self._v3_payload()
            changed_snapshot["baseline_command_results"][
                "snapshot_digest"
            ] = "sha256:" + "c" * 64
            changed = validate_repository_registration(
                changed_snapshot,
                repository_root=root,
            )
            self.assertNotEqual(
                registration.registration_digest,
                changed.registration_digest,
            )
            self.assertNotEqual(
                evidence["baseline_command_results_digest"],
                changed.to_evidence()["baseline_command_results_digest"],
            )
            self.assertEqual(
                registration.verification_commands.digest,
                changed.verification_commands.digest,
            )
            self.assertEqual(
                registration.path_policy.digest,
                changed.path_policy.digest,
            )

    def test_v4_executable_toolchain_identities_are_linked_and_private(
        self,
    ) -> None:
        self.assertEqual(
            EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND,
            "repository_executable_toolchain_identities",
        )
        self.assertEqual(EXECUTABLE_TOOLCHAIN_IDENTITIES_SCHEMA_VERSION, 1)
        self.assertEqual(
            EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
            "controller_supplied",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            payload = self._v4_payload()
            payload["executable_toolchain_identities"][
                "identities"
            ].reverse()
            registration = validate_repository_registration(
                payload,
                repository_root=root,
            )
            self.assertIsInstance(
                registration.executable_toolchain_identities,
                ExecutableToolchainIdentities,
            )
            canonical = registration.to_canonical()
            baseline = canonical["baseline_command_results"]
            identities = canonical["executable_toolchain_identities"]
            self.assertEqual(
                set(canonical),
                LEGACY_REGISTRATION_CANONICAL_KEYS
                | {
                    "baseline_command_results",
                    "executable_toolchain_identities",
                },
            )
            self.assertEqual(
                set(identities),
                {
                    "attestation_source",
                    "baseline_command_results_digest",
                    "identities",
                    "kind",
                    "repository_ref",
                    "schema_version",
                    "verification_commands_digest",
                },
            )
            self.assertEqual(
                identities["kind"],
                EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND,
            )
            self.assertEqual(
                identities["schema_version"],
                EXECUTABLE_TOOLCHAIN_IDENTITIES_SCHEMA_VERSION,
            )
            self.assertEqual(
                identities["attestation_source"],
                EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
            )
            self.assertEqual(
                identities["repository_ref"],
                registration.repository.repository_ref,
            )
            self.assertEqual(
                identities["verification_commands_digest"],
                registration.verification_commands.digest,
            )
            self.assertEqual(
                identities["baseline_command_results_digest"],
                canonical_digest(baseline),
            )
            self.assertEqual(
                [identity["command_id"] for identity in identities["identities"]],
                ["format-check", "unit-tests"],
            )
            for identity in identities["identities"]:
                self.assertEqual(
                    set(identity),
                    {
                        "command_digest",
                        "command_id",
                        "declared_executable_kind",
                        "declared_executable_ref",
                        "executable_identity_digest",
                        "kind",
                        "toolchain_identity_digest",
                    },
                )
                self.assertEqual(
                    identity["declared_executable_kind"],
                    "path_search",
                )
                source_command = next(
                    command
                    for command in payload["verification_commands"][
                        identity["kind"]
                    ]
                    if command["command_id"] == identity["command_id"]
                )
                self.assertEqual(
                    identity["declared_executable_ref"],
                    self._declared_executable_ref(
                        command_digest=identity["command_digest"],
                        declared_executable=source_command["argv"][0],
                    ),
                )

            evidence = registration.to_evidence()
            self.assertEqual(
                set(evidence),
                LEGACY_REGISTRATION_EVIDENCE_KEYS
                | V3_BASELINE_EVIDENCE_KEYS
                | V4_EXECUTABLE_TOOLCHAIN_EVIDENCE_KEYS,
            )
            self.assertEqual(
                evidence["executable_toolchain_identities_digest"],
                canonical_digest(identities),
            )
            self.assertEqual(
                evidence["executable_toolchain_identity_count"],
                2,
            )
            self.assertEqual(
                evidence["executable_toolchain_attestation_source"],
                "controller_supplied",
            )
            for false_fact in (
                "executable_toolchain_authenticity_verified",
                "executable_toolchain_content_verified",
                "executable_toolchain_execution_correspondence_verified",
                "executable_toolchain_freshness_verified",
                "executable_toolchain_resolution_verified",
                "toolchain_completeness_verified",
            ):
                self.assertIs(evidence[false_fact], False)

            projection = json.dumps(evidence, sort_keys=True)
            private_values = (
                payload["baseline_command_results"]["snapshot_digest"],
                "format-check",
                "unit-tests",
                "python3",
                payload["executable_toolchain_identities"]["identities"][0][
                    "executable_identity_digest"
                ],
                payload["executable_toolchain_identities"]["identities"][0][
                    "toolchain_identity_digest"
                ],
            )
            for private_value in private_values:
                self.assertNotIn(private_value, projection)
                self.assertNotIn(private_value, repr(registration))
                self.assertNotIn(
                    private_value,
                    repr(registration.executable_toolchain_identities),
                )

            registration_v3 = validate_repository_registration(
                self._v3_payload(),
                repository_root=root,
            )
            self.assertEqual(
                registration_v3.to_canonical()["baseline_command_results"],
                baseline,
            )
            self.assertEqual(
                registration_v3.to_evidence()["baseline_command_results_digest"],
                evidence["baseline_command_results_digest"],
            )

            reordered = validate_repository_registration(
                self._v4_payload(),
                repository_root=root,
            )
            self.assertEqual(
                registration.registration_digest,
                reordered.registration_digest,
            )

            changed_payload = self._v4_payload()
            changed_payload["executable_toolchain_identities"]["identities"][0][
                "executable_identity_digest"
            ] = "sha256:" + "c" * 64
            changed = validate_repository_registration(
                changed_payload,
                repository_root=root,
            )
            self.assertNotEqual(
                evidence["executable_toolchain_identities_digest"],
                changed.to_evidence()["executable_toolchain_identities_digest"],
            )
            self.assertNotEqual(
                registration.registration_digest,
                changed.registration_digest,
            )
            for section in (
                "baseline_command_results",
                "isolation_requirements",
                "path_policy",
                "resource_limits",
                "review_policy",
                "verification_commands",
            ):
                self.assertEqual(canonical[section], changed.to_canonical()[section])

    def test_v4_identity_coverage_and_declaration_links_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            cases: list[tuple[str, dict[str, object]]] = []

            missing = self._v4_payload()
            missing["executable_toolchain_identities"]["identities"].pop()
            cases.append(("missing", missing))

            duplicate = self._v4_payload()
            duplicate["executable_toolchain_identities"]["identities"][1] = (
                deepcopy(
                    duplicate["executable_toolchain_identities"]["identities"][
                        0
                    ]
                )
            )
            cases.append(("duplicate", duplicate))

            wrong_id = self._v4_payload()
            wrong_id["executable_toolchain_identities"]["identities"][0][
                "command_id"
            ] = "unknown-command"
            cases.append(("unknown-command", wrong_id))

            wrong_kind = self._v4_payload()
            wrong_kind["executable_toolchain_identities"]["identities"][0][
                "kind"
            ] = "test"
            cases.append(("wrong-kind", wrong_kind))

            stale_digest = self._v4_payload()
            stale_digest["executable_toolchain_identities"]["identities"][0][
                "command_digest"
            ] = "sha256:" + "0" * 64
            cases.append(("stale-command-digest", stale_digest))

            stale_after_declaration_change = self._v4_payload()
            stale_after_declaration_change["verification_commands"]["format"][
                0
            ]["argv"].append("private-changed-argument")
            stale_after_declaration_change["baseline_command_results"] = (
                self._baseline_for_payload(stale_after_declaration_change)
            )
            cases.append(
                ("stale-after-declaration-change", stale_after_declaration_change)
            )

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(root, payload)

            baseline = validate_repository_registration(
                self._v4_payload(),
                repository_root=root,
            )
            fully_rebound = self._v4_payload()
            fully_rebound["verification_commands"]["format"][0]["argv"].append(
                "private-changed-argument"
            )
            fully_rebound["baseline_command_results"] = self._baseline_for_payload(
                fully_rebound
            )
            fully_rebound["executable_toolchain_identities"] = (
                self._executable_toolchain_identities_for_payload(fully_rebound)
            )
            changed = validate_repository_registration(
                fully_rebound,
                repository_root=root,
            )
            baseline_identity = baseline.to_canonical()[
                "executable_toolchain_identities"
            ]["identities"][0]
            changed_identity = changed.to_canonical()[
                "executable_toolchain_identities"
            ]["identities"][0]
            self.assertNotEqual(
                baseline_identity["command_digest"],
                changed_identity["command_digest"],
            )
            self.assertNotEqual(
                baseline_identity["declared_executable_ref"],
                changed_identity["declared_executable_ref"],
            )
            self.assertNotEqual(
                baseline.registration_digest,
                changed.registration_digest,
            )

            relative_executable = (
                root / "private-source-path-marker" / "private-check-tool"
            )
            relative_executable.write_text("controller fixture\n", encoding="utf-8")
            relative_executable.chmod(0o700)
            repository_relative = self._v4_payload()
            repository_relative["verification_commands"]["format"][0]["argv"][
                0
            ] = "private-source-path-marker/private-check-tool"
            repository_relative["baseline_command_results"] = (
                self._baseline_for_payload(repository_relative)
            )
            repository_relative["executable_toolchain_identities"] = (
                self._executable_toolchain_identities_for_payload(
                    repository_relative
                )
            )
            relative = validate_repository_registration(
                repository_relative,
                repository_root=root,
            )
            relative_identity = relative.to_canonical()[
                "executable_toolchain_identities"
            ]["identities"][0]
            self.assertEqual(
                relative_identity["declared_executable_kind"],
                "repository_relative",
            )
            self.assertEqual(
                relative_identity["declared_executable_ref"],
                self._declared_executable_ref(
                    command_digest=relative_identity["command_digest"],
                    declared_executable=(
                        "private-source-path-marker/private-check-tool"
                    ),
                ),
            )

            swapped_claims = self._v4_payload()
            claim_records = swapped_claims["executable_toolchain_identities"][
                "identities"
            ]
            for field in (
                "executable_identity_digest",
                "toolchain_identity_digest",
            ):
                claim_records[0][field], claim_records[1][field] = (
                    claim_records[1][field],
                    claim_records[0][field],
                )
            swapped = validate_repository_registration(
                swapped_claims,
                repository_root=root,
            )
            self.assertNotEqual(
                baseline.registration_digest,
                swapped.registration_digest,
            )
            self.assertIs(
                swapped.to_evidence()[
                    "executable_toolchain_authenticity_verified"
                ],
                False,
            )

            shared_claims = self._v4_payload()
            shared_records = shared_claims["executable_toolchain_identities"][
                "identities"
            ]
            for field in (
                "executable_identity_digest",
                "toolchain_identity_digest",
            ):
                shared_records[1][field] = shared_records[0][field]
            validate_repository_registration(shared_claims, repository_root=root)

    def test_v4_identity_shape_privacy_and_digest_syntax_fail_closed(
        self,
    ) -> None:
        private_marker = "private-toolchain-shape-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            cases: list[tuple[str, dict[str, object]]] = []

            for field in ("kind", "attestation_source", "identities"):
                payload = self._v4_payload()
                del payload["executable_toolchain_identities"][field]
                cases.append((f"missing-block-{field}", payload))

            extra_block = self._v4_payload()
            extra_block["executable_toolchain_identities"][private_marker] = (
                private_marker
            )
            cases.append(("extra-block-field", extra_block))

            for field in (
                "kind",
                "command_id",
                "command_digest",
                "executable_identity_digest",
                "toolchain_identity_digest",
            ):
                payload = self._v4_payload()
                del payload["executable_toolchain_identities"]["identities"][0][
                    field
                ]
                cases.append((f"missing-identity-{field}", payload))

            for forbidden in (
                "PATH",
                "argv",
                "complete",
                "content_digest",
                "declared_executable_kind",
                "declared_executable_ref",
                "env",
                "message",
                "output",
                "output_digest",
                "package_name",
                "package_version",
                "path",
                "reason",
                "resolved_path",
                "stderr",
                "stdout",
                "timestamp",
                "trusted",
                "verified",
                "version_output",
            ):
                payload = self._v4_payload()
                payload["executable_toolchain_identities"]["identities"][0][
                    forbidden
                ] = private_marker
                cases.append((f"forbidden-{forbidden}", payload))

            wrong_block_kind = self._v4_payload()
            wrong_block_kind["executable_toolchain_identities"]["kind"] = (
                private_marker
            )
            cases.append(("wrong-block-kind", wrong_block_kind))
            wrong_source = self._v4_payload()
            wrong_source["executable_toolchain_identities"][
                "attestation_source"
            ] = private_marker
            cases.append(("wrong-attestation-source", wrong_source))
            for field, value in (
                ("kind", True),
                ("command_id", True),
                ("command_id", [private_marker]),
            ):
                payload = self._v4_payload()
                payload["executable_toolchain_identities"]["identities"][0][
                    field
                ] = value
                cases.append((f"identity-{field}-{type(value).__name__}", payload))

            for case, value in (
                ("block-null", None),
                ("block-list", []),
                ("block-string", private_marker),
            ):
                payload = self._v4_payload()
                payload["executable_toolchain_identities"] = value
                cases.append((case, payload))
            for case, value in (
                ("identities-null", None),
                ("identities-object", {}),
                ("identities-string", private_marker),
            ):
                payload = self._v4_payload()
                payload["executable_toolchain_identities"]["identities"] = value
                cases.append((case, payload))
            scalar_identity = self._v4_payload()
            scalar_identity["executable_toolchain_identities"]["identities"][
                0
            ] = private_marker
            cases.append(("scalar-identity", scalar_identity))

            invalid_digests: tuple[tuple[str, object], ...] = (
                ("prefixless", "0" * 64),
                ("uppercase", "sha256:" + "A" * 64),
                ("short", "sha256:" + "0" * 63),
                ("trailing-newline", "sha256:" + "0" * 64 + "\n"),
                ("wrong-algorithm", "sha512:" + "0" * 64),
                ("boolean", True),
                ("float", 1.0),
            )
            schema_v4 = json.loads(
                REGISTRATION_SCHEMA_V4.read_text(encoding="utf-8")
            )
            for field in (
                "command_digest",
                "executable_identity_digest",
                "toolchain_identity_digest",
            ):
                for case, value in invalid_digests:
                    payload = self._v4_payload()
                    payload["executable_toolchain_identities"]["identities"][0][
                        field
                    ] = value
                    self.assertFalse(
                        validate_instance(payload, schema_v4).valid
                    )
                    cases.append((f"{field}-{case}", payload))

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

    def test_v3_baseline_coverage_order_and_command_digests_are_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            cases: list[tuple[str, dict[str, object]]] = []

            missing = self._v3_payload()
            missing["baseline_command_results"]["results"].pop()
            cases.append(("missing", missing))

            duplicate = self._v3_payload()
            duplicate["baseline_command_results"]["results"].append(
                deepcopy(
                    duplicate["baseline_command_results"]["results"][0]
                )
            )
            cases.append(("duplicate", duplicate))

            wrong_id = self._v3_payload()
            wrong_id["baseline_command_results"]["results"][0][
                "command_id"
            ] = "unknown-command"
            cases.append(("unknown-command", wrong_id))

            wrong_kind = self._v3_payload()
            wrong_kind["baseline_command_results"]["results"][0][
                "kind"
            ] = "test"
            cases.append(("wrong-category", wrong_kind))

            stale_digest = self._v3_payload()
            stale_digest["baseline_command_results"]["results"][0][
                "command_digest"
            ] = "sha256:" + "0" * 64
            cases.append(("stale-command-digest", stale_digest))

            stale_declaration = self._v3_payload()
            stale_declaration["verification_commands"]["format"][0][
                "argv"
            ].append("private-changed-argument")
            cases.append(("changed-command", stale_declaration))

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(root, payload)

            reordered_declarations = self._v3_payload()
            second_format = deepcopy(
                reordered_declarations["verification_commands"]["format"][0]
            )
            second_format["command_id"] = "second-format-check"
            second_format["argv"] = ["python3", "--version"]
            reordered_declarations["verification_commands"]["format"].append(
                second_format
            )
            reordered_declarations["baseline_command_results"] = (
                self._baseline_for_payload(reordered_declarations)
            )
            baseline = validate_repository_registration(
                reordered_declarations,
                repository_root=root,
            )

            changed_order = deepcopy(reordered_declarations)
            changed_order["verification_commands"]["format"].reverse()
            changed_order["baseline_command_results"] = (
                self._baseline_for_payload(changed_order)
            )
            changed = validate_repository_registration(
                changed_order,
                repository_root=root,
            )
            self.assertNotEqual(
                baseline.registration_digest,
                changed.registration_digest,
            )
            self.assertNotEqual(
                baseline.verification_commands.digest,
                changed.verification_commands.digest,
            )

    def test_v3_baseline_shape_and_tagged_terminations_fail_closed(
        self,
    ) -> None:
        private_marker = "private-baseline-shape-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)

            valid_terminations = (
                {"kind": "exited", "exit_code": 0},
                {"kind": "exited", "exit_code": 255},
                {"kind": "signaled", "signal_number": 1},
                {"kind": "signaled", "signal_number": 64},
                {
                    "kind": "timed_out",
                    "timeout_seconds": 1,
                    "termination_confirmed": True,
                },
            )
            for termination in valid_terminations:
                with self.subTest(valid=termination):
                    payload = self._v3_payload()
                    payload["baseline_command_results"]["results"][0][
                        "termination"
                    ] = termination
                    validate_repository_registration(
                        payload,
                        repository_root=root,
                    )

            invalid_terminations: tuple[object, ...] = (
                None,
                [],
                "exited",
                {"kind": "exited"},
                {"kind": "exited", "exit_code": -1},
                {"kind": "exited", "exit_code": 256},
                {"kind": "exited", "exit_code": True},
                {"kind": "exited", "exit_code": 0.0},
                {"kind": "exited", "exit_code": 0, private_marker: True},
                {"kind": "signaled"},
                {"kind": "signaled", "signal_number": 0},
                {"kind": "signaled", "signal_number": 65},
                {"kind": "signaled", "signal_number": True},
                {"kind": "signaled", "signal_number": 1.0},
                {
                    "kind": "timed_out",
                    "timeout_seconds": 0,
                    "termination_confirmed": True,
                },
                {
                    "kind": "timed_out",
                    "timeout_seconds": 601,
                    "termination_confirmed": True,
                },
                {
                    "kind": "timed_out",
                    "timeout_seconds": 1,
                    "termination_confirmed": False,
                },
                {
                    "kind": "timed_out",
                    "timeout_seconds": 1,
                    "termination_confirmed": 1,
                },
                {"kind": private_marker, "exit_code": 0},
            )
            for termination in invalid_terminations:
                with self.subTest(invalid=termination):
                    payload = self._v3_payload()
                    payload["baseline_command_results"]["results"][0][
                        "termination"
                    ] = termination
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

            shape_cases: list[tuple[str, dict[str, object]]] = []
            for field in (
                "kind",
                "attestation_source",
                "snapshot_digest",
                "results",
            ):
                payload = self._v3_payload()
                del payload["baseline_command_results"][field]
                shape_cases.append((f"missing-baseline-{field}", payload))
            extra_baseline = self._v3_payload()
            extra_baseline["baseline_command_results"][private_marker] = True
            shape_cases.append(("extra-baseline", extra_baseline))
            for field in (
                "kind",
                "command_id",
                "command_digest",
                "started_at_unix_ms",
                "completed_at_unix_ms",
                "termination",
            ):
                payload = self._v3_payload()
                del payload["baseline_command_results"]["results"][0][field]
                shape_cases.append((f"missing-result-{field}", payload))
            extra_result = self._v3_payload()
            extra_result["baseline_command_results"]["results"][0][
                private_marker
            ] = True
            shape_cases.append(("extra-result", extra_result))
            for case, value in (
                ("baseline-null", None),
                ("baseline-list", []),
                ("baseline-string", private_marker),
            ):
                payload = self._v3_payload()
                payload["baseline_command_results"] = value
                shape_cases.append((case, payload))
            for case, value in (
                ("results-null", None),
                ("results-object", {}),
                ("results-string", private_marker),
            ):
                payload = self._v3_payload()
                payload["baseline_command_results"]["results"] = value
                shape_cases.append((case, payload))
            scalar_result = self._v3_payload()
            scalar_result["baseline_command_results"]["results"][0] = (
                private_marker
            )
            shape_cases.append(("scalar-result", scalar_result))
            wrong_source = self._v3_payload()
            wrong_source["baseline_command_results"][
                "attestation_source"
            ] = private_marker
            shape_cases.append(("wrong-source", wrong_source))
            wrong_kind = self._v3_payload()
            wrong_kind["baseline_command_results"]["kind"] = private_marker
            shape_cases.append(("wrong-kind", wrong_kind))
            for case, digest in (
                ("prefixless", "0" * 64),
                ("uppercase", "sha256:" + "A" * 64),
                ("short", "sha256:" + "0" * 63),
                ("wrong-algorithm", "sha512:" + "0" * 64),
                ("boolean", True),
            ):
                payload = self._v3_payload()
                payload["baseline_command_results"][
                    "snapshot_digest"
                ] = digest
                shape_cases.append((f"snapshot-{case}", payload))

            for case, payload in shape_cases:
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

    def test_v3_baseline_timestamps_obey_resource_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            cases: list[tuple[str, object, object]] = (
                ("boolean-start", True, 2_000),
                ("float-start", 1_000.0, 2_000),
                ("string-start", "1000", 2_000),
                ("boolean-complete", 1_000, True),
                ("float-complete", 1_000, 2_000.0),
                ("negative-start", -1, 1_000),
                ("negative-complete", -1, -1),
                ("reverse", 2_001, 2_000),
                ("wall-exceeded", 1_000, 601_001),
            )
            for case, started, completed in cases:
                with self.subTest(case=case):
                    payload = self._v3_payload()
                    result = payload["baseline_command_results"]["results"][0]
                    result["started_at_unix_ms"] = started
                    result["completed_at_unix_ms"] = completed
                    self._assert_invalid(root, payload)

            timed_out_too_soon = self._v3_payload()
            result = timed_out_too_soon["baseline_command_results"][
                "results"
            ][0]
            result["started_at_unix_ms"] = 1_000
            result["completed_at_unix_ms"] = 2_999
            result["termination"] = {
                "kind": "timed_out",
                "timeout_seconds": 2,
                "termination_confirmed": True,
            }
            self._assert_invalid(root, timed_out_too_soon)

            exact_timeout = deepcopy(timed_out_too_soon)
            exact_timeout["baseline_command_results"]["results"][0][
                "completed_at_unix_ms"
            ] = 3_000
            validate_repository_registration(
                exact_timeout,
                repository_root=root,
            )

    def test_v3_baseline_maximum_coverage_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            payload = self._v2_payload()
            payload["schema_version"] = 3
            for kind in ("format", "lint", "type_check", "test", "build"):
                payload["verification_commands"][kind] = [
                    {
                        "command_id": f"{kind.replace('_', '-')}-{index:02d}",
                        "argv": [
                            "python3",
                            "--version",
                            f"private-{kind}-{index:02d}",
                        ],
                        "cwd": ".",
                    }
                    for index in range(16)
                ]
            payload["baseline_command_results"] = self._baseline_for_payload(
                payload
            )

            schema_v3 = json.loads(
                REGISTRATION_SCHEMA_V3.read_text(encoding="utf-8")
            )
            self.assertTrue(validate_instance(payload, schema_v3).valid)
            registration = validate_repository_registration(
                payload,
                repository_root=root,
            )
            self.assertEqual(
                registration.to_evidence()["baseline_result_count"],
                80,
            )
            self.assertEqual(
                len(
                    registration.to_canonical()["baseline_command_results"][
                        "results"
                    ]
                ),
                80,
            )

            too_many = deepcopy(payload)
            too_many["baseline_command_results"]["results"].append(
                deepcopy(
                    too_many["baseline_command_results"]["results"][0]
                )
            )
            self._assert_invalid(root, too_many)

    def test_v4_executable_toolchain_identity_coverage_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            payload = self._v2_payload()
            payload["schema_version"] = 4
            for kind in ("format", "lint", "type_check", "test", "build"):
                payload["verification_commands"][kind] = [
                    {
                        "command_id": f"{kind.replace('_', '-')}-{index:02d}",
                        "argv": [
                            "python3",
                            "--version",
                            f"private-{kind}-{index:02d}",
                        ],
                        "cwd": ".",
                    }
                    for index in range(16)
                ]
            payload["baseline_command_results"] = self._baseline_for_payload(
                payload
            )
            payload["executable_toolchain_identities"] = (
                self._executable_toolchain_identities_for_payload(payload)
            )

            schema_v4 = json.loads(
                REGISTRATION_SCHEMA_V4.read_text(encoding="utf-8")
            )
            self.assertTrue(validate_instance(payload, schema_v4).valid)
            registration = validate_repository_registration(
                payload,
                repository_root=root,
            )
            self.assertEqual(
                registration.to_evidence()[
                    "executable_toolchain_identity_count"
                ],
                80,
            )
            self.assertEqual(
                len(
                    registration.to_canonical()[
                        "executable_toolchain_identities"
                    ]["identities"]
                ),
                80,
            )

            too_many = deepcopy(payload)
            too_many["executable_toolchain_identities"]["identities"].append(
                deepcopy(
                    too_many["executable_toolchain_identities"]["identities"][
                        0
                    ]
                )
            )
            self.assertFalse(validate_instance(too_many, schema_v4).valid)
            self._assert_invalid(root, too_many)

    def test_v3_baseline_hostile_collections_and_typed_forgery_fail_closed(
        self,
    ) -> None:
        private_marker = "private-baseline-hook-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            hook = Path(temporary) / "private-baseline-hook-ran"

            class ExplodingList(list[object]):
                def __iter__(self):
                    hook.write_text(private_marker, encoding="utf-8")
                    raise AssertionError("caller list hook must not run")

            class ExplodingDict(dict[str, object]):
                def items(self):
                    hook.write_text(private_marker, encoding="utf-8")
                    raise AssertionError("caller mapping hook must not run")

            hostile_payloads = []
            hostile_baseline = self._v3_payload()
            hostile_baseline["baseline_command_results"] = ExplodingDict(
                hostile_baseline["baseline_command_results"]
            )
            hostile_payloads.append(hostile_baseline)

            hostile_results = self._v3_payload()
            hostile_results["baseline_command_results"]["results"] = (
                ExplodingList(
                    hostile_results["baseline_command_results"]["results"]
                )
            )
            hostile_payloads.append(hostile_results)

            hostile_result = self._v3_payload()
            hostile_result["baseline_command_results"]["results"][0] = (
                ExplodingDict(
                    hostile_result["baseline_command_results"]["results"][0]
                )
            )
            hostile_payloads.append(hostile_result)

            for payload in hostile_payloads:
                self._assert_invalid(
                    root,
                    payload,
                    private_marker=private_marker,
                )
            self.assertFalse(hook.exists())

            payload = self._v3_payload()
            registration = validate_repository_registration(
                payload,
                repository_root=root,
            )
            self.assertEqual(
                revalidate_repository_registration(registration),
                registration,
            )

            forged_missing = replace(
                registration,
                baseline_command_results=None,
            )
            with self.assertRaisesRegex(
                ValidationError,
                FIXED_VALIDATION_ERROR,
            ):
                revalidate_repository_registration(forged_missing)

            registration_v1 = validate_repository_registration(
                self._payload(),
                repository_root=root,
            )
            forged_v1 = replace(
                registration_v1,
                baseline_command_results=registration.baseline_command_results,
            )
            with self.assertRaisesRegex(
                ValidationError,
                FIXED_VALIDATION_ERROR,
            ):
                revalidate_repository_registration(forged_v1)

            payload["baseline_command_results"]["results"][0][
                "command_id"
            ] = private_marker
            self.assertEqual(
                revalidate_repository_registration(registration),
                registration,
            )

    def test_v4_identity_hostile_collections_and_typed_forgery_fail_closed(
        self,
    ) -> None:
        private_marker = "private-toolchain-hook-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            hook = Path(temporary) / "private-toolchain-hook-ran"

            class ExplodingList(list[object]):
                def __iter__(self):
                    hook.write_text(private_marker, encoding="utf-8")
                    raise AssertionError("caller list hook must not run")

            class ExplodingDict(dict[str, object]):
                def items(self):
                    hook.write_text(private_marker, encoding="utf-8")
                    raise AssertionError("caller mapping hook must not run")

            class ExplodingString(str):
                def __str__(self):
                    hook.write_text(private_marker, encoding="utf-8")
                    raise AssertionError("caller string hook must not run")

            hostile_payloads = []
            hostile_block = self._v4_payload()
            hostile_block["executable_toolchain_identities"] = ExplodingDict(
                hostile_block["executable_toolchain_identities"]
            )
            hostile_payloads.append(hostile_block)

            hostile_identities = self._v4_payload()
            hostile_identities["executable_toolchain_identities"][
                "identities"
            ] = ExplodingList(
                hostile_identities["executable_toolchain_identities"][
                    "identities"
                ]
            )
            hostile_payloads.append(hostile_identities)

            hostile_identity = self._v4_payload()
            hostile_identity["executable_toolchain_identities"]["identities"][
                0
            ] = ExplodingDict(
                hostile_identity["executable_toolchain_identities"][
                    "identities"
                ][0]
            )
            hostile_payloads.append(hostile_identity)

            hostile_digest = self._v4_payload()
            hostile_digest["executable_toolchain_identities"]["identities"][0][
                "executable_identity_digest"
            ] = ExplodingString("sha256:" + "a" * 64)
            hostile_payloads.append(hostile_digest)

            for payload in hostile_payloads:
                self._assert_invalid(
                    root,
                    payload,
                    private_marker=private_marker,
                )
            self.assertFalse(hook.exists())

            registration = validate_repository_registration(
                self._v4_payload(),
                repository_root=root,
            )
            identities = registration.executable_toolchain_identities
            self.assertIsInstance(identities, ExecutableToolchainIdentities)
            self.assertIsInstance(
                identities.identities[0],
                ExecutableToolchainIdentity,
            )
            self.assertEqual(
                revalidate_repository_registration(registration),
                registration,
            )

            forged_missing = replace(
                registration,
                executable_toolchain_identities=None,
            )
            with self.assertRaisesRegex(
                ValidationError,
                FIXED_VALIDATION_ERROR,
            ):
                revalidate_repository_registration(forged_missing)

            for schema_version, legacy_payload in (
                (1, self._payload()),
                (2, self._v2_payload()),
                (3, self._v3_payload()),
            ):
                with self.subTest(forged_schema_version=schema_version):
                    legacy_registration = validate_repository_registration(
                        legacy_payload,
                        repository_root=root,
                    )
                    forged_legacy = replace(
                        legacy_registration,
                        executable_toolchain_identities=identities,
                    )
                    with self.assertRaisesRegex(
                        ValidationError,
                        FIXED_VALIDATION_ERROR,
                    ):
                        revalidate_repository_registration(forged_legacy)

            for field, value in (
                ("command_digest", "sha256:" + "0" * 64),
                ("declared_executable_kind", "repository_relative"),
                ("declared_executable_ref", "sha256:" + "0" * 64),
                ("executable_identity_digest", "sha256:" + "A" * 64),
                ("toolchain_identity_digest", "sha256:" + "A" * 64),
            ):
                with self.subTest(forged_identity_field=field):
                    forged_identity = replace(
                        identities.identities[0],
                        **{field: value},
                    )
                    forged_record = replace(
                        registration,
                        executable_toolchain_identities=replace(
                            identities,
                            identities=(
                                forged_identity,
                                *identities.identities[1:],
                            ),
                        ),
                    )
                    with self.assertRaisesRegex(
                        ValidationError,
                        FIXED_VALIDATION_ERROR,
                    ):
                        revalidate_repository_registration(forged_record)

            for field in (
                "repository_ref",
                "verification_commands_digest",
                "baseline_command_results_digest",
            ):
                with self.subTest(forged_identity_block_field=field):
                    forged_block = replace(
                        registration,
                        executable_toolchain_identities=replace(
                            identities,
                            **{field: "sha256:" + "0" * 64},
                        ),
                    )
                    with self.assertRaisesRegex(
                        ValidationError,
                        FIXED_VALIDATION_ERROR,
                    ):
                        revalidate_repository_registration(forged_block)

            empty_argv_command = replace(
                registration.verification_commands.format[0],
                argv=(),
            )
            forged_empty_argv = replace(
                registration,
                verification_commands=replace(
                    registration.verification_commands,
                    format=(empty_argv_command,),
                ),
            )
            with self.assertRaisesRegex(
                ValidationError,
                FIXED_VALIDATION_ERROR,
            ):
                revalidate_repository_registration(forged_empty_argv)

            forged_baseline = replace(
                registration,
                baseline_command_results=replace(
                    registration.baseline_command_results,
                    snapshot_digest="sha256:" + "c" * 64,
                ),
            )
            with self.assertRaisesRegex(
                ValidationError,
                FIXED_VALIDATION_ERROR,
            ):
                revalidate_repository_registration(forged_baseline)

            payload = self._v4_payload()
            immutable = validate_repository_registration(
                payload,
                repository_root=root,
            )
            payload["executable_toolchain_identities"]["identities"][0][
                "command_id"
            ] = private_marker
            self.assertEqual(
                revalidate_repository_registration(immutable),
                immutable,
            )

    def test_repository_identity_and_set_like_paths_are_digest_stable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            (root / "nested").mkdir()
            payload = self._payload()
            baseline = validate_repository_registration(
                payload,
                repository_root=root,
            )
            reordered_payload = deepcopy(payload)
            reordered_payload["path_policy"]["allowed_paths"].reverse()
            reordered_payload["path_policy"]["protected_paths"].reverse()
            reordered = validate_repository_registration(
                reordered_payload,
                repository_root=root / "nested" / "..",
            )

            self.assertEqual(
                baseline.registration_digest,
                reordered.registration_digest,
            )
            self.assertEqual(baseline.repository, reordered.repository)
            self.assertEqual(baseline.path_policy, reordered.path_policy)

            case_alias = root.with_name(root.name.swapcase())
            if case_alias.exists():
                aliased = validate_repository_registration(
                    payload,
                    repository_root=case_alias,
                )
                self.assertEqual(
                    baseline.registration_digest,
                    aliased.registration_digest,
                )
                self.assertEqual(
                    baseline.repository.canonical_root,
                    aliased.repository.canonical_root,
                )

            second_root = Path(temporary) / "second-private-repository-marker"
            second_root.mkdir()
            (second_root / ".git").mkdir()
            for relative in payload["path_policy"]["allowed_paths"]:
                (second_root / relative).mkdir()
            changed = validate_repository_registration(
                payload,
                repository_root=second_root,
            )
            self.assertNotEqual(
                baseline.registration_digest,
                changed.registration_digest,
            )
            self.assertNotEqual(baseline.repository, changed.repository)

    def test_digest_binds_every_semantic_section_and_exact_argv_order(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            baseline_payload = self._payload()
            baseline = validate_repository_registration(
                baseline_payload,
                repository_root=root,
            )
            cases: tuple[tuple[str, object], ...] = (
                ("registration_version", "1.0.1"),
                ("repository_id", "changed-repository-id"),
                ("cpu_count", 3),
                ("backend", "local_container_v2"),
            )
            for field, value in cases:
                with self.subTest(field=field):
                    changed_payload = deepcopy(baseline_payload)
                    if field == "registration_version":
                        changed_payload[field] = value
                    elif field == "repository_id":
                        changed_payload["repository"][field] = value
                    elif field == "cpu_count":
                        changed_payload["resource_limits"][field] = value
                    else:
                        changed_payload["isolation_requirements"][field] = value
                    try:
                        changed = validate_repository_registration(
                            changed_payload,
                            repository_root=root,
                        )
                    except ValidationError:
                        # Unsupported isolation identifiers must fail closed;
                        # accepted identifiers must remain digest-bound.
                        if field != "backend":
                            raise
                    else:
                        self.assertNotEqual(
                            baseline.registration_digest,
                            changed.registration_digest,
                        )

            reordered_argv = deepcopy(baseline_payload)
            argv = reordered_argv["verification_commands"]["test"][0][
                "argv"
            ]
            argv[-2:] = reversed(argv[-2:])
            changed = validate_repository_registration(
                reordered_argv,
                repository_root=root,
            )
            self.assertNotEqual(
                baseline.registration_digest,
                changed.registration_digest,
            )
            self.assertEqual(
                changed.to_canonical()["verification_commands"]["test"][0][
                    "argv"
                ],
                argv,
            )

    def test_repository_descriptor_and_registration_identity_are_exact(
        self,
    ) -> None:
        private_marker = "private-repository-descriptor-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            cases: list[tuple[str, object]] = []
            for case, field, value in (
                ("wrong-vcs", "vcs", "hg"),
                ("wrong-root", "root", "private-source-path-marker"),
                ("identifier-object", "repository_id", [private_marker]),
                ("identifier-uppercase", "repository_id", "Private/Repo"),
                ("identifier-double-slash", "repository_id", "owner//repo"),
                ("identifier-trailing-slash", "repository_id", "owner/repo/"),
            ):
                payload = self._payload()
                payload["repository"][field] = value
                cases.append((case, payload))
            extra_repository_key = self._payload()
            extra_repository_key["repository"][private_marker] = True
            cases.append(("extra-repository-key", extra_repository_key))
            invalid_registration_id = self._payload()
            invalid_registration_id["registration_id"] = [private_marker]
            cases.append(("invalid-registration-id", invalid_registration_id))
            invalid_version = self._payload()
            invalid_version["registration_version"] = private_marker
            cases.append(("invalid-version", invalid_version))
            leading_zero_version = self._payload()
            leading_zero_version["registration_version"] = "01.0.0"
            cases.append(("leading-zero-version", leading_zero_version))
            unbounded_version = self._payload()
            unbounded_version["registration_version"] = "1" * 10_000 + ".0.0"
            cases.append(("unbounded-version", unbounded_version))

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

    def test_command_shape_shell_credentials_and_controls_fail_closed(
        self,
    ) -> None:
        private_marker = "private-command-validation-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            protected_executable = root / ".git" / "hooks" / "private-check"
            protected_executable.parent.mkdir()
            protected_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            protected_executable.chmod(0o700)
            cases: list[tuple[str, object]] = []

            missing_category = self._payload()
            del missing_category["verification_commands"]["build"]
            cases.append(("missing-category", missing_category))
            extra_category = self._payload()
            extra_category["verification_commands"][private_marker] = []
            cases.append(("extra-category", extra_category))
            empty_tests = self._payload()
            empty_tests["verification_commands"]["test"] = []
            cases.append(("empty-tests", empty_tests))

            command_mutations = (
                ("argv-string", "python3 -m unittest"),
                ("empty-argv", []),
                ("empty-argument", ["python3", ""]),
                ("nested-argument", ["python3", [private_marker]]),
                ("boolean-argument", ["python3", True]),
                ("nul-control", ["python3", private_marker + "\x00"]),
                ("line-control", ["python3", private_marker + "\n"]),
                ("absolute-executable", ["/usr/bin/python3", "--version"]),
                ("shell", ["sh", "-c", "true"]),
                ("alternate-shell", ["ash", "-c", "true"]),
                ("windows-shell", ["powershell.exe", "-Command", "true"]),
                ("windows-pwsh", ["pwsh.exe", "-Command", "true"]),
                ("busybox-shell", ["busybox", "sh", "-c", "true"]),
                ("protected-executable", [".git/hooks/private-check"]),
                (
                    "credential",
                    ["python3", "OPENAI_API_KEY=" + private_marker],
                ),
                (
                    "credential-option-pair",
                    ["tool", "--api-key", "plain-secret-value"],
                ),
                (
                    "password-option-pair",
                    ["tool", "--password", "plain-secret-value"],
                ),
                (
                    "credential-name-pair",
                    ["tool", "OPENAI_API_KEY", "plain-secret-value"],
                ),
                (
                    "credential-file-option",
                    ["tool", "--auth-file=.env"],
                ),
                (
                    "credential-path-option",
                    ["tool", "--config=.env.private"],
                ),
                (
                    "credential-envrc-option",
                    ["tool", "--config=.envrc"],
                ),
            )
            for case, argv in command_mutations:
                payload = self._payload()
                payload["verification_commands"]["test"][0]["argv"] = argv
                cases.append((case, payload))

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

    def test_command_entries_and_cwds_are_strict_and_unique(self) -> None:
        private_marker = "private-command-entry-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, outside = self._repository(temporary)
            (root / "private-internal-link-marker").symlink_to(
                root / "private-source-path-marker",
                target_is_directory=True,
            )
            cases: list[tuple[str, object]] = []
            for case, mutation in (
                ("missing-id", lambda item: item.pop("command_id")),
                (
                    "extra-key",
                    lambda item: item.__setitem__(private_marker, True),
                ),
                (
                    "id-object",
                    lambda item: item.__setitem__(
                        "command_id", {private_marker: True}
                    ),
                ),
                (
                    "absolute-cwd",
                    lambda item: item.__setitem__("cwd", str(outside)),
                ),
                (
                    "escape-cwd",
                    lambda item: item.__setitem__("cwd", "../outside"),
                ),
                (
                    "symlink-cwd",
                    lambda item: item.__setitem__(
                        "cwd", "private-internal-link-marker"
                    ),
                ),
            ):
                payload = self._payload()
                mutation(payload["verification_commands"]["test"][0])
                cases.append((case, payload))
            duplicate_id = self._payload()
            duplicate_id["verification_commands"]["test"].append(
                deepcopy(
                    duplicate_id["verification_commands"]["test"][0]
                )
            )
            cases.append(("duplicate-id", duplicate_id))

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

    def test_paths_reject_controller_roots_traversal_and_symlinks(self) -> None:
        private_marker = "private-invalid-path-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, outside = self._repository(temporary)
            (root / "private-internal-link-marker").symlink_to(
                root / "private-source-path-marker",
                target_is_directory=True,
            )
            (root / "private-external-link-marker").symlink_to(
                outside,
                target_is_directory=True,
            )

            allowed_values = (
                ".",
                ".git",
                ".GIT/hooks",
                ".git/hooks",
                ".ordomata",
                ".OrDoMaTa/runs",
                ".ordomata/runs",
                ".agentops",
                ".AgEnToPs/runs",
                ".agentops/runs",
                "../private-outside-marker",
                str(outside),
                "private-source-path-marker/../private-test-path-marker",
                "private-internal-link-marker",
                "private-external-link-marker",
                private_marker + "\x00",
                r"private\windows\path",
            )
            for value in allowed_values:
                with self.subTest(scope="allowed", value=value):
                    payload = self._payload()
                    payload["path_policy"]["allowed_paths"] = [value]
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

            for value in (
                "../private-outside-marker",
                str(outside),
                "private-internal-link-marker",
                "private-external-link-marker",
                private_marker + "\x00",
            ):
                with self.subTest(scope="protected", value=value):
                    payload = self._payload()
                    payload["path_policy"]["protected_paths"].append(value)
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

            for mandatory in (".git", ".ordomata", ".agentops"):
                with self.subTest(scope="mandatory", value=mandatory):
                    payload = self._payload()
                    payload["path_policy"]["protected_paths"].remove(
                        mandatory
                    )
                    self._assert_invalid(root, payload)

            for case, allowed in (
                (
                    "duplicate",
                    [
                        "private-source-path-marker",
                        "private-source-path-marker",
                    ],
                ),
                (
                    "overlap",
                    [
                        "private-source-path-marker",
                        "private-source-path-marker/nested",
                    ],
                ),
            ):
                with self.subTest(scope="set-like", value=case):
                    payload = self._payload()
                    payload["path_policy"]["allowed_paths"] = allowed
                    self._assert_invalid(root, payload)

            case_alias_overlap = self._payload()
            case_alias_overlap["path_policy"]["allowed_paths"] = [
                "private-source-path-marker"
            ]
            case_alias_overlap["path_policy"]["protected_paths"].append(
                "PRIVATE-SOURCE-PATH-MARKER/nested"
            )
            self._assert_invalid(root, case_alias_overlap)

    def test_v2_exclusion_paths_reject_ambiguous_or_sensitive_syntax(
        self,
    ) -> None:
        private_marker = "private-exclusion-syntax-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, outside = self._repository(temporary)
            prefix = "private-source-path-marker/"
            values = (
                ".",
                "/private-absolute",
                "//private-host/share",
                str(outside),
                "C:/private-drive",
                "C:private-drive-relative",
                "~/private-expansion",
                "file:private-uri",
                prefix + "/generated",
                prefix + "./generated",
                prefix + "../generated",
                prefix + "generated/",
                "private-source-path-marker" + chr(92) + "generated",
                prefix + "*",
                prefix + "[ab]",
                prefix + "{one,two}",
                prefix + "$PRIVATE",
                prefix + chr(96) + "private" + chr(96),
                prefix + "!(vendor)",
                prefix + "@(one|two)",
                prefix + "<(private)",
                prefix + "nested/~private",
                prefix + "nested/private!",
                prefix + "nested/private^value",
                prefix + "private" + chr(0),
                prefix + "private" + chr(10),
                prefix + "private" + chr(127),
                prefix + "private" + chr(0x202E),
                prefix + "cafe" + chr(0x0301),
                prefix + chr(0xD800),
                prefix + "CON/generated",
                prefix + "CON .txt/generated",
                prefix + "nul.txt/generated",
                prefix + "vendor./generated",
                prefix + "vendor /generated",
                prefix + 'vendor"/generated',
                prefix + ".git/generated",
                prefix + ".ordomata/generated",
                prefix + ".agentops/generated",
                prefix + ".env",
                prefix + ".env.private",
                prefix + ".aws/cache",
                private_marker,
            )
            for value in values:
                with self.subTest(value=repr(value)):
                    payload = self._v2_payload()
                    payload["path_policy"]["generated_paths"] = [value]
                    payload["path_policy"]["vendor_paths"] = []
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

    def test_v2_exclusion_relationships_are_strict_and_unambiguous(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            cases: list[tuple[str, dict[str, object]]] = []

            equal_allowed = self._v2_payload()
            equal_allowed["path_policy"]["generated_paths"] = [
                "private-source-path-marker"
            ]
            equal_allowed["path_policy"]["vendor_paths"] = []
            cases.append(("equal-allowed", equal_allowed))

            contains_allowed = self._v2_payload()
            contains_allowed["path_policy"]["allowed_paths"] = [
                "private-source-path-marker/nested"
            ]
            contains_allowed["path_policy"]["generated_paths"] = [
                "private-source-path-marker"
            ]
            contains_allowed["path_policy"]["vendor_paths"] = []
            cases.append(("contains-allowed", contains_allowed))

            unrelated = self._v2_payload()
            unrelated["path_policy"]["generated_paths"] = [
                "private-unrelated-generated-marker"
            ]
            unrelated["path_policy"]["vendor_paths"] = []
            cases.append(("unrelated", unrelated))

            protected_descendant = self._v2_payload()
            protected_descendant["path_policy"]["protected_paths"].append(
                "private-source-path-marker/generated/locked"
            )
            protected_descendant["path_policy"]["vendor_paths"] = []
            cases.append(("contains-protected", protected_descendant))

            protected_ancestor = self._v2_payload()
            protected_ancestor["path_policy"]["protected_paths"].append(
                "private-source-path-marker"
            )
            protected_ancestor["path_policy"]["vendor_paths"] = []
            cases.append(("below-protected", protected_ancestor))

            cross_nested = self._v2_payload()
            cross_nested["path_policy"]["vendor_paths"] = [
                "private-source-path-marker/generated/vendor"
            ]
            cases.append(("cross-category-nested", cross_nested))

            casefold_alias = self._v2_payload()
            casefold_alias["path_policy"]["vendor_paths"] = [
                "PRIVATE-SOURCE-PATH-MARKER/GENERATED"
            ]
            cases.append(("cross-category-casefold", casefold_alias))

            allowed_casefold = self._v2_payload()
            allowed_casefold["path_policy"]["generated_paths"] = [
                "PRIVATE-SOURCE-PATH-MARKER/generated"
            ]
            allowed_casefold["path_policy"]["vendor_paths"] = []
            cases.append(("allowed-casefold", allowed_casefold))

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(root, payload)

            valid = self._v2_payload()
            valid["path_policy"]["generated_paths"] = [
                "private-source-path-marker/generated",
                "private-docs-path-marker/cache",
            ]
            valid["path_policy"]["vendor_paths"] = [
                "private-test-path-marker/vendor",
            ]
            registration = validate_repository_registration(
                valid,
                repository_root=root,
            )
            self.assertEqual(len(registration.path_policy.generated_paths), 2)
            self.assertEqual(len(registration.path_policy.vendor_paths), 1)

    def test_v2_exclusions_reject_symlinks_special_files_and_bounds(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, outside = self._repository(temporary)
            source = root / "private-source-path-marker"
            (source / "Vendor").mkdir()
            case_alias = self._v2_payload()
            case_alias["path_policy"]["generated_paths"] = [
                "private-source-path-marker/vendor/generated"
            ]
            case_alias["path_policy"]["vendor_paths"] = []
            self._assert_invalid(root, case_alias)

            casefold_sibling = source / "vendor"
            try:
                casefold_sibling.mkdir()
            except FileExistsError:
                pass
            else:
                ambiguous = self._v2_payload()
                ambiguous["path_policy"]["generated_paths"] = [
                    "private-source-path-marker/Vendor/generated"
                ]
                ambiguous["path_policy"]["vendor_paths"] = []
                self._assert_invalid(root, ambiguous)

            (source / "internal-link").symlink_to(
                root / "private-test-path-marker",
                target_is_directory=True,
            )
            (source / "external-link").symlink_to(
                outside,
                target_is_directory=True,
            )
            (source / "broken-link").symlink_to(
                outside / "missing",
                target_is_directory=True,
            )
            for name in ("internal-link", "external-link", "broken-link"):
                with self.subTest(link=name):
                    payload = self._v2_payload()
                    payload["path_policy"]["generated_paths"] = [
                        f"private-source-path-marker/{name}"
                    ]
                    payload["path_policy"]["vendor_paths"] = []
                    self._assert_invalid(root, payload)

            if hasattr(os, "mkfifo"):
                fifo = source / "private-fifo"
                os.mkfifo(fifo)
                payload = self._v2_payload()
                payload["path_policy"]["generated_paths"] = [
                    "private-source-path-marker/private-fifo"
                ]
                payload["path_policy"]["vendor_paths"] = []
                self._assert_invalid(root, payload)

            too_many = self._v2_payload()
            too_many["path_policy"]["generated_paths"] = [
                f"private-source-path-marker/generated-{index:03d}"
                for index in range(65)
            ]
            too_many["path_policy"]["vendor_paths"] = []
            self._assert_invalid(root, too_many)

            at_byte_limit = self._v2_payload()
            at_byte_limit["path_policy"]["generated_paths"] = [
                "private-source-path-marker/"
                + ("g" * 226)
                + f"-{index:03d}"
                for index in range(64)
            ]
            at_byte_limit["path_policy"]["vendor_paths"] = [
                "private-test-path-marker/"
                + ("v" * 226)
                + f"-{index:03d}"
                for index in range(64)
            ]
            total_bytes = sum(
                len(path.encode("utf-8"))
                for name in ("generated_paths", "vendor_paths")
                for path in at_byte_limit["path_policy"][name]
            )
            self.assertEqual(total_bytes, 32_768)
            at_limit_registration = validate_repository_registration(
                at_byte_limit,
                repository_root=root,
            )
            self.assertEqual(
                len(at_limit_registration.path_policy.generated_paths),
                64,
            )
            self.assertEqual(
                len(at_limit_registration.path_policy.vendor_paths),
                64,
            )

            over_byte_limit = deepcopy(at_byte_limit)
            over_byte_limit["path_policy"]["generated_paths"][0] += "x"
            self._assert_invalid(root, over_byte_limit)

    def test_v2_typed_and_caller_owned_exclusion_forgery_fails_closed(
        self,
    ) -> None:
        private_marker = "private-exclusion-hook-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            registration_v1 = validate_repository_registration(
                self._payload(),
                repository_root=root,
            )
            forged_v1 = replace(
                registration_v1,
                path_policy=replace(
                    registration_v1.path_policy,
                    generated_paths=(
                        "private-source-path-marker/generated",
                    ),
                ),
            )
            with self.assertRaisesRegex(
                ValidationError,
                FIXED_VALIDATION_ERROR,
            ):
                revalidate_repository_registration(forged_v1)

            hook = Path(temporary) / "private-exclusion-hook-ran"

            class ExplodingList(list[str]):
                def __iter__(self):
                    hook.write_text(private_marker, encoding="utf-8")
                    raise AssertionError("caller collection hook must not run")

            payload = self._v2_payload()
            payload["path_policy"]["generated_paths"] = ExplodingList(
                ["private-source-path-marker/generated"]
            )
            self._assert_invalid(
                root,
                payload,
                private_marker=private_marker,
            )
            self.assertFalse(hook.exists())

    def test_repository_root_and_git_metadata_must_be_ordinary_directories(
        self,
    ) -> None:
        private_marker = "private-invalid-root-marker"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            ordinary, _outside = self._repository(temporary)
            missing = base / private_marker
            file_root = base / (private_marker + "-file")
            file_root.write_text("not a directory", encoding="utf-8")
            symlink_root = base / (private_marker + "-symlink")
            symlink_root.symlink_to(ordinary, target_is_directory=True)
            for case, root in (
                ("missing", missing),
                ("file", file_root),
                ("symlink", symlink_root),
            ):
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        self._payload(),
                        private_marker=private_marker,
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-git-root-marker"
            root.mkdir()
            git_target = Path(temporary) / "private-git-target-marker"
            git_target.mkdir()
            (root / ".git").symlink_to(git_target, target_is_directory=True)
            self._assert_invalid(root, self._payload())

    def test_resource_limits_reject_bools_nonintegers_and_invalid_relations(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            fields = tuple(self._payload()["resource_limits"])
            for field in fields:
                for value in (True, "1", 1.5, 0, -1, 2**63):
                    with self.subTest(field=field, value=value):
                        payload = self._payload()
                        payload["resource_limits"][field] = value
                        self._assert_invalid(root, payload)

            for case, changes in (
                (
                    "idle-exceeds-wall",
                    {"idle_seconds": 601},
                ),
                (
                    "cpu-exceeds-core-wall-envelope",
                    {"cpu_count": 1, "cpu_seconds": 601},
                ),
                (
                    "output-exceeds-workspace",
                    {
                        "workspace_bytes": 1_048_576,
                        "output_bytes": 1_048_577,
                    },
                ),
                (
                    "artifact-exceeds-workspace",
                    {
                        "workspace_bytes": 1_048_576,
                        "artifact_bytes": 1_048_577,
                    },
                ),
            ):
                with self.subTest(case=case):
                    payload = self._payload()
                    payload["resource_limits"].update(changes)
                    self._assert_invalid(root, payload)

    def test_isolation_and_review_policy_cannot_enable_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            isolation_booleans = (
                "non_root",
                "read_only_base_repository",
                "read_only_root_filesystem",
                "explicit_mounts_only",
                "git_metadata_hidden",
                "credential_paths_denied",
                "control_sockets_denied",
                "fresh_cell_per_attempt",
            )
            for field in isolation_booleans:
                for value in (False, 1, "true"):
                    with self.subTest(section="isolation", field=field, value=value):
                        payload = self._payload()
                        payload["isolation_requirements"][field] = value
                        self._assert_invalid(root, payload)

            for field, value in (
                ("backend", "host"),
                ("backend", ["local_container"]),
                ("network_mode", "open"),
                ("network_mode", True),
            ):
                with self.subTest(section="isolation", field=field, value=value):
                    payload = self._payload()
                    payload["isolation_requirements"][field] = value
                    self._assert_invalid(root, payload)

            for field in (
                "branch_creation",
                "commit",
                "push",
                "pull_request",
                "promotion",
            ):
                with self.subTest(section="review", field=field):
                    payload = self._payload()
                    payload["review_policy"][field] = True
                    self._assert_invalid(root, payload)
            payload = self._payload()
            payload["review_policy"]["output"] = "branch"
            self._assert_invalid(root, payload)

    def test_malformed_unhashable_and_boolean_values_are_fixed_and_redacted(
        self,
    ) -> None:
        private_marker = "private-malformed-registration-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            cases: list[tuple[str, object]] = [
                ("string-root", private_marker),
                ("list-root", [private_marker]),
                ("set-root", {private_marker}),
            ]
            extra_key = self._payload()
            extra_key[private_marker] = True
            cases.append(("extra-key", extra_key))
            boolean_schema = self._payload()
            boolean_schema["schema_version"] = True
            cases.append(("boolean-schema", boolean_schema))
            wrong_kind = self._payload()
            wrong_kind["kind"] = private_marker
            cases.append(("wrong-kind", wrong_kind))
            unhashable_identifier = self._payload()
            unhashable_identifier["registration_id"] = [private_marker]
            cases.append(("unhashable-identifier", unhashable_identifier))
            unhashable_repository = self._payload()
            unhashable_repository["repository"]["vcs"] = [private_marker]
            cases.append(("unhashable-repository", unhashable_repository))

            for case, payload in cases:
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

            conversion_sentinel = Path(temporary) / "conversion-hook-ran"

            class CallerDefinedValue:
                def to_canonical(self):
                    conversion_sentinel.write_text("unsafe", encoding="utf-8")
                    return private_marker

            caller_object = self._payload()
            caller_object["registration_id"] = CallerDefinedValue()
            self._assert_invalid(
                root,
                caller_object,
                private_marker=private_marker,
            )
            self.assertFalse(conversion_sentinel.exists())

    def test_loader_uses_the_schema_and_redacts_filesystem_and_content(
        self,
    ) -> None:
        private_marker = "private-loader-error-marker"
        with tempfile.TemporaryDirectory() as temporary:
            root, _outside = self._repository(temporary)
            registration_path = Path(temporary) / (
                private_marker + "-registration.json"
            )
            registration_path.write_text(
                json.dumps(self._payload(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            loaded = load_repository_registration(
                registration_path,
                repository_root=root,
                definition_schema_path=REGISTRATION_SCHEMA,
            )
            direct = validate_repository_registration(
                self._payload(),
                repository_root=root,
            )
            self.assertEqual(
                loaded.registration_digest,
                direct.registration_digest,
            )

            malformed_path = Path(temporary) / (
                private_marker + "-malformed.json"
            )
            malformed_path.write_text(
                '{"private":"' + private_marker + '",',
                encoding="utf-8",
            )
            invalid_payload = self._payload()
            invalid_payload[private_marker] = private_marker
            invalid_path = Path(temporary) / (
                private_marker + "-invalid.json"
            )
            invalid_path.write_text(
                json.dumps(invalid_payload),
                encoding="utf-8",
            )
            missing_path = Path(temporary) / (
                private_marker + "-missing.json"
            )
            missing_schema = Path(temporary) / (
                private_marker + "-missing-schema.json"
            )
            for case, path, schema in (
                ("malformed", malformed_path, REGISTRATION_SCHEMA),
                ("invalid", invalid_path, REGISTRATION_SCHEMA),
                ("missing-registration", missing_path, REGISTRATION_SCHEMA),
                ("missing-schema", registration_path, missing_schema),
            ):
                with self.subTest(case=case):
                    with self.assertRaises(ConfigurationError) as caught:
                        load_repository_registration(
                            path,
                            repository_root=root,
                            definition_schema_path=schema,
                        )
                    projection = str(caught.exception)
                    self.assertNotIn(private_marker, projection)
                    self.assertNotIn(str(root), projection)
                    self.assertNotIn(str(path), projection)
                    self.assertNotIn(str(schema), projection)

    def test_loader_and_direct_snapshot_bounds_fail_with_fixed_errors(
        self,
    ) -> None:
        private_marker = "private-registration-bound-marker"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, _outside = self._repository(temporary)
            valid_path = base / "valid-registration.json"
            valid_path.write_text(
                json.dumps(self._payload(), sort_keys=True),
                encoding="utf-8",
            )

            huge_integer_path = base / f"{private_marker}-integer.json"
            huge_integer_path.write_text(
                '{"schema_version":' + "9" * 5_000 + "}",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError,
                f"^{FIXED_LOAD_ERROR}$",
            ) as huge_integer_error:
                load_repository_registration(
                    huge_integer_path,
                    repository_root=root,
                    definition_schema_path=REGISTRATION_SCHEMA,
                )
            self.assertNotIn(private_marker, str(huge_integer_error.exception))
            self.assertNotIn(
                str(huge_integer_path),
                str(huge_integer_error.exception),
            )

            oversized_registration_path = (
                base / f"{private_marker}-oversized-registration.json"
            )
            with oversized_registration_path.open("wb") as oversized:
                oversized.seek(MAX_REGISTRATION_DOCUMENT_BYTES)
                oversized.write(b"x")
            self.assertEqual(
                oversized_registration_path.stat().st_size,
                MAX_REGISTRATION_DOCUMENT_BYTES + 1,
            )
            with self.assertRaisesRegex(
                ConfigurationError,
                f"^{FIXED_LOAD_ERROR}$",
            ) as registration_error:
                load_repository_registration(
                    oversized_registration_path,
                    repository_root=root,
                    definition_schema_path=REGISTRATION_SCHEMA,
                )
            self.assertNotIn(private_marker, str(registration_error.exception))
            self.assertNotIn(
                str(oversized_registration_path),
                str(registration_error.exception),
            )

            oversized_schema_path = (
                base / f"{private_marker}-oversized-schema.json"
            )
            with oversized_schema_path.open("wb") as oversized:
                oversized.seek(MAX_SCHEMA_DOCUMENT_BYTES)
                oversized.write(b"x")
            self.assertEqual(
                oversized_schema_path.stat().st_size,
                MAX_SCHEMA_DOCUMENT_BYTES + 1,
            )
            with self.assertRaisesRegex(
                ConfigurationError,
                f"^{FIXED_SCHEMA_LOAD_ERROR}$",
            ) as schema_error:
                load_repository_registration(
                    valid_path,
                    repository_root=root,
                    definition_schema_path=oversized_schema_path,
                )
            self.assertNotIn(private_marker, str(schema_error.exception))
            self.assertNotIn(
                str(oversized_schema_path),
                str(schema_error.exception),
            )

            oversized_text = self._payload()
            oversized_text["registration_id"] = (
                private_marker
                + "x" * (MAX_DIRECT_SNAPSHOT_BYTES + 1)
            )
            oversized_key = self._payload()
            oversized_key[
                private_marker + "x" * (MAX_DIRECT_SNAPSHOT_BYTES + 1)
            ] = None
            huge_integer = self._payload()
            huge_integer["schema_version"] = 1 << 4_096
            for case, payload in (
                ("oversized-text", oversized_text),
                ("oversized-key", oversized_key),
                ("huge-integer", huge_integer),
            ):
                with self.subTest(case=case):
                    self._assert_invalid(
                        root,
                        payload,
                        private_marker=private_marker,
                    )

    def test_loader_dispatches_exact_versioned_schemas_without_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, _outside = self._repository(temporary)
            configuration = base / "config"
            schemas = base / "schemas"
            configuration.mkdir()
            schemas.mkdir()
            schema_v1 = schemas / REGISTRATION_SCHEMA.name
            schema_v2 = schemas / REGISTRATION_SCHEMA_V2.name
            schema_v3 = schemas / REGISTRATION_SCHEMA_V3.name
            schema_v4 = schemas / REGISTRATION_SCHEMA_V4.name
            schema_v1.write_bytes(REGISTRATION_SCHEMA.read_bytes())
            schema_v2.write_bytes(REGISTRATION_SCHEMA_V2.read_bytes())
            schema_v3.write_bytes(REGISTRATION_SCHEMA_V3.read_bytes())
            schema_v4.write_bytes(REGISTRATION_SCHEMA_V4.read_bytes())

            path_v1 = configuration / "registration-v1.json"
            path_v2 = configuration / "registration-v2.json"
            path_v3 = configuration / "registration-v3.json"
            path_v4 = configuration / "registration-v4.json"
            path_v1.write_text(
                json.dumps(self._payload(), sort_keys=True),
                encoding="utf-8",
            )
            path_v2.write_text(
                json.dumps(self._v2_payload(), sort_keys=True),
                encoding="utf-8",
            )
            path_v3.write_text(
                json.dumps(self._v3_payload(), sort_keys=True),
                encoding="utf-8",
            )
            path_v4.write_text(
                json.dumps(self._v4_payload(), sort_keys=True),
                encoding="utf-8",
            )

            paths = {1: path_v1, 2: path_v2, 3: path_v3, 4: path_v4}
            schema_paths = {
                1: schema_v1,
                2: schema_v2,
                3: schema_v3,
                4: schema_v4,
            }
            for version, path in paths.items():
                with self.subTest(version=version):
                    self.assertEqual(
                        load_repository_registration(
                            path,
                            repository_root=root,
                        ).schema_version,
                        version,
                    )

            for payload_version, path in paths.items():
                for schema_version, schema in schema_paths.items():
                    if payload_version == schema_version:
                        continue
                    with self.subTest(
                        payload_version=payload_version,
                        schema_version=schema_version,
                    ):
                        with self.assertRaisesRegex(
                            ConfigurationError,
                            FIXED_VALIDATION_ERROR,
                        ):
                            load_repository_registration(
                                path,
                                repository_root=root,
                                definition_schema_path=schema,
                            )

            for case, version in (
                ("boolean", True),
                ("float", 4.0),
                ("string", "4"),
                ("unsupported", 5),
            ):
                with self.subTest(case=case):
                    unsupported = self._v4_payload()
                    unsupported["schema_version"] = version
                    unsupported_path = configuration / f"{case}.json"
                    unsupported_path.write_text(
                        json.dumps(unsupported, sort_keys=True),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        ConfigurationError,
                        FIXED_VALIDATION_ERROR,
                    ):
                        load_repository_registration(
                            unsupported_path,
                            repository_root=root,
                        )

            schema_v4.unlink()
            with self.assertRaisesRegex(
                ConfigurationError,
                "repository registration schema could not be loaded",
            ):
                load_repository_registration(
                    path_v4,
                    repository_root=root,
                )
            self.assertEqual(
                load_repository_registration(
                    path_v3,
                    repository_root=root,
                ).schema_version,
                3,
            )

            schema_v3.unlink()
            with self.assertRaisesRegex(
                ConfigurationError,
                "repository registration schema could not be loaded",
            ):
                load_repository_registration(
                    path_v3,
                    repository_root=root,
                )
            self.assertEqual(
                load_repository_registration(
                    path_v2,
                    repository_root=root,
                ).schema_version,
                2,
            )

            schema_v2.unlink()
            with self.assertRaisesRegex(
                ConfigurationError,
                "repository registration schema could not be loaded",
            ):
                load_repository_registration(
                    path_v2,
                    repository_root=root,
                )

    def test_validation_is_read_only_and_never_invokes_a_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, outside = self._repository(temporary)
            payload = self._payload()
            registration_path = Path(temporary) / "registration.json"
            registration_path.write_text(
                json.dumps(payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            registration_file_before = registration_path.read_bytes()
            repository_before = self._tree_snapshot(root)
            outside_before = self._tree_snapshot(outside)

            with (
                patch.object(
                    subprocess,
                    "run",
                    side_effect=AssertionError("validation must not run a command"),
                ) as run,
                patch.object(
                    subprocess,
                    "Popen",
                    side_effect=AssertionError("validation must not start a process"),
                ) as popen,
                patch.object(
                    subprocess,
                    "call",
                    side_effect=AssertionError("validation must not call a process"),
                ) as call,
                patch.object(
                    subprocess,
                    "check_call",
                    side_effect=AssertionError("validation must not call a process"),
                ) as check_call,
                patch.object(
                    subprocess,
                    "check_output",
                    side_effect=AssertionError("validation must not read output"),
                ) as check_output,
                patch.object(
                    asyncio,
                    "create_subprocess_exec",
                    side_effect=AssertionError("validation must not start a worker"),
                ) as create_subprocess,
                patch.object(
                    asyncio,
                    "create_subprocess_shell",
                    side_effect=AssertionError("validation must not use a shell"),
                ) as create_subprocess_shell,
                patch.object(
                    os,
                    "system",
                    side_effect=AssertionError("validation must not use a shell"),
                ) as system,
                patch.object(
                    shutil,
                    "which",
                    side_effect=AssertionError(
                        "validation must not resolve a bare executable"
                    ),
                ) as which,
                patch.object(
                    Path,
                    "mkdir",
                    side_effect=AssertionError(
                        "validation must not create a directory"
                    ),
                ) as mkdir,
                patch.object(
                    Path,
                    "write_text",
                    side_effect=AssertionError("validation must not write a file"),
                ) as write_text,
                patch.object(
                    Path,
                    "write_bytes",
                    side_effect=AssertionError("validation must not write bytes"),
                ) as write_bytes,
                patch.object(
                    Path,
                    "touch",
                    side_effect=AssertionError("validation must not touch a file"),
                ) as touch,
                patch.object(
                    Path,
                    "unlink",
                    side_effect=AssertionError("validation must not remove a file"),
                ) as unlink,
                patch.object(
                    Path,
                    "rename",
                    side_effect=AssertionError("validation must not rename a file"),
                ) as rename,
                patch.object(
                    Path,
                    "replace",
                    side_effect=AssertionError("validation must not replace a file"),
                ) as replace,
            ):
                registration = validate_repository_registration(
                    payload,
                    repository_root=root,
                )
                registration_v2 = validate_repository_registration(
                    self._v2_payload(),
                    repository_root=root,
                )
                registration_v3 = validate_repository_registration(
                    self._v3_payload(),
                    repository_root=root,
                )
                refreshed_v3 = revalidate_repository_registration(
                    registration_v3
                )
                evidence_v3 = fresh_repository_registration_evidence(
                    registration_v3
                )
                registration_v4 = validate_repository_registration(
                    self._v4_payload(),
                    repository_root=root,
                )
                refreshed_v4 = revalidate_repository_registration(
                    registration_v4
                )
                evidence_v4 = fresh_repository_registration_evidence(
                    registration_v4
                )
                loaded = load_repository_registration(
                    registration_path,
                    repository_root=root,
                    definition_schema_path=REGISTRATION_SCHEMA,
                )

            self.assertRegex(
                registration.registration_digest,
                r"^sha256:[0-9a-f]{64}$",
            )
            self.assertEqual(
                loaded.registration_digest,
                registration.registration_digest,
            )
            self.assertEqual(registration_v2.schema_version, 2)
            self.assertEqual(refreshed_v3, registration_v3)
            self.assertEqual(evidence_v3["schema_version"], 3)
            self.assertFalse(evidence_v3["baseline_authenticity_verified"])
            self.assertFalse(evidence_v3["baseline_freshness_verified"])
            self.assertEqual(refreshed_v4, registration_v4)
            self.assertEqual(evidence_v4["schema_version"], 4)
            for false_fact in (
                "executable_toolchain_authenticity_verified",
                "executable_toolchain_content_verified",
                "executable_toolchain_execution_correspondence_verified",
                "executable_toolchain_freshness_verified",
                "executable_toolchain_resolution_verified",
                "toolchain_completeness_verified",
            ):
                self.assertIs(evidence_v4[false_fact], False)
            for observed in (
                run,
                popen,
                call,
                check_call,
                check_output,
                create_subprocess,
                create_subprocess_shell,
                system,
                which,
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
            self.assertEqual(
                registration_path.read_bytes(),
                registration_file_before,
            )
            self.assertFalse((root / ".git" / "worktrees").exists())
            self.assertFalse((root / ".ordomata").exists())
            self.assertFalse(
                (root / "private-source-path-marker" / "generated").exists()
            )
            self.assertFalse(
                (root / "private-test-path-marker" / "vendor").exists()
            )


if __name__ == "__main__":
    unittest.main()
