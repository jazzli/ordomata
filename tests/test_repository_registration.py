from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.errors import ConfigurationError, ValidationError
from ordomata.repository_registration import (
    REPOSITORY_REGISTRATION_KIND,
    REPOSITORY_REGISTRATION_SCHEMA_VERSION,
    load_repository_registration,
    validate_repository_registration,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
REGISTRATION_SCHEMA = (
    REPOSITORY_ROOT / "schemas" / "repository-registration.schema.json"
)
FIXED_VALIDATION_ERROR = "repository registration is invalid"


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
        self.assertEqual(REPOSITORY_REGISTRATION_SCHEMA_VERSION, 1)
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
            with self.assertRaises(FrozenInstanceError):
                registration.registration_digest = "sha256:" + "0" * 64

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
                    asyncio,
                    "create_subprocess_exec",
                    side_effect=AssertionError("validation must not start a worker"),
                ) as create_subprocess,
                patch.object(
                    os,
                    "system",
                    side_effect=AssertionError("validation must not use a shell"),
                ) as system,
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
            for observed in (
                run,
                popen,
                create_subprocess,
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
            self.assertEqual(
                registration_path.read_bytes(),
                registration_file_before,
            )
            self.assertFalse((root / ".git" / "worktrees").exists())
            self.assertFalse((root / ".ordomata").exists())


if __name__ == "__main__":
    unittest.main()
