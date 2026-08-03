from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
import inspect
import json
import unittest
from unittest.mock import patch

import ordomata.repository_worker_job_tree as job_tree_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
from ordomata.repository_registration import (
    BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
    REPOSITORY_REGISTRATION_EVIDENCE_KIND,
)
from ordomata.repository_worker_job_tree import (
    REPOSITORY_WORKER_JOB_TREE_CONTRACT_KIND,
    REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION,
    RepositoryWorkerJobTreeSourceBundle,
    RepositoryWorkerJobTreeSourceFile,
    derive_repository_worker_job_tree_contract,
)


_PRIVATE_MARKER = "private-job-tree-source-marker"


def _ref(label: str) -> str:
    return canonical_digest({"fixture": label})


def _path_policy() -> dict[str, object]:
    return {
        "allowed_paths": ["docs", "source", "tests"],
        "generated_paths": ["source/generated"],
        "protected_paths": [
            ".agentops",
            ".git",
            ".ordomata",
            "protected.txt",
        ],
        "vendor_paths": ["vendor"],
    }


def _resource_limits() -> dict[str, int]:
    return {
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
    }


def _registration_evidence(
    *,
    path_policy: dict[str, object],
    resource_limits: dict[str, int],
) -> dict[str, object]:
    return {
        "authority_granted": False,
        "baseline_attestation_source": (
            BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE
        ),
        "baseline_authenticity_verified": False,
        "baseline_command_results_digest": _ref("baseline"),
        "baseline_freshness_verified": False,
        "baseline_result_count": 2,
        "dispatch_enabled": False,
        "executable_toolchain_attestation_source": (
            EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE
        ),
        "executable_toolchain_authenticity_verified": False,
        "executable_toolchain_content_verified": False,
        "executable_toolchain_execution_correspondence_verified": False,
        "executable_toolchain_freshness_verified": False,
        "executable_toolchain_identities_digest": _ref("identities"),
        "executable_toolchain_identity_count": 2,
        "executable_toolchain_resolution_verified": False,
        "filesystem_identity_ref": _ref("filesystem"),
        "isolation_requirements_digest": _ref("isolation"),
        "kind": REPOSITORY_REGISTRATION_EVIDENCE_KIND,
        "path_policy_digest": canonical_digest(path_policy),
        "registration_digest": _ref("registration"),
        "registration_ref": _ref("registration-id"),
        "registration_version": "4.0.0",
        "repository_ref": _ref("repository"),
        "resource_limits_digest": canonical_digest(resource_limits),
        "review_policy_digest": _ref("review-policy"),
        "schema_version": 4,
        "toolchain_completeness_verified": False,
        "validation_mode": "read_only",
        "verification_commands_digest": _ref("commands"),
    }


def _source_bundle() -> RepositoryWorkerJobTreeSourceBundle:
    return RepositoryWorkerJobTreeSourceBundle(
        files=(
            RepositoryWorkerJobTreeSourceFile(
                "docs/guide.md", b"documentation"
            ),
            RepositoryWorkerJobTreeSourceFile(
                "source/main.py", b"print('safe')\n", executable=True
            ),
            RepositoryWorkerJobTreeSourceFile(
                "tests/test_main.py", _PRIVATE_MARKER.encode("utf-8")
            ),
        )
    )


class RepositoryWorkerJobTreeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path_policy = _path_policy()
        self.resource_limits = _resource_limits()
        self.registration_evidence = _registration_evidence(
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
        )
        self.source_bundle = _source_bundle()
        self.contract = derive_repository_worker_job_tree_contract(
            self.registration_evidence,
            path_policy=self.path_policy,
            resource_limits=self.resource_limits,
            source_bundle=self.source_bundle,
        )

    def test_contract_is_digest_only_and_cannot_enable_materialization(self) -> None:
        mapping = self.contract.to_mapping()

        self.assertEqual(
            mapping["kind"], REPOSITORY_WORKER_JOB_TREE_CONTRACT_KIND
        )
        self.assertEqual(
            mapping["schema_version"], REPOSITORY_WORKER_JOB_TREE_SCHEMA_VERSION
        )
        self.assertEqual(
            mapping["required_job_tree_mode"], "controller_owned_no_git"
        )
        self.assertEqual(
            mapping["required_patch_reconciliation"], "controller_owned"
        )
        self.assertTrue(mapping["git_metadata_prohibited"])
        self.assertTrue(mapping["path_policy_bound"])
        self.assertEqual(mapping["source_file_count"], 3)
        self.assertEqual(
            mapping["source_total_bytes"], self.source_bundle.source_total_bytes
        )
        for name in (
            "authority_granted",
            "dispatch_enabled",
            "materialization_implemented",
            "materialization_permitted",
            "reconciliation_implemented",
            "registration_evidence_revalidated",
            "source_snapshot_verified",
            "worker_execution_permitted",
        ):
            self.assertFalse(mapping[name])
        rendered = json.dumps(mapping, sort_keys=True)
        self.assertNotIn(_PRIVATE_MARKER, rendered)
        self.assertNotIn("source/main.py", rendered)

    def test_policy_resource_and_entry_failures_are_fixed_and_private(self) -> None:
        outside = RepositoryWorkerJobTreeSourceBundle(
            files=(RepositoryWorkerJobTreeSourceFile("outside/file.txt", b"x"),)
        )
        protected = RepositoryWorkerJobTreeSourceBundle(
            files=(RepositoryWorkerJobTreeSourceFile("protected.txt", b"x"),)
        )
        generated = RepositoryWorkerJobTreeSourceBundle(
            files=(
                RepositoryWorkerJobTreeSourceFile(
                    "source/generated/file.py", b"x"
                ),
            )
        )
        altered_policy = _path_policy()
        altered_policy["allowed_paths"] = ["docs", "other", "source", "tests"]
        altered_limits = _resource_limits()
        altered_limits["workspace_bytes"] = 1_073_741_823
        cases = (
            ("outside", self.path_policy, self.resource_limits, outside),
            ("protected", self.path_policy, self.resource_limits, protected),
            ("generated", self.path_policy, self.resource_limits, generated),
            (
                "policy-digest",
                altered_policy,
                self.resource_limits,
                self.source_bundle,
            ),
            (
                "limits-digest",
                self.path_policy,
                altered_limits,
                self.source_bundle,
            ),
        )

        for name, policy, limits, bundle in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError) as raised:
                    derive_repository_worker_job_tree_contract(
                        self.registration_evidence,
                        path_policy=policy,
                        resource_limits=limits,
                        source_bundle=bundle,
                    )
                self.assertEqual(
                    str(raised.exception),
                    "repository worker job tree contract is invalid",
                )
                self.assertNotIn(_PRIVATE_MARKER, str(raised.exception))

    def test_non_v4_or_authority_evidence_is_wrapped_in_contract_failure(self) -> None:
        schema = dict(self.registration_evidence)
        schema["schema_version"] = 3
        authority = dict(self.registration_evidence)
        authority["authority_granted"] = True
        for name, evidence in (("schema", schema), ("authority", authority)):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    ValidationError,
                    "^repository worker job tree contract is invalid$",
                ):
                    derive_repository_worker_job_tree_contract(
                        evidence,
                        path_policy=self.path_policy,
                        resource_limits=self.resource_limits,
                        source_bundle=self.source_bundle,
                    )

    def test_source_bundle_rejects_unsafe_or_ambiguous_entries(self) -> None:
        cases = (
            (
                "git",
                (
                    RepositoryWorkerJobTreeSourceFile(
                        "source/.git/config", b"x"
                    ),
                ),
            ),
            (
                "credential-shaped",
                (
                    RepositoryWorkerJobTreeSourceFile(
                        "source/.env.example", b"x"
                    ),
                ),
            ),
            (
                "casefold-alias",
                (
                    RepositoryWorkerJobTreeSourceFile("source/Foo.py", b"x"),
                    RepositoryWorkerJobTreeSourceFile("source/foo.py", b"y"),
                ),
            ),
            (
                "file-directory-conflict",
                (
                    RepositoryWorkerJobTreeSourceFile("source/item", b"x"),
                    RepositoryWorkerJobTreeSourceFile(
                        "source/item/child.py", b"y"
                    ),
                ),
            ),
        )
        for name, files in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    ValidationError,
                    "^repository worker job tree source bundle is invalid$",
                ):
                    RepositoryWorkerJobTreeSourceBundle(files=files)

    def test_source_bundle_is_immutable_and_capacity_bound_by_registration(
        self,
    ) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.source_bundle.files = ()

        capacity_limits = _resource_limits()
        capacity_limits["workspace_bytes"] = 1024 * 1024
        capacity_limits["output_bytes"] = 1024 * 1024
        capacity_limits["artifact_bytes"] = 1024 * 1024
        capacity_evidence = _registration_evidence(
            path_policy=self.path_policy,
            resource_limits=capacity_limits,
        )
        within_capacity = RepositoryWorkerJobTreeSourceBundle(
            files=(
                RepositoryWorkerJobTreeSourceFile(
                    "source/exact.py", b"x" * (1024 * 1024)
                ),
            )
        )
        self.assertEqual(
            derive_repository_worker_job_tree_contract(
                capacity_evidence,
                path_policy=self.path_policy,
                resource_limits=capacity_limits,
                source_bundle=within_capacity,
            ).source_total_bytes,
            1024 * 1024,
        )
        oversized = RepositoryWorkerJobTreeSourceBundle(
            files=(
                RepositoryWorkerJobTreeSourceFile(
                    "source/large.py", b"x" * (1024 * 1024 + 1)
                ),
            )
        )
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree contract is invalid$",
        ):
            derive_repository_worker_job_tree_contract(
                capacity_evidence,
                path_policy=self.path_policy,
                resource_limits=capacity_limits,
                source_bundle=oversized,
            )

    def test_contract_rechecks_its_own_shape_and_captures_the_evidence_boundary(
        self,
    ) -> None:
        object.__setattr__(self.contract, "source_file_count", 0)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker job tree contract is invalid$",
        ):
            self.contract.to_mapping()

        with patch.object(
            job_tree_module,
            "derive_repository_worker_cell_containment_contract",
            side_effect=AssertionError("public helper must not run"),
        ):
            contract = job_tree_module.derive_repository_worker_job_tree_contract(
                self.registration_evidence,
                path_policy=self.path_policy,
                resource_limits=self.resource_limits,
                source_bundle=self.source_bundle,
            )
        self.assertEqual(
            contract.source_bundle_digest, self.source_bundle.source_bundle_digest
        )

    def test_module_has_no_effectful_runtime_imports(self) -> None:
        tree = ast.parse(inspect.getsource(job_tree_module))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertFalse(
            imported
            & {
                "asyncio",
                "os",
                "pathlib",
                "socket",
                "sqlite3",
                "subprocess",
                "tempfile",
                "urllib",
            }
        )


if __name__ == "__main__":
    unittest.main()
