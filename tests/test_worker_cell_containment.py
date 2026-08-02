from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
import inspect
import json
import math
import unittest

import ordomata.worker_cell_containment as containment_module
from ordomata.authorization import canonical_digest
from ordomata.errors import ValidationError
from ordomata.repository_registration import (
    BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
    REPOSITORY_REGISTRATION_EVIDENCE_KIND,
)
from ordomata.worker_cell_containment import (
    DeterministicWorkerCellContainmentBackend,
    REPOSITORY_WORKER_CELL_CONTAINMENT_ASSESSMENT_KIND,
    REPOSITORY_WORKER_CELL_CONTAINMENT_CONTRACT_KIND,
    REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION,
    WorkerCellContainmentBackendKind,
    WorkerCellPostflightAttestation,
    WorkerCellPreflightAttestation,
    assess_repository_worker_cell_containment,
    derive_repository_worker_cell_containment_contract,
)


_PRIVATE_MARKER = "private-worker-cell-containment-marker"


def _ref(label: str) -> str:
    return canonical_digest({"fixture": label})


def _registration_evidence() -> dict[str, object]:
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
        "path_policy_digest": _ref("path-policy"),
        "registration_digest": _ref("registration"),
        "registration_ref": _ref("registration-id"),
        "registration_version": "4.0.0",
        "repository_ref": _ref("repository"),
        "resource_limits_digest": _ref("resource-limits"),
        "review_policy_digest": _ref("review-policy"),
        "schema_version": 4,
        "toolchain_completeness_verified": False,
        "validation_mode": "read_only",
        "verification_commands_digest": _ref("commands"),
    }


class WorkerCellContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = derive_repository_worker_cell_containment_contract(
            _registration_evidence()
        )

    def test_contract_is_digest_only_and_cannot_enable_execution(self) -> None:
        mapping = self.contract.to_mapping()

        self.assertEqual(
            mapping["kind"],
            REPOSITORY_WORKER_CELL_CONTAINMENT_CONTRACT_KIND,
        )
        self.assertEqual(
            mapping["schema_version"],
            REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION,
        )
        self.assertEqual(mapping["required_backend"], "local_container")
        self.assertEqual(mapping["required_network_mode"], "disabled")
        for name in (
            "authority_granted",
            "backend_implemented",
            "containment_proven",
            "dispatch_enabled",
            "registration_evidence_revalidated",
            "worker_execution_permitted",
        ):
            self.assertFalse(mapping[name])
        self.assertNotIn(_PRIVATE_MARKER, json.dumps(mapping, sort_keys=True))

    def test_contract_rejects_non_v4_or_authority_claims_without_leaking_input(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []
        schema = _registration_evidence()
        schema["schema_version"] = 3
        cases.append(("schema", schema))
        authority = _registration_evidence()
        authority["authority_granted"] = True
        cases.append(("authority", authority))
        extra = _registration_evidence()
        extra["private"] = _PRIVATE_MARKER
        cases.append(("extra", extra))
        malformed = _registration_evidence()
        malformed["repository_ref"] = _PRIVATE_MARKER
        cases.append(("reference", malformed))
        unbounded_count = _registration_evidence()
        unbounded_count["baseline_result_count"] = 4_097
        cases.append(("count", unbounded_count))
        zero_count = _registration_evidence()
        zero_count["baseline_result_count"] = 0
        cases.append(("zero-count", zero_count))
        oversized_identity_count = _registration_evidence()
        oversized_identity_count["executable_toolchain_identity_count"] = 81
        cases.append(("identity-count", oversized_identity_count))

        for case, value in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValidationError) as raised:
                    derive_repository_worker_cell_containment_contract(value)
                self.assertEqual(
                    str(raised.exception),
                    "repository worker cell containment contract is invalid",
                )
                self.assertNotIn(_PRIVATE_MARKER, str(raised.exception))

    def test_mock_attestations_are_complete_but_never_authoritative(self) -> None:
        backend = DeterministicWorkerCellContainmentBackend()
        preflight = backend.preflight(
            self.contract,
            attempt_ref=_ref("attempt"),
            observed_at=100.0,
        )
        postflight = backend.postflight(preflight, observed_at=101.0)
        assessment = assess_repository_worker_cell_containment(
            self.contract,
            preflight=preflight,
            postflight=postflight,
        )
        mapping = assessment.to_mapping()

        self.assertTrue(assessment.declared_contract_satisfied)
        self.assertEqual(
            assessment.finding_codes,
            ("deterministic_mock_not_authoritative",),
        )
        self.assertEqual(
            mapping["kind"],
            REPOSITORY_WORKER_CELL_CONTAINMENT_ASSESSMENT_KIND,
        )
        self.assertEqual(
            mapping["backend_kind"],
            WorkerCellContainmentBackendKind.DETERMINISTIC_MOCK.value,
        )
        self.assertTrue(mapping["backend_matched"])
        self.assertTrue(mapping["cell_ref_matched"])
        for name in (
            "authority_granted",
            "backend_implemented",
            "containment_proven",
            "dispatch_enabled",
            "enforcement_enabled",
            "state_persisted",
            "worker_execution_permitted",
        ):
            self.assertFalse(mapping[name])

    def test_missing_mismatched_or_incomplete_attestations_fail_closed(self) -> None:
        backend = DeterministicWorkerCellContainmentBackend()
        preflight = backend.preflight(
            self.contract,
            attempt_ref=_ref("attempt"),
            observed_at=100.0,
        )
        postflight = backend.postflight(preflight, observed_at=101.0)
        other_evidence = _registration_evidence()
        other_evidence["repository_ref"] = _ref("other-repository")
        other_contract = derive_repository_worker_cell_containment_contract(
            other_evidence
        )
        other_preflight = backend.preflight(
            other_contract,
            attempt_ref=_ref("other-attempt"),
            observed_at=100.0,
        )

        cases = {
            "missing": (None, None, {"preflight_missing", "postflight_missing"}),
            "contract": (
                replace(preflight, contract_digest=other_contract.contract_digest),
                postflight,
                {"preflight_contract_mismatch"},
            ),
            "cell": (
                preflight,
                replace(postflight, cell_ref=other_preflight.cell_ref),
                {"cell_reference_mismatch"},
            ),
            "time": (
                preflight,
                replace(postflight, observed_at=99.0),
                {"attestation_time_order_invalid"},
            ),
            "preflight-assurance": (
                replace(preflight, network_disabled=False),
                postflight,
                {"preflight_assurances_incomplete"},
            ),
            "postflight-assurance": (
                preflight,
                replace(postflight, execution_started=True),
                {"postflight_assurances_incomplete"},
            ),
        }
        for case, (candidate_preflight, candidate_postflight, expected) in cases.items():
            with self.subTest(case=case):
                assessment = assess_repository_worker_cell_containment(
                    self.contract,
                    preflight=candidate_preflight,
                    postflight=candidate_postflight,
                )
                self.assertTrue(expected.issubset(assessment.finding_codes))
                self.assertFalse(assessment.to_mapping()["containment_proven"])
                self.assertFalse(
                    assessment.to_mapping()["worker_execution_permitted"]
                )

    def test_attestation_validation_and_immutability_fail_closed(self) -> None:
        backend = DeterministicWorkerCellContainmentBackend()
        preflight = backend.preflight(
            self.contract,
            attempt_ref=_ref("attempt"),
            observed_at=100.0,
        )
        with self.assertRaises(FrozenInstanceError):
            preflight.cell_ref = _ref("mutated")
        for observed_at in (math.inf, 10**400):
            with self.subTest(observed_at=observed_at):
                with self.assertRaises(ValidationError):
                    WorkerCellPreflightAttestation(
                        contract_digest=self.contract.contract_digest,
                        cell_ref=_ref("cell"),
                        backend_kind=(
                            WorkerCellContainmentBackendKind.DETERMINISTIC_MOCK
                        ),
                        observed_at=observed_at,
                        effective_user_non_root=True,
                        base_repository_read_only=True,
                        root_filesystem_read_only=True,
                        explicit_mounts_only=True,
                        git_metadata_hidden=True,
                        network_disabled=True,
                        credential_paths_denied=True,
                        control_sockets_denied=True,
                        fresh_cell_per_attempt=True,
                        resource_limits_attested=True,
                    )
        with self.assertRaises(ValidationError):
            WorkerCellPostflightAttestation(
                contract_digest=self.contract.contract_digest,
                cell_ref=_ref("cell"),
                backend_kind=WorkerCellContainmentBackendKind.DETERMINISTIC_MOCK,
                observed_at=100.0,
                execution_started=False,
                process_cleanup_verified=True,
                filesystem_containment_verified=True,
                outside_worktree_writes_absent=True,
                network_access_absent=True,
                credential_access_absent=True,
                control_socket_access_absent=True,
                resource_cleanup_verified=1,
            )
        corrupted = backend.preflight(
            self.contract,
            attempt_ref=_ref("corrupted-attempt"),
            observed_at=100.0,
        )
        object.__setattr__(corrupted, "observed_at", 10**400)
        with self.assertRaisesRegex(
            ValidationError,
            "^repository worker cell containment attestation is invalid$",
        ):
            assess_repository_worker_cell_containment(
                self.contract,
                preflight=corrupted,
                postflight=None,
            )

    def test_contract_module_has_no_effectful_runtime_imports(self) -> None:
        tree = ast.parse(inspect.getsource(containment_module))
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
