from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import builtins
import inspect
import json
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
import urllib.request
from collections.abc import Mapping
from types import MappingProxyType
from unittest.mock import patch

from ordomata import (
    repository_proposal_admission as repository_proposal_admission_module,
)
from ordomata import (
    repository_proposal_admission_verification
    as repository_proposal_admission_verification_module,
)
from ordomata.authorization import canonical_digest
from ordomata.models import PermissionClass
from ordomata.repository_proposal_admission import (
    evaluate_repository_proposal_admission_shadow,
)
from ordomata.repository_proposal_inspection import (
    RepositoryProposalInspectionFinding,
    RepositoryProposalInspectionReport,
)
from ordomata.repository_proposal_admission_verification import (
    REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_KIND,
    REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_SCHEMA_VERSION,
    RepositoryProposalAdmissionVerificationFinding,
    RepositoryProposalAdmissionVerificationReport,
    verify_repository_proposal_admission_shadow_mapping,
)


_RUN_ID = "private-admission-verification-run-marker"
_OTHER_RUN_ID = "private-admission-verification-other-run-marker"
_PRIVATE_MARKERS = (
    _RUN_ID,
    _OTHER_RUN_ID,
    "private-admission-verification-extra-marker",
    "private-admission-verification-hostile-marker",
    "private-admission-verification-request-marker",
    "private-admission-verification-policy-marker",
    "private-admission-verification-decision-marker",
)
_REPORT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "verification_scope",
        "verification_mode",
        "source_trust",
        "verification_complete",
        "truncated",
        "contract_valid",
        "verified_variant",
        "input_authenticated",
        "durable_evidence_reinspected",
        "durable_evidence_verified",
        "fresh_authorization_established",
        "decision_authoritative",
        "enforcement_enabled",
        "authority_granted",
        "admission_performed",
        "action_performed",
        "action_receipt_created",
        "evidence_persisted",
        "repair_performed",
        "dispatch_enabled",
        "route_selected",
        "billing_assessed",
        "obligations_enforced",
        "finding_count",
        "findings",
    }
)
_REPORT_FALSE_KEYS = (
    "input_authenticated",
    "durable_evidence_reinspected",
    "durable_evidence_verified",
    "fresh_authorization_established",
    "decision_authoritative",
    "enforcement_enabled",
    "authority_granted",
    "admission_performed",
    "action_performed",
    "action_receipt_created",
    "evidence_persisted",
    "repair_performed",
    "dispatch_enabled",
    "route_selected",
    "billing_assessed",
    "obligations_enforced",
)
_SHADOW_FALSE_KEYS = (
    "decision_authoritative",
    "enforcement_enabled",
    "authority_granted",
    "admission_performed",
    "action_performed",
    "action_receipt_created",
    "evidence_persisted",
    "repair_performed",
    "dispatch_enabled",
    "route_selected",
    "billing_assessed",
    "obligations_enforced",
)


def _ref(label: str) -> str:
    return canonical_digest({"fixture": label})


def _complete_inspection(
    run_id: str = _RUN_ID,
    *,
    permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
) -> RepositoryProposalInspectionReport:
    return RepositoryProposalInspectionReport(
        run_ref=canonical_digest({"run_id": run_id}),
        coverage="complete",
        truncated=False,
        inspected_event_count=3,
        permission_class=int(permission_class),
        current_status="created",
        proposal_digest=_ref("proposal"),
        proposal_ref=_ref("proposal-id"),
        proposal_version_ref=_ref("proposal-version"),
        registration_digest=_ref("registration"),
        registration_ref=_ref("registration-id"),
        registration_version="1.0.0",
        repository_ref=_ref("repository"),
        registration_selection_digest=_ref("selection"),
        repository_proposal_binding_digest=_ref("binding"),
        selection_sequence=2,
        binding_sequence=3,
        findings=(),
    )


def _incomplete_inspection(
    run_id: str = _RUN_ID,
    *,
    permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
) -> RepositoryProposalInspectionReport:
    return RepositoryProposalInspectionReport(
        run_ref=canonical_digest({"run_id": run_id}),
        coverage="incomplete",
        truncated=False,
        inspected_event_count=1,
        permission_class=int(permission_class),
        current_status="created",
        proposal_digest=None,
        proposal_ref=None,
        proposal_version_ref=None,
        registration_digest=None,
        registration_ref=None,
        registration_version=None,
        repository_ref=None,
        registration_selection_digest=None,
        repository_proposal_binding_digest=None,
        selection_sequence=None,
        binding_sequence=None,
        findings=(
            RepositoryProposalInspectionFinding(
                "registration_selection_missing"
            ),
            RepositoryProposalInspectionFinding(
                "repository_proposal_binding_missing"
            ),
        ),
    )


def _mapping_for_inspection(
    inspection: RepositoryProposalInspectionReport,
    *,
    run_id: str = _RUN_ID,
    evaluated_at: float = 200.0,
) -> dict[str, object]:
    with patch.object(
        repository_proposal_admission_module,
        "_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE",
        return_value=inspection,
    ):
        return evaluate_repository_proposal_admission_shadow(
            "unused-verification-fixture.sqlite3",
            run_id=run_id,
            evaluated_at=evaluated_at,
        ).to_mapping()


def _evaluated_mapping(
    permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
) -> dict[str, object]:
    return _mapping_for_inspection(
        _complete_inspection(permission_class=permission_class)
    )


def _failed_mapping(reason: str) -> dict[str, object]:
    inspection = _complete_inspection()
    if reason == "inspection_run_binding_mismatch":
        return _mapping_for_inspection(
            _complete_inspection(_OTHER_RUN_ID),
            run_id=_RUN_ID,
        )

    if reason == "authorization_evaluation_failed":
        with (
            patch.object(
                repository_proposal_admission_module,
                "_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE",
                return_value=inspection,
            ),
            patch.object(
                repository_proposal_admission_module,
                "ShadowAuthorizationEvaluator",
                side_effect=RuntimeError(
                    "private-admission-verification-hostile-marker"
                ),
            ),
        ):
            return evaluate_repository_proposal_admission_shadow(
                "unused-verification-fixture.sqlite3",
                run_id=_RUN_ID,
                evaluated_at=200.0,
            ).to_mapping()

    if reason == "authorization_replay_mismatch":
        baseline = _mapping_for_inspection(inspection)
        with patch.object(
            repository_proposal_admission_module,
            "_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE",
            return_value=inspection,
        ):
            typed = evaluate_repository_proposal_admission_shadow(
                "unused-verification-fixture.sqlite3",
                run_id=_RUN_ID,
                evaluated_at=200.0,
            )
        assert typed.decision is not None
        forged = replace(
            typed.decision,
            reason_details=(
                "private-admission-verification-decision-marker",
            ),
        )

        class SubstitutedEvaluator:
            def evaluate(self, request, policy):
                del request, policy
                return forged

        with (
            patch.object(
                repository_proposal_admission_module,
                "_BUILTIN_INSPECT_REPOSITORY_PROPOSAL_EVIDENCE",
                return_value=inspection,
            ),
            patch.object(
                repository_proposal_admission_module,
                "ShadowAuthorizationEvaluator",
                SubstitutedEvaluator,
            ),
        ):
            mismatch = evaluate_repository_proposal_admission_shadow(
                "unused-verification-fixture.sqlite3",
                run_id=_RUN_ID,
                evaluated_at=200.0,
            ).to_mapping()
        assert mismatch != baseline
        return mismatch

    raise AssertionError(reason)


def _rehash(mapping: dict[str, object], name: str) -> None:
    mapping[f"{name}_digest"] = canonical_digest(mapping[name])


class _ExplodingMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise AssertionError(
            "private-admission-verification-hostile-marker"
        )

    def __iter__(self):
        raise AssertionError(
            "private-admission-verification-hostile-marker"
        )

    def __len__(self) -> int:
        raise AssertionError(
            "private-admission-verification-hostile-marker"
        )


class _ExplodingValue:
    def __repr__(self) -> str:
        raise AssertionError(
            "private-admission-verification-hostile-marker"
        )

    def __eq__(self, other: object) -> bool:
        del other
        raise AssertionError(
            "private-admission-verification-hostile-marker"
        )

    def to_canonical(self) -> object:
        raise AssertionError(
            "private-admission-verification-hostile-marker"
        )


class RepositoryProposalAdmissionVerificationTests(unittest.TestCase):
    def _assert_private_values_absent(self, value: object) -> None:
        projection = json.dumps(value, sort_keys=True, default=str)
        for marker in _PRIVATE_MARKERS:
            self.assertNotIn(marker, projection)

    def _assert_report(
        self,
        report: RepositoryProposalAdmissionVerificationReport,
        *,
        codes: tuple[str, ...] = (),
        variant: str | None = None,
    ) -> dict[str, object]:
        mapping = report.to_mapping()
        self.assertEqual(frozenset(mapping), _REPORT_KEYS)
        self.assertEqual(
            mapping["schema_version"],
            REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            mapping["kind"],
            REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_KIND,
        )
        self.assertEqual(mapping["verification_scope"], "supplied_mapping")
        self.assertEqual(
            mapping["verification_mode"], "independent_replay"
        )
        self.assertEqual(mapping["source_trust"], "untrusted")
        for key in _REPORT_FALSE_KEYS:
            self.assertIs(mapping[key], False, key)
        self.assertEqual(mapping["verified_variant"], variant)
        self.assertEqual(
            tuple(item["code"] for item in mapping["findings"]),
            codes,
        )
        self.assertEqual(mapping["finding_count"], len(codes))
        self.assertIs(mapping["contract_valid"], not codes)
        self.assertIs(report.contract_valid, not codes)
        self._assert_private_values_absent(mapping)
        self._assert_private_values_absent(repr(report))
        return mapping

    def _verify_code(
        self,
        value: object,
        code: str,
    ) -> RepositoryProposalAdmissionVerificationReport:
        report = verify_repository_proposal_admission_shadow_mapping(value)
        self._assert_report(report, codes=(code,))
        return report

    def _verify_codes(
        self,
        value: object,
        *codes: str,
    ) -> RepositoryProposalAdmissionVerificationReport:
        report = verify_repository_proposal_admission_shadow_mapping(value)
        self._assert_report(report, codes=tuple(codes))
        return report

    def test_actual_class_zero_and_one_mappings_replay_exactly(self) -> None:
        cases = (
            (PermissionClass.READ_ONLY, "evaluated_class_0"),
            (PermissionClass.LOCAL_DRAFT, "evaluated_class_1"),
        )
        for permission_class, variant in cases:
            with self.subTest(permission_class=permission_class):
                supplied = _evaluated_mapping(permission_class)
                before = deepcopy(supplied)
                first = verify_repository_proposal_admission_shadow_mapping(
                    supplied
                )
                second = verify_repository_proposal_admission_shadow_mapping(
                    deepcopy(supplied)
                )
                self._assert_report(first, variant=variant)
                self._assert_report(second, variant=variant)
                self.assertTrue(first.verification_complete)
                self.assertFalse(first.truncated)
                self.assertEqual(first, second)
                self.assertEqual(supplied, before)

                reordered = {
                    key: deepcopy(supplied[key])
                    for key in reversed(tuple(supplied))
                }
                self.assertEqual(
                    verify_repository_proposal_admission_shadow_mapping(
                        reordered
                    ),
                    first,
                )

    def test_non_evaluated_and_all_failed_variants_are_exact(self) -> None:
        cases = (
            (
                _mapping_for_inspection(_incomplete_inspection()),
                "not_evaluated",
            ),
            (
                _failed_mapping("inspection_run_binding_mismatch"),
                "failed_run_binding",
            ),
            (
                _failed_mapping("authorization_evaluation_failed"),
                "failed_evaluation",
            ),
            (
                _failed_mapping("authorization_replay_mismatch"),
                "failed_replay",
            ),
        )
        for supplied, variant in cases:
            with self.subTest(variant=variant):
                before = deepcopy(supplied)
                report = verify_repository_proposal_admission_shadow_mapping(
                    supplied
                )
                self._assert_report(report, variant=variant)
                self.assertEqual(supplied, before)

    def test_all_valid_nonclean_inspection_variants_are_mirrored(
        self,
    ) -> None:
        complete = _complete_inspection()
        selection_only = replace(
            complete,
            coverage="incomplete",
            inspected_event_count=2,
            proposal_ref=None,
            proposal_version_ref=None,
            repository_proposal_binding_digest=None,
            binding_sequence=None,
            findings=(
                RepositoryProposalInspectionFinding(
                    "repository_proposal_binding_missing"
                ),
            ),
        )
        invalid = replace(
            _incomplete_inspection(),
            coverage="invalid",
            inspected_event_count=4,
            findings=(
                RepositoryProposalInspectionFinding("unexpected_event"),
            ),
        )
        truncated_invalid = replace(
            invalid,
            truncated=True,
            findings=(
                RepositoryProposalInspectionFinding(
                    "event_limit_exceeded"
                ),
            ),
        )
        for inspection in (
            selection_only,
            invalid,
            truncated_invalid,
        ):
            with self.subTest(
                coverage=inspection.coverage,
                truncated=inspection.truncated,
            ):
                report = verify_repository_proposal_admission_shadow_mapping(
                    _mapping_for_inspection(inspection)
                )
                self._assert_report(report, variant="not_evaluated")

    def test_contract_valid_is_internal_consistency_not_an_anchor(self) -> None:
        original = _mapping_for_inspection(
            _complete_inspection(_RUN_ID),
            run_id=_RUN_ID,
        )
        replay_from_another_run = _mapping_for_inspection(
            _complete_inspection(_OTHER_RUN_ID),
            run_id=_OTHER_RUN_ID,
        )
        first = verify_repository_proposal_admission_shadow_mapping(original)
        repeated = verify_repository_proposal_admission_shadow_mapping(original)
        other = verify_repository_proposal_admission_shadow_mapping(
            replay_from_another_run
        )
        for report in (first, repeated, other):
            mapping = self._assert_report(
                report,
                variant="evaluated_class_1",
            )
            self.assertTrue(mapping["contract_valid"])
            for key in _REPORT_FALSE_KEYS:
                self.assertFalse(mapping[key])
        self.assertEqual(first, repeated)

    def test_outer_and_nested_hostile_types_are_not_invoked(self) -> None:
        class OuterDictSubclass(dict):
            def items(self):
                raise AssertionError(
                    "private-admission-verification-hostile-marker"
                )

        for supplied, code in (
            (None, "input_type_invalid"),
            ([], "input_type_invalid"),
            ((), "input_type_invalid"),
            (MappingProxyType({}), "input_type_invalid"),
            (_ExplodingMapping(), "input_type_invalid"),
            (OuterDictSubclass(), "input_type_invalid"),
        ):
            with self.subTest(type=type(supplied).__name__):
                self._verify_code(supplied, code)

        baseline = _evaluated_mapping()
        hostile_values = (
            _ExplodingValue(),
            {"safe": _ExplodingValue()},
            ["safe", _ExplodingValue()],
        )
        for hostile in hostile_values:
            with self.subTest(type=type(hostile).__name__):
                supplied = deepcopy(baseline)
                supplied["request"] = hostile
                self._verify_code(supplied, "input_tree_invalid")

        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class StringSubclass(str):
            pass

        for hostile in (
            DictSubclass(),
            ListSubclass(),
            StringSubclass("private-admission-verification-hostile-marker"),
            PermissionClass.LOCAL_DRAFT,
        ):
            with self.subTest(type=type(hostile).__name__):
                supplied = deepcopy(baseline)
                supplied["request"] = hostile
                self._verify_code(supplied, "input_tree_invalid")

        non_string_key = deepcopy(baseline)
        assert isinstance(non_string_key["request"], dict)
        non_string_key["request"][1] = "value"
        self._verify_code(non_string_key, "input_tree_invalid")

    def test_cycles_aliases_and_scalar_bounds_fail_before_replay(self) -> None:
        baseline = _evaluated_mapping()
        recursive_dict: dict[str, object] = {}
        recursive_dict["cycle"] = recursive_dict
        recursive_list: list[object] = []
        recursive_list.append(recursive_list)
        alias: dict[str, object] = {"leaf": "safe"}

        cases: list[tuple[dict[str, object], str]] = []
        for value in (recursive_dict, recursive_list):
            supplied = deepcopy(baseline)
            supplied["request"] = value
            cases.append((supplied, "input_tree_invalid"))
        supplied = deepcopy(baseline)
        supplied["alias_one"] = alias
        supplied["alias_two"] = alias
        cases.append((supplied, "input_tree_invalid"))
        for value in (float("nan"), float("inf"), -float("inf")):
            supplied = deepcopy(baseline)
            supplied["evaluated_at"] = value
            cases.append((supplied, "input_tree_invalid"))
        supplied = deepcopy(baseline)
        supplied["evaluated_at"] = 2**63
        cases.append((supplied, "input_bounds_exceeded"))
        supplied = deepcopy(baseline)
        supplied["mode"] = "\ud800"
        cases.append((supplied, "input_tree_invalid"))

        for supplied, code in cases:
            with self.subTest(code=code, value=type(supplied).__name__):
                with patch.object(
                    repository_proposal_admission_verification_module,
                    "_BUILTIN_CANONICAL_DIGEST",
                    side_effect=AssertionError(
                        "rejected input reached canonical hashing"
                    ),
                ):
                    self._verify_code(supplied, code)

    def test_depth_text_and_container_bounds_are_applied_first(self) -> None:
        baseline = _evaluated_mapping()
        too_deep: object = "leaf"
        for _ in range(
            repository_proposal_admission_verification_module._MAX_DEPTH + 1
        ):
            too_deep = [too_deep]
        cases: list[dict[str, object]] = []
        supplied = deepcopy(baseline)
        supplied["extra"] = too_deep
        cases.append(supplied)
        supplied = deepcopy(baseline)
        supplied["extra"] = "x" * (
            repository_proposal_admission_verification_module._MAX_TEXT_BYTES
            + 1
        )
        cases.append(supplied)
        supplied = deepcopy(baseline)
        supplied["extra"] = {
            str(index): index
            for index in range(
                repository_proposal_admission_verification_module
                ._MAX_DICT_ENTRIES
                + 1
            )
        }
        cases.append(supplied)
        supplied = deepcopy(baseline)
        supplied["extra"] = [
            "x"
            * repository_proposal_admission_verification_module._MAX_TEXT_BYTES
            for _ in range(
                repository_proposal_admission_verification_module
                ._MAX_LIST_ITEMS
            )
        ]
        cases.append(supplied)
        supplied = deepcopy(baseline)
        supplied["extra"] = [
            [0 for _ in range(32)] for _ in range(32)
        ]
        cases.append(supplied)
        supplied = deepcopy(baseline)
        supplied["extra"] = [
            [{} for _ in range(4)] for _ in range(32)
        ]
        cases.append(supplied)

        for supplied in cases:
            with (
                self.subTest(case=len(json.dumps(supplied))),
                patch.object(
                    repository_proposal_admission_verification_module,
                    "_BUILTIN_CANONICAL_DIGEST",
                    side_effect=AssertionError(
                        "oversized input reached canonical hashing"
                    ),
                ),
            ):
                report = self._verify_code(
                    supplied,
                    "input_bounds_exceeded",
                )
                self.assertTrue(report.truncated)
                self.assertFalse(report.verification_complete)

    def test_top_level_shape_and_fixed_semantics_are_exact(self) -> None:
        baseline = _evaluated_mapping()
        missing = deepcopy(baseline)
        del missing["request"]
        self._verify_code(missing, "shadow_shape_invalid")

        extra = deepcopy(baseline)
        extra["unexpected"] = (
            "private-admission-verification-extra-marker"
        )
        self._verify_code(extra, "shadow_shape_invalid")

        for key, value in (
            ("schema_version", 2),
            ("kind", "forged"),
            ("mode", "enforcing"),
            ("action_scope", "all_actions"),
        ):
            with self.subTest(key=key, value=value):
                supplied = deepcopy(baseline)
                supplied[key] = value
                self._verify_code(
                    supplied,
                    "shadow_fixed_semantics_mismatch",
                )

        wrong_schema_type = deepcopy(baseline)
        wrong_schema_type["schema_version"] = True
        self._verify_code(wrong_schema_type, "shadow_shape_invalid")

        for key in _SHADOW_FALSE_KEYS:
            with self.subTest(key=key):
                supplied = deepcopy(baseline)
                supplied[key] = True
                self._verify_code(
                    supplied,
                    "shadow_fixed_semantics_mismatch",
                )

        false_like = deepcopy(baseline)
        false_like["authority_granted"] = 0
        self._verify_code(false_like, "shadow_shape_invalid")

    def test_inspection_shape_semantics_and_digest_are_independent(self) -> None:
        baseline = _evaluated_mapping()
        wrong_shape = deepcopy(baseline)
        assert isinstance(wrong_shape["inspection"], dict)
        wrong_shape["inspection"]["unexpected"] = False
        self._verify_code(wrong_shape, "inspection_shape_invalid")

        wrong_semantics = deepcopy(baseline)
        assert isinstance(wrong_semantics["inspection"], dict)
        wrong_semantics["inspection"]["clean"] = False
        wrong_semantics["inspection_digest"] = canonical_digest(
            wrong_semantics["inspection"]
        )
        self._verify_code(
            wrong_semantics,
            "inspection_semantics_mismatch",
        )

        wrong_nested_effect = deepcopy(baseline)
        assert isinstance(wrong_nested_effect["inspection"], dict)
        wrong_nested_effect["inspection"]["authority_granted"] = True
        wrong_nested_effect["inspection_digest"] = canonical_digest(
            wrong_nested_effect["inspection"]
        )
        self._verify_code(
            wrong_nested_effect,
            "inspection_semantics_mismatch",
        )

        wrong_digest = deepcopy(baseline)
        wrong_digest["inspection_digest"] = "sha256:" + "f" * 64
        self._verify_code(wrong_digest, "inspection_digest_mismatch")

    def test_inspection_finding_and_scalar_invariants_are_bounded(self) -> None:
        incomplete = _mapping_for_inspection(_incomplete_inspection())
        mutations = []

        wrong_count = deepcopy(incomplete)
        assert isinstance(wrong_count["inspection"], dict)
        wrong_count["inspection"]["finding_count"] = 1
        mutations.append(wrong_count)

        wrong_order = deepcopy(incomplete)
        assert isinstance(wrong_order["inspection"], dict)
        findings = wrong_order["inspection"]["findings"]
        assert isinstance(findings, list)
        findings.reverse()
        mutations.append(wrong_order)

        unknown_finding = deepcopy(incomplete)
        assert isinstance(unknown_finding["inspection"], dict)
        unknown_finding["inspection"]["findings"] = [
            {
                "code": (
                    "private-admission-verification-extra-marker"
                )
            }
        ]
        unknown_finding["inspection"]["finding_count"] = 1
        mutations.append(unknown_finding)

        future_schema = deepcopy(incomplete)
        assert isinstance(future_schema["inspection"], dict)
        future_schema["inspection"]["schema_version"] = 2
        mutations.append(future_schema)

        bad_sequence = _evaluated_mapping()
        assert isinstance(bad_sequence["inspection"], dict)
        bad_sequence["inspection"]["selection_sequence"] = 0
        mutations.append(bad_sequence)

        for supplied in mutations:
            supplied["inspection_digest"] = canonical_digest(
                supplied["inspection"]
            )
            self._verify_code(
                supplied,
                "inspection_semantics_mismatch",
            )

        bool_class = deepcopy(incomplete)
        assert isinstance(bool_class["inspection"], dict)
        bool_class["inspection"]["permission_class"] = True
        bool_class["inspection_digest"] = canonical_digest(
            bool_class["inspection"]
        )
        self._verify_code(bool_class, "inspection_shape_invalid")

    def test_run_and_evaluation_branch_coherence_is_exact(self) -> None:
        baseline = _evaluated_mapping()
        wrong_run = deepcopy(baseline)
        wrong_run["run_ref"] = _ref("different-top-level-run")
        self._verify_code(wrong_run, "run_binding_state_mismatch")

        wrong_status = deepcopy(baseline)
        wrong_status["evaluation_status"] = "failed"
        self._verify_code(wrong_status, "evaluation_state_mismatch")

        wrong_block = deepcopy(baseline)
        wrong_block["block_reason_codes"] = [
            "authorization_evaluation_failed"
        ]
        self._verify_code(wrong_block, "evaluation_state_mismatch")

        incomplete = _mapping_for_inspection(_incomplete_inspection())
        incomplete["request"] = deepcopy(baseline["request"])
        incomplete["request_digest"] = baseline["request_digest"]
        self._verify_code(incomplete, "evaluation_state_mismatch")

    def test_individual_authorization_digest_mismatches_are_fixed(self) -> None:
        for name, code in (
            ("request", "request_digest_mismatch"),
            ("policy", "policy_digest_mismatch"),
            ("decision", "decision_digest_mismatch"),
        ):
            with self.subTest(name=name):
                supplied = _evaluated_mapping()
                supplied[f"{name}_digest"] = "sha256:" + "f" * 64
                self._verify_code(supplied, code)

    def test_authorization_material_shape_and_nullability_are_exact(self) -> None:
        baseline = _evaluated_mapping()
        for name in ("request", "policy", "decision"):
            with self.subTest(name=name, variant="wrong_type"):
                supplied = deepcopy(baseline)
                supplied[name] = []
                self._verify_code(supplied, "shadow_shape_invalid")
            with self.subTest(name=name, variant="missing"):
                supplied = deepcopy(baseline)
                supplied[name] = None
                supplied[f"{name}_digest"] = None
                self._verify_code(supplied, "evaluation_state_mismatch")

        incomplete = _mapping_for_inspection(_incomplete_inspection())
        for name in ("request", "policy", "decision"):
            with self.subTest(name=name, variant="unexpected"):
                supplied = deepcopy(incomplete)
                supplied[name] = deepcopy(baseline[name])
                supplied[f"{name}_digest"] = baseline[f"{name}_digest"]
                self._verify_code(supplied, "evaluation_state_mismatch")

    def test_coherent_request_policy_and_decision_tampering_is_replayed(
        self,
    ) -> None:
        request_tamper = _evaluated_mapping()
        request = request_tamper["request"]
        decision = request_tamper["decision"]
        assert isinstance(request, dict)
        assert isinstance(decision, dict)
        assert isinstance(request["subject"], dict)
        request["subject"]["role"] = "reviewer"
        _rehash(request_tamper, "request")
        decision["request_digest"] = request_tamper["request_digest"]
        _rehash(request_tamper, "decision")
        self._verify_codes(
            request_tamper,
            "request_projection_mismatch",
            "decision_projection_mismatch",
        )

        policy_tamper = _evaluated_mapping()
        policy = policy_tamper["policy"]
        decision = policy_tamper["decision"]
        assert isinstance(policy, dict)
        assert isinstance(decision, dict)
        policy["allowed_roles"] = ["reviewer"]
        _rehash(policy_tamper, "policy")
        decision["policy_digest"] = policy_tamper["policy_digest"]
        _rehash(policy_tamper, "decision")
        self._verify_codes(
            policy_tamper,
            "policy_projection_mismatch",
            "decision_projection_mismatch",
        )

        decision_tamper = _evaluated_mapping()
        decision = decision_tamper["decision"]
        assert isinstance(decision, dict)
        decision["reason_details"] = [
            "private-admission-verification-decision-marker"
        ]
        _rehash(decision_tamper, "decision")
        self._verify_code(
            decision_tamper,
            "decision_projection_mismatch",
        )

    def test_numeric_type_confusion_cannot_match_canonical_projection(
        self,
    ) -> None:
        for field, value in (
            ("derived_permission_class", True),
            ("issued_at", 200),
            ("expires_at", 230),
        ):
            with self.subTest(surface="decision", field=field):
                supplied = _evaluated_mapping()
                decision = supplied["decision"]
                assert isinstance(decision, dict)
                decision[field] = value
                _rehash(supplied, "decision")
                self._verify_code(
                    supplied,
                    "decision_projection_mismatch",
                )

        policy_type = _evaluated_mapping()
        policy = policy_type["policy"]
        decision = policy_type["decision"]
        assert isinstance(policy, dict)
        assert isinstance(decision, dict)
        policy["issued_at"] = -0.0
        _rehash(policy_type, "policy")
        decision["policy_digest"] = policy_type["policy_digest"]
        _rehash(policy_type, "decision")
        self._verify_codes(
            policy_type,
            "policy_projection_mismatch",
            "decision_projection_mismatch",
        )

        request_type = _evaluated_mapping()
        request = request_type["request"]
        decision = request_type["decision"]
        assert isinstance(request, dict)
        assert isinstance(decision, dict)
        environment = request["environment"]
        assert isinstance(environment, dict)
        environment["evaluated_at"] = 200
        _rehash(request_type, "request")
        decision["request_digest"] = request_type["request_digest"]
        _rehash(request_type, "decision")
        self._verify_codes(
            request_type,
            "request_projection_mismatch",
            "decision_projection_mismatch",
        )

    def test_cross_class_and_cross_run_material_cannot_be_spliced(self) -> None:
        class_zero = _evaluated_mapping(PermissionClass.READ_ONLY)
        class_one = _evaluated_mapping(PermissionClass.LOCAL_DRAFT)
        spliced = deepcopy(class_zero)
        for name in ("request", "request_digest", "decision", "decision_digest"):
            spliced[name] = deepcopy(class_one[name])
        report = verify_repository_proposal_admission_shadow_mapping(spliced)
        mapping = report.to_mapping()
        self.assertFalse(mapping["contract_valid"])
        self.assertTrue(mapping["findings"])
        self.assertTrue(
            {
                item["code"] for item in mapping["findings"]
            }
            & {
                "request_projection_mismatch",
                "decision_projection_mismatch",
                "authorization_replay_mismatch",
            }
        )

    def test_canonical_sequence_order_is_part_of_the_projection(self) -> None:
        cases = []
        request_order = _evaluated_mapping()
        request = request_order["request"]
        decision = request_order["decision"]
        assert isinstance(request, dict)
        assert isinstance(decision, dict)
        assert isinstance(request["evidence"], list)
        request["evidence"].reverse()
        _rehash(request_order, "request")
        decision["request_digest"] = request_order["request_digest"]
        _rehash(request_order, "decision")
        cases.append(
            (
                request_order,
                {
                    "request_projection_mismatch",
                    "decision_projection_mismatch",
                },
            )
        )

        policy_order = _evaluated_mapping()
        policy = policy_order["policy"]
        decision = policy_order["decision"]
        assert isinstance(policy, dict)
        assert isinstance(decision, dict)
        assert isinstance(policy["evidence_requirements"], list)
        policy["evidence_requirements"].reverse()
        _rehash(policy_order, "policy")
        decision["policy_digest"] = policy_order["policy_digest"]
        _rehash(policy_order, "decision")
        cases.append(
            (
                policy_order,
                {
                    "policy_projection_mismatch",
                    "decision_projection_mismatch",
                },
            )
        )

        decision_order = _evaluated_mapping()
        decision = decision_order["decision"]
        assert isinstance(decision, dict)
        assert isinstance(decision["obligations"], list)
        decision["obligations"].reverse()
        _rehash(decision_order, "decision")
        cases.append(
            (decision_order, {"decision_projection_mismatch"})
        )

        for supplied, expected_codes in cases:
            report = verify_repository_proposal_admission_shadow_mapping(
                supplied
            )
            actual_codes = {
                finding.code for finding in report.findings
            }
            self.assertEqual(actual_codes, expected_codes)
            self.assertFalse(report.contract_valid)

    def test_public_evaluator_alias_cannot_replace_captured_replay(self) -> None:
        supplied = _evaluated_mapping()
        with patch.object(
            repository_proposal_admission_verification_module,
            "ShadowAuthorizationEvaluator",
            side_effect=AssertionError(
                "private-admission-verification-hostile-marker"
            ),
        ) as substituted:
            report = verify_repository_proposal_admission_shadow_mapping(
                supplied
            )
        substituted.assert_not_called()
        self._assert_report(report, variant="evaluated_class_1")

        with patch.object(
            repository_proposal_admission_verification_module,
            "_BUILTIN_SHADOW_AUTHORIZATION_EVALUATE",
            return_value=object(),
        ):
            mismatch = verify_repository_proposal_admission_shadow_mapping(
                supplied
            )
        self._assert_report(
            mismatch,
            codes=("authorization_replay_mismatch",),
        )

        with (
            patch.object(
                repository_proposal_admission_verification_module,
                "canonical_digest",
                side_effect=AssertionError(
                    "public digest alias must not define replay"
                ),
            ),
            patch.object(
                repository_proposal_admission_verification_module,
                "derive_permission_class",
                side_effect=AssertionError(
                    "public derivation alias must not define replay"
                ),
            ),
        ):
            captured = verify_repository_proposal_admission_shadow_mapping(
                supplied
            )
        self._assert_report(captured, variant="evaluated_class_1")

    def test_summary_projection_cannot_be_promoted(self) -> None:
        baseline = _evaluated_mapping()
        for key, value in (
            ("effect", "indeterminate"),
            ("derived_permission_class", 0),
            ("decision_current_at_evaluation", False),
            ("permission_class_matches", False),
            ("obligations_exact", False),
            ("shadow_eligible", False),
        ):
            with self.subTest(key=key):
                supplied = deepcopy(baseline)
                supplied[key] = value
                self._verify_code(supplied, "shadow_summary_mismatch")

        failed = _failed_mapping("authorization_evaluation_failed")
        failed["shadow_eligible"] = True
        self._verify_code(failed, "shadow_summary_mismatch")

    def test_failed_replay_requires_a_constructible_replay_boundary(
        self,
    ) -> None:
        impossible = _failed_mapping("authorization_replay_mismatch")
        impossible["evaluated_at"] = sys.float_info.max
        self._verify_code(impossible, "evaluation_state_mismatch")

    def test_private_values_and_internal_failures_are_value_free(self) -> None:
        supplied = _evaluated_mapping()
        decision = supplied["decision"]
        assert isinstance(decision, dict)
        decision["reason_details"] = [
            "private-admission-verification-decision-marker"
        ]
        _rehash(supplied, "decision")
        report = verify_repository_proposal_admission_shadow_mapping(supplied)
        self._assert_private_values_absent(report.to_mapping())
        self._assert_private_values_absent(repr(report))

        with patch.object(
            repository_proposal_admission_verification_module,
            "_inspection_facts",
            side_effect=RuntimeError(
                "private-admission-verification-hostile-marker"
            ),
        ):
            failed = verify_repository_proposal_admission_shadow_mapping(
                _evaluated_mapping()
            )
        self._assert_report(failed, codes=("verification_failed",))

    def test_verifier_is_pure_and_has_no_effect_api(self) -> None:
        supplied = _evaluated_mapping()
        before = deepcopy(supplied)
        with (
            patch.object(
                builtins,
                "open",
                side_effect=AssertionError("verifier must not open files"),
            ),
            patch.object(
                os,
                "open",
                side_effect=AssertionError("verifier must not open files"),
            ),
            patch.object(
                sqlite3,
                "connect",
                side_effect=AssertionError("verifier must not open state"),
            ),
            patch.object(
                subprocess,
                "Popen",
                side_effect=AssertionError("verifier must not spawn"),
            ),
            patch.object(
                subprocess,
                "run",
                side_effect=AssertionError("verifier must not execute"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("verifier must not use network"),
            ),
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=AssertionError("verifier must not use network"),
            ),
        ):
            report = verify_repository_proposal_admission_shadow_mapping(
                supplied
            )
        self._assert_report(report, variant="evaluated_class_1")
        self.assertEqual(supplied, before)

        signature = inspect.signature(
            verify_repository_proposal_admission_shadow_mapping
        )
        self.assertEqual(tuple(signature.parameters), ("value",))
        for forbidden in (
            "admit",
            "authorize",
            "dispatch",
            "enforce",
            "execute",
            "persist",
            "receipt",
            "repair",
            "route",
        ):
            self.assertFalse(
                any(
                    forbidden in name.casefold()
                    for name in (
                        repository_proposal_admission_verification_module
                        .__all__
                    )
                    if name
                    != "verify_repository_proposal_admission_shadow_mapping"
                ),
                forbidden,
            )

    def test_report_is_frozen_bounded_and_returns_fresh_mappings(self) -> None:
        report = verify_repository_proposal_admission_shadow_mapping(
            _evaluated_mapping()
        )
        mapping = self._assert_report(
            report,
            variant="evaluated_class_1",
        )
        with self.assertRaises(FrozenInstanceError):
            report.verified_variant = "failed_replay"  # type: ignore[misc]
        mapping["findings"].append({"code": "verification_failed"})
        self.assertEqual(report.to_mapping()["findings"], [])

        with self.assertRaises(Exception) as caught:
            RepositoryProposalAdmissionVerificationFinding(
                "private-admission-verification-hostile-marker"
            )
        self.assertEqual(
            str(caught.exception),
            "repository proposal admission verification report is invalid",
        )
        self._assert_private_values_absent(str(caught.exception))

        with self.assertRaises(TypeError) as caught:
            RepositoryProposalAdmissionVerificationReport(
                verification_complete=True,
                truncated=False,
                verified_variant="evaluated_class_1",
                findings=(),
            )
        self.assertEqual(
            str(caught.exception),
            (
                "repository proposal admission verification reports are "
                "factory-created"
            ),
        )

        failed = verify_repository_proposal_admission_shadow_mapping(None)
        object.__setattr__(failed, "findings", ())
        self.assertFalse(failed.contract_valid)
        with self.assertRaises(Exception) as caught:
            failed.to_mapping()
        self.assertEqual(
            str(caught.exception),
            "repository proposal admission verification report is invalid",
        )

        nested = verify_repository_proposal_admission_shadow_mapping(None)
        finding = nested.findings[0]
        object.__setattr__(
            finding,
            "code",
            "private-admission-verification-hostile-marker",
        )
        self.assertFalse(nested.contract_valid)
        for value in (finding, nested):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(Exception) as caught:
                    value.to_mapping()
                self.assertEqual(
                    str(caught.exception),
                    (
                        "repository proposal admission verification "
                        "report is invalid"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
