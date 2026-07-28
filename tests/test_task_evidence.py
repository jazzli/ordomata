from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from ordomata.authorization import canonical_digest
from ordomata.contracts import load_task_contract
from ordomata.errors import ValidationError
from ordomata.models import PermissionClass, RunRequest
from ordomata.task_evidence import (
    TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
    TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
    build_candidate_artifact_action_receipt,
    build_candidate_artifact_pre_effect_receipt,
    build_task_attempt_binding_event,
)


ROOT = Path(__file__).resolve().parents[1]


def _digest(label: str) -> str:
    return canonical_digest({"fixture": label})


class TaskEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_task_contract(
            ROOT / "tasks" / "chief-of-staff-lite.json"
        )
        self.request = RunRequest(
            run_id="task-evidence-run",
            task_id=self.contract.task_id,
            task_version=self.contract.version,
            prompt="fixed prompt",
            workspace=Path("/tmp/ordomata-task-evidence/workspace"),
            run_directory=Path("/tmp/ordomata-task-evidence"),
            output_schema=self.contract.output_schema,
            permission_class=PermissionClass.LOCAL_DRAFT,
            timeout_seconds=self.contract.timeout_seconds,
            attempt=1,
            runner_overrides={"fixture": "chief_of_staff.valid"},
        )
        self.binding_kwargs = {
            "contract": self.contract,
            "request": self.request,
            "runner_id": "mock",
            "context_digest": _digest("context"),
            "prompt_digest": _digest("prompt"),
            "project_root": "/tmp/ordomata-task-evidence-project",
            "profile_id": "mock.deterministic.local-draft",
            "authorization_intent_digest": _digest("intent"),
        }
        self.selection_kwargs = {
            "execution_selection_digest": _digest("selection"),
            "profile_version_ref": _digest("profile-version"),
            "profile_configuration_digest": _digest("profile-configuration"),
        }
        self.shadow = self._publication_shadow()
        self.authorization = self._publication_authorization()
        self.authorization_event_id = _digest("publication-event")
        self.pre_effect_kwargs = {
            "task_attempt_binding_digest": _digest("task-binding"),
            "publication_shadow": self.shadow,
            "publication_shadow_persisted": True,
            "requested_permission_class": PermissionClass.LOCAL_DRAFT,
            "artifact_kind": "local_draft",
            "destination_digest": _digest("destination"),
            "artifact_digest": _digest("artifact"),
            "artifact_size_bytes": 25,
            "artifact_metadata_digest": _digest("metadata"),
            "billing_disposition_digest": _digest("billing"),
            "started_at": 100.0,
        }

    @staticmethod
    def _publication_shadow() -> dict[str, object]:
        request = {
            "action": {
                "verb": "create",
                "operation": "artifact.publish_local_candidate",
                "parameters_digest": _digest("shadow-parameters"),
                "intended_effect": "create_isolated_local_candidate",
            },
            "resource": {
                "resource_type": "local_candidate_artifact",
                "identifier": _digest("shadow-resource"),
            },
        }
        decision = {
            "obligations": [
                {"kind": "audit_receipt", "value": "append_after_action"},
                {"kind": "isolated_local_only", "value": "required"},
            ]
        }
        return {
            "request": request,
            "request_digest": canonical_digest(request),
            "decision": decision,
            "decision_digest": canonical_digest(decision),
        }

    @staticmethod
    def _publication_authorization() -> dict[str, object]:
        action = {
            "intended_effect": "create_isolated_local_candidate",
            "operation": "artifact.publish_local_candidate",
            "parameters_digest": _digest("parameters"),
            "verb": "create",
        }
        resource = {
            "content_digest": _digest("artifact"),
            "identifier": _digest("resource"),
            "owner": "operator:local",
            "protected": False,
            "repository_id": _digest("repository"),
            "resource_type": "local_candidate_artifact",
            "sensitivity": "low",
            "trust_boundary": "isolated_run_workspace",
            "version": _digest("artifact"),
        }
        request = {
            "action": action,
            "consequences": {
                "availability": "low",
                "blast_radius": "single_resource",
                "confidentiality": "low",
                "destructive": False,
                "integrity": "low",
                "reach": "local",
                "reversible": True,
                "sensitivity": "low",
            },
            "environment": {
                "approval_grants": [],
                "billing_route": "local_non_ai",
                "capacity_state": "not_applicable",
                "circuit_state": "closed",
                "evaluated_at": 100.0,
                "flow_state": "local_candidate_publication_proposed",
                "isolation_state": "verified",
                "network_state": "disabled",
                "paid_continuation_protection": "not_applicable",
            },
            "evidence": [],
            "request_id": "local-candidate-publication:task-evidence-run",
            "resource": resource,
            "subject": {
                "controller_id": "ordomata:local-controller",
                "principal_id": "agent:task-attempt",
                "profile_id": _digest("profile"),
                "role": "implementer",
                "role_version": "1",
                "runner_id": "mock",
                "session_id": "attempt:task-evidence-run",
            },
        }
        request_digest = canonical_digest(request)
        obligations = [
            {"kind": "audit_receipt", "value": "append_after_action"},
            {"kind": "isolated_local_only", "value": "required"},
        ]
        decision = {
            "derived_permission_class": 1,
            "effect": "permit",
            "evidence_refs": [],
            "expires_at": 220.0,
            "issued_at": 100.0,
            "matched_rule_ids": ["phase-1c-class-1"],
            "obligations": obligations,
            "policy_bundle_id": "ordomata.phase-1c.local-publication",
            "policy_digest": _digest("policy"),
            "policy_version": "1.0.0",
            "reason_codes": ["current_stage_permit"],
            "reason_details": ["fixed permit"],
            "request_digest": request_digest,
            "request_id": request["request_id"],
        }
        return {
            "schema_version": 1,
            "mode": "enforcing",
            "action_scope": "ordinary_local_candidate_publication_only",
            "enforcement_coverage": (
                TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE
            ),
            "request": request,
            "request_digest": request_digest,
            "decision": decision,
            "decision_digest": canonical_digest(decision),
            "effect": "permit",
            "authorization_eligible": True,
        }

    def _enforcement_receipt(
        self,
        *,
        outcome: str = "succeeded",
        result_digest: str | None = None,
    ) -> dict[str, object]:
        request = self.authorization["request"]
        assert isinstance(request, dict)
        action = request["action"]
        resource = request["resource"]
        if result_digest is None and outcome == "succeeded":
            result_digest = self.pre_effect_kwargs["artifact_digest"]
        return {
            "completed_at": 102.0,
            "decision_digest": self.authorization["decision_digest"],
            "enforced_action_digest": canonical_digest(
                {"action": action, "resource": resource}
            ),
            "executor_id": "ordomata:local-controller",
            "obligation_results": [
                {
                    "kind": "audit_receipt",
                    "satisfied": True,
                    "value": "append_after_action",
                },
                {
                    "kind": "isolated_local_only",
                    "satisfied": True,
                    "value": "required",
                },
            ],
            "outcome": outcome,
            "receipt_id": canonical_digest(
                {
                    "decision_digest": self.authorization[
                        "decision_digest"
                    ],
                    "destination_digest": self.pre_effect_kwargs[
                        "destination_digest"
                    ],
                    "request_digest": self.authorization[
                        "request_digest"
                    ],
                    "task_attempt_binding_digest": self.pre_effect_kwargs[
                        "task_attempt_binding_digest"
                    ],
                    "receipt_kind": (
                        "local_candidate_publication_action"
                    ),
                }
            ),
            "request_digest": self.authorization["request_digest"],
            "result_digest": result_digest,
            "started_at": 101.0,
        }

    def _action_kwargs(
        self,
        pre_effect: dict[str, object],
    ) -> dict[str, object]:
        return {
            "task_attempt_binding_digest": self.pre_effect_kwargs[
                "task_attempt_binding_digest"
            ],
            "pre_effect_receipt": pre_effect,
            "publication_shadow": self.shadow,
            "publication_shadow_persisted": True,
            "requested_permission_class": PermissionClass.LOCAL_DRAFT,
            "artifact_kind": "local_draft",
            "destination_digest": self.pre_effect_kwargs[
                "destination_digest"
            ],
            "intended_artifact_digest": self.pre_effect_kwargs[
                "artifact_digest"
            ],
            "intended_artifact_size_bytes": 25,
            "artifact_metadata_digest": self.pre_effect_kwargs[
                "artifact_metadata_digest"
            ],
            "billing_disposition_digest": self.pre_effect_kwargs[
                "billing_disposition_digest"
            ],
            "started_at": 100.0,
            "completed_at": 102.0,
            "outcome": "succeeded",
            "result_digest": self.pre_effect_kwargs["artifact_digest"],
            "observed_artifact_size_bytes": 25,
            "failure_code": None,
        }

    def test_binding_v1_v2_v3_shapes_are_unchanged(self) -> None:
        v1 = build_task_attempt_binding_event(**self.binding_kwargs)
        self.assertEqual(
            v1,
            build_task_attempt_binding_event(
                **self.binding_kwargs,
                enforce_mock_dispatch=False,
                enforce_local_candidate_publication=False,
                enforce_task_admission=False,
            ),
        )
        self.assertEqual(v1["schema_version"], 1)
        self.assertEqual(
            set(v1),
            {
                "authorization_action_receipt_coverage",
                "authorization_shadow_coverage",
                "binding",
                "binding_digest",
                "schema_version",
            },
        )
        self.assertEqual(
            canonical_digest(v1),
            "sha256:9bfb8ccf3fce27b7a81e9191b3e961c53491bfad3ca1587a8c6b70fa25523142",
        )

        v2 = build_task_attempt_binding_event(
            **self.binding_kwargs,
            **self.selection_kwargs,
        )
        self.assertEqual(v2["schema_version"], 2)
        self.assertEqual(set(v2), set(v1))
        self.assertEqual(
            canonical_digest(v2),
            "sha256:ea722defe20f24ed0732569adfbd3b44757cc1600ab5d79cae31975ef1afaacc",
        )

        v3 = build_task_attempt_binding_event(
            **self.binding_kwargs,
            **self.selection_kwargs,
            enforce_mock_dispatch=True,
        )
        self.assertEqual(v3["schema_version"], 3)
        self.assertEqual(
            v3["authorization_enforcement_coverage"],
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
        )
        self.assertNotIn(
            "publication_authorization_enforcement_coverage",
            v3,
        )
        self.assertNotIn(
            "admission_authorization_enforcement_coverage",
            v3,
        )
        self.assertEqual(
            canonical_digest(v3),
            "sha256:45451049237b97b060f82c0d3597eba6b8b674c2668edf0f1448c815169aa64c",
        )

    def test_schema_v4_adds_only_publication_coverage_to_v3(self) -> None:
        v3 = build_task_attempt_binding_event(
            **self.binding_kwargs,
            **self.selection_kwargs,
            enforce_mock_dispatch=True,
        )
        v4 = build_task_attempt_binding_event(
            **self.binding_kwargs,
            **self.selection_kwargs,
            enforce_mock_dispatch=True,
            enforce_local_candidate_publication=True,
            enforce_task_admission=False,
        )

        self.assertEqual(v4["schema_version"], 4)
        self.assertEqual(v4["binding"], v3["binding"])
        self.assertEqual(v4["binding_digest"], v3["binding_digest"])
        self.assertEqual(
            v4["authorization_enforcement_coverage"],
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            v4["publication_authorization_enforcement_coverage"],
            TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            set(v4) - set(v3),
            {"publication_authorization_enforcement_coverage"},
        )
        self.assertNotIn(
            "admission_authorization_enforcement_coverage",
            v4,
        )
        self.assertEqual(
            canonical_digest(v4),
            "sha256:aa962ee1b4ab96f3930cfbc757b7f6448b4a36e3aa620d949116ee1058097eb8",
        )

    def test_schema_v5_adds_only_admission_coverage_to_v4(self) -> None:
        v4 = build_task_attempt_binding_event(
            **self.binding_kwargs,
            **self.selection_kwargs,
            enforce_mock_dispatch=True,
            enforce_local_candidate_publication=True,
            enforce_task_admission=False,
        )
        v5 = build_task_attempt_binding_event(
            **self.binding_kwargs,
            **self.selection_kwargs,
            enforce_mock_dispatch=True,
            enforce_local_candidate_publication=True,
            enforce_task_admission=True,
        )

        self.assertEqual(v5["schema_version"], 5)
        self.assertEqual(v5["binding"], v4["binding"])
        self.assertEqual(v5["binding_digest"], v4["binding_digest"])
        self.assertEqual(
            v5["authorization_enforcement_coverage"],
            TASK_ATTEMPT_MOCK_DISPATCH_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            v5["publication_authorization_enforcement_coverage"],
            TASK_ATTEMPT_LOCAL_CANDIDATE_PUBLICATION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            v5["admission_authorization_enforcement_coverage"],
            TASK_ATTEMPT_ADMISSION_ENFORCEMENT_COVERAGE,
        )
        self.assertEqual(
            set(v5) - set(v4),
            {"admission_authorization_enforcement_coverage"},
        )

    def test_publication_enforcement_requires_boolean_mock_enforcement(self) -> None:
        with self.assertRaisesRegex(
            ValidationError,
            "requires mock dispatch enforcement",
        ):
            build_task_attempt_binding_event(
                **self.binding_kwargs,
                **self.selection_kwargs,
                enforce_local_candidate_publication=True,
            )
        with self.assertRaisesRegex(ValidationError, "flag must be a boolean"):
            build_task_attempt_binding_event(
                **self.binding_kwargs,
                **self.selection_kwargs,
                enforce_mock_dispatch=True,
                enforce_local_candidate_publication=1,  # type: ignore[arg-type]
            )

    def test_admission_enforcement_requires_boolean_dispatch_and_publication(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValidationError, "flag must be a boolean"):
            build_task_attempt_binding_event(
                **self.binding_kwargs,
                **self.selection_kwargs,
                enforce_mock_dispatch=True,
                enforce_local_candidate_publication=True,
                enforce_task_admission=1,  # type: ignore[arg-type]
            )

        for enforce_dispatch, enforce_publication in (
            (False, False),
            (True, False),
            (False, True),
        ):
            with (
                self.subTest(
                    enforce_mock_dispatch=enforce_dispatch,
                    enforce_local_candidate_publication=(
                        enforce_publication
                    ),
                ),
                self.assertRaises(ValidationError),
            ):
                build_task_attempt_binding_event(
                    **self.binding_kwargs,
                    **self.selection_kwargs,
                    enforce_mock_dispatch=enforce_dispatch,
                    enforce_local_candidate_publication=(
                        enforce_publication
                    ),
                    enforce_task_admission=True,
                )

    def test_shadow_receipt_shapes_remain_schema_v2(self) -> None:
        implicit_pre = build_candidate_artifact_pre_effect_receipt(
            **self.pre_effect_kwargs
        )
        explicit_pre = build_candidate_artifact_pre_effect_receipt(
            **self.pre_effect_kwargs,
            publication_authorization=None,
            publication_authorization_event_id=None,
        )
        self.assertEqual(implicit_pre, explicit_pre)
        self.assertEqual(implicit_pre["schema_version"], 2)
        self.assertEqual(implicit_pre["mode"], "shadow")
        self.assertFalse(implicit_pre["authorization_enforced"])
        self.assertNotIn("publication_shadow_request_digest", implicit_pre)
        self.assertEqual(
            canonical_digest(implicit_pre),
            "sha256:825b6044c840f37cdafb14a3778ea08f20d07b4c843fe321a232b63d164dcce0",
        )

        action_kwargs = self._action_kwargs(implicit_pre)
        implicit_action = build_candidate_artifact_action_receipt(
            **action_kwargs
        )
        explicit_action = build_candidate_artifact_action_receipt(
            **action_kwargs,
            publication_authorization=None,
            publication_authorization_event_id=None,
            effect_started_at=None,
            enforcement_receipt=None,
        )
        self.assertEqual(implicit_action, explicit_action)
        self.assertEqual(implicit_action["schema_version"], 2)
        self.assertEqual(implicit_action["mode"], "shadow")
        self.assertFalse(implicit_action["authorization_enforced"])
        self.assertNotIn("enforcement_receipt", implicit_action)
        self.assertEqual(
            canonical_digest(implicit_action),
            "sha256:48806a15437553f926f425ffcc276498e88ade72aa0cdfc4927d45f83da8cc75",
        )

    def test_enforcing_receipts_link_authoritative_and_shadow_evidence(self) -> None:
        pre_effect = build_candidate_artifact_pre_effect_receipt(
            **self.pre_effect_kwargs,
            publication_authorization=self.authorization,
            publication_authorization_event_id=self.authorization_event_id,
        )
        self.assertEqual(pre_effect["schema_version"], 3)
        self.assertEqual(pre_effect["mode"], "enforcing")
        self.assertTrue(pre_effect["authorization_enforced"])
        self.assertEqual(
            pre_effect["authority_basis"],
            "abac_exact_permit_and_legacy_permission_class_gate",
        )
        self.assertEqual(
            pre_effect["publication_request_digest"],
            self.authorization["request_digest"],
        )
        self.assertEqual(
            pre_effect["publication_decision_digest"],
            self.authorization["decision_digest"],
        )
        self.assertEqual(
            pre_effect["publication_shadow_request_digest"],
            self.shadow["request_digest"],
        )
        self.assertEqual(
            pre_effect["publication_shadow_decision_digest"],
            self.shadow["decision_digest"],
        )
        pre_body = dict(pre_effect)
        pre_digest = pre_body.pop("receipt_digest")
        self.assertEqual(pre_digest, canonical_digest(pre_body))

        enforcement_receipt = self._enforcement_receipt()
        action = build_candidate_artifact_action_receipt(
            **self._action_kwargs(pre_effect),
            publication_authorization=self.authorization,
            publication_authorization_event_id=self.authorization_event_id,
            effect_started_at=101.0,
            enforcement_receipt=enforcement_receipt,
        )
        self.assertEqual(action["schema_version"], 3)
        self.assertEqual(action["mode"], "enforcing")
        self.assertTrue(action["authorization_enforced"])
        self.assertEqual(action["effect_started_at"], 101.0)
        self.assertEqual(action["enforcement_receipt"], enforcement_receipt)
        self.assertEqual(
            action["enforcement_receipt_digest"],
            canonical_digest(enforcement_receipt),
        )
        self.assertEqual(
            action["obligation_results"],
            [
                {
                    "kind": "audit_receipt",
                    "satisfied": True,
                    "value_digest": canonical_digest(
                        {"value": "append_after_action"}
                    ),
                },
                {
                    "kind": "isolated_local_only",
                    "satisfied": True,
                    "value_digest": canonical_digest({"value": "required"}),
                },
            ],
        )
        action_body = dict(action)
        action_digest = action_body.pop("receipt_digest")
        self.assertEqual(action_digest, canonical_digest(action_body))

    def test_enforcing_inputs_are_all_or_nothing_and_exact(self) -> None:
        with self.assertRaisesRegex(ValidationError, "provided together"):
            build_candidate_artifact_pre_effect_receipt(
                **self.pre_effect_kwargs,
                publication_authorization=self.authorization,
            )
        with self.assertRaisesRegex(ValidationError, "provided together"):
            build_candidate_artifact_pre_effect_receipt(
                **self.pre_effect_kwargs,
                publication_authorization_event_id=self.authorization_event_id,
            )

        pre_effect = build_candidate_artifact_pre_effect_receipt(
            **self.pre_effect_kwargs,
            publication_authorization=self.authorization,
            publication_authorization_event_id=self.authorization_event_id,
        )
        partial_action = self._action_kwargs(pre_effect)
        partial_action["publication_authorization"] = self.authorization
        partial_action["publication_authorization_event_id"] = (
            self.authorization_event_id
        )
        with self.assertRaisesRegex(ValidationError, "provided together"):
            build_candidate_artifact_action_receipt(**partial_action)

        for label, mutate in (
            (
                "authorization digest",
                lambda authorization: authorization.__setitem__(
                    "request_digest", _digest("wrong-request")
                ),
            ),
            (
                "non-permit",
                lambda authorization: authorization.__setitem__(
                    "effect", "deny"
                ),
            ),
        ):
            with self.subTest(label=label):
                authorization = deepcopy(self.authorization)
                mutate(authorization)
                with self.assertRaises(ValidationError):
                    build_candidate_artifact_pre_effect_receipt(
                        **self.pre_effect_kwargs,
                        publication_authorization=authorization,
                        publication_authorization_event_id=(
                            self.authorization_event_id
                        ),
                    )

    def test_enforcement_action_receipt_rejects_misbound_canonical_values(
        self,
    ) -> None:
        pre_effect = build_candidate_artifact_pre_effect_receipt(
            **self.pre_effect_kwargs,
            publication_authorization=self.authorization,
            publication_authorization_event_id=self.authorization_event_id,
        )
        for label, mutate in (
            (
                "request",
                lambda receipt: receipt.__setitem__(
                    "request_digest", _digest("wrong-request")
                ),
            ),
            (
                "action",
                lambda receipt: receipt.__setitem__(
                    "enforced_action_digest", _digest("wrong-action")
                ),
            ),
            (
                "receipt identifier",
                lambda receipt: receipt.__setitem__(
                    "receipt_id", _digest("wrong-receipt")
                ),
            ),
            (
                "executor",
                lambda receipt: receipt.__setitem__(
                    "executor_id", "attacker:executor"
                ),
            ),
            (
                "start",
                lambda receipt: receipt.__setitem__("started_at", 100.5),
            ),
            (
                "obligation",
                lambda receipt: receipt["obligation_results"][0].__setitem__(
                    "satisfied", False
                ),
            ),
            (
                "extra",
                lambda receipt: receipt.__setitem__("unexpected", True),
            ),
        ):
            with self.subTest(label=label):
                receipt = deepcopy(self._enforcement_receipt())
                mutate(receipt)
                with self.assertRaisesRegex(ValidationError, "inconsistent"):
                    build_candidate_artifact_action_receipt(
                        **self._action_kwargs(pre_effect),
                        publication_authorization=self.authorization,
                        publication_authorization_event_id=(
                            self.authorization_event_id
                        ),
                        effect_started_at=101.0,
                        enforcement_receipt=receipt,
                    )


if __name__ == "__main__":
    unittest.main()
