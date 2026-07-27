from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ordomata.authorization import canonical_digest
from ordomata.authorization_inspection import (
    ADMISSION_SCOPE,
    COMPARISON_ACTION_RECEIPT_COVERAGE,
    COMPARISON_FULL_SHADOW_COVERAGE,
    COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
    DISPATCH_SCOPE,
    PUBLICATION_SCOPE,
    inspect_authorization_shadows,
)
from ordomata.errors import ConfigurationError
from ordomata.models import PermissionClass, RunStatus
from ordomata.state import (
    ArtifactRecord,
    RecordNotFoundError,
    RunRecord,
    SQLiteStateStore,
)


_PRIVATE_MARKERS = (
    "private-profile-marker",
    "private-accounting-marker",
    "/private/worktree-marker",
    "private-receipt-marker",
    "private-source-marker",
    "private-reason-marker",
    "private-obligation-marker",
    "private-evidence-marker",
    "private-rule-marker",
)


class AuthorizationInspectionTests(unittest.TestCase):
    @staticmethod
    def _comparison_billing_payload() -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": 1,
            "runner_id": "mock",
            "route": "mock",
            "confidence": "high",
            "subscription_ref": None,
            "capacity_state": "unknown",
            "paid_continuation_protection": "unknown",
            "paid_credit_balance": "unknown",
            "account_identity_ref": None,
            "capacity_observed_at": None,
            "capacity_expires_at": None,
            "attestation": None,
        }
        payload["assessment_digest"] = canonical_digest(payload)
        return payload

    @staticmethod
    def _comparison_execution_accounting_payload() -> dict[str, object]:
        billing_disposition = {
            "identity_matches": True,
            "billing_matches": True,
            "capacity_state": "not_applicable",
            "paid_capacity_consumed": "not_applicable",
            "incremental_ai_charge": "none",
            "quarantine_required": False,
            "circuit_breaker_required": False,
            "reason_codes": [],
        }
        return {
            "schema_version": 2,
            "result_observed": True,
            "identity_matches": True,
            "billing_matches": True,
            "runner_event_count": 0,
            "result_status": "succeeded",
            "harness_process_started": False,
            "live_model_execution_occurred": False,
            "subscription_capacity_consumed": False,
            "paid_capacity_consumed": "not_applicable",
            "incremental_ai_charge": "none",
            "capacity_state": "not_applicable",
            "billing_disposition_reason_codes": [],
            "billing_disposition_digest": canonical_digest(
                billing_disposition
            ),
            "usage_observation": "not_applicable",
            "billing_quarantine_required": False,
            "billing_circuit_breaker_required": False,
            "failure_code": None,
            "wall_seconds": 1.0,
        }

    def _create_run(
        self,
        database: Path,
        *,
        run_id: str = "run-inspect",
        permission_class: PermissionClass = PermissionClass.LOCAL_DRAFT,
        runner_id: str = "mock",
        context_digest: str = "a" * 64,
        timeout_seconds: int = 60,
        attempt: int = 1,
    ) -> SQLiteStateStore:
        store = SQLiteStateStore(database, clock=lambda: 100.0)
        store.create_run(
            RunRecord(
                run_id=run_id,
                task_id="inspect-task",
                task_version="1.0.0",
                runner_id=runner_id,
                workspace="/private/worktree-marker",
                run_directory="/private/run-marker",
                context_digest=context_digest,
                permission_class=permission_class,
                timeout_seconds=timeout_seconds,
                attempt=attempt,
                created_at=100.0,
            )
        )
        return store

    def _comparison_binding_payload(
        self,
        *,
        context_digest: str | None = None,
        runner_id: str = "mock",
        timeout_seconds: int = 60,
        attempt: int = 1,
        schema_version: int = 1,
    ) -> dict[str, object]:
        self.assertIn(schema_version, (1, 2))
        binding = {
            "kind": "controlled_comparison_trial",
            "comparison_ref": canonical_digest(
                {"comparison_id": "private-comparison-marker"}
            ),
            "trial_ref": canonical_digest(
                {"trial_id": "private-trial-marker"}
            ),
            "plan_digest": canonical_digest({"plan": "bounded"}),
            "snapshot_digest": canonical_digest({"snapshot": "bounded"}),
            "controls_digest": canonical_digest({"controls": "bounded"}),
            "context_digest": (
                canonical_digest({"context": "bounded"})
                if context_digest is None
                else context_digest
            ),
            "prompt_digest": canonical_digest({"prompt": "bounded"}),
            "task_definition_digest": canonical_digest(
                {"task_definition": "bounded"}
            ),
            "output_schema_digest": canonical_digest(
                {"output_schema": "bounded"}
            ),
            "repository_ref": canonical_digest(
                {"repository": "private-repository-marker"}
            ),
            "profile_ref": canonical_digest(
                {"profile_id": "private-profile-marker"}
            ),
            "profile_version_ref": canonical_digest(
                {"profile_version": "private-profile-version-marker"}
            ),
            "profile_configuration_digest": canonical_digest(
                {"profile_configuration": "bounded"}
            ),
            "runner_overrides_digest": canonical_digest(
                {"runner_overrides": {}}
            ),
            "billing_assessment_digest": self._comparison_billing_payload()[
                "assessment_digest"
            ],
            "runner_id": runner_id,
            "repetition": 1,
            "order_index": 0,
            "timeout_seconds": timeout_seconds,
            "attempt": attempt,
            "permission_class": 0,
        }
        payload: dict[str, object] = {
            "schema_version": schema_version,
            "authorization_shadow_coverage": (
                "partial_admission_dispatch_shadow"
                if schema_version == 1
                else COMPARISON_FULL_SHADOW_COVERAGE
            ),
            "binding": binding,
            "binding_digest": canonical_digest(binding),
        }
        if schema_version == 2:
            payload["authorization_action_receipt_coverage"] = (
                COMPARISON_ACTION_RECEIPT_COVERAGE
            )
        return payload

    def _comparison_shadow_payload(
        self,
        scope: str,
        binding_payload: dict[str, object],
        *,
        run_id: str = "run-comparison",
    ) -> dict[str, object]:
        self.assertIn(scope, (ADMISSION_SCOPE, DISPATCH_SCOPE))
        binding = binding_payload["binding"]
        binding_digest = binding_payload["binding_digest"]
        self.assertIsInstance(binding, dict)
        self.assertIsInstance(binding_digest, str)
        assert isinstance(binding, dict)
        assert isinstance(binding_digest, str)

        task_intent = {
            "action": {
                "verb": "read",
                "operation": "comparison.evaluate_immutable_snapshot",
                "intended_effect": "evaluate_immutable_comparison_snapshot",
            },
            "resource": {
                "resource_type": "comparison_snapshot",
                "trust_boundary": "isolated_run_workspace",
                "protected": False,
                "sensitivity": "low",
            },
            "consequences": {
                "confidentiality": "low",
                "integrity": "low",
                "availability": "low",
                "reach": "local",
                "destructive": False,
                "reversible": True,
                "sensitivity": "low",
                "blast_radius": "single_resource",
            },
        }
        intent_digest = canonical_digest(task_intent)
        parameters = {
            "comparison_binding_digest": binding_digest,
            (
                "context_digest"
                if scope == ADMISSION_SCOPE
                else "prompt_digest"
            ): (
                binding["context_digest"]
                if scope == ADMISSION_SCOPE
                else binding["prompt_digest"]
            ),
            "snapshot_digest": binding["snapshot_digest"],
        }
        action = {
            "descriptive_claims": [],
            "verb": "read",
            "operation": "comparison.evaluate_immutable_snapshot",
            "parameters_digest": canonical_digest(
                {
                    "action_scope": scope,
                    "intent_digest": intent_digest,
                    "intent_source": "comparison_trial_projection",
                    "legacy_permission_class": 0,
                    "output_schema_digest": binding["output_schema_digest"],
                    "parameters": parameters,
                    "profile_ref": binding["profile_ref"],
                    "runner_id": binding["runner_id"],
                    "task_definition_digest": binding[
                        "task_definition_digest"
                    ],
                    "task_id": "inspect-task",
                    "task_version": "1.0.0",
                }
            ),
            "intended_effect": "evaluate_immutable_comparison_snapshot",
            "tool_id": None,
        }
        subject = {
            "principal_id": "agent:task-attempt",
            "controller_id": "agentops:local-controller",
            "role": "implementer",
            "role_version": "1",
            "profile_id": binding["profile_ref"],
            "runner_id": binding["runner_id"],
            "session_id": f"attempt:{run_id}",
        }
        resource = {
            "resource_type": "comparison_snapshot",
            "identifier": canonical_digest(
                {
                    "action_scope": scope,
                    "resource_type": "comparison_snapshot",
                    "run_id": run_id,
                }
            ),
            "version": binding["snapshot_digest"],
            "owner": "operator:local",
            "trust_boundary": "isolated_run_workspace",
            "protected": False,
            "sensitivity": "low",
            "repository_id": binding["repository_ref"],
            "content_digest": (
                binding["context_digest"]
                if scope == ADMISSION_SCOPE
                else binding["prompt_digest"]
            ),
        }
        environment = {
            "approval_grants": [],
            "evaluated_at": 110.0,
            "isolation_state": "verified",
            "network_state": "disabled",
            "billing_route": "mock",
            "capacity_state": "not_applicable",
            "paid_continuation_protection": "not_applicable",
            "circuit_state": "closed",
            "flow_state": {
                ADMISSION_SCOPE: "admission_proposed",
                DISPATCH_SCOPE: "runner_dispatch_proposed",
            }[scope],
        }
        consequences = dict(task_intent["consequences"])
        attributes = {
            "subject": subject,
            "action": action,
            "resource": resource,
            "environment": environment,
            "consequences": consequences,
        }
        evidence = [
            {
                "attribute": attribute,
                "authenticated": True,
                "evidence_id": f"private-evidence-marker:{attribute}",
                "expires_at": 230.0 if attribute == "environment" else 200.0,
                "observed_at": 110.0 if attribute == "environment" else 100.0,
                "source": "controller",
                "source_id": "private-source-marker",
                "value_digest": canonical_digest(value),
            }
            for attribute, value in attributes.items()
        ]
        request = {
            "action": action,
            "consequences": consequences,
            "environment": environment,
            "evidence": evidence,
            "request_id": f"{scope}:{run_id}",
            "resource": resource,
            "subject": subject,
        }
        request_digest = canonical_digest(request)
        decision = {
            "derived_permission_class": 0,
            "effect": "permit",
            "evidence_refs": ["private-evidence-marker"],
            "expires_at": 150.0,
            "issued_at": 110.0,
            "matched_rule_ids": ["private-rule-marker"],
            "obligations": [
                {"kind": "audit_receipt", "value": "private-obligation-marker"}
            ],
            "policy_bundle_id": "private-policy-marker",
            "policy_digest": canonical_digest({"policy": "bounded"}),
            "policy_version": "1",
            "reason_codes": ["current_stage_permit"],
            "reason_details": ["private-reason-marker"],
            "request_digest": request_digest,
            "request_id": f"{scope}:{run_id}",
        }
        return {
            "schema_version": 3,
            "mode": "shadow",
            "action_scope": scope,
            "intent_source": "comparison_trial_projection",
            "intent_digest": intent_digest,
            "task_authorization_intent": task_intent,
            "comparison_binding_digest": binding_digest,
            "request": request,
            "request_digest": request_digest,
            "decision": decision,
            "decision_digest": canonical_digest(decision),
            "policy_bundle_id": decision["policy_bundle_id"],
            "policy_version": decision["policy_version"],
            "policy_digest": decision["policy_digest"],
            "effect": decision["effect"],
            "reason_codes": decision["reason_codes"],
            "matched_rule_ids": decision["matched_rule_ids"],
            "evidence_refs": decision["evidence_refs"],
            "obligations": decision["obligations"],
            "derived_permission_class": 0,
            "requested_permission_class": 0,
            "legacy_executable": True,
            "execution_parity": True,
            "authority_ceiling_parity": True,
        }

    def _comparison_publication_chain(
        self,
        binding_payload: dict[str, object],
        *,
        run_id: str = "run-comparison",
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        binding = binding_payload["binding"]
        binding_digest = binding_payload["binding_digest"]
        self.assertIsInstance(binding, dict)
        self.assertIsInstance(binding_digest, str)
        assert isinstance(binding, dict)
        assert isinstance(binding_digest, str)

        artifact_digest = canonical_digest(
            {"artifact": "private-review-output"}
        )
        destination_digest = canonical_digest(
            {"destination": "private-review-output"}
        )
        billing_disposition_digest = self._comparison_execution_accounting_payload()[
            "billing_disposition_digest"
        ]
        self.assertIsInstance(billing_disposition_digest, str)
        assert isinstance(billing_disposition_digest, str)
        task_intent = {
            "action": {
                "verb": "create",
                "operation": "artifact.publish_private_review",
                "intended_effect": "create_owner_private_review_artifact",
            },
            "resource": {
                "resource_type": "private_review_artifact",
                "trust_boundary": "isolated_run_workspace",
                "protected": False,
                "sensitivity": "low",
            },
            "consequences": {
                "confidentiality": "low",
                "integrity": "low",
                "availability": "low",
                "reach": "local",
                "destructive": False,
                "reversible": True,
                "sensitivity": "low",
                "blast_radius": "single_resource",
            },
        }
        intent_digest = canonical_digest(task_intent)
        parameters = {
            "artifact_digest": artifact_digest,
            "artifact_kind": "private_review_output",
            "artifact_size_bytes": 128,
            "billing_disposition_digest": billing_disposition_digest,
            "comparison_binding_digest": binding_digest,
            "destination_digest": destination_digest,
            "output_withheld": False,
        }
        action = {
            "descriptive_claims": [],
            "verb": "create",
            "operation": "artifact.publish_private_review",
            "parameters_digest": canonical_digest(
                {
                    "action_scope": PUBLICATION_SCOPE,
                    "intent_digest": intent_digest,
                    "intent_source": (
                        "comparison_review_artifact_projection"
                    ),
                    "legacy_permission_class": 1,
                    "output_schema_digest": binding["output_schema_digest"],
                    "parameters": parameters,
                    "profile_ref": binding["profile_ref"],
                    "runner_id": binding["runner_id"],
                    "task_definition_digest": binding[
                        "task_definition_digest"
                    ],
                    "task_id": "inspect-task",
                    "task_version": "1.0.0",
                }
            ),
            "intended_effect": "create_owner_private_review_artifact",
            "tool_id": None,
        }
        subject = {
            "principal_id": "agent:task-attempt",
            "controller_id": "agentops:local-controller",
            "role": "implementer",
            "role_version": "1",
            "profile_id": binding["profile_ref"],
            "runner_id": binding["runner_id"],
            "session_id": f"attempt:{run_id}",
        }
        resource = {
            "resource_type": "private_review_artifact",
            "identifier": canonical_digest(
                {
                    "action_scope": PUBLICATION_SCOPE,
                    "resource_type": "private_review_artifact",
                    "run_id": run_id,
                }
            ),
            "version": artifact_digest,
            "owner": "operator:local",
            "trust_boundary": "isolated_run_workspace",
            "protected": False,
            "sensitivity": "low",
            "repository_id": binding["repository_ref"],
            "content_digest": artifact_digest,
        }
        environment = {
            "approval_grants": [],
            "evaluated_at": 113.0,
            "isolation_state": "verified",
            "network_state": "disabled",
            "billing_route": "local_non_ai",
            "capacity_state": "not_applicable",
            "paid_continuation_protection": "not_applicable",
            "circuit_state": "closed",
            "flow_state": "local_candidate_publication_proposed",
        }
        consequences = dict(task_intent["consequences"])
        attributes = {
            "subject": subject,
            "action": action,
            "resource": resource,
            "environment": environment,
            "consequences": consequences,
        }
        evidence = [
            {
                "attribute": attribute,
                "authenticated": True,
                "evidence_id": f"private-evidence-marker:{attribute}",
                "expires_at": 233.0,
                "observed_at": 113.0,
                "source": "controller",
                "source_id": "private-source-marker",
                "value_digest": canonical_digest(value),
            }
            for attribute, value in attributes.items()
        ]
        request = {
            "action": action,
            "consequences": consequences,
            "environment": environment,
            "evidence": evidence,
            "request_id": f"{PUBLICATION_SCOPE}:{run_id}",
            "resource": resource,
            "subject": subject,
        }
        request_digest = canonical_digest(request)
        obligation = {
            "kind": "audit_receipt",
            "value": "private-obligation-marker",
        }
        decision = {
            "derived_permission_class": 1,
            "effect": "permit",
            "evidence_refs": ["private-evidence-marker"],
            "expires_at": 200.0,
            "issued_at": 113.0,
            "matched_rule_ids": ["private-rule-marker"],
            "obligations": [obligation],
            "policy_bundle_id": "private-policy-marker",
            "policy_digest": canonical_digest({"policy": "bounded"}),
            "policy_version": "1",
            "reason_codes": ["current_stage_permit"],
            "reason_details": ["private-reason-marker"],
            "request_digest": request_digest,
            "request_id": f"{PUBLICATION_SCOPE}:{run_id}",
        }
        shadow: dict[str, object] = {
            "schema_version": 4,
            "mode": "shadow",
            "action_scope": PUBLICATION_SCOPE,
            "intent_source": "comparison_review_artifact_projection",
            "intent_digest": intent_digest,
            "task_authorization_intent": task_intent,
            "comparison_binding_digest": binding_digest,
            "request": request,
            "request_digest": request_digest,
            "decision": decision,
            "decision_digest": canonical_digest(decision),
            "policy_bundle_id": decision["policy_bundle_id"],
            "policy_version": decision["policy_version"],
            "policy_digest": decision["policy_digest"],
            "effect": decision["effect"],
            "reason_codes": decision["reason_codes"],
            "matched_rule_ids": decision["matched_rule_ids"],
            "evidence_refs": decision["evidence_refs"],
            "obligations": decision["obligations"],
            "derived_permission_class": 1,
            "requested_permission_class": 1,
            "legacy_executable": True,
            "execution_parity": True,
            "authority_ceiling_parity": True,
        }
        action_digest = canonical_digest(
            {"action": action, "resource": resource}
        )
        pre_effect: dict[str, object] = {
            "schema_version": 2,
            "mode": "shadow",
            "receipt_kind": "pre_effect",
            "authorization_enforced": False,
            "authority_basis": "legacy_class_1_local_draft_gate",
            "comparison_binding_digest": binding_digest,
            "publication_shadow_persisted": True,
            "publication_request_digest": request_digest,
            "publication_decision_digest": shadow["decision_digest"],
            "action_digest": action_digest,
            "requested_permission_class": 1,
            "artifact_kind": "private_review_output",
            "destination_digest": destination_digest,
            "artifact_digest": artifact_digest,
            "artifact_size_bytes": 128,
            "output_withheld": False,
            "billing_disposition_digest": billing_disposition_digest,
            "started_at": 114.0,
        }
        pre_effect["receipt_digest"] = canonical_digest(pre_effect)
        pre_effect_digest = pre_effect["receipt_digest"]
        self.assertIsInstance(pre_effect_digest, str)
        assert isinstance(pre_effect_digest, str)
        action_receipt: dict[str, object] = {
            "schema_version": 2,
            "mode": "shadow",
            "receipt_kind": "action",
            "authorization_enforced": False,
            "authority_basis": "legacy_class_1_local_draft_gate",
            "receipt_id": canonical_digest(
                {
                    "comparison_binding_digest": binding_digest,
                    "destination_digest": destination_digest,
                    "pre_effect_receipt_digest": pre_effect_digest,
                }
            ),
            "comparison_binding_digest": binding_digest,
            "pre_effect_receipt_digest": pre_effect_digest,
            "publication_shadow_persisted": True,
            "publication_request_digest": request_digest,
            "publication_decision_digest": shadow["decision_digest"],
            "action_digest": action_digest,
            "executor_id": "ordomata:local-controller",
            "started_at": 114.0,
            "completed_at": 115.0,
            "outcome": "succeeded",
            "obligation_results": [
                {
                    "kind": obligation["kind"],
                    "satisfied": True,
                    "value_digest": canonical_digest(
                        {"value": obligation["value"]}
                    ),
                }
            ],
            "artifact_kind": "private_review_output",
            "destination_digest": destination_digest,
            "intended_artifact_digest": artifact_digest,
            "intended_artifact_size_bytes": 128,
            "output_withheld": False,
            "billing_disposition_digest": billing_disposition_digest,
            "result_digest": artifact_digest,
            "observed_artifact_size_bytes": 128,
            "failure_code": None,
        }
        action_receipt["receipt_digest"] = canonical_digest(action_receipt)
        return shadow, pre_effect, action_receipt

    def _append_v2_comparison_prefix(
        self,
        store: SQLiteStateStore,
        binding_payload: dict[str, object],
        *,
        accounting_payload: dict[str, object] | None = None,
        include_accounting: bool = True,
    ) -> None:
        store.append_event(
            "run-comparison",
            "comparison_trial_binding",
            binding_payload,
            occurred_at=105.0,
        )
        store.append_event(
            "run-comparison",
            "authorization_shadow_decision",
            self._comparison_shadow_payload(
                ADMISSION_SCOPE,
                binding_payload,
            ),
            occurred_at=110.0,
        )
        store.append_event(
            "run-comparison",
            "billing_assessment",
            self._comparison_billing_payload(),
            occurred_at=110.5,
        )
        store.append_event(
            "run-comparison",
            "status",
            {"phase": "runner_execution"},
            status=RunStatus.RUNNING,
            occurred_at=111.0,
        )
        store.append_event(
            "run-comparison",
            "authorization_shadow_decision",
            self._comparison_shadow_payload(
                DISPATCH_SCOPE,
                binding_payload,
            ),
            occurred_at=112.0,
        )
        if include_accounting:
            store.append_event(
                "run-comparison",
                "execution_accounting",
                (
                    self._comparison_execution_accounting_payload()
                    if accounting_payload is None
                    else accounting_payload
                ),
                occurred_at=112.5,
            )

    @staticmethod
    def _resign_receipt(payload: dict[str, object]) -> None:
        payload.pop("receipt_digest", None)
        payload["receipt_digest"] = canonical_digest(payload)

    def _resign_publication_chain(
        self,
        publication: dict[str, object],
        pre_effect: dict[str, object],
        action_receipt: dict[str, object],
        binding_payload: dict[str, object],
    ) -> None:
        binding = binding_payload["binding"]
        intent = publication["task_authorization_intent"]
        request = publication["request"]
        self.assertIsInstance(binding, dict)
        self.assertIsInstance(intent, dict)
        self.assertIsInstance(request, dict)
        assert isinstance(binding, dict)
        assert isinstance(intent, dict)
        assert isinstance(request, dict)
        request_action = request["action"]
        request_resource = request["resource"]
        self.assertIsInstance(request_action, dict)
        self.assertIsInstance(request_resource, dict)
        assert isinstance(request_action, dict)
        assert isinstance(request_resource, dict)

        intent_digest = canonical_digest(intent)
        publication["intent_digest"] = intent_digest
        request_action["parameters_digest"] = canonical_digest(
            {
                "action_scope": PUBLICATION_SCOPE,
                "intent_digest": intent_digest,
                "intent_source": publication["intent_source"],
                "legacy_permission_class": 1,
                "output_schema_digest": binding["output_schema_digest"],
                "parameters": {
                    "artifact_digest": pre_effect["artifact_digest"],
                    "artifact_kind": pre_effect["artifact_kind"],
                    "artifact_size_bytes": pre_effect[
                        "artifact_size_bytes"
                    ],
                    "billing_disposition_digest": pre_effect[
                        "billing_disposition_digest"
                    ],
                    "comparison_binding_digest": binding_payload[
                        "binding_digest"
                    ],
                    "destination_digest": pre_effect[
                        "destination_digest"
                    ],
                    "output_withheld": pre_effect["output_withheld"],
                },
                "profile_ref": binding["profile_ref"],
                "runner_id": binding["runner_id"],
                "task_definition_digest": binding[
                    "task_definition_digest"
                ],
                "task_id": "inspect-task",
                "task_version": "1.0.0",
            }
        )
        evidence = request["evidence"]
        self.assertIsInstance(evidence, list)
        assert isinstance(evidence, list)
        for item in evidence:
            self.assertIsInstance(item, dict)
            assert isinstance(item, dict)
            attribute = item.get("attribute")
            if isinstance(attribute, str) and attribute in request:
                item["value_digest"] = canonical_digest(request[attribute])

        request_digest = canonical_digest(request)
        publication["request_digest"] = request_digest
        decision = publication["decision"]
        self.assertIsInstance(decision, dict)
        assert isinstance(decision, dict)
        decision["request_digest"] = request_digest
        decision_digest = canonical_digest(decision)
        publication["decision_digest"] = decision_digest

        action_digest = canonical_digest(
            {"action": request_action, "resource": request_resource}
        )
        pre_effect["publication_request_digest"] = request_digest
        pre_effect["publication_decision_digest"] = decision_digest
        pre_effect["action_digest"] = action_digest
        self._resign_receipt(pre_effect)

        pre_effect_receipt_digest = pre_effect["receipt_digest"]
        action_receipt["pre_effect_receipt_digest"] = (
            pre_effect_receipt_digest
        )
        action_receipt["publication_request_digest"] = request_digest
        action_receipt["publication_decision_digest"] = decision_digest
        action_receipt["action_digest"] = action_digest
        action_receipt["receipt_id"] = canonical_digest(
            {
                "comparison_binding_digest": action_receipt[
                    "comparison_binding_digest"
                ],
                "destination_digest": action_receipt[
                    "destination_digest"
                ],
                "pre_effect_receipt_digest": pre_effect_receipt_digest,
            }
        )
        self._resign_receipt(action_receipt)

    def _shadow_payload(
        self,
        scope: str,
        *,
        effect: str = "permit",
        legacy_executable: bool = True,
        reported_parity: bool | None = None,
        schema_version: int = 2,
    ) -> dict[str, object]:
        publication = scope == PUBLICATION_SCOPE
        subject = {
            "principal_id": "agent:test",
            "controller_id": "controller:test",
            "role": "implementer",
            "role_version": "1",
            "profile_id": "private-profile-marker",
            "runner_id": "mock",
            "session_id": "attempt:run-inspect",
        }
        action = {
            "descriptive_claims": [],
            "verb": "create",
            "operation": (
                "artifact.publish_local_candidate"
                if publication
                else "chief_of_staff.local_brief"
            ),
            "parameters_digest": canonical_digest({"parameters": "bounded"}),
            "intended_effect": (
                "create_isolated_local_candidate"
                if publication
                else "create_local_structured_brief"
            ),
            "tool_id": None,
        }
        resource = {
            "resource_type": (
                "local_candidate_artifact" if publication else "local_artifact"
            ),
            "identifier": canonical_digest(
                {
                    "action_scope": scope,
                    "resource_type": (
                        "local_candidate_artifact"
                        if publication
                        else "local_artifact"
                    ),
                    "run_id": "run-inspect",
                }
            ),
            "version": "v1",
            "owner": "operator:local",
            "trust_boundary": "isolated_run_workspace",
            "protected": False,
            "sensitivity": "low",
            "repository_id": canonical_digest({"repository": "test"}),
            "content_digest": canonical_digest({"content": "test"}),
        }
        environment = {
            "approval_grants": [],
            "evaluated_at": 110.0,
            "isolation_state": "verified",
            "network_state": "disabled",
            "billing_route": "mock",
            "capacity_state": "not_applicable",
            "paid_continuation_protection": "not_applicable",
            "circuit_state": "closed",
            "flow_state": {
                ADMISSION_SCOPE: "admission_proposed",
                DISPATCH_SCOPE: "runner_dispatch_proposed",
                PUBLICATION_SCOPE: "local_candidate_publication_proposed",
            }[scope],
        }
        consequences = {
            "availability": "low",
            "blast_radius": "single_resource",
            "confidentiality": "low",
            "destructive": False,
            "integrity": "low",
            "reach": "local",
            "reversible": True,
            "sensitivity": "low",
        }
        attributes = {
            "subject": subject,
            "action": action,
            "resource": resource,
            "environment": environment,
            "consequences": consequences,
        }
        evidence = [
            {
                "attribute": attribute,
                "authenticated": True,
                "evidence_id": f"private-evidence-marker:{attribute}",
                "expires_at": 200.0,
                "observed_at": 100.0,
                "source": "controller",
                "source_id": "private-source-marker",
                "value_digest": canonical_digest(value),
            }
            for attribute, value in attributes.items()
        ]
        request = {
            "action": action,
            "consequences": consequences,
            "environment": environment,
            "evidence": evidence,
            "request_id": f"{scope}:run-inspect",
            "resource": resource,
            "subject": subject,
        }
        request_digest = canonical_digest(request)
        obligation = {
            "kind": "audit_receipt",
            "value": "private-obligation-marker",
        }
        decision = {
            "derived_permission_class": 1,
            "effect": effect,
            "evidence_refs": ["private-evidence-marker"],
            "expires_at": 150.0,
            "issued_at": 110.0,
            "matched_rule_ids": ["private-rule-marker"],
            "obligations": [obligation],
            "policy_bundle_id": "private-policy-marker",
            "policy_digest": canonical_digest({"policy": "bounded"}),
            "policy_version": "1",
            "reason_codes": ["current_stage_permit"],
            "reason_details": ["private-reason-marker"],
            "request_digest": request_digest,
            "request_id": f"{scope}:run-inspect",
        }
        recomputed_parity = (effect == "permit") == legacy_executable
        payload: dict[str, object] = {
            "schema_version": schema_version,
            "mode": "shadow",
            "action_scope": scope,
            "request": request,
            "request_digest": request_digest,
            "decision": decision,
            "decision_digest": canonical_digest(decision),
            "policy_bundle_id": decision["policy_bundle_id"],
            "policy_version": decision["policy_version"],
            "policy_digest": decision["policy_digest"],
            "effect": effect,
            "reason_codes": decision["reason_codes"],
            "matched_rule_ids": decision["matched_rule_ids"],
            "evidence_refs": decision["evidence_refs"],
            "obligations": decision["obligations"],
            "derived_permission_class": 1,
            "requested_permission_class": 1,
            "legacy_executable": legacy_executable,
            "execution_parity": (
                recomputed_parity if reported_parity is None else reported_parity
            ),
            "authority_ceiling_parity": True,
        }
        if schema_version == 2:
            task_intent = {
                "action": {
                    "intended_effect": action["intended_effect"],
                    "operation": action["operation"],
                    "verb": action["verb"],
                },
                "consequences": consequences,
                "resource": {
                    "protected": resource["protected"],
                    "resource_type": resource["resource_type"],
                    "sensitivity": resource["sensitivity"],
                    "trust_boundary": resource["trust_boundary"],
                },
            }
            payload.update(
                {
                    "intent_source": (
                        "controller_boundary_projection"
                        if publication
                        else "task_contract"
                    ),
                    "intent_digest": canonical_digest(task_intent),
                    "task_authorization_intent": task_intent,
                }
            )
        else:
            payload.pop("requested_permission_class")
            payload.pop("authority_ceiling_parity")
        return payload

    def _resign_payload(self, payload: dict[str, object]) -> None:
        request = payload["request"]
        decision = payload["decision"]
        self.assertIsInstance(request, dict)
        self.assertIsInstance(decision, dict)
        assert isinstance(request, dict)
        assert isinstance(decision, dict)
        request_digest = canonical_digest(request)
        payload["request_digest"] = request_digest
        decision["request_digest"] = request_digest
        payload["decision_digest"] = canonical_digest(decision)

    def test_absent_database_is_clean_and_does_not_create_state_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_directory = Path(temporary) / ".ordomata"
            database = state_directory / "state.sqlite3"

            report = inspect_authorization_shadows(database, now=300.0)

            self.assertTrue(report.clean)
            self.assertFalse(report.database_present)
            self.assertEqual(report.runs, ())
            self.assertFalse(state_directory.exists())

    def test_baseline_schema_tampering_is_reported_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = SQLiteStateStore(database)
            store.close()
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("DROP TRIGGER runs_no_update")
                connection.commit()

            report = inspect_authorization_shadows(database, now=300.0)

            self.assertFalse(report.clean)
            self.assertEqual(report.integrity_issues, ("baseline_schema_mismatch",))
            self.assertEqual(report.integrity_issue_count, 1)
            with closing(sqlite3.connect(database)) as connection:
                trigger = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name = 'runs_no_update'"
                ).fetchone()
            self.assertIsNone(trigger)

    def test_migration_schema_and_version_findings_are_value_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing_guard = Path(temporary) / "missing-guard.sqlite3"
            store = SQLiteStateStore(missing_guard)
            store.close()
            with closing(sqlite3.connect(missing_guard)) as connection:
                connection.execute(
                    "DROP TRIGGER state_schema_migrations_no_update"
                )
                connection.commit()

            guard_report = inspect_authorization_shadows(
                missing_guard, now=300.0
            )
            self.assertEqual(
                guard_report.integrity_issues,
                ("migration_schema_mismatch",),
            )

            future = Path(temporary) / "future.sqlite3"
            store = SQLiteStateStore(future)
            store.close()
            with closing(sqlite3.connect(future)) as connection:
                connection.execute(
                    """
                    INSERT INTO state_schema_migrations (
                        version, name, script_sha256, applied_at
                    ) VALUES (5, 'private-future-marker', ?, 301.0)
                    """,
                    ("f" * 64,),
                )
                connection.commit()

            future_report = inspect_authorization_shadows(future, now=302.0)
            projection = json.dumps(future_report.to_mapping(), sort_keys=True)
            self.assertEqual(
                future_report.integrity_issues,
                ("migration_version_set_mismatch",),
            )
            self.assertNotIn("private-future-marker", projection)

    def test_invalid_migration_timestamp_is_reported_value_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = SQLiteStateStore(database)
            store.close()
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "DROP TRIGGER state_schema_migrations_no_update"
                )
                connection.execute(
                    """
                    UPDATE state_schema_migrations
                    SET applied_at = 'private-timestamp-marker'
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER state_schema_migrations_no_update
                    BEFORE UPDATE ON state_schema_migrations BEGIN
                        SELECT RAISE(ABORT, 'schema migrations are append-only');
                    END
                    """
                )
                connection.commit()

            report = inspect_authorization_shadows(database, now=300.0)
            projection = json.dumps(report.to_mapping(), sort_keys=True)

            self.assertEqual(
                report.integrity_issues,
                ("migration_applied_at_invalid",),
            )
            self.assertNotIn("private-timestamp-marker", projection)

    def test_migration_version_schema_disagreement_is_reported(self) -> None:
        from ordomata.supervisor import SQLiteSupervisorStore

        with tempfile.TemporaryDirectory() as temporary:
            missing_current = Path(temporary) / "missing-current.sqlite3"
            supervisor = SQLiteSupervisorStore(missing_current)
            supervisor.close()
            with closing(sqlite3.connect(missing_current)) as connection:
                connection.execute(
                    """
                    DROP TABLE
                    supervisor_bookkeeping_authorization_observations
                    """
                )
                connection.commit()

            premature = Path(temporary) / "premature.sqlite3"
            store = SQLiteStateStore(premature)
            store.close()
            with closing(sqlite3.connect(premature)) as connection:
                connection.execute(
                    """
                    CREATE TABLE supervisor_control_events(
                        private_marker TEXT
                    )
                    """
                )
                connection.commit()

            for database in (missing_current, premature):
                with self.subTest(database=database.name):
                    report = inspect_authorization_shadows(
                        database,
                        now=300.0,
                    )
                    self.assertIn(
                        "migration_ledger_schema_mismatch",
                        report.integrity_issues,
                    )

    def test_malformed_baseline_columns_return_bounded_schema_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = SQLiteStateStore(database)
            store.close()
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    ALTER TABLE runs
                    RENAME COLUMN permission_class TO permission_level
                    """
                )
                connection.commit()

            report = inspect_authorization_shadows(database, now=300.0)

            self.assertEqual(
                report.integrity_issues,
                ("baseline_schema_mismatch",),
            )
            self.assertEqual(report.runs, ())

    def test_exact_preledger_baseline_is_legacy_clean_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = SQLiteStateStore(database)
            store.close()
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("DROP TABLE state_schema_migrations")
                connection.commit()

            report = inspect_authorization_shadows(database, now=300.0)

            self.assertTrue(report.clean)
            self.assertEqual(report.integrity_issues, ())
            with closing(sqlite3.connect(database)) as connection:
                ledger = connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'state_schema_migrations'
                    """
                ).fetchone()
            self.assertIsNone(ledger)

    def test_requested_missing_run_raises_without_echoing_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.close()

            with self.assertRaises(RecordNotFoundError) as caught:
                inspect_authorization_shadows(
                    database,
                    run_id="private-missing-run-marker",
                    now=300.0,
                )

            self.assertNotIn("private-missing-run-marker", str(caught.exception))

    def test_complete_history_is_clean_read_only_and_strictly_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE),
                occurred_at=110.0,
            )
            store.append_event(
                "run-inspect",
                "billing_assessment",
                {"route": "mock"},
                occurred_at=110.5,
            )
            store.append_event(
                "run-inspect",
                "status",
                {"phase": "runner_execution"},
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(DISPATCH_SCOPE),
                occurred_at=112.0,
            )
            store.append_event(
                "run-inspect",
                "execution_accounting",
                {"incremental_api_charge": "none"},
                occurred_at=112.5,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(PUBLICATION_SCOPE),
                occurred_at=113.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                {"phase": "complete"},
                status=RunStatus.SUCCEEDED,
                occurred_at=114.0,
            )
            store.append_artifact(
                ArtifactRecord(
                    artifact_id="artifact-inspect",
                    run_id="run-inspect",
                    kind="candidate",
                    path="/private/artifact-marker",
                    sha256="b" * 64,
                    media_type="application/json",
                    size_bytes=10,
                    created_at=115.0,
                )
            )
            store.close()
            before = database.read_bytes()
            before_names = sorted(path.name for path in database.parent.iterdir())
            original_connect = sqlite3.connect
            connect_calls: list[tuple[object, dict[str, object]]] = []

            def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                connect_calls.append((args[0], dict(kwargs)))
                return original_connect(*args, **kwargs)

            with patch(
                "ordomata.authorization_inspection.sqlite3.connect",
                side_effect=recording_connect,
            ):
                report = inspect_authorization_shadows(database, now=300.0)

            self.assertTrue(report.clean)
            self.assertEqual(report.inspected_run_count, 1)
            self.assertEqual(report.inspected_event_count, 3)
            self.assertEqual(report.runs[0].run_kind, "task_attempt")
            self.assertEqual(
                report.runs[0].authorization_shadow_coverage,
                "task_attempt_admission_dispatch_publication_shadow",
            )
            self.assertEqual(
                report.runs[0].observed_scopes,
                tuple(sorted((ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE))),
            )
            self.assertEqual(report.runs[0].missing_scopes, ())
            for event in report.runs[0].events:
                self.assertTrue(event.request_digest_valid)
                self.assertTrue(event.decision_digest_valid)
                self.assertTrue(event.recomputed_execution_parity)
                self.assertEqual(len(event.evidence), 5)
                self.assertTrue(event.evidence[0].fresh_at_evaluation)
                self.assertFalse(event.evidence[0].fresh_now)
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            for marker in _PRIVATE_MARKERS:
                self.assertNotIn(marker, projection)
            self.assertEqual(database.read_bytes(), before)
            self.assertEqual(
                sorted(path.name for path in database.parent.iterdir()),
                before_names,
            )
            self.assertEqual(len(connect_calls), 1)
            self.assertIn("?mode=ro", str(connect_calls[0][0]))
            self.assertTrue(connect_calls[0][1]["uri"])

    def test_live_wal_is_read_through_a_private_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            try:
                store.append_event(
                    "run-inspect",
                    "authorization_shadow_decision",
                    self._shadow_payload(ADMISSION_SCOPE),
                    occurred_at=110.0,
                )
                before_names = sorted(
                    path.name for path in database.parent.iterdir()
                )

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertTrue(report.clean)
                self.assertEqual(report.inspected_event_count, 1)
                self.assertEqual(
                    sorted(path.name for path in database.parent.iterdir()),
                    before_names,
                )
            finally:
                store.close()

    def test_schema_v1_history_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE, schema_version=1),
                occurred_at=110.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertTrue(report.clean)
            self.assertEqual(report.inspected_event_count, 1)
            self.assertEqual(report.runs[0].events[0].integrity_issues, ())

    def test_comparison_v3_shadows_validate_without_hiding_publication_gap(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            binding_payload = self._comparison_binding_payload()
            binding = binding_payload["binding"]
            self.assertIsInstance(binding, dict)
            assert isinstance(binding, dict)
            store = self._create_run(
                database,
                run_id="run-comparison",
                permission_class=PermissionClass.READ_ONLY,
                context_digest=str(binding["context_digest"]),
            )
            store.append_event(
                "run-comparison",
                "comparison_trial_binding",
                binding_payload,
                occurred_at=105.0,
            )
            store.append_event(
                "run-comparison",
                "authorization_shadow_decision",
                self._comparison_shadow_payload(
                    ADMISSION_SCOPE,
                    binding_payload,
                ),
                occurred_at=110.0,
            )
            store.append_event(
                "run-comparison",
                "billing_assessment",
                self._comparison_billing_payload(),
                occurred_at=110.5,
            )
            store.append_event(
                "run-comparison",
                "status",
                {"phase": "runner_execution"},
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-comparison",
                "authorization_shadow_decision",
                self._comparison_shadow_payload(
                    DISPATCH_SCOPE,
                    binding_payload,
                ),
                occurred_at=112.0,
            )
            store.append_event(
                "run-comparison",
                "comparison_review_artifact_intent",
                {},
                occurred_at=112.5,
            )
            store.append_event(
                "run-comparison",
                "execution_accounting",
                {"incremental_api_charge": "none"},
                occurred_at=113.0,
            )
            store.append_event(
                "run-comparison",
                "status",
                {"phase": "complete"},
                status=RunStatus.SUCCEEDED,
                occurred_at=114.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            self.assertEqual(report.inspected_run_count, 1)
            self.assertEqual(report.inspected_event_count, 2)
            self.assertEqual(report.coverage_gap_count, 1)
            run = report.runs[0]
            self.assertEqual(run.run_kind, "controlled_comparison_trial")
            self.assertEqual(
                run.authorization_shadow_coverage,
                "partial_admission_dispatch_shadow",
            )
            self.assertIsNone(run.authorization_action_receipt_coverage)
            self.assertIsNone(
                report.to_mapping()["runs"][0][
                    "authorization_action_receipt_coverage"
                ]
            )
            self.assertEqual(
                run.expected_scopes,
                tuple(
                    sorted(
                        (ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE)
                    )
                ),
            )
            self.assertEqual(
                run.observed_scopes,
                tuple(sorted((ADMISSION_SCOPE, DISPATCH_SCOPE))),
            )
            self.assertEqual(run.missing_scopes, (PUBLICATION_SCOPE,))
            self.assertEqual(run.integrity_issues, ())
            for event in run.events:
                self.assertEqual(event.integrity_issues, ())
                self.assertEqual(event.derived_permission_class, 0)
                self.assertEqual(event.requested_permission_class, 0)
                self.assertTrue(event.request_digest_valid)
                self.assertTrue(event.decision_digest_valid)
                self.assertTrue(event.recomputed_execution_parity)
                self.assertTrue(event.recomputed_authority_ceiling_parity)
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            for marker in _PRIVATE_MARKERS:
                self.assertNotIn(marker, projection)

    def test_comparison_v2_full_publication_history_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            binding_payload = self._comparison_binding_payload(
                schema_version=2
            )
            binding = binding_payload["binding"]
            self.assertIsInstance(binding, dict)
            assert isinstance(binding, dict)
            store = self._create_run(
                database,
                run_id="run-comparison",
                permission_class=PermissionClass.READ_ONLY,
                context_digest=str(binding["context_digest"]),
            )
            self._append_v2_comparison_prefix(store, binding_payload)
            publication, pre_effect, action_receipt = (
                self._comparison_publication_chain(binding_payload)
            )
            store.append_event(
                "run-comparison",
                "authorization_shadow_decision",
                publication,
                occurred_at=113.0,
            )
            store.append_event(
                "run-comparison",
                "comparison_review_artifact_intent",
                pre_effect,
                occurred_at=114.0,
            )
            store.append_event(
                "run-comparison",
                COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                action_receipt,
                occurred_at=115.0,
            )
            store.append_event(
                "run-comparison",
                "status",
                {"phase": "complete", "artifact_observed": True},
                status=RunStatus.SUCCEEDED,
                occurred_at=116.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertTrue(report.clean)
            self.assertEqual(report.inspected_run_count, 1)
            self.assertEqual(report.inspected_event_count, 3)
            self.assertEqual(report.coverage_gap_count, 0)
            self.assertEqual(report.integrity_issue_count, 0)
            self.assertEqual(report.authority_ceiling_mismatch_count, 0)
            run = report.runs[0]
            self.assertEqual(run.run_kind, "controlled_comparison_trial")
            self.assertEqual(
                run.authorization_shadow_coverage,
                COMPARISON_FULL_SHADOW_COVERAGE,
            )
            self.assertEqual(
                run.authorization_action_receipt_coverage,
                COMPARISON_ACTION_RECEIPT_COVERAGE,
            )
            self.assertEqual(
                report.to_mapping()["runs"][0][
                    "authorization_action_receipt_coverage"
                ],
                COMPARISON_ACTION_RECEIPT_COVERAGE,
            )
            self.assertEqual(
                run.observed_scopes,
                tuple(
                    sorted(
                        (ADMISSION_SCOPE, DISPATCH_SCOPE, PUBLICATION_SCOPE)
                    )
                ),
            )
            self.assertEqual(run.missing_scopes, ())
            self.assertEqual(run.integrity_issues, ())
            classes = {
                event.action_scope: (
                    event.derived_permission_class,
                    event.requested_permission_class,
                    event.recomputed_authority_ceiling_parity,
                )
                for event in run.events
            }
            self.assertEqual(
                classes,
                {
                    ADMISSION_SCOPE: (0, 0, True),
                    DISPATCH_SCOPE: (0, 0, True),
                    PUBLICATION_SCOPE: (1, 1, True),
                },
            )
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            for marker in _PRIVATE_MARKERS:
                self.assertNotIn(marker, projection)

    def test_comparison_v2_receipt_failures_are_fixed_and_value_free(
        self,
    ) -> None:
        cases = (
            (
                "missing_pre_effect",
                "comparison_publication_pre_effect_receipt_missing",
            ),
            (
                "missing_action",
                "comparison_publication_action_receipt_missing",
            ),
            (
                "duplicate_pre_effect",
                "comparison_publication_pre_effect_receipt_duplicate",
            ),
            (
                "duplicate_action",
                "comparison_publication_action_receipt_duplicate",
            ),
            (
                "tampered_pre_effect_digest",
                "comparison_publication_pre_effect_digest_mismatch",
            ),
            (
                "tampered_action_digest",
                "comparison_publication_action_receipt_digest_mismatch",
            ),
            (
                "tampered_linkage",
                "comparison_publication_receipt_linkage_mismatch",
            ),
            (
                "tampered_receipt_identifier",
                (
                    "comparison_publication_action_receipt_"
                    "identifier_mismatch"
                ),
            ),
            (
                "unsatisfied_success_obligation",
                "comparison_publication_obligation_results_invalid",
            ),
            (
                "tampered_accounting_digest",
                "comparison_execution_accounting_digest_mismatch",
            ),
            (
                "missing_accounting",
                "comparison_execution_accounting_missing",
            ),
            (
                "duplicate_accounting",
                "comparison_execution_accounting_duplicate",
            ),
            (
                "invalid_accounting",
                "comparison_execution_accounting_invalid",
            ),
            (
                "extra_accounting_field",
                "comparison_execution_accounting_invalid",
            ),
            (
                "null_accounting_digest",
                "comparison_publication_billing_disposition_mismatch",
            ),
            (
                "tampered_billing_linkage",
                "comparison_publication_billing_disposition_mismatch",
            ),
            (
                "pre_effect_before_shadow",
                "comparison_publication_pre_effect_order_invalid",
            ),
            (
                "action_before_pre_effect",
                "comparison_publication_action_receipt_order_invalid",
            ),
            (
                "private_executor_value",
                "comparison_publication_action_receipt_invalid",
            ),
            (
                "legacy_observed_mixed",
                "comparison_publication_legacy_observation_unexpected",
            ),
        )
        for case, expected_issue in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                database = Path(temporary) / "state.sqlite3"
                binding_payload = self._comparison_binding_payload(
                    schema_version=2
                )
                binding = binding_payload["binding"]
                self.assertIsInstance(binding, dict)
                assert isinstance(binding, dict)
                store = self._create_run(
                    database,
                    run_id="run-comparison",
                    permission_class=PermissionClass.READ_ONLY,
                    context_digest=str(binding["context_digest"]),
                )
                accounting_payload = (
                    self._comparison_execution_accounting_payload()
                )
                if case == "tampered_accounting_digest":
                    accounting_payload["billing_disposition_digest"] = (
                        "sha256:" + "0" * 64
                    )
                elif case == "invalid_accounting":
                    accounting_payload = {"schema_version": 1}
                elif case == "extra_accounting_field":
                    accounting_payload["private_extra"] = (
                        "private-accounting-marker"
                    )
                elif case == "null_accounting_digest":
                    accounting_payload["billing_disposition_digest"] = None
                self._append_v2_comparison_prefix(
                    store,
                    binding_payload,
                    accounting_payload=accounting_payload,
                    include_accounting=(case != "missing_accounting"),
                )
                if case == "duplicate_accounting":
                    store.append_event(
                        "run-comparison",
                        "execution_accounting",
                        self._comparison_execution_accounting_payload(),
                        occurred_at=112.75,
                    )
                publication, pre_effect, action_receipt = (
                    self._comparison_publication_chain(binding_payload)
                )

                if case == "tampered_pre_effect_digest":
                    pre_effect["receipt_digest"] = "sha256:" + "0" * 64
                elif case == "tampered_action_digest":
                    action_receipt["receipt_digest"] = "sha256:" + "0" * 64
                elif case == "tampered_linkage":
                    action_receipt["output_withheld"] = True
                    self._resign_receipt(action_receipt)
                elif case == "tampered_receipt_identifier":
                    action_receipt["receipt_id"] = "sha256:" + "0" * 64
                    self._resign_receipt(action_receipt)
                elif case == "unsatisfied_success_obligation":
                    obligation_results = action_receipt[
                        "obligation_results"
                    ]
                    self.assertIsInstance(obligation_results, list)
                    assert isinstance(obligation_results, list)
                    self.assertIsInstance(obligation_results[0], dict)
                    assert isinstance(obligation_results[0], dict)
                    obligation_results[0]["satisfied"] = False
                    self._resign_receipt(action_receipt)
                elif case == "tampered_billing_linkage":
                    other_billing_digest = canonical_digest(
                        {"billing_disposition": "other"}
                    )
                    pre_effect["billing_disposition_digest"] = (
                        other_billing_digest
                    )
                    action_receipt["billing_disposition_digest"] = (
                        other_billing_digest
                    )
                    self._resign_publication_chain(
                        publication,
                        pre_effect,
                        action_receipt,
                        binding_payload,
                    )
                elif case == "private_executor_value":
                    action_receipt["executor_id"] = "private-receipt-marker"
                    self._resign_receipt(action_receipt)

                events: list[tuple[str, dict[str, object]]] = [
                    ("authorization_shadow_decision", publication),
                    ("comparison_review_artifact_intent", pre_effect),
                    (
                        COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                        action_receipt,
                    ),
                ]
                if case == "missing_pre_effect":
                    events.pop(1)
                elif case == "missing_action":
                    events.pop()
                elif case == "duplicate_pre_effect":
                    events.insert(
                        2,
                        ("comparison_review_artifact_intent", pre_effect),
                    )
                elif case == "duplicate_action":
                    events.append(
                        (
                            COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                            action_receipt,
                        )
                    )
                elif case == "pre_effect_before_shadow":
                    events[0], events[1] = events[1], events[0]
                elif case == "action_before_pre_effect":
                    events[1], events[2] = events[2], events[1]
                elif case == "legacy_observed_mixed":
                    events.append(
                        (
                            "comparison_review_artifact_observed",
                            {"schema_version": 1},
                        )
                    )

                for offset, (event_type, payload) in enumerate(events):
                    store.append_event(
                        "run-comparison",
                        event_type,
                        payload,
                        occurred_at=113.0 + offset,
                    )
                store.append_event(
                    "run-comparison",
                    "status",
                    {"phase": "complete"},
                    status=RunStatus.SUCCEEDED,
                    occurred_at=118.0,
                )
                store.close()

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertFalse(report.clean)
                self.assertIn(
                    expected_issue,
                    report.runs[0].integrity_issues,
                )
                if case == "missing_pre_effect":
                    self.assertIn(
                        "comparison_publication_action_receipt_orphaned",
                        report.runs[0].integrity_issues,
                    )
                elif case == "null_accounting_digest":
                    self.assertIn(
                        "comparison_execution_accounting_invalid",
                        report.runs[0].integrity_issues,
                    )
                projection = json.dumps(report.to_mapping(), sort_keys=True)
                for marker in _PRIVATE_MARKERS:
                    self.assertNotIn(marker, projection)
                for issue in report.runs[0].integrity_issues:
                    self.assertEqual(issue, issue.lower())
                    self.assertTrue(issue.replace("_", "").isalnum())

    def test_comparison_v2_wrong_class_one_projection_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            binding_payload = self._comparison_binding_payload(
                schema_version=2
            )
            binding = binding_payload["binding"]
            self.assertIsInstance(binding, dict)
            assert isinstance(binding, dict)
            store = self._create_run(
                database,
                run_id="run-comparison",
                permission_class=PermissionClass.READ_ONLY,
                context_digest=str(binding["context_digest"]),
            )
            self._append_v2_comparison_prefix(store, binding_payload)
            publication, pre_effect, action_receipt = (
                self._comparison_publication_chain(binding_payload)
            )
            intent = publication["task_authorization_intent"]
            request = publication["request"]
            self.assertIsInstance(intent, dict)
            self.assertIsInstance(request, dict)
            assert isinstance(intent, dict)
            assert isinstance(request, dict)
            intent_action = intent["action"]
            request_action = request["action"]
            self.assertIsInstance(intent_action, dict)
            self.assertIsInstance(request_action, dict)
            assert isinstance(intent_action, dict)
            assert isinstance(request_action, dict)
            intent_action["operation"] = "repository.modify_source"
            request_action["operation"] = "repository.modify_source"
            self._resign_publication_chain(
                publication,
                pre_effect,
                action_receipt,
                binding_payload,
            )
            store.append_event(
                "run-comparison",
                "authorization_shadow_decision",
                publication,
                occurred_at=113.0,
            )
            store.append_event(
                "run-comparison",
                "comparison_review_artifact_intent",
                pre_effect,
                occurred_at=114.0,
            )
            store.append_event(
                "run-comparison",
                COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                action_receipt,
                occurred_at=115.0,
            )
            store.append_event(
                "run-comparison",
                "status",
                {"phase": "complete"},
                status=RunStatus.SUCCEEDED,
                occurred_at=116.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            publication_event = next(
                event
                for event in report.runs[0].events
                if event.action_scope == PUBLICATION_SCOPE
            )
            self.assertIn(
                "comparison_publication_intent_invalid",
                publication_event.integrity_issues,
            )
            self.assertFalse(
                publication_event.recomputed_authority_ceiling_parity
            )
            self.assertIn(
                "authority_ceiling_parity_mismatch",
                publication_event.integrity_issues,
            )
            self.assertIn(
                "derived_class_exceeds_run_authority",
                publication_event.integrity_issues,
            )
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            for marker in _PRIVATE_MARKERS:
                self.assertNotIn(marker, projection)

    def test_comparison_v2_failed_and_cancelled_receipt_shapes(
        self,
    ) -> None:
        cases = (
            (
                "valid_failed",
                "failed",
                "artifact_persistence_failed",
                RunStatus.FAILED,
                None,
            ),
            (
                "valid_cancelled",
                "cancelled",
                "artifact_persistence_interrupted",
                RunStatus.CANCELLED,
                None,
            ),
            (
                "failed_with_result",
                "failed",
                "artifact_persistence_failed",
                RunStatus.FAILED,
                "comparison_publication_action_outcome_invalid",
            ),
            (
                "cancelled_with_wrong_failure",
                "cancelled",
                "artifact_persistence_failed",
                RunStatus.CANCELLED,
                "comparison_publication_action_outcome_invalid",
            ),
            (
                "failed_with_succeeded_terminal",
                "failed",
                "artifact_persistence_failed",
                RunStatus.SUCCEEDED,
                "comparison_action_receipt_terminal_mismatch",
            ),
            (
                "succeeded_with_artifact_absent",
                "succeeded",
                None,
                RunStatus.BLOCKED,
                "comparison_action_receipt_terminal_mismatch",
            ),
            (
                "succeeded_without_artifact_observation",
                "succeeded",
                None,
                RunStatus.QUARANTINED,
                "comparison_action_receipt_terminal_mismatch",
            ),
            (
                "succeeded_without_terminal",
                "succeeded",
                None,
                None,
                "comparison_action_receipt_terminal_missing",
            ),
        )
        for case, outcome, failure_code, terminal_status, issue in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                database = Path(temporary) / "state.sqlite3"
                binding_payload = self._comparison_binding_payload(
                    schema_version=2
                )
                binding = binding_payload["binding"]
                self.assertIsInstance(binding, dict)
                assert isinstance(binding, dict)
                store = self._create_run(
                    database,
                    run_id="run-comparison",
                    permission_class=PermissionClass.READ_ONLY,
                    context_digest=str(binding["context_digest"]),
                )
                self._append_v2_comparison_prefix(store, binding_payload)
                publication, pre_effect, action_receipt = (
                    self._comparison_publication_chain(binding_payload)
                )
                action_receipt["outcome"] = outcome
                action_receipt["failure_code"] = failure_code
                action_receipt["result_digest"] = None
                action_receipt["observed_artifact_size_bytes"] = None
                if outcome == "succeeded":
                    action_receipt["result_digest"] = action_receipt[
                        "intended_artifact_digest"
                    ]
                    action_receipt["observed_artifact_size_bytes"] = (
                        action_receipt["intended_artifact_size_bytes"]
                    )
                if case == "failed_with_result":
                    action_receipt["result_digest"] = action_receipt[
                        "intended_artifact_digest"
                    ]
                    action_receipt["observed_artifact_size_bytes"] = (
                        action_receipt["intended_artifact_size_bytes"]
                    )
                self._resign_receipt(action_receipt)
                store.append_event(
                    "run-comparison",
                    "authorization_shadow_decision",
                    publication,
                    occurred_at=113.0,
                )
                store.append_event(
                    "run-comparison",
                    "comparison_review_artifact_intent",
                    pre_effect,
                    occurred_at=114.0,
                )
                store.append_event(
                    "run-comparison",
                    COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                    action_receipt,
                    occurred_at=115.0,
                )
                if terminal_status is not None:
                    store.append_event(
                        "run-comparison",
                        "status",
                        {
                            "phase": "complete",
                            **(
                                {"artifact_observed": False}
                                if case == "succeeded_with_artifact_absent"
                                else {}
                            ),
                        },
                        status=terminal_status,
                        occurred_at=116.0,
                    )
                store.close()

                report = inspect_authorization_shadows(
                    database,
                    now=120.0,
                )

                if issue is None:
                    self.assertTrue(report.clean)
                    self.assertEqual(report.runs[0].integrity_issues, ())
                else:
                    self.assertFalse(report.clean)
                    self.assertIn(
                        issue,
                        report.runs[0].integrity_issues,
                    )
                projection = json.dumps(
                    report.to_mapping(),
                    sort_keys=True,
                )
                for marker in _PRIVATE_MARKERS:
                    self.assertNotIn(marker, projection)

    def test_comparison_publication_class_one_exception_is_v2_only(
        self,
    ) -> None:
        for origin in ("ordinary", "comparison_v1"):
            with (
                self.subTest(origin=origin),
                tempfile.TemporaryDirectory() as temporary,
            ):
                database = Path(temporary) / "state.sqlite3"
                fixture_binding = self._comparison_binding_payload(
                    schema_version=2
                )
                binding = fixture_binding["binding"]
                self.assertIsInstance(binding, dict)
                assert isinstance(binding, dict)
                store = self._create_run(
                    database,
                    run_id="run-comparison",
                    permission_class=PermissionClass.READ_ONLY,
                    context_digest=str(binding["context_digest"]),
                )
                if origin == "comparison_v1":
                    legacy_binding = self._comparison_binding_payload()
                    store.append_event(
                        "run-comparison",
                        "comparison_trial_binding",
                        legacy_binding,
                        occurred_at=105.0,
                    )
                    store.append_event(
                        "run-comparison",
                        "billing_assessment",
                        self._comparison_billing_payload(),
                        occurred_at=110.0,
                    )
                store.append_event(
                    "run-comparison",
                    "status",
                    {"phase": "runner_execution"},
                    status=RunStatus.RUNNING,
                    occurred_at=111.0,
                )
                store.append_event(
                    "run-comparison",
                    "execution_accounting",
                    {"incremental_api_charge": "none"},
                    occurred_at=112.0,
                )
                publication, pre_effect, action_receipt = (
                    self._comparison_publication_chain(fixture_binding)
                )
                store.append_event(
                    "run-comparison",
                    "authorization_shadow_decision",
                    publication,
                    occurred_at=113.0,
                )
                store.append_event(
                    "run-comparison",
                    "comparison_review_artifact_intent",
                    pre_effect,
                    occurred_at=114.0,
                )
                store.append_event(
                    "run-comparison",
                    COMPARISON_REVIEW_ARTIFACT_ACTION_RECEIPT_EVENT_TYPE,
                    action_receipt,
                    occurred_at=115.0,
                )
                store.append_event(
                    "run-comparison",
                    "status",
                    {"phase": "complete"},
                    status=RunStatus.SUCCEEDED,
                    occurred_at=116.0,
                )
                store.close()

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertFalse(report.clean)
                run = report.runs[0]
                self.assertIsNone(
                    run.authorization_action_receipt_coverage
                )
                self.assertIn(
                    "comparison_publication_receipt_binding_invalid",
                    run.integrity_issues,
                )
                publication_event = next(
                    event
                    for event in run.events
                    if event.action_scope == PUBLICATION_SCOPE
                )
                self.assertFalse(
                    publication_event.recomputed_authority_ceiling_parity
                )
                self.assertIn(
                    "requested_permission_class_run_mismatch",
                    publication_event.integrity_issues,
                )
                self.assertIn(
                    "derived_class_exceeds_run_authority",
                    publication_event.integrity_issues,
                )

    def test_duplicate_comparison_billing_is_fixed_and_value_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            binding_payload = self._comparison_binding_payload()
            binding = binding_payload["binding"]
            self.assertIsInstance(binding, dict)
            assert isinstance(binding, dict)
            store = self._create_run(
                database,
                run_id="run-comparison",
                permission_class=PermissionClass.READ_ONLY,
                context_digest=str(binding["context_digest"]),
            )
            store.append_event(
                "run-comparison",
                "comparison_trial_binding",
                binding_payload,
                occurred_at=105.0,
            )
            store.append_event(
                "run-comparison",
                "authorization_shadow_decision",
                self._comparison_shadow_payload(
                    ADMISSION_SCOPE,
                    binding_payload,
                ),
                occurred_at=110.0,
            )
            store.append_event(
                "run-comparison",
                "billing_assessment",
                self._comparison_billing_payload(),
                occurred_at=110.5,
            )
            store.append_event(
                "run-comparison",
                "status",
                {"phase": "runner_execution"},
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-comparison",
                "authorization_shadow_decision",
                self._comparison_shadow_payload(
                    DISPATCH_SCOPE,
                    binding_payload,
                ),
                occurred_at=112.0,
            )
            store.append_event(
                "run-comparison",
                "comparison_review_artifact_intent",
                {},
                occurred_at=112.5,
            )
            store.append_event(
                "run-comparison",
                "execution_accounting",
                {"incremental_api_charge": "none"},
                occurred_at=113.0,
            )
            store.append_event(
                "run-comparison",
                "status",
                {"phase": "complete"},
                status=RunStatus.SUCCEEDED,
                occurred_at=114.0,
            )
            store.close()

            private_key = "private-duplicate-billing-marker"
            private_value = "private-duplicate-billing-value"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    """
                    DROP TRIGGER run_events_no_update;
                    DROP TRIGGER run_events_no_delete;
                    """
                )
                connection.execute(
                    """
                    INSERT INTO run_events (
                        event_id, run_id, event_type, status,
                        payload_json, occurred_at
                    ) VALUES (?, ?, 'billing_assessment', NULL, ?, ?)
                    """,
                    (
                        "duplicate-comparison-billing",
                        "run-comparison",
                        json.dumps({private_key: private_value}),
                        114.5,
                    ),
                )
                connection.executescript(
                    """
                    CREATE TRIGGER run_events_no_update
                    BEFORE UPDATE ON run_events BEGIN
                        SELECT RAISE(ABORT, 'run events are append-only');
                    END;
                    CREATE TRIGGER run_events_no_delete
                    BEFORE DELETE ON run_events BEGIN
                        SELECT RAISE(ABORT, 'run events are append-only');
                    END;
                    """
                )
                connection.commit()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            self.assertEqual(report.inspected_run_count, 1)
            self.assertEqual(
                report.runs[0].integrity_issues,
                ("comparison_billing_duplicate",),
            )
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            self.assertNotIn(private_key, projection)
            self.assertNotIn(private_value, projection)

    def test_comparison_binding_tampering_fails_closed_without_private_leaks(
        self,
    ) -> None:
        cases = (
            ("missing", "comparison_binding_missing", "run"),
            ("duplicate", "comparison_binding_duplicate", "run"),
            ("digest", "comparison_binding_digest_mismatch", "run"),
            ("order", "comparison_binding_order_invalid", "run"),
            ("record", "comparison_binding_record_mismatch", "run"),
            ("request", "comparison_request_binding_mismatch", "event"),
            ("billing_digest", "comparison_billing_digest_mismatch", "run"),
            ("billing_binding", "comparison_billing_binding_mismatch", "run"),
            (
                "billing_environment",
                "comparison_billing_environment_mismatch",
                "event",
            ),
            (
                "billing_window",
                "comparison_billing_evidence_window_mismatch",
                "event",
            ),
        )
        for case, expected_issue, issue_location in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                database = Path(temporary) / "state.sqlite3"
                binding_payload = self._comparison_binding_payload()
                if case == "digest":
                    binding_payload["binding_digest"] = "sha256:" + "0" * 64
                binding = binding_payload["binding"]
                self.assertIsInstance(binding, dict)
                assert isinstance(binding, dict)
                run_context_digest = str(binding["context_digest"])
                if case == "record":
                    run_context_digest = canonical_digest(
                        {"context": "different-run-record"}
                    )
                store = self._create_run(
                    database,
                    run_id="run-comparison",
                    permission_class=PermissionClass.READ_ONLY,
                    context_digest=run_context_digest,
                )
                if case not in {"missing", "order"}:
                    store.append_event(
                        "run-comparison",
                        "comparison_trial_binding",
                        binding_payload,
                        occurred_at=105.0,
                    )
                    if case == "duplicate":
                        store.append_event(
                            "run-comparison",
                            "comparison_trial_binding",
                            binding_payload,
                            occurred_at=106.0,
                        )
                admission_payload = self._comparison_shadow_payload(
                    ADMISSION_SCOPE,
                    binding_payload,
                )
                if case in {"billing_environment", "billing_window"}:
                    request = admission_payload["request"]
                    self.assertIsInstance(request, dict)
                    assert isinstance(request, dict)
                    environment = request["environment"]
                    evidence = request["evidence"]
                    self.assertIsInstance(environment, dict)
                    self.assertIsInstance(evidence, list)
                    assert isinstance(environment, dict)
                    assert isinstance(evidence, list)
                    environment_evidence = next(
                        item
                        for item in evidence
                        if isinstance(item, dict)
                        and item.get("attribute") == "environment"
                    )
                    if case == "billing_environment":
                        environment["capacity_state"] = "available"
                        environment_evidence["value_digest"] = canonical_digest(
                            environment
                        )
                    else:
                        environment_evidence["expires_at"] = 231.0
                    self._resign_payload(admission_payload)
                store.append_event(
                    "run-comparison",
                    "authorization_shadow_decision",
                    admission_payload,
                    occurred_at=110.0,
                )
                billing_payload = self._comparison_billing_payload()
                if case == "billing_digest":
                    billing_payload["assessment_digest"] = "sha256:" + "0" * 64
                elif case == "billing_binding":
                    billing_payload["confidence"] = "low"
                    billing_body = dict(billing_payload)
                    del billing_body["assessment_digest"]
                    billing_payload["assessment_digest"] = canonical_digest(
                        billing_body
                    )
                store.append_event(
                    "run-comparison",
                    "billing_assessment",
                    billing_payload,
                    occurred_at=110.5,
                )
                store.append_event(
                    "run-comparison",
                    "status",
                    {"phase": "runner_execution"},
                    status=RunStatus.RUNNING,
                    occurred_at=111.0,
                )
                if case == "order":
                    store.append_event(
                        "run-comparison",
                        "comparison_trial_binding",
                        binding_payload,
                        occurred_at=111.5,
                    )
                dispatch_payload = self._comparison_shadow_payload(
                    DISPATCH_SCOPE,
                    binding_payload,
                )
                if case == "request":
                    request = dispatch_payload["request"]
                    self.assertIsInstance(request, dict)
                    assert isinstance(request, dict)
                    action = request["action"]
                    evidence = request["evidence"]
                    self.assertIsInstance(action, dict)
                    self.assertIsInstance(evidence, list)
                    assert isinstance(action, dict)
                    assert isinstance(evidence, list)
                    action["parameters_digest"] = canonical_digest(
                        {"parameters": "private-comparison-request-marker"}
                    )
                    action_evidence = next(
                        item
                        for item in evidence
                        if isinstance(item, dict)
                        and item.get("attribute") == "action"
                    )
                    action_evidence["value_digest"] = canonical_digest(action)
                    self._resign_payload(dispatch_payload)
                store.append_event(
                    "run-comparison",
                    "authorization_shadow_decision",
                    dispatch_payload,
                    occurred_at=112.0,
                )
                store.append_event(
                    "run-comparison",
                    "comparison_review_artifact_intent",
                    {},
                    occurred_at=112.5,
                )
                store.append_event(
                    "run-comparison",
                    "execution_accounting",
                    {"incremental_api_charge": "none"},
                    occurred_at=113.0,
                )
                store.append_event(
                    "run-comparison",
                    "status",
                    {"phase": "complete"},
                    status=RunStatus.SUCCEEDED,
                    occurred_at=114.0,
                )
                store.close()

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertFalse(report.clean)
                run = report.runs[0]
                if issue_location == "run":
                    self.assertIn(expected_issue, run.integrity_issues)
                else:
                    self.assertTrue(
                        any(
                            expected_issue in event.integrity_issues
                            for event in run.events
                        )
                    )
                self.assertIn(PUBLICATION_SCOPE, run.missing_scopes)
                self.assertTrue(
                    all(
                        issue.replace("_", "").isalnum()
                        and issue == issue.lower()
                        for issue in run.integrity_issues
                    )
                )
                projection = json.dumps(report.to_mapping(), sort_keys=True)
                for marker in _PRIVATE_MARKERS:
                    self.assertNotIn(marker, projection)

    def test_tampering_and_legacy_disagreement_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            payload = self._shadow_payload(
                ADMISSION_SCOPE,
                effect="deny",
                legacy_executable=True,
                reported_parity=True,
            )
            payload["request_digest"] = "sha256:" + ("0" * 64)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                payload,
                occurred_at=110.0,
            )
            store.close()

            report = inspect_authorization_shadows(
                database,
                mismatches_only=True,
                now=120.0,
            )

            self.assertFalse(report.clean)
            self.assertEqual(report.parity_mismatch_count, 1)
            self.assertEqual(len(report.runs), 1)
            event = report.runs[0].events[0]
            self.assertFalse(event.recomputed_execution_parity)
            self.assertFalse(event.request_digest_valid)
            self.assertIn("request_digest_mismatch", event.integrity_issues)
            self.assertIn("execution_parity_mismatch", event.integrity_issues)
            self.assertIn(
                "decision_request_digest_mismatch", event.integrity_issues
            )

    def test_v2_scope_intent_and_requested_class_tampering_are_detected(
        self,
    ) -> None:
        cases: list[tuple[str, tuple[str, ...]]] = []

        swapped_scope = self._shadow_payload(ADMISSION_SCOPE)
        swapped_scope["action_scope"] = DISPATCH_SCOPE
        cases.append(
            (
                json.dumps(swapped_scope),
                (
                    "boundary_flow_state_mismatch",
                    "boundary_request_identifier_mismatch",
                    "boundary_resource_identifier_mismatch",
                ),
            )
        )

        intent_tampered = self._shadow_payload(ADMISSION_SCOPE)
        intent = intent_tampered["task_authorization_intent"]
        self.assertIsInstance(intent, dict)
        assert isinstance(intent, dict)
        action = intent["action"]
        self.assertIsInstance(action, dict)
        assert isinstance(action, dict)
        action["operation"] = "artifact.different_operation"
        intent_tampered["intent_digest"] = canonical_digest(intent)
        cases.append(
            (
                json.dumps(intent_tampered),
                ("task_intent_request_projection_mismatch",),
            )
        )

        class_tampered = self._shadow_payload(ADMISSION_SCOPE)
        class_tampered["requested_permission_class"] = 0
        cases.append(
            (
                json.dumps(class_tampered),
                ("requested_permission_class_run_mismatch",),
            )
        )

        source_tampered = self._shadow_payload(PUBLICATION_SCOPE)
        source_tampered["intent_source"] = "task_contract"
        cases.append(
            (
                json.dumps(source_tampered),
                ("task_intent_source_invalid",),
            )
        )

        derived_tampered = self._shadow_payload(ADMISSION_SCOPE)
        request = derived_tampered["request"]
        intent = derived_tampered["task_authorization_intent"]
        self.assertIsInstance(request, dict)
        self.assertIsInstance(intent, dict)
        assert isinstance(request, dict)
        assert isinstance(intent, dict)
        request_consequences = request["consequences"]
        intent_consequences = intent["consequences"]
        evidence = request["evidence"]
        assert isinstance(request_consequences, dict)
        assert isinstance(intent_consequences, dict)
        assert isinstance(evidence, list)
        request_consequences["confidentiality"] = "high"
        intent_consequences["confidentiality"] = "high"
        derived_tampered["intent_digest"] = canonical_digest(intent)
        consequence_evidence = next(
            item
            for item in evidence
            if isinstance(item, dict) and item.get("attribute") == "consequences"
        )
        consequence_evidence["value_digest"] = canonical_digest(
            request_consequences
        )
        self._resign_payload(derived_tampered)
        cases.append(
            (
                json.dumps(derived_tampered),
                (
                    "authority_ceiling_parity_mismatch",
                    "derived_class_exceeds_run_authority",
                    "derived_permission_class_mismatch",
                ),
            )
        )

        for index, (encoded, expected_issues) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "state.sqlite3"
                store = self._create_run(database)
                store.append_event(
                    "run-inspect",
                    "authorization_shadow_decision",
                    json.loads(encoded),
                    occurred_at=110.0,
                )
                store.close()

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertFalse(report.clean)
                issues = report.runs[0].events[0].integrity_issues
                for expected in expected_issues:
                    self.assertIn(expected, issues)

    def test_legacy_executable_is_recomputed_from_the_run_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            payload = self._shadow_payload(
                ADMISSION_SCOPE,
                effect="deny",
                legacy_executable=False,
                reported_parity=True,
            )
            decision = payload["decision"]
            self.assertIsInstance(decision, dict)
            assert isinstance(decision, dict)
            decision["effect"] = "deny"
            self._resign_payload(payload)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                payload,
                occurred_at=110.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            event = report.runs[0].events[0]
            self.assertFalse(event.legacy_executable)
            self.assertTrue(event.recomputed_legacy_executable)
            self.assertFalse(event.recomputed_execution_parity)
            self.assertIn(
                "legacy_executable_run_mismatch", event.integrity_issues
            )
            self.assertIn("execution_parity_mismatch", event.integrity_issues)

    def test_evidence_must_be_authenticated_and_fresh_at_evaluation(self) -> None:
        def unauthenticated(payload: dict[str, object]) -> None:
            request = payload["request"]
            assert isinstance(request, dict)
            evidence = request["evidence"]
            assert isinstance(evidence, list)
            assert isinstance(evidence[0], dict)
            evidence[0]["authenticated"] = False

        def stale(payload: dict[str, object]) -> None:
            request = payload["request"]
            assert isinstance(request, dict)
            evidence = request["evidence"]
            assert isinstance(evidence, list)
            assert isinstance(evidence[0], dict)
            evidence[0]["expires_at"] = 105.0

        def future(payload: dict[str, object]) -> None:
            request = payload["request"]
            assert isinstance(request, dict)
            evidence = request["evidence"]
            assert isinstance(evidence, list)
            assert isinstance(evidence[0], dict)
            evidence[0]["observed_at"] = 115.0

        for mutator, expected_issue in (
            (unauthenticated, "evidence_unauthenticated"),
            (stale, "evidence_stale_at_evaluation"),
            (future, "evidence_from_future_at_evaluation"),
        ):
            with (
                self.subTest(expected_issue=expected_issue),
                tempfile.TemporaryDirectory() as temporary,
            ):
                database = Path(temporary) / "state.sqlite3"
                store = self._create_run(database)
                payload = self._shadow_payload(ADMISSION_SCOPE)
                mutator(payload)
                self._resign_payload(payload)
                store.append_event(
                    "run-inspect",
                    "authorization_shadow_decision",
                    payload,
                    occurred_at=110.0,
                )
                store.close()

                report = inspect_authorization_shadows(database, now=120.0)

                self.assertFalse(report.clean)
                self.assertIn(
                    expected_issue,
                    report.runs[0].events[0].integrity_issues,
                )

    def test_expected_boundary_coverage_uses_status_and_artifact_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE),
                occurred_at=110.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.SUCCEEDED,
                occurred_at=112.0,
            )
            store.append_artifact(
                ArtifactRecord(
                    artifact_id="artifact-inspect",
                    run_id="run-inspect",
                    kind="candidate",
                    path="artifacts/candidate.json",
                    sha256="b" * 64,
                    media_type="application/json",
                    size_bytes=10,
                    created_at=113.0,
                )
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            self.assertEqual(report.coverage_gap_count, 2)
            self.assertEqual(
                report.runs[0].missing_scopes,
                (PUBLICATION_SCOPE, DISPATCH_SCOPE),
            )

    def test_boundary_order_is_checked_against_controller_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.append_event(
                "run-inspect",
                "billing_assessment",
                {"route": "mock"},
                occurred_at=109.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(ADMISSION_SCOPE),
                occurred_at=110.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.RUNNING,
                occurred_at=111.0,
            )
            store.append_event(
                "run-inspect",
                "runner_event_observed",
                {"ordinal": 1},
                occurred_at=112.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(DISPATCH_SCOPE),
                occurred_at=113.0,
            )
            store.append_event(
                "run-inspect",
                "authorization_shadow_decision",
                self._shadow_payload(PUBLICATION_SCOPE),
                occurred_at=114.0,
            )
            store.append_event(
                "run-inspect",
                "execution_accounting",
                {"incremental_api_charge": "none"},
                occurred_at=115.0,
            )
            store.append_event(
                "run-inspect",
                "status",
                status=RunStatus.SUCCEEDED,
                occurred_at=116.0,
            )
            store.close()

            report = inspect_authorization_shadows(database, now=120.0)

            self.assertFalse(report.clean)
            self.assertEqual(
                report.runs[0].integrity_issues,
                (
                    "admission_boundary_order_invalid",
                    "dispatch_boundary_order_invalid",
                    "publication_boundary_order_invalid",
                ),
            )

    def test_malformed_event_and_database_return_only_fixed_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite3"
            store = self._create_run(database)
            store.close()
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """
                    INSERT INTO run_events (
                        event_id, run_id, event_type, status, payload_json, occurred_at
                    ) VALUES (?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        "malformed-event",
                        "run-inspect",
                        "authorization_shadow_decision",
                        '{"private-reason-marker":',
                        110.0,
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            report = inspect_authorization_shadows(database, now=120.0)
            projection = json.dumps(report.to_mapping(), sort_keys=True)
            self.assertIn("payload_json_invalid", projection)
            self.assertNotIn("private-reason-marker", projection)

            malformed_database = Path(temporary) / "malformed.sqlite3"
            malformed_database.write_text("private-database-marker", encoding="utf-8")
            with self.assertRaises(ConfigurationError) as caught:
                inspect_authorization_shadows(malformed_database, now=120.0)
            self.assertNotIn("private-database-marker", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
