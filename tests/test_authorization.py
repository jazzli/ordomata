from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import unittest

from ordomata.approval import ApprovalPolicy
from ordomata.authorization import (
    ActionAttributes,
    ActionReceipt,
    ActionVerb,
    ApprovalGrant,
    ApprovalRequirement,
    AttributeEvidence,
    AuthorizationEffect,
    AuthorizationRequest,
    BlastRadius,
    CircuitState,
    ClaimSource,
    ConsequenceVector,
    DecisionReason,
    DescriptiveClaim,
    EnvironmentAttributes,
    EvidenceSource,
    ImpactLevel,
    IsolationState,
    NetworkState,
    ObligationResult,
    PolicyBundle,
    Reach,
    ReceiptOutcome,
    ResourceAttributes,
    Role,
    ShadowAuthorizationEvaluator,
    SubjectAttributes,
    canonical_digest,
    derive_permission_class,
)
from ordomata.models import (
    BillingRoute,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
)


NOW = 1_000.0


def _low_consequences() -> ConsequenceVector:
    return ConsequenceVector(
        confidentiality=ImpactLevel.LOW,
        integrity=ImpactLevel.LOW,
        availability=ImpactLevel.LOW,
        reach=Reach.LOCAL,
        destructive=False,
        reversible=True,
        sensitivity=ImpactLevel.LOW,
        blast_radius=BlastRadius.SINGLE_RESOURCE,
    )


def _request(
    *,
    request_id: str = "request-1",
    verb: ActionVerb = ActionVerb.READ,
    consequences: ConsequenceVector | None = None,
    claims: tuple[DescriptiveClaim, ...] = (),
) -> AuthorizationRequest:
    request = AuthorizationRequest(
        request_id=request_id,
        subject=SubjectAttributes(
            principal_id="agent:test",
            controller_id="controller:test",
            role=Role.IMPLEMENTER,
            role_version="1",
            profile_id="profile:test",
            runner_id="mock",
            session_id="session:test",
        ),
        action=ActionAttributes(
            verb=verb,
            operation="repository.inspect" if verb is ActionVerb.READ else "repository.patch",
            parameters_digest=canonical_digest({"path": "src"}),
            intended_effect="inspect files" if verb is ActionVerb.READ else "write isolated draft",
            descriptive_claims=claims,
        ),
        resource=ResourceAttributes(
            resource_type="isolated_worktree",
            identifier="repo:test/worktree:attempt-1",
            version="git:abc123",
            owner="operator:local",
            trust_boundary="local_worker_cell",
            protected=False,
            sensitivity=ImpactLevel.LOW,
            repository_id="repo:test",
        ),
        environment=EnvironmentAttributes(
            evaluated_at=NOW,
            isolation_state=IsolationState.VERIFIED,
            network_state=NetworkState.DISABLED,
            billing_route=BillingRoute.MOCK,
            capacity_state=CapacityState.NOT_APPLICABLE,
            paid_continuation_protection=(
                PaidContinuationProtection.NOT_APPLICABLE
            ),
            circuit_state=CircuitState.CLOSED,
            flow_state="admitted",
        ),
        consequences=consequences or _low_consequences(),
    )
    return _bind_evidence(request)


def _bind_evidence(request: AuthorizationRequest) -> AuthorizationRequest:
    source_by_attribute = {
        "subject": EvidenceSource.CONTROLLER,
        "action": EvidenceSource.LOCAL_REGISTRY,
        "resource": EvidenceSource.LOCAL_REGISTRY,
        "environment": EvidenceSource.VERIFIED_ATTESTATION,
        "consequences": EvidenceSource.CONTROLLER,
    }
    evidence = tuple(
        AttributeEvidence.bind(
            evidence_id=f"evidence:{attribute}",
            attribute=attribute,
            value=request.attribute_value(attribute),
            source=source,
            source_id=f"test:{source.value}",
            observed_at=NOW - 1,
            expires_at=NOW + 120,
            authenticated=True,
        )
        for attribute, source in source_by_attribute.items()
    )
    return replace(request, evidence=evidence)


class ShadowAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyBundle.current_stage(issued_at=NOW - 10)
        self.evaluator = ShadowAuthorizationEvaluator()

    def test_shadow_effect_matches_legacy_class_zero_and_one_ceiling(self) -> None:
        cases = (
            (_request(verb=ActionVerb.READ), PermissionClass.READ_ONLY),
            (_request(verb=ActionVerb.MODIFY), PermissionClass.LOCAL_DRAFT),
            (
                _request(
                    verb=ActionVerb.MODIFY,
                    consequences=replace(_low_consequences(), reach=Reach.SHARED),
                ),
                PermissionClass.REVERSIBLE_INTERNAL_WRITE,
            ),
            (
                _request(
                    verb=ActionVerb.READ,
                    consequences=replace(_low_consequences(), reach=Reach.EXTERNAL),
                ),
                PermissionClass.EXTERNAL_CONSEQUENTIAL,
            ),
        )
        legacy = ApprovalPolicy()
        for request, expected_class in cases:
            with self.subTest(expected_class=expected_class):
                decision = self.evaluator.evaluate(request, self.policy)
                self.assertEqual(decision.derived_permission_class, expected_class)
                self.assertEqual(
                    decision.effect is AuthorizationEffect.PERMIT,
                    legacy.classify(expected_class).executable_now,
                )
        self.assertIs(cases[2][0].consequences.reach, Reach.SHARED)

    def test_missing_stale_and_contradictory_evidence_fail_closed(self) -> None:
        request = _request()
        missing = replace(
            request,
            evidence=tuple(item for item in request.evidence if item.attribute != "action"),
        )
        missing_decision = self.evaluator.evaluate(missing, self.policy)
        self.assertIs(missing_decision.effect, AuthorizationEffect.INDETERMINATE)
        self.assertIn(DecisionReason.EVIDENCE_MISSING, missing_decision.reason_codes)

        stale_records = tuple(
            replace(item, observed_at=NOW - 500, expires_at=NOW - 1)
            if item.attribute == "action"
            else item
            for item in request.evidence
        )
        stale_decision = self.evaluator.evaluate(
            replace(request, evidence=stale_records), self.policy
        )
        self.assertIs(stale_decision.effect, AuthorizationEffect.INDETERMINATE)
        self.assertIn(DecisionReason.EVIDENCE_STALE, stale_decision.reason_codes)

        resource_record = next(
            item for item in request.evidence if item.attribute == "resource"
        )
        conflict = replace(
            resource_record,
            evidence_id="evidence:resource:conflict",
            value_digest=canonical_digest({"different": "resource"}),
        )
        contradictory = replace(request, evidence=request.evidence + (conflict,))
        contradictory_decision = self.evaluator.evaluate(contradictory, self.policy)
        self.assertIs(
            contradictory_decision.effect, AuthorizationEffect.INDETERMINATE
        )
        self.assertIn(
            DecisionReason.EVIDENCE_CONTRADICTORY,
            contradictory_decision.reason_codes,
        )

    def test_unknown_or_open_runtime_environment_does_not_permit(self) -> None:
        request = _request(verb=ActionVerb.MODIFY)
        unknown_network = _bind_evidence(
            replace(
                request,
                environment=replace(
                    request.environment,
                    network_state=NetworkState.UNKNOWN,
                ),
                evidence=(),
            )
        )
        network_decision = self.evaluator.evaluate(unknown_network, self.policy)
        self.assertIs(network_decision.effect, AuthorizationEffect.INDETERMINATE)
        self.assertIn(DecisionReason.NETWORK_UNKNOWN, network_decision.reason_codes)

        unknown_circuit = _bind_evidence(
            replace(
                request,
                environment=replace(
                    request.environment,
                    circuit_state=CircuitState.UNKNOWN,
                ),
                evidence=(),
            )
        )
        circuit_decision = self.evaluator.evaluate(unknown_circuit, self.policy)
        self.assertIs(circuit_decision.effect, AuthorizationEffect.INDETERMINATE)
        self.assertIn(DecisionReason.CIRCUIT_UNKNOWN, circuit_decision.reason_codes)

        open_network = _bind_evidence(
            replace(
                request,
                environment=replace(
                    request.environment,
                    network_state=NetworkState.OPEN,
                ),
                evidence=(),
            )
        )
        open_decision = self.evaluator.evaluate(open_network, self.policy)
        self.assertIs(open_decision.effect, AuthorizationEffect.DENY)
        self.assertIn(DecisionReason.NETWORK_PROHIBITED, open_decision.reason_codes)

    def test_known_mandatory_denies_override_unknown_or_missing_evidence(self) -> None:
        high_impact = _request(
            verb=ActionVerb.READ,
            consequences=replace(
                _low_consequences(), confidentiality=ImpactLevel.HIGH
            ),
        )
        high_impact = replace(
            high_impact,
            environment=replace(
                high_impact.environment,
                circuit_state=CircuitState.UNKNOWN,
            ),
            evidence=(),
        )
        class_decision = self.evaluator.evaluate(high_impact, self.policy)
        self.assertIs(class_decision.effect, AuthorizationEffect.DENY)
        self.assertEqual(
            class_decision.reason_codes, (DecisionReason.CLASS_DISABLED,)
        )

        paid_route = _request(verb=ActionVerb.MODIFY)
        paid_route = replace(
            paid_route,
            environment=replace(
                paid_route.environment,
                circuit_state=CircuitState.UNKNOWN,
                billing_route=BillingRoute.SUBSCRIPTION_OVERAGE,
            ),
            evidence=(),
        )
        billing_decision = self.evaluator.evaluate(paid_route, self.policy)
        self.assertIs(billing_decision.effect, AuthorizationEffect.DENY)
        self.assertEqual(
            billing_decision.reason_codes, (DecisionReason.BILLING_PROHIBITED,)
        )

    def test_current_stage_policy_denies_unregistered_scope(self) -> None:
        base = _request(verb=ActionVerb.MODIFY)
        cases = (
            (
                replace(
                    base,
                    action=replace(base.action, operation="credential.dump"),
                ),
                DecisionReason.OPERATION_NOT_ALLOWED,
            ),
            (
                replace(
                    base,
                    resource=replace(
                        base.resource,
                        resource_type="primary_repository",
                    ),
                ),
                DecisionReason.RESOURCE_NOT_ALLOWED,
            ),
            (
                replace(
                    base,
                    environment=replace(base.environment, flow_state="cancelled"),
                ),
                DecisionReason.FLOW_STATE_NOT_ALLOWED,
            ),
            (
                replace(
                    base,
                    environment=replace(
                        base.environment,
                        network_state=NetworkState.RESTRICTED,
                    ),
                ),
                DecisionReason.NETWORK_PROHIBITED,
            ),
            (
                replace(
                    base,
                    environment=replace(
                        base.environment,
                        isolation_state=IsolationState.ABSENT,
                    ),
                ),
                DecisionReason.ISOLATION_REQUIRED,
            ),
        )
        for request, reason in cases:
            with self.subTest(reason=reason):
                decision = self.evaluator.evaluate(request, self.policy)
                self.assertIs(decision.effect, AuthorizationEffect.DENY)
                self.assertEqual(decision.reason_codes, (reason,))

    def test_mcp_or_provider_claims_never_grant_authority(self) -> None:
        request = _request()
        subject = next(item for item in request.evidence if item.attribute == "subject")
        untrusted = replace(
            subject,
            source=EvidenceSource.PROVIDER_CLAIM,
            source_id="provider:reported",
        )
        request = replace(
            request,
            evidence=tuple(
                untrusted if item.attribute == "subject" else item
                for item in request.evidence
            ),
        )
        decision = self.evaluator.evaluate(request, self.policy)
        self.assertIs(decision.effect, AuthorizationEffect.INDETERMINATE)
        self.assertIn(DecisionReason.UNTRUSTED_CLAIM_ONLY, decision.reason_codes)

    def test_high_impact_read_derives_class_three_despite_read_only_hint(self) -> None:
        request = _request(
            verb=ActionVerb.READ,
            claims=(DescriptiveClaim(ClaimSource.MCP, "readOnlyHint", "true"),),
            consequences=replace(
                _low_consequences(),
                confidentiality=ImpactLevel.HIGH,
                blast_radius=BlastRadius.BROAD,
            ),
        )
        self.assertEqual(
            derive_permission_class(request), PermissionClass.EXTERNAL_CONSEQUENTIAL
        )
        decision = self.evaluator.evaluate(request, self.policy)
        self.assertIs(decision.effect, AuthorizationEffect.DENY)
        self.assertIn(DecisionReason.CLASS_DISABLED, decision.reason_codes)

    def test_defer_is_only_for_a_satisfiable_digest_bound_approval(self) -> None:
        requirement = ApprovalRequirement(
            requirement_id="operator-approve-read",
            verbs=(ActionVerb.READ,),
            permission_classes=(PermissionClass.READ_ONLY,),
            allowed_approver_ids=("operator:local",),
        )
        policy = PolicyBundle.current_stage(
            issued_at=NOW - 10,
            approval_requirements=(requirement,),
        )
        request = _request()
        deferred = self.evaluator.evaluate(request, policy)
        self.assertIs(deferred.effect, AuthorizationEffect.DEFER)
        self.assertIn(DecisionReason.APPROVAL_REQUIRED, deferred.reason_codes)
        self.assertEqual(deferred.obligations[0].value, requirement.requirement_id)

        approval = ApprovalGrant.for_request(
            approval_id="approval-1",
            requirement_id=requirement.requirement_id,
            approver_id="operator:local",
            request=request,
            policy=policy,
            issued_at=NOW - 0.5,
            expires_at=NOW + 60,
        )
        approved = replace(
            request,
            environment=replace(request.environment, approval_grants=(approval,)),
            evidence=(),
        )
        approved = _bind_evidence(approved)
        self.assertIs(
            self.evaluator.evaluate(approved, policy).effect,
            AuthorizationEffect.PERMIT,
        )

        high_impact = _request(
            consequences=replace(
                _low_consequences(), confidentiality=ImpactLevel.HIGH
            )
        )
        self.assertIs(
            self.evaluator.evaluate(high_impact, policy).effect,
            AuthorizationEffect.DENY,
        )

    def test_action_specific_approval_cannot_be_replayed_or_self_approved(self) -> None:
        requirement = ApprovalRequirement(
            requirement_id="operator-approve-read",
            verbs=(ActionVerb.READ,),
            permission_classes=(PermissionClass.READ_ONLY,),
            allowed_approver_ids=("operator:local",),
        )
        policy = PolicyBundle.current_stage(
            issued_at=NOW - 10,
            approval_requirements=(requirement,),
        )
        first = _request(request_id="request:first")
        grant = ApprovalGrant.for_request(
            approval_id="approval:first",
            requirement_id=requirement.requirement_id,
            approver_id="operator:local",
            request=first,
            policy=policy,
            issued_at=NOW - 1,
            expires_at=NOW + 30,
        )
        second = _request(request_id="request:second")
        second = _bind_evidence(
            replace(
                second,
                environment=replace(
                    second.environment,
                    approval_grants=(grant,),
                ),
                evidence=(),
            )
        )
        replay = self.evaluator.evaluate(second, policy)
        self.assertIs(replay.effect, AuthorizationEffect.INDETERMINATE)
        self.assertIn(DecisionReason.APPROVAL_INVALID, replay.reason_codes)

        self_approval = ApprovalGrant.for_request(
            approval_id="approval:self",
            requirement_id=requirement.requirement_id,
            approver_id=first.subject.principal_id,
            request=first,
            policy=policy,
            issued_at=NOW - 1,
            expires_at=NOW + 30,
        )
        self_approved = _bind_evidence(
            replace(
                first,
                environment=replace(
                    first.environment,
                    approval_grants=(self_approval,),
                ),
                evidence=(),
            )
        )
        self.assertIs(
            self.evaluator.evaluate(self_approved, policy).effect,
            AuthorizationEffect.INDETERMINATE,
        )

        with self.assertRaisesRegex(ValueError, "identifiers must be unique"):
            replace(
                first.environment,
                approval_grants=(grant, grant),
            )

    def test_action_receipt_is_separate_from_immutable_pre_action_decision(self) -> None:
        request = _request()
        decision = self.evaluator.evaluate(request, self.policy)
        self.assertIs(decision.effect, AuthorizationEffect.PERMIT)
        before = decision.digest
        receipt = ActionReceipt.record(
            receipt_id="receipt-1",
            decision=decision,
            request=request,
            executor_id="controller-executor:test",
            started_at=NOW + 1,
            completed_at=NOW + 2,
            outcome=ReceiptOutcome.SUCCEEDED,
            obligation_results=tuple(
                ObligationResult(item.kind, item.value, True)
                for item in decision.obligations
            ),
            result_digest=canonical_digest({"artifact": "candidate"}),
        )
        self.assertEqual(receipt.decision_digest, before)
        self.assertEqual(decision.digest, before)
        self.assertNotIn("outcome", decision.to_canonical())
        self.assertEqual(receipt.outcome, ReceiptOutcome.SUCCEEDED)
        with self.assertRaises(FrozenInstanceError):
            decision.effect = AuthorizationEffect.DENY  # type: ignore[misc]
        with self.assertRaisesRegex(ValueError, "permit is not current"):
            ActionReceipt.record(
                receipt_id="receipt-expired",
                decision=decision,
                request=request,
                executor_id="controller-executor:test",
                started_at=decision.expires_at,
                completed_at=decision.expires_at + 1,
                outcome=ReceiptOutcome.SUCCEEDED,
                obligation_results=tuple(
                    ObligationResult(item.kind, item.value, True)
                    for item in decision.obligations
                ),
            )
        with self.assertRaisesRegex(ValueError, "exact decision obligation"):
            ActionReceipt.record(
                receipt_id="receipt-missing-obligations",
                decision=decision,
                request=request,
                executor_id="controller-executor:test",
                started_at=NOW + 1,
                completed_at=NOW + 2,
                outcome=ReceiptOutcome.SUCCEEDED,
                obligation_results=(),
            )
        with self.assertRaisesRegex(ValueError, "expiry must follow"):
            replace(decision, expires_at=decision.issued_at)

    def test_malformed_typed_attributes_are_rejected_at_construction(self) -> None:
        request = _request()
        with self.assertRaisesRegex(ValueError, "network state"):
            replace(request.environment, network_state="disabled")  # type: ignore[arg-type]

    def test_canonical_digest_is_stable_for_unordered_evidence(self) -> None:
        request = _request()
        reordered = replace(request, evidence=tuple(reversed(request.evidence)))
        self.assertEqual(request.digest, reordered.digest)


if __name__ == "__main__":
    unittest.main()
