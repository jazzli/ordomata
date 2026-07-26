"""Pure shadow authorization types and evaluator for the Phase 1C migration.

This module deliberately has no enforcement integration.  It can describe and
evaluate an exact request, but it cannot execute an action or widen the current
Class 0/1 runtime ceiling.  The legacy permission checks remain authoritative
until a later, separately reviewed migration phase.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any

from .models import (
    BillingRoute,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
)


_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_UNTRUSTED_EVIDENCE_SOURCES: frozenset["EvidenceSource"]


def _canonical_value(value: Any) -> Any:
    """Convert supported immutable values to a JSON-compatible representation."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON does not permit non-finite numbers")
        return value
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, PermissionClass):
        return int(value)
    to_canonical = getattr(value, "to_canonical", None)
    if callable(to_canonical):
        return _canonical_value(to_canonical())
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return {key: _canonical_value(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(child) for child in value]
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return deterministic UTF-8 JSON text for supported authorization values."""

    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_digest(value: Any) -> str:
    """Return a stable SHA-256 digest of :func:`canonical_json`."""

    encoded = canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _require_text(name: str, value: str, *, maximum: int = 4096) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    if "\x00" in value or any(
        ord(character) < 32 and character not in "\t\n\r" for character in value
    ):
        raise ValueError(f"{name} contains unsupported control characters")


def _require_instance(name: str, value: Any, expected: type[Any]) -> None:
    if not isinstance(value, expected):
        raise ValueError(f"{name} must be a {expected.__name__}")


def _require_tuple(name: str, value: Any) -> None:
    if not isinstance(value, tuple):
        raise ValueError(f"{name} must be an immutable tuple")


def _require_timestamp(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite timestamp")
    if not math.isfinite(float(value)) or float(value) < 0:
        raise ValueError(f"{name} must be a finite non-negative timestamp")


def _require_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical sha256 digest")


class AuthorizationEffect(StrEnum):
    PERMIT = "permit"
    DEFER = "defer"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


class ActionVerb(StrEnum):
    READ = "read"
    CREATE = "create"
    MODIFY = "modify"
    EXECUTE = "execute"
    DELETE = "delete"
    SEND = "send"
    APPROVE = "approve"


class Role(StrEnum):
    OPERATOR = "operator"
    CONTROLLER = "controller"
    PLANNER = "planner"
    IMPLEMENTER = "implementer"
    VERIFIER = "verifier"
    REVIEWER = "reviewer"
    RECOVERY = "recovery"


class ImpactLevel(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class Reach(StrEnum):
    LOCAL = "local"
    SHARED = "shared"
    EXTERNAL = "external"


class BlastRadius(StrEnum):
    SINGLE_RESOURCE = "single_resource"
    BOUNDED = "bounded"
    BROAD = "broad"


class IsolationState(StrEnum):
    VERIFIED = "verified"
    NOT_REQUIRED = "not_required"
    UNVERIFIED = "unverified"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class NetworkState(StrEnum):
    DISABLED = "disabled"
    RESTRICTED = "restricted"
    OPEN = "open"
    UNKNOWN = "unknown"


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    UNKNOWN = "unknown"


class ClaimSource(StrEnum):
    MCP = "mcp"
    PROVIDER = "provider"
    MODEL = "model"


class EvidenceSource(StrEnum):
    CONTROLLER = "controller"
    OPERATOR_POLICY = "operator_policy"
    LOCAL_REGISTRY = "local_registry"
    VERIFIED_ATTESTATION = "verified_attestation"
    APPROVAL_AUTHORITY = "approval_authority"
    MCP_CLAIM = "mcp_claim"
    PROVIDER_CLAIM = "provider_claim"
    MODEL_CLAIM = "model_claim"


_UNTRUSTED_EVIDENCE_SOURCES = frozenset(
    {
        EvidenceSource.MCP_CLAIM,
        EvidenceSource.PROVIDER_CLAIM,
        EvidenceSource.MODEL_CLAIM,
    }
)


class DecisionReason(StrEnum):
    CURRENT_STAGE_PERMIT = "current_stage_permit"
    CLASS_DISABLED = "class_disabled"
    ROLE_NOT_ALLOWED = "role_not_allowed"
    VERB_NOT_ALLOWED = "verb_not_allowed"
    OPERATION_NOT_ALLOWED = "operation_not_allowed"
    RESOURCE_NOT_ALLOWED = "resource_not_allowed"
    TRUST_BOUNDARY_NOT_ALLOWED = "trust_boundary_not_allowed"
    FLOW_STATE_NOT_ALLOWED = "flow_state_not_allowed"
    POLICY_NOT_CURRENT = "policy_not_current"
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_STALE = "evidence_stale"
    EVIDENCE_FROM_FUTURE = "evidence_from_future"
    EVIDENCE_UNAUTHENTICATED = "evidence_unauthenticated"
    EVIDENCE_CONTRADICTORY = "evidence_contradictory"
    EVIDENCE_VALUE_MISMATCH = "evidence_value_mismatch"
    EVIDENCE_IDENTIFIER_DUPLICATED = "evidence_identifier_duplicated"
    UNTRUSTED_CLAIM_ONLY = "untrusted_claim_only"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    BILLING_PROHIBITED = "billing_prohibited"
    BILLING_EVIDENCE_UNKNOWN = "billing_evidence_unknown"
    CIRCUIT_OPEN = "circuit_open"
    CIRCUIT_UNKNOWN = "circuit_unknown"
    NETWORK_PROHIBITED = "network_prohibited"
    NETWORK_UNKNOWN = "network_unknown"
    ISOLATION_REQUIRED = "isolation_required"
    ISOLATION_UNKNOWN = "isolation_unknown"


class ObligationKind(StrEnum):
    AUDIT_RECEIPT = "audit_receipt"
    READ_ONLY = "read_only"
    ISOLATED_LOCAL_ONLY = "isolated_local_only"
    APPROVAL = "approval"


class ReceiptOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class DescriptiveClaim:
    """Untrusted MCP, provider, or model metadata retained for provenance."""

    source: ClaimSource
    name: str
    value: str

    def __post_init__(self) -> None:
        _require_instance("claim source", self.source, ClaimSource)
        _require_text("claim name", self.name)
        _require_text("claim value", self.value)

    def to_canonical(self) -> dict[str, Any]:
        return {"name": self.name, "source": self.source.value, "value": self.value}


@dataclass(frozen=True, slots=True)
class SubjectAttributes:
    principal_id: str
    controller_id: str
    role: Role
    role_version: str
    profile_id: str
    runner_id: str
    session_id: str | None = None

    def __post_init__(self) -> None:
        _require_instance("subject role", self.role, Role)
        for name in (
            "principal_id",
            "controller_id",
            "role_version",
            "profile_id",
            "runner_id",
        ):
            _require_text(name, getattr(self, name))
        if self.session_id is not None:
            _require_text("session_id", self.session_id)

    def to_canonical(self) -> dict[str, Any]:
        return {
            "controller_id": self.controller_id,
            "principal_id": self.principal_id,
            "profile_id": self.profile_id,
            "role": self.role.value,
            "role_version": self.role_version,
            "runner_id": self.runner_id,
            "session_id": self.session_id,
        }


@dataclass(frozen=True, slots=True)
class ActionAttributes:
    verb: ActionVerb
    operation: str
    parameters_digest: str
    intended_effect: str
    tool_id: str | None = None
    descriptive_claims: tuple[DescriptiveClaim, ...] = ()

    def __post_init__(self) -> None:
        _require_instance("action verb", self.verb, ActionVerb)
        _require_text("operation", self.operation)
        _require_text("intended_effect", self.intended_effect)
        _require_digest("parameters_digest", self.parameters_digest)
        if self.tool_id is not None:
            _require_text("tool_id", self.tool_id)
        _require_tuple("descriptive claims", self.descriptive_claims)
        if any(
            not isinstance(claim, DescriptiveClaim)
            for claim in self.descriptive_claims
        ):
            raise ValueError("descriptive claims contain an invalid value")

    def to_canonical(self) -> dict[str, Any]:
        claims = sorted(
            (claim.to_canonical() for claim in self.descriptive_claims),
            key=canonical_json,
        )
        return {
            "descriptive_claims": claims,
            "intended_effect": self.intended_effect,
            "operation": self.operation,
            "parameters_digest": self.parameters_digest,
            "tool_id": self.tool_id,
            "verb": self.verb.value,
        }


@dataclass(frozen=True, slots=True)
class ResourceAttributes:
    resource_type: str
    identifier: str
    version: str
    owner: str
    trust_boundary: str
    protected: bool
    sensitivity: ImpactLevel
    repository_id: str | None = None
    content_digest: str | None = None

    def __post_init__(self) -> None:
        _require_instance("resource sensitivity", self.sensitivity, ImpactLevel)
        if not isinstance(self.protected, bool):
            raise ValueError("resource protected must be a boolean")
        for name in ("resource_type", "identifier", "version", "owner", "trust_boundary"):
            _require_text(name, getattr(self, name))
        if self.repository_id is not None:
            _require_text("repository_id", self.repository_id)
        if self.content_digest is not None:
            _require_digest("content_digest", self.content_digest)

    def to_canonical(self) -> dict[str, Any]:
        return {
            "content_digest": self.content_digest,
            "identifier": self.identifier,
            "owner": self.owner,
            "protected": self.protected,
            "repository_id": self.repository_id,
            "resource_type": self.resource_type,
            "sensitivity": self.sensitivity.value,
            "trust_boundary": self.trust_boundary,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    approval_id: str
    requirement_id: str
    approver_id: str
    scope_digest: str
    policy_digest: str
    issued_at: float
    expires_at: float
    approver_role: Role
    source: EvidenceSource
    authenticated: bool

    def __post_init__(self) -> None:
        _require_instance("approver role", self.approver_role, Role)
        _require_instance("approval source", self.source, EvidenceSource)
        if not isinstance(self.authenticated, bool):
            raise ValueError("approval authenticated must be a boolean")
        for name in ("approval_id", "requirement_id", "approver_id"):
            _require_text(name, getattr(self, name))
        _require_digest("scope_digest", self.scope_digest)
        _require_digest("policy_digest", self.policy_digest)
        _require_timestamp("issued_at", self.issued_at)
        _require_timestamp("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("approval expiry must follow approval issuance")

    @classmethod
    def for_request(
        cls,
        *,
        approval_id: str,
        requirement_id: str,
        approver_id: str,
        request: "AuthorizationRequest",
        policy: "PolicyBundle",
        issued_at: float,
        expires_at: float,
        approver_role: Role = Role.OPERATOR,
    ) -> "ApprovalGrant":
        return cls(
            approval_id=approval_id,
            requirement_id=requirement_id,
            approver_id=approver_id,
            scope_digest=request.approval_scope_digest,
            policy_digest=policy.digest,
            issued_at=issued_at,
            expires_at=expires_at,
            approver_role=approver_role,
            source=EvidenceSource.APPROVAL_AUTHORITY,
            authenticated=True,
        )

    def to_canonical(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "approver_id": self.approver_id,
            "approver_role": self.approver_role.value,
            "authenticated": self.authenticated,
            "expires_at": float(self.expires_at),
            "issued_at": float(self.issued_at),
            "policy_digest": self.policy_digest,
            "requirement_id": self.requirement_id,
            "scope_digest": self.scope_digest,
            "source": self.source.value,
        }


@dataclass(frozen=True, slots=True)
class EnvironmentAttributes:
    evaluated_at: float
    isolation_state: IsolationState
    network_state: NetworkState
    billing_route: BillingRoute
    capacity_state: CapacityState
    paid_continuation_protection: PaidContinuationProtection
    circuit_state: CircuitState
    flow_state: str
    approval_grants: tuple[ApprovalGrant, ...] = ()

    def __post_init__(self) -> None:
        _require_timestamp("evaluated_at", self.evaluated_at)
        _require_text("flow_state", self.flow_state)
        for name, value, expected in (
            ("isolation state", self.isolation_state, IsolationState),
            ("network state", self.network_state, NetworkState),
            ("billing route", self.billing_route, BillingRoute),
            ("capacity state", self.capacity_state, CapacityState),
            (
                "paid continuation protection",
                self.paid_continuation_protection,
                PaidContinuationProtection,
            ),
            ("circuit state", self.circuit_state, CircuitState),
        ):
            _require_instance(name, value, expected)
        if any(not isinstance(grant, ApprovalGrant) for grant in self.approval_grants):
            raise ValueError("approval grants must contain ApprovalGrant values")
        _require_tuple("approval grants", self.approval_grants)
        approval_ids = [grant.approval_id for grant in self.approval_grants]
        if len(approval_ids) != len(set(approval_ids)):
            raise ValueError("approval grant identifiers must be unique")

    def to_canonical(self) -> dict[str, Any]:
        approvals = sorted(
            (approval.to_canonical() for approval in self.approval_grants),
            key=canonical_json,
        )
        return {
            "approval_grants": approvals,
            "billing_route": self.billing_route.value,
            "capacity_state": self.capacity_state.value,
            "circuit_state": self.circuit_state.value,
            "evaluated_at": float(self.evaluated_at),
            "flow_state": self.flow_state,
            "isolation_state": self.isolation_state.value,
            "network_state": self.network_state.value,
            "paid_continuation_protection": self.paid_continuation_protection.value,
        }

    def approval_scope_canonical(self) -> dict[str, Any]:
        """Return exact environment facts without the approval-grant cycle."""

        return {
            "billing_route": self.billing_route.value,
            "capacity_state": self.capacity_state.value,
            "circuit_state": self.circuit_state.value,
            "evaluated_at": float(self.evaluated_at),
            "flow_state": self.flow_state,
            "isolation_state": self.isolation_state.value,
            "network_state": self.network_state.value,
            "paid_continuation_protection": self.paid_continuation_protection.value,
        }


@dataclass(frozen=True, slots=True)
class ConsequenceVector:
    confidentiality: ImpactLevel
    integrity: ImpactLevel
    availability: ImpactLevel
    reach: Reach
    destructive: bool
    reversible: bool
    sensitivity: ImpactLevel
    blast_radius: BlastRadius

    def __post_init__(self) -> None:
        for name, value in (
            ("confidentiality impact", self.confidentiality),
            ("integrity impact", self.integrity),
            ("availability impact", self.availability),
            ("sensitivity impact", self.sensitivity),
        ):
            _require_instance(name, value, ImpactLevel)
        _require_instance("reach", self.reach, Reach)
        _require_instance("blast radius", self.blast_radius, BlastRadius)
        if not isinstance(self.destructive, bool) or not isinstance(
            self.reversible, bool
        ):
            raise ValueError("destructive and reversible must be booleans")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "availability": self.availability.value,
            "blast_radius": self.blast_radius.value,
            "confidentiality": self.confidentiality.value,
            "destructive": self.destructive,
            "integrity": self.integrity.value,
            "reach": self.reach.value,
            "reversible": self.reversible,
            "sensitivity": self.sensitivity.value,
        }


@dataclass(frozen=True, slots=True)
class AttributeEvidence:
    evidence_id: str
    attribute: str
    value_digest: str
    source: EvidenceSource
    source_id: str
    observed_at: float
    expires_at: float
    authenticated: bool

    def __post_init__(self) -> None:
        _require_instance("evidence source", self.source, EvidenceSource)
        if not isinstance(self.authenticated, bool):
            raise ValueError("evidence authenticated must be a boolean")
        for name in ("evidence_id", "attribute", "source_id"):
            _require_text(name, getattr(self, name))
        _require_digest("value_digest", self.value_digest)
        _require_timestamp("observed_at", self.observed_at)
        _require_timestamp("expires_at", self.expires_at)

    @classmethod
    def bind(
        cls,
        *,
        evidence_id: str,
        attribute: str,
        value: Any,
        source: EvidenceSource,
        source_id: str,
        observed_at: float,
        expires_at: float,
        authenticated: bool,
    ) -> "AttributeEvidence":
        return cls(
            evidence_id=evidence_id,
            attribute=attribute,
            value_digest=canonical_digest(value),
            source=source,
            source_id=source_id,
            observed_at=observed_at,
            expires_at=expires_at,
            authenticated=authenticated,
        )

    def to_canonical(self) -> dict[str, Any]:
        return {
            "attribute": self.attribute,
            "authenticated": self.authenticated,
            "evidence_id": self.evidence_id,
            "expires_at": float(self.expires_at),
            "observed_at": float(self.observed_at),
            "source": self.source.value,
            "source_id": self.source_id,
            "value_digest": self.value_digest,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    request_id: str
    subject: SubjectAttributes
    action: ActionAttributes
    resource: ResourceAttributes
    environment: EnvironmentAttributes
    consequences: ConsequenceVector
    evidence: tuple[AttributeEvidence, ...] = ()

    def __post_init__(self) -> None:
        _require_text("request_id", self.request_id)
        _require_tuple("attribute evidence", self.evidence)
        if any(not isinstance(item, AttributeEvidence) for item in self.evidence):
            raise ValueError("attribute evidence contains an invalid value")

    def to_canonical(self) -> dict[str, Any]:
        evidence = sorted(
            (record.to_canonical() for record in self.evidence),
            key=lambda item: (item["attribute"], item["evidence_id"]),
        )
        return {
            "action": self.action.to_canonical(),
            "consequences": self.consequences.to_canonical(),
            "environment": self.environment.to_canonical(),
            "evidence": evidence,
            "request_id": self.request_id,
            "resource": self.resource.to_canonical(),
            "subject": self.subject.to_canonical(),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())

    @property
    def approval_scope_digest(self) -> str:
        stable_environment = self.environment.approval_scope_canonical()
        stable_evidence: list[dict[str, Any]] = []
        for record in self.evidence:
            item = record.to_canonical()
            if record.attribute == "environment":
                item["value_digest"] = canonical_digest(stable_environment)
            stable_evidence.append(item)
        stable_evidence.sort(key=lambda item: (item["attribute"], item["evidence_id"]))
        return canonical_digest(
            {
                "action": self.action.to_canonical(),
                "consequences": self.consequences.to_canonical(),
                "evidence": stable_evidence,
                "environment": stable_environment,
                "request_id": self.request_id,
                "resource": self.resource.to_canonical(),
                "subject": self.subject.to_canonical(),
            }
        )

    def attribute_value(self, attribute: str) -> Any:
        values: dict[str, Any] = {
            "subject": self.subject.to_canonical(),
            "action": self.action.to_canonical(),
            "resource": self.resource.to_canonical(),
            "environment": self.environment.to_canonical(),
            "consequences": self.consequences.to_canonical(),
        }
        if attribute not in values:
            raise KeyError(attribute)
        return values[attribute]


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    attribute: str
    trusted_sources: tuple[EvidenceSource, ...]
    max_age_seconds: float

    def __post_init__(self) -> None:
        _require_text("attribute", self.attribute)
        _require_tuple("trusted evidence sources", self.trusted_sources)
        if self.attribute not in {
            "subject",
            "action",
            "resource",
            "environment",
            "consequences",
        }:
            raise ValueError(f"unsupported evidence attribute: {self.attribute}")
        if not self.trusted_sources:
            raise ValueError("evidence requirement must name a trusted source")
        if any(
            not isinstance(source, EvidenceSource)
            for source in self.trusted_sources
        ):
            raise ValueError("trusted evidence sources contain an invalid value")
        if any(source in _UNTRUSTED_EVIDENCE_SOURCES for source in self.trusted_sources):
            raise ValueError("MCP, provider, and model claims can never be trusted evidence")
        if self.max_age_seconds <= 0 or not math.isfinite(self.max_age_seconds):
            raise ValueError("max_age_seconds must be finite and positive")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "attribute": self.attribute,
            "max_age_seconds": float(self.max_age_seconds),
            "trusted_sources": sorted(source.value for source in self.trusted_sources),
        }


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    requirement_id: str
    verbs: tuple[ActionVerb, ...] = ()
    resource_types: tuple[str, ...] = ()
    permission_classes: tuple[PermissionClass, ...] = ()
    allowed_approver_ids: tuple[str, ...] = ()
    allowed_approver_roles: tuple[Role, ...] = (Role.OPERATOR,)
    require_distinct_principal: bool = True

    def __post_init__(self) -> None:
        _require_text("requirement_id", self.requirement_id)
        for name, values in (
            ("approval verbs", self.verbs),
            ("approval resource types", self.resource_types),
            ("approval permission classes", self.permission_classes),
            ("allowed approver ids", self.allowed_approver_ids),
            ("allowed approver roles", self.allowed_approver_roles),
        ):
            _require_tuple(name, values)
        if any(not isinstance(verb, ActionVerb) for verb in self.verbs):
            raise ValueError("approval verbs contain an invalid value")
        if any(
            not isinstance(value, PermissionClass)
            for value in self.permission_classes
        ):
            raise ValueError("approval permission classes contain an invalid value")
        if any(not isinstance(role, Role) for role in self.allowed_approver_roles):
            raise ValueError("allowed approver roles contain an invalid value")
        if not isinstance(self.require_distinct_principal, bool):
            raise ValueError("require_distinct_principal must be a boolean")
        for resource_type in self.resource_types:
            _require_text("resource_type", resource_type)
        for approver_id in self.allowed_approver_ids:
            _require_text("allowed approver id", approver_id)
        if not self.allowed_approver_ids:
            raise ValueError("approval requirement must name an approver identity")
        if not self.allowed_approver_roles:
            raise ValueError("approval requirement must name an approver role")
        if len(self.allowed_approver_ids) != len(set(self.allowed_approver_ids)):
            raise ValueError("allowed approver identifiers must be unique")
        if len(self.allowed_approver_roles) != len(set(self.allowed_approver_roles)):
            raise ValueError("allowed approver roles must be unique")

    def matches(
        self,
        request: AuthorizationRequest,
        permission_class: PermissionClass,
    ) -> bool:
        return bool(
            (not self.verbs or request.action.verb in self.verbs)
            and (
                not self.resource_types
                or request.resource.resource_type in self.resource_types
            )
            and (
                not self.permission_classes
                or permission_class in self.permission_classes
            )
        )

    def to_canonical(self) -> dict[str, Any]:
        return {
            "allowed_approver_ids": sorted(self.allowed_approver_ids),
            "allowed_approver_roles": sorted(
                role.value for role in self.allowed_approver_roles
            ),
            "permission_classes": sorted(int(value) for value in self.permission_classes),
            "require_distinct_principal": self.require_distinct_principal,
            "requirement_id": self.requirement_id,
            "resource_types": sorted(self.resource_types),
            "verbs": sorted(verb.value for verb in self.verbs),
        }


_PROHIBITED_BILLING_ROUTES = frozenset(
    {
        BillingRoute.PURCHASED_PRODUCT_CREDIT,
        BillingRoute.SUBSCRIPTION_OVERAGE,
        BillingRoute.SEPARATELY_BILLED_API,
        BillingRoute.CLOUD_PROVIDER_BILLING,
        BillingRoute.UNKNOWN,
    }
)


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    bundle_id: str
    version: str
    issued_at: float
    evidence_requirements: tuple[EvidenceRequirement, ...]
    enabled_classes: tuple[PermissionClass, ...] = (
        PermissionClass.READ_ONLY,
        PermissionClass.LOCAL_DRAFT,
    )
    allowed_verbs: tuple[ActionVerb, ...] = (
        ActionVerb.READ,
        ActionVerb.CREATE,
        ActionVerb.MODIFY,
        ActionVerb.EXECUTE,
    )
    allowed_roles: tuple[Role, ...] = (Role.IMPLEMENTER,)
    allowed_operations: tuple[str, ...] = (
        "artifact.publish_local_candidate",
        "repository.inspect",
        "repository.patch",
        "task_attempt_admission",
    )
    allowed_resource_types: tuple[str, ...] = (
        "isolated_worktree",
        "local_candidate_artifact",
    )
    allowed_trust_boundaries: tuple[str, ...] = (
        "isolated_run_workspace",
        "local_worker_cell",
        "repository_run_workspace",
    )
    allowed_flow_states: tuple[str, ...] = (
        "admission_proposed",
        "admitted",
        "local_candidate_publication_proposed",
        "proposed",
        "runner_dispatch_proposed",
    )
    allowed_network_states: tuple[NetworkState, ...] = (NetworkState.DISABLED,)
    allowed_billing_routes: tuple[BillingRoute, ...] = (
        BillingRoute.SUBSCRIPTION_INCLUDED,
        BillingRoute.LOCAL_NON_AI,
        BillingRoute.MOCK,
    )
    approval_requirements: tuple[ApprovalRequirement, ...] = ()
    decision_ttl_seconds: float = 60.0
    schema_version: int = 1

    def __post_init__(self) -> None:
        _require_text("bundle_id", self.bundle_id)
        _require_text("version", self.version)
        _require_timestamp("issued_at", self.issued_at)
        tuple_fields = (
            ("evidence requirements", self.evidence_requirements),
            ("enabled classes", self.enabled_classes),
            ("allowed verbs", self.allowed_verbs),
            ("allowed roles", self.allowed_roles),
            ("allowed operations", self.allowed_operations),
            ("allowed resource types", self.allowed_resource_types),
            ("allowed trust boundaries", self.allowed_trust_boundaries),
            ("allowed flow states", self.allowed_flow_states),
            ("allowed network states", self.allowed_network_states),
            ("allowed billing routes", self.allowed_billing_routes),
            ("approval requirements", self.approval_requirements),
        )
        for name, values in tuple_fields:
            _require_tuple(name, values)
        typed_fields: tuple[tuple[str, tuple[Any, ...], type[Any]], ...] = (
            ("evidence requirements", self.evidence_requirements, EvidenceRequirement),
            ("enabled classes", self.enabled_classes, PermissionClass),
            ("allowed verbs", self.allowed_verbs, ActionVerb),
            ("allowed roles", self.allowed_roles, Role),
            ("allowed network states", self.allowed_network_states, NetworkState),
            ("allowed billing routes", self.allowed_billing_routes, BillingRoute),
            ("approval requirements", self.approval_requirements, ApprovalRequirement),
        )
        for name, values, expected in typed_fields:
            if any(not isinstance(value, expected) for value in values):
                raise ValueError(f"{name} contain an invalid value")
        if self.schema_version != 1:
            raise ValueError("unsupported authorization policy schema version")
        if not self.evidence_requirements:
            raise ValueError("policy must require provenance-bearing evidence")
        attributes = [item.attribute for item in self.evidence_requirements]
        if len(attributes) != len(set(attributes)):
            raise ValueError("policy evidence attributes must be unique")
        if not self.enabled_classes:
            raise ValueError("policy must explicitly enable at least one class")
        if any(value > PermissionClass.LOCAL_DRAFT for value in self.enabled_classes):
            raise ValueError("Phase 1C policy bundles cannot enable Classes 2 or 3")
        if len(self.enabled_classes) != len(set(self.enabled_classes)):
            raise ValueError("enabled permission classes must be unique")
        if not self.allowed_verbs:
            raise ValueError("policy must explicitly allow at least one verb")
        if len(self.allowed_verbs) != len(set(self.allowed_verbs)):
            raise ValueError("allowed verbs must be unique")
        named_sets: tuple[tuple[str, tuple[Any, ...]], ...] = (
            ("roles", self.allowed_roles),
            ("operations", self.allowed_operations),
            ("resource types", self.allowed_resource_types),
            ("trust boundaries", self.allowed_trust_boundaries),
            ("flow states", self.allowed_flow_states),
            ("network states", self.allowed_network_states),
        )
        for label, values in named_sets:
            if not values:
                raise ValueError(f"policy must explicitly allow at least one {label}")
            if len(values) != len(set(values)):
                raise ValueError(f"allowed {label} must be unique")
        for value in (
            *self.allowed_operations,
            *self.allowed_resource_types,
            *self.allowed_trust_boundaries,
            *self.allowed_flow_states,
        ):
            _require_text("allowed policy value", value)
        if not self.allowed_billing_routes:
            raise ValueError("policy must explicitly allow a billing route")
        if len(self.allowed_billing_routes) != len(set(self.allowed_billing_routes)):
            raise ValueError("allowed billing routes must be unique")
        if any(route in _PROHIBITED_BILLING_ROUTES for route in self.allowed_billing_routes):
            raise ValueError("policy bundle cannot enable a prohibited billing route")
        if self.decision_ttl_seconds <= 0 or not math.isfinite(self.decision_ttl_seconds):
            raise ValueError("decision_ttl_seconds must be finite and positive")
        requirement_ids = [item.requirement_id for item in self.approval_requirements]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("approval requirement identifiers must be unique")

    @classmethod
    def current_stage(
        cls,
        *,
        issued_at: float = 0.0,
        approval_requirements: tuple[ApprovalRequirement, ...] = (),
    ) -> "PolicyBundle":
        return cls(
            bundle_id="agentops.phase-1c.shadow",
            version="1.1.0",
            issued_at=issued_at,
            evidence_requirements=(
                EvidenceRequirement(
                    "subject", (EvidenceSource.CONTROLLER,), 300.0
                ),
                EvidenceRequirement(
                    "action",
                    (EvidenceSource.CONTROLLER, EvidenceSource.LOCAL_REGISTRY),
                    300.0,
                ),
                EvidenceRequirement(
                    "resource",
                    (EvidenceSource.CONTROLLER, EvidenceSource.LOCAL_REGISTRY),
                    300.0,
                ),
                EvidenceRequirement(
                    "environment",
                    (EvidenceSource.CONTROLLER, EvidenceSource.VERIFIED_ATTESTATION),
                    300.0,
                ),
                EvidenceRequirement(
                    "consequences",
                    (EvidenceSource.CONTROLLER, EvidenceSource.LOCAL_REGISTRY),
                    300.0,
                ),
            ),
            approval_requirements=approval_requirements,
        )

    def to_canonical(self) -> dict[str, Any]:
        return {
            "allowed_billing_routes": sorted(route.value for route in self.allowed_billing_routes),
            "allowed_flow_states": sorted(self.allowed_flow_states),
            "allowed_network_states": sorted(
                state.value for state in self.allowed_network_states
            ),
            "allowed_operations": sorted(self.allowed_operations),
            "allowed_resource_types": sorted(self.allowed_resource_types),
            "allowed_roles": sorted(role.value for role in self.allowed_roles),
            "allowed_trust_boundaries": sorted(self.allowed_trust_boundaries),
            "allowed_verbs": sorted(verb.value for verb in self.allowed_verbs),
            "approval_requirements": sorted(
                (item.to_canonical() for item in self.approval_requirements),
                key=lambda item: item["requirement_id"],
            ),
            "bundle_id": self.bundle_id,
            "decision_ttl_seconds": float(self.decision_ttl_seconds),
            "enabled_classes": sorted(int(value) for value in self.enabled_classes),
            "evidence_requirements": sorted(
                (item.to_canonical() for item in self.evidence_requirements),
                key=lambda item: item["attribute"],
            ),
            "issued_at": float(self.issued_at),
            "schema_version": self.schema_version,
            "version": self.version,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class DecisionObligation:
    kind: ObligationKind
    value: str

    def __post_init__(self) -> None:
        _require_instance("obligation kind", self.kind, ObligationKind)
        _require_text("obligation value", self.value)

    def to_canonical(self) -> dict[str, str]:
        return {"kind": self.kind.value, "value": self.value}


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    request_id: str
    request_digest: str
    policy_bundle_id: str
    policy_version: str
    policy_digest: str
    effect: AuthorizationEffect
    derived_permission_class: PermissionClass
    reason_codes: tuple[DecisionReason, ...]
    reason_details: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    issued_at: float
    expires_at: float
    obligations: tuple[DecisionObligation, ...] = ()

    def __post_init__(self) -> None:
        _require_text("request_id", self.request_id)
        _require_text("policy_bundle_id", self.policy_bundle_id)
        _require_text("policy_version", self.policy_version)
        _require_digest("request_digest", self.request_digest)
        _require_digest("policy_digest", self.policy_digest)
        _require_timestamp("issued_at", self.issued_at)
        _require_timestamp("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("decision expiry must follow decision issuance")
        _require_instance("decision effect", self.effect, AuthorizationEffect)
        _require_instance(
            "derived permission class",
            self.derived_permission_class,
            PermissionClass,
        )
        for name, values in (
            ("decision reasons", self.reason_codes),
            ("decision reason details", self.reason_details),
            ("matched rules", self.matched_rule_ids),
            ("evidence references", self.evidence_refs),
            ("decision obligations", self.obligations),
        ):
            _require_tuple(name, values)
        if any(not isinstance(reason, DecisionReason) for reason in self.reason_codes):
            raise ValueError("decision reasons contain an invalid value")
        if any(
            not isinstance(obligation, DecisionObligation)
            for obligation in self.obligations
        ):
            raise ValueError("decision obligations contain an invalid value")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "derived_permission_class": int(self.derived_permission_class),
            "effect": self.effect.value,
            "evidence_refs": sorted(self.evidence_refs),
            "expires_at": float(self.expires_at),
            "issued_at": float(self.issued_at),
            "matched_rule_ids": sorted(self.matched_rule_ids),
            "obligations": sorted(
                (item.to_canonical() for item in self.obligations),
                key=lambda item: (item["kind"], item["value"]),
            ),
            "policy_bundle_id": self.policy_bundle_id,
            "policy_digest": self.policy_digest,
            "policy_version": self.policy_version,
            "reason_codes": [reason.value for reason in self.reason_codes],
            "reason_details": list(self.reason_details),
            "request_digest": self.request_digest,
            "request_id": self.request_id,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())

    @property
    def decision_id(self) -> str:
        return self.digest


@dataclass(frozen=True, slots=True)
class ObligationResult:
    kind: ObligationKind
    value: str
    satisfied: bool

    def __post_init__(self) -> None:
        _require_instance("obligation result kind", self.kind, ObligationKind)
        _require_text("obligation result value", self.value)
        if not isinstance(self.satisfied, bool):
            raise ValueError("obligation result satisfied must be a boolean")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "satisfied": self.satisfied,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    receipt_id: str
    decision_digest: str
    request_digest: str
    enforced_action_digest: str
    executor_id: str
    started_at: float
    completed_at: float
    outcome: ReceiptOutcome
    obligation_results: tuple[ObligationResult, ...]
    result_digest: str | None = None

    def __post_init__(self) -> None:
        _require_text("receipt_id", self.receipt_id)
        _require_text("executor_id", self.executor_id)
        for name in ("decision_digest", "request_digest", "enforced_action_digest"):
            _require_digest(name, getattr(self, name))
        if self.result_digest is not None:
            _require_digest("result_digest", self.result_digest)
        _require_timestamp("started_at", self.started_at)
        _require_timestamp("completed_at", self.completed_at)
        if self.completed_at < self.started_at:
            raise ValueError("receipt completion cannot precede action start")
        _require_instance("receipt outcome", self.outcome, ReceiptOutcome)
        _require_tuple("obligation results", self.obligation_results)
        if any(
            not isinstance(item, ObligationResult)
            for item in self.obligation_results
        ):
            raise ValueError("obligation results contain an invalid value")

    @classmethod
    def record(
        cls,
        *,
        receipt_id: str,
        decision: AuthorizationDecision,
        request: AuthorizationRequest,
        executor_id: str,
        started_at: float,
        completed_at: float,
        outcome: ReceiptOutcome,
        obligation_results: tuple[ObligationResult, ...],
        result_digest: str | None = None,
    ) -> "ActionReceipt":
        if decision.effect is not AuthorizationEffect.PERMIT:
            raise ValueError("an action receipt can be started only from a permit")
        if decision.request_digest != request.digest:
            raise ValueError("decision and receipt request digests do not match")
        if started_at < decision.issued_at or started_at >= decision.expires_at:
            raise ValueError("permit is not current at action start")
        expected_obligations = {
            (item.kind, item.value) for item in decision.obligations
        }
        received_obligations = {
            (item.kind, item.value) for item in obligation_results
        }
        if len(received_obligations) != len(obligation_results):
            raise ValueError("obligation results must be unique")
        if received_obligations != expected_obligations or any(
            not item.satisfied for item in obligation_results
        ):
            raise ValueError("every exact decision obligation must be satisfied")
        enforced_action_digest = canonical_digest(
            {
                "action": request.action.to_canonical(),
                "resource": request.resource.to_canonical(),
            }
        )
        return cls(
            receipt_id=receipt_id,
            decision_digest=decision.digest,
            request_digest=request.digest,
            enforced_action_digest=enforced_action_digest,
            executor_id=executor_id,
            started_at=started_at,
            completed_at=completed_at,
            outcome=outcome,
            obligation_results=obligation_results,
            result_digest=result_digest,
        )

    def to_canonical(self) -> dict[str, Any]:
        return {
            "completed_at": float(self.completed_at),
            "decision_digest": self.decision_digest,
            "enforced_action_digest": self.enforced_action_digest,
            "executor_id": self.executor_id,
            "obligation_results": sorted(
                (item.to_canonical() for item in self.obligation_results),
                key=lambda item: (item["kind"], item["value"]),
            ),
            "outcome": self.outcome.value,
            "receipt_id": self.receipt_id,
            "request_digest": self.request_digest,
            "result_digest": self.result_digest,
            "started_at": float(self.started_at),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


_IMPACT_RANK = {
    ImpactLevel.LOW: 0,
    ImpactLevel.MODERATE: 1,
    ImpactLevel.HIGH: 2,
}


def derive_permission_class_from_attributes(
    action: ActionAttributes,
    resource: ResourceAttributes,
    consequences: ConsequenceVector,
) -> PermissionClass:
    """Conservatively derive Class 0-3 from authoritative typed attributes.

    Every applicable dimension contributes and the highest class wins.  Tool
    and provider claims are deliberately absent from this calculation.
    """

    if not isinstance(action, ActionAttributes):
        raise ValueError("class derivation action must be ActionAttributes")
    if not isinstance(resource, ResourceAttributes):
        raise ValueError("class derivation resource must be ResourceAttributes")
    if not isinstance(consequences, ConsequenceVector):
        raise ValueError("class derivation consequences must be ConsequenceVector")
    result = (
        PermissionClass.READ_ONLY
        if action.verb is ActionVerb.READ
        else PermissionClass.LOCAL_DRAFT
    )

    impacts = (
        consequences.confidentiality,
        consequences.integrity,
        consequences.availability,
        consequences.sensitivity,
        resource.sensitivity,
    )
    if any(_IMPACT_RANK[value] == 1 for value in impacts):
        result = max(result, PermissionClass.REVERSIBLE_INTERNAL_WRITE)
    if any(_IMPACT_RANK[value] == 2 for value in impacts):
        result = PermissionClass.EXTERNAL_CONSEQUENTIAL

    if consequences.reach is Reach.SHARED:
        result = max(result, PermissionClass.REVERSIBLE_INTERNAL_WRITE)
    elif consequences.reach is Reach.EXTERNAL:
        result = PermissionClass.EXTERNAL_CONSEQUENTIAL

    if resource.protected:
        result = max(result, PermissionClass.REVERSIBLE_INTERNAL_WRITE)
    if consequences.blast_radius is BlastRadius.BOUNDED:
        result = max(result, PermissionClass.REVERSIBLE_INTERNAL_WRITE)
    elif consequences.blast_radius is BlastRadius.BROAD:
        result = PermissionClass.EXTERNAL_CONSEQUENTIAL

    if (
        consequences.destructive
        or not consequences.reversible
        or action.verb in {ActionVerb.DELETE, ActionVerb.SEND, ActionVerb.APPROVE}
    ):
        result = PermissionClass.EXTERNAL_CONSEQUENTIAL
    return PermissionClass(result)


def derive_permission_class(request: AuthorizationRequest) -> PermissionClass:
    """Conservatively derive the lossy Class 0-3 operator summary."""

    if not isinstance(request, AuthorizationRequest):
        raise ValueError("class derivation request must be AuthorizationRequest")
    return derive_permission_class_from_attributes(
        request.action,
        request.resource,
        request.consequences,
    )


@dataclass(frozen=True, slots=True)
class _EvidenceValidation:
    valid: bool
    reason_codes: tuple[DecisionReason, ...]
    details: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    earliest_expiry: float


class ShadowAuthorizationEvaluator:
    """Deterministic deny-by-default Phase 1C policy decision point."""

    def evaluate(
        self,
        request: AuthorizationRequest,
        policy: PolicyBundle,
    ) -> AuthorizationDecision:
        now = float(request.environment.evaluated_at)
        derived = derive_permission_class(request)
        mandatory_deny = self._mandatory_deny_effect(request, policy, derived)
        if mandatory_deny is not None:
            reason, detail, rule_id = mandatory_deny
            return self._decision(
                request,
                policy,
                derived,
                AuthorizationEffect.DENY,
                (reason,),
                (detail,),
                (rule_id,),
                (),
                now + policy.decision_ttl_seconds,
            )
        if policy.issued_at > now:
            return self._decision(
                request,
                policy,
                derived,
                AuthorizationEffect.INDETERMINATE,
                (DecisionReason.POLICY_NOT_CURRENT,),
                ("the policy bundle is not yet current",),
                ("phase-1c-policy-time",),
                (),
                now + policy.decision_ttl_seconds,
            )
        evidence = self._validate_evidence(request, policy, now)
        expiry = min(now + policy.decision_ttl_seconds, evidence.earliest_expiry)
        if not evidence.valid:
            return self._decision(
                request,
                policy,
                derived,
                AuthorizationEffect.INDETERMINATE,
                evidence.reason_codes,
                evidence.details,
                ("phase-1c-evidence",),
                evidence.evidence_refs,
                expiry,
            )

        environment_effect = self._environment_indeterminate_effect(request)
        if environment_effect is not None:
            effect, reason, detail = environment_effect
            return self._decision(
                request,
                policy,
                derived,
                effect,
                (reason,),
                (detail,),
                ("phase-1c-environment-evidence",),
                evidence.evidence_refs,
                expiry,
            )

        approval_result = self._approval_effect(request, policy, derived, now)
        if approval_result is not None:
            effect, reasons, details, obligations, approval_expiry = approval_result
            return self._decision(
                request,
                policy,
                derived,
                effect,
                reasons,
                details,
                ("phase-1c-digest-bound-approval",),
                evidence.evidence_refs,
                min(expiry, approval_expiry),
                obligations,
            )

        obligations = [
            DecisionObligation(ObligationKind.AUDIT_RECEIPT, "append_after_action")
        ]
        obligations.append(
            DecisionObligation(
                ObligationKind.READ_ONLY
                if derived is PermissionClass.READ_ONLY
                else ObligationKind.ISOLATED_LOCAL_ONLY,
                "required",
            )
        )
        return self._decision(
            request,
            policy,
            derived,
            AuthorizationEffect.PERMIT,
            (DecisionReason.CURRENT_STAGE_PERMIT,),
            (f"derived Class {int(derived)} is enabled in shadow policy",),
            (f"phase-1c-class-{int(derived)}",),
            evidence.evidence_refs,
            expiry,
            tuple(obligations),
        )

    def _validate_evidence(
        self,
        request: AuthorizationRequest,
        policy: PolicyBundle,
        now: float,
    ) -> _EvidenceValidation:
        identifiers = [record.evidence_id for record in request.evidence]
        if len(identifiers) != len(set(identifiers)):
            return _EvidenceValidation(
                False,
                (DecisionReason.EVIDENCE_IDENTIFIER_DUPLICATED,),
                ("evidence identifiers must be unique",),
                (),
                now + policy.decision_ttl_seconds,
            )

        reasons: list[DecisionReason] = []
        details: list[str] = []
        accepted: list[str] = []
        expiries: list[float] = [now + policy.decision_ttl_seconds]
        for requirement in policy.evidence_requirements:
            records = tuple(
                record
                for record in request.evidence
                if record.attribute == requirement.attribute
            )
            trusted = tuple(
                record
                for record in records
                if record.source in requirement.trusted_sources
                and record.source not in _UNTRUSTED_EVIDENCE_SOURCES
            )
            if not trusted:
                if records and all(
                    record.source in _UNTRUSTED_EVIDENCE_SOURCES for record in records
                ):
                    reasons.append(DecisionReason.UNTRUSTED_CLAIM_ONLY)
                    details.append(
                        f"{requirement.attribute} has only MCP/provider/model claims"
                    )
                else:
                    reasons.append(DecisionReason.EVIDENCE_MISSING)
                    details.append(
                        f"{requirement.attribute} lacks evidence from a trusted source"
                    )
                continue
            if any(not record.authenticated for record in trusted):
                reasons.append(DecisionReason.EVIDENCE_UNAUTHENTICATED)
                details.append(f"{requirement.attribute} evidence is unauthenticated")
                continue
            if any(record.observed_at > now for record in trusted):
                reasons.append(DecisionReason.EVIDENCE_FROM_FUTURE)
                details.append(f"{requirement.attribute} evidence is from the future")
                continue
            if any(
                record.expires_at <= record.observed_at
                or now >= record.expires_at
                or now - record.observed_at > requirement.max_age_seconds
                for record in trusted
            ):
                reasons.append(DecisionReason.EVIDENCE_STALE)
                details.append(f"{requirement.attribute} evidence is stale or malformed")
                continue
            observed_values = {record.value_digest for record in trusted}
            if len(observed_values) != 1:
                reasons.append(DecisionReason.EVIDENCE_CONTRADICTORY)
                details.append(f"{requirement.attribute} evidence values conflict")
                continue
            expected = canonical_digest(request.attribute_value(requirement.attribute))
            if next(iter(observed_values)) != expected:
                reasons.append(DecisionReason.EVIDENCE_VALUE_MISMATCH)
                details.append(
                    f"{requirement.attribute} evidence is not bound to this request"
                )
                continue
            accepted.extend(record.evidence_id for record in trusted)
            expiries.extend(record.expires_at for record in trusted)

        return _EvidenceValidation(
            not reasons,
            tuple(dict.fromkeys(reasons)),
            tuple(details),
            tuple(sorted(accepted)),
            min(expiries),
        )

    def _mandatory_deny_effect(
        self,
        request: AuthorizationRequest,
        policy: PolicyBundle,
        derived: PermissionClass,
    ) -> tuple[DecisionReason, str, str] | None:
        environment = request.environment
        if derived > PermissionClass.LOCAL_DRAFT or derived not in policy.enabled_classes:
            return (
                DecisionReason.CLASS_DISABLED,
                f"current stage disables derived Class {int(derived)}",
                "phase-1c-class-ceiling",
            )
        if request.subject.role not in policy.allowed_roles:
            return (
                DecisionReason.ROLE_NOT_ALLOWED,
                "the subject role is not enabled",
                "phase-1c-role-allowlist",
            )
        if request.action.verb not in policy.allowed_verbs:
            return (
                DecisionReason.VERB_NOT_ALLOWED,
                "the action verb is not enabled",
                "phase-1c-verb-allowlist",
            )
        if request.action.operation not in policy.allowed_operations:
            return (
                DecisionReason.OPERATION_NOT_ALLOWED,
                "the operation is not enabled",
                "phase-1c-operation-allowlist",
            )
        if request.resource.resource_type not in policy.allowed_resource_types:
            return (
                DecisionReason.RESOURCE_NOT_ALLOWED,
                "the resource type is not enabled",
                "phase-1c-resource-allowlist",
            )
        if request.resource.trust_boundary not in policy.allowed_trust_boundaries:
            return (
                DecisionReason.TRUST_BOUNDARY_NOT_ALLOWED,
                "the resource trust boundary is not enabled",
                "phase-1c-trust-boundary-allowlist",
            )
        if environment.flow_state not in policy.allowed_flow_states:
            return (
                DecisionReason.FLOW_STATE_NOT_ALLOWED,
                "the workflow state is not eligible for admission",
                "phase-1c-flow-state-allowlist",
            )
        if environment.circuit_state is CircuitState.OPEN:
            return (
                DecisionReason.CIRCUIT_OPEN,
                "the applicable circuit breaker is open",
                "phase-1c-circuit-hard-stop",
            )
        if (
            environment.network_state is not NetworkState.UNKNOWN
            and environment.network_state not in policy.allowed_network_states
        ):
            return (
                DecisionReason.NETWORK_PROHIBITED,
                "the effective network state is not enabled",
                "phase-1c-network-allowlist",
            )
        if environment.isolation_state in {
            IsolationState.ABSENT,
            IsolationState.NOT_REQUIRED,
        }:
            return (
                DecisionReason.ISOLATION_REQUIRED,
                "current-stage work requires verified isolation",
                "phase-1c-isolation-requirement",
            )
        if (
            environment.billing_route is not BillingRoute.UNKNOWN
            and environment.billing_route not in policy.allowed_billing_routes
        ):
            return (
                DecisionReason.BILLING_PROHIBITED,
                "billing route is prohibited by mandatory policy",
                "phase-1c-billing-hard-stop",
            )
        if environment.billing_route is BillingRoute.SUBSCRIPTION_INCLUDED:
            if environment.capacity_state not in {
                CapacityState.AVAILABLE,
                CapacityState.UNKNOWN,
            }:
                return (
                    DecisionReason.BILLING_PROHIBITED,
                    "included subscription capacity is unavailable",
                    "phase-1c-capacity-hard-stop",
                )
            protection = environment.paid_continuation_protection
            if protection not in {
                PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED,
                PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED,
                PaidContinuationProtection.UNKNOWN,
            }:
                return (
                    DecisionReason.BILLING_PROHIBITED,
                    "paid continuation is not disabled",
                    "phase-1c-paid-continuation-hard-stop",
                )
        return None

    @staticmethod
    def _environment_indeterminate_effect(
        request: AuthorizationRequest,
    ) -> tuple[AuthorizationEffect, DecisionReason, str] | None:
        environment = request.environment
        if environment.circuit_state is not CircuitState.CLOSED:
            return (
                AuthorizationEffect.INDETERMINATE,
                DecisionReason.CIRCUIT_UNKNOWN,
                "the applicable circuit state is unknown",
            )
        if environment.network_state is NetworkState.UNKNOWN:
            return (
                AuthorizationEffect.INDETERMINATE,
                DecisionReason.NETWORK_UNKNOWN,
                "the effective network state is unknown",
            )
        if environment.isolation_state in {
            IsolationState.UNKNOWN,
            IsolationState.UNVERIFIED,
        }:
            return (
                AuthorizationEffect.INDETERMINATE,
                DecisionReason.ISOLATION_UNKNOWN,
                "effective isolation has not been verified",
            )
        if environment.billing_route is BillingRoute.UNKNOWN:
            return (
                AuthorizationEffect.INDETERMINATE,
                DecisionReason.BILLING_EVIDENCE_UNKNOWN,
                "billing route is unknown",
            )
        if environment.billing_route is BillingRoute.SUBSCRIPTION_INCLUDED:
            if environment.capacity_state is CapacityState.UNKNOWN:
                return (
                    AuthorizationEffect.INDETERMINATE,
                    DecisionReason.BILLING_EVIDENCE_UNKNOWN,
                    "included subscription capacity is unknown",
                )
            if (
                environment.paid_continuation_protection
                is PaidContinuationProtection.UNKNOWN
            ):
                return (
                    AuthorizationEffect.INDETERMINATE,
                    DecisionReason.BILLING_EVIDENCE_UNKNOWN,
                    "paid-continuation protection is unknown",
                )
        return None

    def _approval_effect(
        self,
        request: AuthorizationRequest,
        policy: PolicyBundle,
        derived: PermissionClass,
        now: float,
    ) -> tuple[
        AuthorizationEffect,
        tuple[DecisionReason, ...],
        tuple[str, ...],
        tuple[DecisionObligation, ...],
        float,
    ] | None:
        requirements = tuple(
            item
            for item in policy.approval_requirements
            if item.matches(request, derived)
        )
        if not requirements:
            return None
        missing: list[ApprovalRequirement] = []
        accepted_expiries: list[float] = [now + policy.decision_ttl_seconds]
        for requirement in requirements:
            grants = tuple(
                grant
                for grant in request.environment.approval_grants
                if grant.requirement_id == requirement.requirement_id
            )
            if not grants:
                missing.append(requirement)
                continue
            if any(
                not grant.authenticated
                or grant.source is not EvidenceSource.APPROVAL_AUTHORITY
                or (
                    requirement.allowed_approver_ids
                    and grant.approver_id not in requirement.allowed_approver_ids
                )
                or grant.approver_role not in requirement.allowed_approver_roles
                or (
                    requirement.require_distinct_principal
                    and grant.approver_id == request.subject.principal_id
                )
                or grant.scope_digest != request.approval_scope_digest
                or grant.policy_digest != policy.digest
                or grant.issued_at < policy.issued_at
                or grant.issued_at > now
                or grant.expires_at <= grant.issued_at
                or now >= grant.expires_at
                for grant in grants
            ):
                return (
                    AuthorizationEffect.INDETERMINATE,
                    (DecisionReason.APPROVAL_INVALID,),
                    (f"approval {requirement.requirement_id} is stale or misbound",),
                    (),
                    min(accepted_expiries),
                )
            accepted_expiries.extend(grant.expires_at for grant in grants)
        if missing:
            obligations = tuple(
                DecisionObligation(ObligationKind.APPROVAL, item.requirement_id)
                for item in missing
            )
            return (
                AuthorizationEffect.DEFER,
                (DecisionReason.APPROVAL_REQUIRED,),
                tuple(
                    f"digest-bound approval {item.requirement_id} is required"
                    for item in missing
                ),
                obligations,
                min(accepted_expiries),
            )
        return None

    @staticmethod
    def _decision(
        request: AuthorizationRequest,
        policy: PolicyBundle,
        derived: PermissionClass,
        effect: AuthorizationEffect,
        reasons: tuple[DecisionReason, ...],
        details: tuple[str, ...],
        matched_rules: tuple[str, ...],
        evidence_refs: tuple[str, ...],
        expires_at: float,
        obligations: tuple[DecisionObligation, ...] = (),
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            request_id=request.request_id,
            request_digest=request.digest,
            policy_bundle_id=policy.bundle_id,
            policy_version=policy.version,
            policy_digest=policy.digest,
            effect=effect,
            derived_permission_class=derived,
            reason_codes=reasons,
            reason_details=details,
            matched_rule_ids=matched_rules,
            evidence_refs=evidence_refs,
            issued_at=float(request.environment.evaluated_at),
            expires_at=max(float(request.environment.evaluated_at), expires_at),
            obligations=obligations,
        )


# Concise aliases for callers that prefer the ABAC category names.
Subject = SubjectAttributes
Action = ActionAttributes
Resource = ResourceAttributes
Environment = EnvironmentAttributes
AgentRole = Role
DecisionEffect = AuthorizationEffect
AuthorizationEvaluator = ShadowAuthorizationEvaluator
