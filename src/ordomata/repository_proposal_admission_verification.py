"""Pure verification of one untrusted repository-proposal admission mapping.

The verifier accepts only an exact built-in dictionary, takes one bounded
detached JSON snapshot, and independently replays the fixed admission-shadow
contract.  A valid report establishes internal contract consistency only.  It
does not authenticate the mapping, reinspect durable evidence, establish
current freshness, grant authority, or perform an effect.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
import re
from typing import Any

from .authorization import (
    ActionAttributes,
    ActionVerb,
    AttributeEvidence,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationRequest,
    BlastRadius,
    CircuitState,
    ConsequenceVector,
    DecisionObligation,
    DecisionReason,
    EnvironmentAttributes,
    EvidenceRequirement,
    EvidenceSource,
    ImpactLevel,
    IsolationState,
    NetworkState,
    ObligationKind,
    PolicyBundle,
    Reach,
    ResourceAttributes,
    Role,
    ShadowAuthorizationEvaluator,
    SubjectAttributes,
    canonical_digest,
    derive_permission_class,
)
from .errors import ValidationError
from .models import (
    BillingRoute,
    CapacityState,
    PaidContinuationProtection,
    PermissionClass,
)
from .repository_proposal_admission import (
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION,
    REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION,
    REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION,
    REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE,
    REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION,
    REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE,
)
from .repository_proposal_inspection import (
    REPOSITORY_PROPOSAL_INSPECTION_KIND,
    REPOSITORY_PROPOSAL_INSPECTION_SCHEMA_VERSION,
)


REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_SCHEMA_VERSION = 1
REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_KIND = (
    "repository_proposal_admission_shadow_verification"
)

_MAX_DEPTH = 12
_MAX_NODES = 1_024
_MAX_CONTAINERS = 128
_MAX_DICT_ENTRIES = 64
_MAX_LIST_ITEMS = 32
_MAX_TEXT_BYTES = 4_096
_MAX_TOTAL_TEXT_BYTES = 131_072
_MAX_FINDINGS = 24

_RUNNER_ID = "repository-proposal-disabled"
_FLOW_STATE = "repository_proposal_admission_proposed"
_TRUST_BOUNDARY = "local_control_plane"
_EVIDENCE_LIFETIME_SECONDS = 60.0
_DECISION_TTL_SECONDS = 30.0

_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\Z"
)

_SHADOW_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "mode",
        "action_scope",
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
        "run_ref",
        "inspection",
        "inspection_digest",
        "requested_permission_class",
        "evaluation_status",
        "request",
        "request_digest",
        "policy",
        "policy_digest",
        "decision",
        "decision_digest",
        "effect",
        "derived_permission_class",
        "decision_current_at_evaluation",
        "permission_class_matches",
        "obligations_exact",
        "shadow_eligible",
        "block_reason_codes",
        "evaluated_at",
    }
)
_NO_EFFECT_KEYS = (
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

_INSPECTION_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "inspection_scope",
        "inspection_mode",
        "validation_mode",
        "repair_performed",
        "dispatch_enabled",
        "authority_granted",
        "run_ref",
        "coverage",
        "truncated",
        "clean",
        "evidence_complete",
        "inspected_event_count",
        "permission_class",
        "current_status",
        "proposal_digest",
        "proposal_ref",
        "proposal_version_ref",
        "registration_digest",
        "registration_ref",
        "registration_version",
        "repository_ref",
        "registration_selection_digest",
        "repository_proposal_binding_digest",
        "selection_sequence",
        "binding_sequence",
        "finding_count",
        "findings",
    }
)
_INSPECTION_FINDING_ORDER = (
    "run_record_invalid",
    "runner_invalid",
    "permission_class_invalid",
    "history_cardinality_invalid",
    "created_event_invalid",
    "run_status_invalid",
    "unexpected_event",
    "event_limit_exceeded",
    "registration_selection_missing",
    "registration_selection_duplicate",
    "registration_selection_status_invalid",
    "registration_selection_payload_invalid",
    "registration_selection_event_identifier_mismatch",
    "repository_proposal_binding_missing",
    "repository_proposal_binding_duplicate",
    "repository_proposal_binding_status_invalid",
    "repository_proposal_binding_payload_invalid",
    "repository_proposal_binding_event_identifier_mismatch",
    "proposal_event_order_invalid",
    "durable_run_linkage_mismatch",
    "proposal_linkage_mismatch",
    "registration_component_linkage_mismatch",
    "disabled_semantics_mismatch",
)
_INSPECTION_FINDING_CODES = frozenset(_INSPECTION_FINDING_ORDER)
_INSPECTION_FINDING_RANK = {
    code: index for index, code in enumerate(_INSPECTION_FINDING_ORDER)
}

_BLOCK_REASON_ORDER = (
    "inspection_not_clean_complete",
    "inspection_run_binding_mismatch",
    "authorization_evaluation_failed",
    "authorization_replay_mismatch",
    "authorization_effect_not_permit",
    "authorization_decision_not_current",
    "authorization_permission_class_mismatch",
    "authorization_obligations_unexpected",
)
_BLOCK_REASON_CODES = frozenset(_BLOCK_REASON_ORDER)
_BLOCK_REASON_RANK = {
    code: index for index, code in enumerate(_BLOCK_REASON_ORDER)
}

_FINDING_ORDER = (
    "input_type_invalid",
    "input_tree_invalid",
    "input_bounds_exceeded",
    "shadow_shape_invalid",
    "shadow_fixed_semantics_mismatch",
    "inspection_shape_invalid",
    "inspection_semantics_mismatch",
    "inspection_digest_mismatch",
    "run_binding_state_mismatch",
    "evaluation_state_mismatch",
    "request_projection_mismatch",
    "request_digest_mismatch",
    "policy_projection_mismatch",
    "policy_digest_mismatch",
    "decision_projection_mismatch",
    "decision_digest_mismatch",
    "authorization_replay_mismatch",
    "shadow_summary_mismatch",
    "verification_failed",
)
_FINDING_CODES = frozenset(_FINDING_ORDER)
_FINDING_RANK = {code: index for index, code in enumerate(_FINDING_ORDER)}

_VERIFIED_VARIANTS = frozenset(
    {
        "evaluated_class_0",
        "evaluated_class_1",
        "not_evaluated",
        "failed_run_binding",
        "failed_evaluation",
        "failed_replay",
    }
)
_INVALID_REPORT_MESSAGE = (
    "repository proposal admission verification report is invalid"
)

# Capture the shipped evaluator boundary.  The verifier has no injection hook.
_BUILTIN_SHADOW_AUTHORIZATION_EVALUATOR = ShadowAuthorizationEvaluator
_BUILTIN_SHADOW_AUTHORIZATION_EVALUATE = (
    ShadowAuthorizationEvaluator.evaluate
)
_BUILTIN_CANONICAL_DIGEST = canonical_digest
_BUILTIN_DERIVE_PERMISSION_CLASS = derive_permission_class


@dataclass(frozen=True, slots=True)
class RepositoryProposalAdmissionVerificationFinding:
    """One fixed, value-free verification finding."""

    code: str

    def __post_init__(self) -> None:
        if type(self.code) is not str or self.code not in _FINDING_CODES:
            raise ValidationError(_INVALID_REPORT_MESSAGE)

    def to_mapping(self) -> dict[str, str]:
        self.__post_init__()
        return {"code": self.code}


@dataclass(frozen=True, slots=True, init=False)
class RepositoryProposalAdmissionVerificationReport:
    """No-effect result for internal replay of one untrusted mapping."""

    verification_complete: bool
    truncated: bool
    verified_variant: str | None
    findings: tuple[RepositoryProposalAdmissionVerificationFinding, ...]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError(
            "repository proposal admission verification reports are "
            "factory-created"
        )

    def __setstate__(self, state: Any) -> None:
        del state
        raise TypeError(
            "repository proposal admission verification reports are "
            "factory-created"
        )

    def __post_init__(self) -> None:
        if (
            type(self.verification_complete) is not bool
            or type(self.truncated) is not bool
            or (
                self.verified_variant is not None
                and (
                    type(self.verified_variant) is not str
                    or self.verified_variant not in _VERIFIED_VARIANTS
                )
            )
            or type(self.findings) is not tuple
            or len(self.findings) > _MAX_FINDINGS
            or any(
                type(finding)
                is not RepositoryProposalAdmissionVerificationFinding
                for finding in self.findings
            )
            or any(
                type(finding.code) is not str
                or finding.code not in _FINDING_CODES
                for finding in self.findings
            )
            or (self.truncated and self.verification_complete)
            or (not self.findings and not self.verification_complete)
            or (not self.findings and self.verified_variant is None)
            or (self.findings and self.verified_variant is not None)
        ):
            raise ValidationError(_INVALID_REPORT_MESSAGE)
        codes = tuple(finding.code for finding in self.findings)
        if (
            len(set(codes)) != len(codes)
            or codes
            != tuple(sorted(codes, key=_FINDING_RANK.__getitem__))
        ):
            raise ValidationError(_INVALID_REPORT_MESSAGE)

    @property
    def contract_valid(self) -> bool:
        """Whether the supplied mapping exactly matched the fixed contract."""

        try:
            self.__post_init__()
        except Exception:
            return False
        return bool(
            self.verification_complete
            and not self.truncated
            and self.verified_variant is not None
            and not self.findings
        )

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_mapping(self) -> dict[str, Any]:
        """Return a fresh privacy-safe mapping with explicit trust limits."""

        self.__post_init__()
        return {
            "schema_version": (
                REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_SCHEMA_VERSION
            ),
            "kind": REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_KIND,
            "verification_scope": "supplied_mapping",
            "verification_mode": "independent_replay",
            "source_trust": "untrusted",
            "verification_complete": self.verification_complete,
            "truncated": self.truncated,
            "contract_valid": self.contract_valid,
            "verified_variant": self.verified_variant,
            "input_authenticated": False,
            "durable_evidence_reinspected": False,
            "durable_evidence_verified": False,
            "fresh_authorization_established": False,
            "decision_authoritative": False,
            "enforcement_enabled": False,
            "authority_granted": False,
            "admission_performed": False,
            "action_performed": False,
            "action_receipt_created": False,
            "evidence_persisted": False,
            "repair_performed": False,
            "dispatch_enabled": False,
            "route_selected": False,
            "billing_assessed": False,
            "obligations_enforced": False,
            "finding_count": self.finding_count,
            "findings": [finding.to_mapping() for finding in self.findings],
        }


class _SnapshotFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


@dataclass(slots=True)
class _SnapshotState:
    nodes: int = 0
    containers: int = 0
    text_bytes: int = 0
    seen_container_ids: set[int] | None = None

    def __post_init__(self) -> None:
        self.seen_container_ids = set()

    def add_node(self) -> None:
        self.nodes += 1
        if self.nodes > _MAX_NODES:
            raise _SnapshotFailure("input_bounds_exceeded")

    def add_text(self, value: str) -> str:
        if len(value) > _MAX_TEXT_BYTES:
            raise _SnapshotFailure("input_bounds_exceeded")
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError:
            raise _SnapshotFailure("input_tree_invalid") from None
        if size > _MAX_TEXT_BYTES:
            raise _SnapshotFailure("input_bounds_exceeded")
        self.text_bytes += size
        if self.text_bytes > _MAX_TOTAL_TEXT_BYTES:
            raise _SnapshotFailure("input_bounds_exceeded")
        return value

    def add_container(self, value: dict[Any, Any] | list[Any]) -> None:
        assert self.seen_container_ids is not None
        identity = id(value)
        if identity in self.seen_container_ids:
            raise _SnapshotFailure("input_tree_invalid")
        self.seen_container_ids.add(identity)
        self.containers += 1
        if self.containers > _MAX_CONTAINERS:
            raise _SnapshotFailure("input_bounds_exceeded")


def _snapshot_json_tree(value: Any) -> dict[str, Any]:
    state = _SnapshotState()

    def copy_item(item: Any, depth: int) -> Any:
        if depth > _MAX_DEPTH:
            raise _SnapshotFailure("input_bounds_exceeded")
        state.add_node()
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if item.bit_length() > 63:
                raise _SnapshotFailure("input_bounds_exceeded")
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise _SnapshotFailure("input_tree_invalid")
            return item
        if type(item) is str:
            return state.add_text(item)
        if type(item) is list:
            state.add_container(item)
            expected_length = len(item)
            if expected_length > _MAX_LIST_ITEMS:
                raise _SnapshotFailure("input_bounds_exceeded")
            copied = [
                copy_item(child, depth + 1)
                for child in list.__iter__(item)
            ]
            if len(item) != expected_length or len(copied) != expected_length:
                raise _SnapshotFailure("input_tree_invalid")
            return copied
        if type(item) is dict:
            state.add_container(item)
            expected_length = len(item)
            if expected_length > _MAX_DICT_ENTRIES:
                raise _SnapshotFailure("input_bounds_exceeded")
            copied_dict: dict[str, Any] = {}
            try:
                for key, child in dict.items(item):
                    if type(key) is not str:
                        raise _SnapshotFailure("input_tree_invalid")
                    state.add_node()
                    copied_key = state.add_text(key)
                    copied_dict[copied_key] = copy_item(child, depth + 1)
            except RuntimeError:
                raise _SnapshotFailure("input_tree_invalid") from None
            if (
                len(item) != expected_length
                or len(copied_dict) != expected_length
            ):
                raise _SnapshotFailure("input_tree_invalid")
            return copied_dict
        raise _SnapshotFailure("input_tree_invalid")

    copied = copy_item(value, 0)
    if type(copied) is not dict:
        raise _SnapshotFailure("input_type_invalid")
    return copied


@dataclass(frozen=True, slots=True)
class _InspectionFacts:
    mapping: dict[str, Any]
    run_ref: str
    coverage: str
    truncated: bool
    inspected_event_count: int
    permission_class: int | None
    current_status: str | None
    proposal_digest: str | None
    proposal_ref: str | None
    proposal_version_ref: str | None
    registration_digest: str | None
    registration_ref: str | None
    registration_version: str | None
    repository_ref: str | None
    registration_selection_digest: str | None
    repository_proposal_binding_digest: str | None
    selection_sequence: int | None
    binding_sequence: int | None
    finding_codes: tuple[str, ...]

    @property
    def evidence_complete(self) -> bool:
        return self.coverage == "complete"

    @property
    def clean(self) -> bool:
        return bool(
            self.evidence_complete
            and not self.truncated
            and not self.finding_codes
        )

    @property
    def clean_complete(self) -> bool:
        required = (
            self.proposal_digest,
            self.proposal_ref,
            self.proposal_version_ref,
            self.registration_digest,
            self.registration_ref,
            self.registration_version,
            self.repository_ref,
            self.registration_selection_digest,
            self.repository_proposal_binding_digest,
            self.selection_sequence,
            self.binding_sequence,
        )
        return bool(
            self.clean
            and self.inspected_event_count == 3
            and self.permission_class in (0, 1)
            and self.current_status == "created"
            and all(value is not None for value in required)
            and self.selection_sequence < self.binding_sequence
        )


class _ContractFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def _is_digest(value: Any) -> bool:
    return bool(
        type(value) is str
        and _DIGEST_PATTERN.fullmatch(value) is not None
    )


def _optional_digest(value: Any) -> bool:
    return value is None or _is_digest(value)


def _inspection_facts(mapping: Any) -> _InspectionFacts:
    if type(mapping) is not dict or frozenset(mapping) != _INSPECTION_KEYS:
        raise _ContractFailure("inspection_shape_invalid")

    boolean_keys = (
        "repair_performed",
        "dispatch_enabled",
        "authority_granted",
        "truncated",
        "clean",
        "evidence_complete",
    )
    digest_keys = (
        "proposal_digest",
        "proposal_ref",
        "proposal_version_ref",
        "registration_digest",
        "registration_ref",
        "repository_ref",
        "registration_selection_digest",
        "repository_proposal_binding_digest",
    )
    if (
        type(mapping["schema_version"]) is not int
        or type(mapping["kind"]) is not str
        or type(mapping["inspection_scope"]) is not str
        or type(mapping["inspection_mode"]) is not str
        or type(mapping["validation_mode"]) is not str
        or any(type(mapping[key]) is not bool for key in boolean_keys)
        or type(mapping["run_ref"]) is not str
        or type(mapping["coverage"]) is not str
        or type(mapping["inspected_event_count"]) is not int
        or (
            mapping["permission_class"] is not None
            and type(mapping["permission_class"]) is not int
        )
        or (
            mapping["current_status"] is not None
            and type(mapping["current_status"]) is not str
        )
        or any(
            mapping[key] is not None and type(mapping[key]) is not str
            for key in digest_keys
        )
        or (
            mapping["registration_version"] is not None
            and type(mapping["registration_version"]) is not str
        )
        or any(
            mapping[key] is not None and type(mapping[key]) is not int
            for key in ("selection_sequence", "binding_sequence")
        )
        or type(mapping["finding_count"]) is not int
        or type(mapping["findings"]) is not list
        or any(
            type(finding) is not dict
            or frozenset(finding) != {"code"}
            or type(finding["code"]) is not str
            for finding in mapping["findings"]
        )
    ):
        raise _ContractFailure("inspection_shape_invalid")

    if (
        mapping["schema_version"]
        != REPOSITORY_PROPOSAL_INSPECTION_SCHEMA_VERSION
        or mapping["kind"] != REPOSITORY_PROPOSAL_INSPECTION_KIND
        or mapping["inspection_scope"] != "single_run"
        or mapping["inspection_mode"] != "read_only"
        or mapping["validation_mode"] != "read_only"
        or any(mapping[key] is not False for key in boolean_keys[:3])
        or not _is_digest(mapping["run_ref"])
        or mapping["coverage"] not in {"complete", "incomplete", "invalid"}
        or not 0 <= mapping["inspected_event_count"] <= 4
        or mapping["permission_class"] not in (None, 0, 1)
        or mapping["current_status"] not in (None, "created")
        or any(not _optional_digest(mapping[key]) for key in digest_keys)
        or (
            mapping["registration_version"] is not None
            and _VERSION_PATTERN.fullmatch(mapping["registration_version"])
            is None
        )
        or any(
            mapping[key] is not None
            and not 0 < mapping[key] <= (2**63) - 1
            for key in ("selection_sequence", "binding_sequence")
        )
        or not 0 <= mapping["finding_count"] <= 24
        or len(mapping["findings"]) > 24
    ):
        raise _ContractFailure("inspection_semantics_mismatch")

    finding_codes = tuple(
        finding["code"] for finding in mapping["findings"]
    )
    if (
        any(code not in _INSPECTION_FINDING_CODES for code in finding_codes)
        or len(set(finding_codes)) != len(finding_codes)
        or finding_codes
        != tuple(
            sorted(finding_codes, key=_INSPECTION_FINDING_RANK.__getitem__)
        )
        or mapping["finding_count"] != len(finding_codes)
    ):
        raise _ContractFailure("inspection_semantics_mismatch")

    facts = _InspectionFacts(
        mapping=mapping,
        run_ref=mapping["run_ref"],
        coverage=mapping["coverage"],
        truncated=mapping["truncated"],
        inspected_event_count=mapping["inspected_event_count"],
        permission_class=mapping["permission_class"],
        current_status=mapping["current_status"],
        proposal_digest=mapping["proposal_digest"],
        proposal_ref=mapping["proposal_ref"],
        proposal_version_ref=mapping["proposal_version_ref"],
        registration_digest=mapping["registration_digest"],
        registration_ref=mapping["registration_ref"],
        registration_version=mapping["registration_version"],
        repository_ref=mapping["repository_ref"],
        registration_selection_digest=(
            mapping["registration_selection_digest"]
        ),
        repository_proposal_binding_digest=(
            mapping["repository_proposal_binding_digest"]
        ),
        selection_sequence=mapping["selection_sequence"],
        binding_sequence=mapping["binding_sequence"],
        finding_codes=finding_codes,
    )
    if (
        mapping["evidence_complete"] is not facts.evidence_complete
        or mapping["clean"] is not facts.clean
    ):
        raise _ContractFailure("inspection_semantics_mismatch")

    selection_fields = (
        facts.proposal_digest,
        facts.registration_digest,
        facts.registration_ref,
        facts.registration_version,
        facts.repository_ref,
        facts.registration_selection_digest,
        facts.selection_sequence,
    )
    binding_fields = (
        facts.proposal_ref,
        facts.proposal_version_ref,
        facts.repository_proposal_binding_digest,
        facts.binding_sequence,
    )
    if facts.coverage == "complete":
        valid_variant = bool(
            not facts.truncated
            and facts.inspected_event_count == 3
            and facts.permission_class in (0, 1)
            and facts.current_status == "created"
            and all(value is not None for value in selection_fields)
            and all(value is not None for value in binding_fields)
            and facts.selection_sequence < facts.binding_sequence
            and not facts.finding_codes
        )
    elif facts.coverage == "incomplete":
        created_only = bool(
            facts.inspected_event_count == 1
            and all(value is None for value in selection_fields)
            and all(value is None for value in binding_fields)
            and facts.finding_codes
            == (
                "registration_selection_missing",
                "repository_proposal_binding_missing",
            )
        )
        selection_only = bool(
            facts.inspected_event_count == 2
            and all(value is not None for value in selection_fields)
            and all(value is None for value in binding_fields)
            and facts.finding_codes
            == ("repository_proposal_binding_missing",)
        )
        valid_variant = bool(
            not facts.truncated
            and facts.permission_class in (0, 1)
            and facts.current_status == "created"
            and (created_only or selection_only)
        )
    else:
        valid_variant = bool(
            facts.finding_codes
            and all(value is None for value in selection_fields)
            and all(value is None for value in binding_fields)
            and (
                not facts.truncated
                or "event_limit_exceeded" in facts.finding_codes
            )
        )
    if not valid_variant:
        raise _ContractFailure("inspection_semantics_mismatch")
    return facts


@dataclass(frozen=True, slots=True)
class _AdmissionProjection:
    permission_class: PermissionClass
    verb: ActionVerb
    operation: str
    intended_effect: str
    resource_type: str
    obligation_kind: ObligationKind


_PROJECTIONS = {
    PermissionClass.READ_ONLY: _AdmissionProjection(
        permission_class=PermissionClass.READ_ONLY,
        verb=ActionVerb.READ,
        operation=REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_OPERATION,
        intended_effect=(
            "observe_read_only_repository_proposal_admission_without_effect"
        ),
        resource_type=REPOSITORY_PROPOSAL_READ_ONLY_ADMISSION_RESOURCE_TYPE,
        obligation_kind=ObligationKind.READ_ONLY,
    ),
    PermissionClass.LOCAL_DRAFT: _AdmissionProjection(
        permission_class=PermissionClass.LOCAL_DRAFT,
        verb=ActionVerb.CREATE,
        operation=REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_OPERATION,
        intended_effect=(
            "nominate_local_draft_repository_proposal_without_effect"
        ),
        resource_type=REPOSITORY_PROPOSAL_LOCAL_DRAFT_ADMISSION_RESOURCE_TYPE,
        obligation_kind=ObligationKind.ISOLATED_LOCAL_ONLY,
    ),
}


def _build_request(
    *,
    inspection: _InspectionFacts,
    inspection_digest: str,
    evaluated_at: float,
    permission_class: PermissionClass,
) -> AuthorizationRequest:
    projection = _PROJECTIONS[permission_class]
    lineage = {
        "admission_shadow_schema_version": (
            REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION
        ),
        "binding_sequence": inspection.binding_sequence,
        "inspection_digest": inspection_digest,
        "permission_class": int(permission_class),
        "proposal_digest": inspection.proposal_digest,
        "proposal_ref": inspection.proposal_ref,
        "proposal_version_ref": inspection.proposal_version_ref,
        "registration_digest": inspection.registration_digest,
        "registration_ref": inspection.registration_ref,
        "registration_selection_digest": (
            inspection.registration_selection_digest
        ),
        "registration_version": inspection.registration_version,
        "repository_proposal_binding_digest": (
            inspection.repository_proposal_binding_digest
        ),
        "repository_ref": inspection.repository_ref,
        "run_ref": inspection.run_ref,
        "selection_sequence": inspection.selection_sequence,
    }
    environment = EnvironmentAttributes(
        evaluated_at=evaluated_at,
        isolation_state=IsolationState.VERIFIED,
        network_state=NetworkState.DISABLED,
        billing_route=BillingRoute.LOCAL_NON_AI,
        capacity_state=CapacityState.NOT_APPLICABLE,
        paid_continuation_protection=(
            PaidContinuationProtection.NOT_APPLICABLE
        ),
        circuit_state=CircuitState.CLOSED,
        flow_state=_FLOW_STATE,
    )
    request = AuthorizationRequest(
        request_id=(
            f"{REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE}:"
            f"{inspection.run_ref}"
        ),
        subject=SubjectAttributes(
            principal_id="controller:repository-proposal-admission-shadow",
            controller_id="ordomata:local-controller",
            role=Role.CONTROLLER,
            role_version="1",
            profile_id="profile:not-applicable-local-non-ai",
            runner_id=_RUNNER_ID,
            session_id=f"repository-proposal:{inspection.run_ref}",
        ),
        action=ActionAttributes(
            verb=projection.verb,
            operation=projection.operation,
            parameters_digest=_BUILTIN_CANONICAL_DIGEST(lineage),
            intended_effect=projection.intended_effect,
        ),
        resource=ResourceAttributes(
            resource_type=projection.resource_type,
            identifier=_BUILTIN_CANONICAL_DIGEST(
                {
                    "inspection_digest": inspection_digest,
                    "repository_proposal_binding_digest": (
                        inspection.repository_proposal_binding_digest
                    ),
                    "resource_type": projection.resource_type,
                    "run_ref": inspection.run_ref,
                }
            ),
            version=str(inspection.repository_proposal_binding_digest),
            owner="operator:local",
            trust_boundary=_TRUST_BOUNDARY,
            protected=False,
            sensitivity=ImpactLevel.LOW,
            repository_id=inspection.repository_ref,
            content_digest=inspection_digest,
        ),
        environment=environment,
        consequences=ConsequenceVector(
            confidentiality=ImpactLevel.LOW,
            integrity=ImpactLevel.LOW,
            availability=ImpactLevel.LOW,
            reach=Reach.LOCAL,
            destructive=False,
            reversible=True,
            sensitivity=ImpactLevel.LOW,
            blast_radius=BlastRadius.SINGLE_RESOURCE,
        ),
    )
    evidence = tuple(
        AttributeEvidence(
            evidence_id=(
                f"{REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE}:"
                f"{inspection.run_ref}:{attribute}"
            ),
            attribute=attribute,
            value_digest=_BUILTIN_CANONICAL_DIGEST(
                request.attribute_value(attribute)
            ),
            source=source,
            source_id=source_id,
            observed_at=evaluated_at,
            expires_at=evaluated_at + _EVIDENCE_LIFETIME_SECONDS,
            authenticated=True,
        )
        for attribute, source, source_id in (
            ("subject", EvidenceSource.CONTROLLER, "ordomata:local-controller"),
            ("action", EvidenceSource.CONTROLLER, "ordomata:local-controller"),
            (
                "resource",
                EvidenceSource.LOCAL_REGISTRY,
                "ordomata:repository-proposal-inspection",
            ),
            (
                "environment",
                EvidenceSource.CONTROLLER,
                "ordomata:local-controller",
            ),
            (
                "consequences",
                EvidenceSource.CONTROLLER,
                "ordomata:local-controller",
            ),
        )
    )
    return replace(request, evidence=evidence)


def _build_policy(permission_class: PermissionClass) -> PolicyBundle:
    projection = _PROJECTIONS[permission_class]
    return PolicyBundle(
        bundle_id=(
            f"{REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_ID}."
            f"class-{int(permission_class)}"
        ),
        version=REPOSITORY_PROPOSAL_ADMISSION_SHADOW_POLICY_VERSION,
        issued_at=0.0,
        evidence_requirements=(
            EvidenceRequirement(
                "subject",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "action",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "resource",
                (EvidenceSource.LOCAL_REGISTRY,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "environment",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
            EvidenceRequirement(
                "consequences",
                (EvidenceSource.CONTROLLER,),
                _EVIDENCE_LIFETIME_SECONDS,
            ),
        ),
        enabled_classes=(permission_class,),
        allowed_verbs=(projection.verb,),
        allowed_roles=(Role.CONTROLLER,),
        allowed_operations=(projection.operation,),
        allowed_resource_types=(projection.resource_type,),
        allowed_trust_boundaries=(_TRUST_BOUNDARY,),
        allowed_flow_states=(_FLOW_STATE,),
        allowed_network_states=(NetworkState.DISABLED,),
        allowed_billing_routes=(BillingRoute.LOCAL_NON_AI,),
        approval_requirements=(),
        decision_ttl_seconds=_DECISION_TTL_SECONDS,
    )


def _expected_obligations(
    permission_class: PermissionClass,
) -> tuple[DecisionObligation, ...]:
    projection = _PROJECTIONS[permission_class]
    return (
        DecisionObligation(
            ObligationKind.AUDIT_RECEIPT,
            "append_after_action",
        ),
        DecisionObligation(projection.obligation_kind, "required"),
    )


def _expected_decision(
    request: AuthorizationRequest,
    policy: PolicyBundle,
    permission_class: PermissionClass,
) -> AuthorizationDecision:
    evaluated_at = float(request.environment.evaluated_at)
    return AuthorizationDecision(
        request_id=request.request_id,
        request_digest=_BUILTIN_CANONICAL_DIGEST(request.to_canonical()),
        policy_bundle_id=policy.bundle_id,
        policy_version=policy.version,
        policy_digest=_BUILTIN_CANONICAL_DIGEST(policy.to_canonical()),
        effect=AuthorizationEffect.PERMIT,
        derived_permission_class=permission_class,
        reason_codes=(DecisionReason.CURRENT_STAGE_PERMIT,),
        reason_details=(
            f"derived Class {int(permission_class)} is enabled in shadow policy",
        ),
        matched_rule_ids=(f"phase-1c-class-{int(permission_class)}",),
        evidence_refs=tuple(
            sorted(record.evidence_id for record in request.evidence)
        ),
        issued_at=evaluated_at,
        expires_at=evaluated_at + _DECISION_TTL_SECONDS,
        obligations=_expected_obligations(permission_class),
    )


def _findings(
    codes: tuple[str, ...] | list[str] | set[str],
) -> tuple[RepositoryProposalAdmissionVerificationFinding, ...]:
    ordered = sorted(set(codes), key=_FINDING_RANK.__getitem__)
    return tuple(
        RepositoryProposalAdmissionVerificationFinding(code)
        for code in ordered[:_MAX_FINDINGS]
    )


def _report(
    codes: tuple[str, ...] | list[str] | set[str] = (),
    *,
    verification_complete: bool,
    truncated: bool = False,
    verified_variant: str | None = None,
) -> RepositoryProposalAdmissionVerificationReport:
    result = object.__new__(RepositoryProposalAdmissionVerificationReport)
    for name, value in (
        ("verification_complete", verification_complete),
        ("truncated", truncated),
        ("verified_variant", verified_variant),
        ("findings", _findings(codes)),
    ):
        object.__setattr__(result, name, value)
    result.__post_init__()
    return result


def _exact_json_equal(left: Any, right: Any) -> bool:
    """Compare already bounded JSON trees without numeric type coercion."""

    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return bool(
            frozenset(left) == frozenset(right)
            and all(
                _exact_json_equal(left[key], right[key]) for key in left
            )
        )
    if type(left) is list:
        return bool(
            len(left) == len(right)
            and all(
                _exact_json_equal(left_item, right_item)
                for left_item, right_item in zip(left, right, strict=True)
            )
        )
    return bool(left == right)


def _shadow_shape_valid(mapping: dict[str, Any]) -> bool:
    return bool(
        frozenset(mapping) == _SHADOW_KEYS
        and type(mapping["schema_version"]) is int
        and type(mapping["kind"]) is str
        and type(mapping["mode"]) is str
        and type(mapping["action_scope"]) is str
        and all(type(mapping[key]) is bool for key in _NO_EFFECT_KEYS)
        and type(mapping["run_ref"]) is str
        and type(mapping["inspection"]) is dict
        and type(mapping["inspection_digest"]) is str
        and (
            mapping["requested_permission_class"] is None
            or type(mapping["requested_permission_class"]) is int
        )
        and type(mapping["evaluation_status"]) is str
        and all(
            mapping[key] is None or type(mapping[key]) is dict
            for key in ("request", "policy", "decision")
        )
        and all(
            mapping[key] is None or type(mapping[key]) is str
            for key in ("request_digest", "policy_digest", "decision_digest")
        )
        and type(mapping["effect"]) is str
        and (
            mapping["derived_permission_class"] is None
            or type(mapping["derived_permission_class"]) is int
        )
        and all(
            type(mapping[key]) is bool
            for key in (
                "decision_current_at_evaluation",
                "permission_class_matches",
                "obligations_exact",
                "shadow_eligible",
            )
        )
        and type(mapping["block_reason_codes"]) is list
        and all(
            type(code) is str for code in mapping["block_reason_codes"]
        )
        and type(mapping["evaluated_at"]) is float
    )


def _fixed_semantics_valid(mapping: dict[str, Any]) -> bool:
    return bool(
        mapping["schema_version"]
        == REPOSITORY_PROPOSAL_ADMISSION_SHADOW_SCHEMA_VERSION
        and mapping["kind"] == REPOSITORY_PROPOSAL_ADMISSION_SHADOW_KIND
        and mapping["mode"] == "shadow"
        and mapping["action_scope"]
        == REPOSITORY_PROPOSAL_ADMISSION_SHADOW_ACTION_SCOPE
        and all(mapping[key] is False for key in _NO_EFFECT_KEYS)
    )


def _outer_scalar_semantics_valid(mapping: dict[str, Any]) -> bool:
    blocks = tuple(mapping["block_reason_codes"])
    return bool(
        _is_digest(mapping["run_ref"])
        and _is_digest(mapping["inspection_digest"])
        and mapping["requested_permission_class"] in (None, 0, 1)
        and mapping["evaluation_status"]
        in {"evaluated", "not_evaluated", "failed"}
        and all(
            mapping[key] is None or _is_digest(mapping[key])
            for key in ("request_digest", "policy_digest", "decision_digest")
        )
        and mapping["effect"] in {"permit", "indeterminate"}
        and mapping["derived_permission_class"] in (None, 0, 1)
        and all(code in _BLOCK_REASON_CODES for code in blocks)
        and len(set(blocks)) == len(blocks)
        and blocks
        == tuple(sorted(blocks, key=_BLOCK_REASON_RANK.__getitem__))
        and math.isfinite(mapping["evaluated_at"])
        and mapping["evaluated_at"] >= 0
    )


def _null_authorization_material(mapping: dict[str, Any]) -> bool:
    return all(
        mapping[key] is None
        for key in (
            "request",
            "request_digest",
            "policy",
            "policy_digest",
            "decision",
            "decision_digest",
        )
    )


def _indeterminate_summary_valid(mapping: dict[str, Any]) -> bool:
    return bool(
        mapping["effect"] == "indeterminate"
        and mapping["derived_permission_class"] is None
        and mapping["decision_current_at_evaluation"] is False
        and mapping["permission_class_matches"] is False
        and mapping["obligations_exact"] is False
        and mapping["shadow_eligible"] is False
    )


def _verify_evaluated(
    mapping: dict[str, Any],
    *,
    inspection: _InspectionFacts,
    inspection_digest: str,
) -> RepositoryProposalAdmissionVerificationReport:
    if mapping["run_ref"] != inspection.run_ref:
        return _report(
            ("run_binding_state_mismatch",),
            verification_complete=True,
        )
    if (
        not inspection.clean_complete
        or mapping["requested_permission_class"]
        != inspection.permission_class
        or tuple(mapping["block_reason_codes"])
        or any(
            mapping[key] is None
            for key in (
                "request",
                "request_digest",
                "policy",
                "policy_digest",
                "decision",
                "decision_digest",
            )
        )
    ):
        return _report(
            ("evaluation_state_mismatch",),
            verification_complete=True,
        )

    permission_class = PermissionClass(inspection.permission_class)
    request = _build_request(
        inspection=inspection,
        inspection_digest=inspection_digest,
        evaluated_at=mapping["evaluated_at"],
        permission_class=permission_class,
    )
    policy = _build_policy(permission_class)
    expected_decision = _expected_decision(
        request,
        policy,
        permission_class,
    )
    replayed = _BUILTIN_SHADOW_AUTHORIZATION_EVALUATE(
        _BUILTIN_SHADOW_AUTHORIZATION_EVALUATOR(),
        request,
        policy,
    )

    codes: list[str] = []
    if _BUILTIN_DERIVE_PERMISSION_CLASS(request) is not permission_class:
        codes.append("authorization_replay_mismatch")
    if (
        type(replayed) is not AuthorizationDecision
        or replayed != expected_decision
    ):
        codes.append("authorization_replay_mismatch")

    reported_request = mapping["request"]
    reported_policy = mapping["policy"]
    reported_decision = mapping["decision"]
    expected_request_mapping = request.to_canonical()
    expected_policy_mapping = policy.to_canonical()
    expected_decision_mapping = expected_decision.to_canonical()
    expected_request_digest = _BUILTIN_CANONICAL_DIGEST(
        expected_request_mapping
    )
    expected_policy_digest = _BUILTIN_CANONICAL_DIGEST(
        expected_policy_mapping
    )
    expected_decision_digest = _BUILTIN_CANONICAL_DIGEST(
        expected_decision_mapping
    )
    reported_request_digest = _BUILTIN_CANONICAL_DIGEST(
        reported_request
    )
    if reported_request_digest != mapping["request_digest"]:
        codes.append("request_digest_mismatch")
    if (
        reported_request_digest != expected_request_digest
        or not _exact_json_equal(
            reported_request,
            expected_request_mapping,
        )
    ):
        codes.append("request_projection_mismatch")
    reported_policy_digest = _BUILTIN_CANONICAL_DIGEST(reported_policy)
    if reported_policy_digest != mapping["policy_digest"]:
        codes.append("policy_digest_mismatch")
    if (
        reported_policy_digest != expected_policy_digest
        or not _exact_json_equal(
            reported_policy,
            expected_policy_mapping,
        )
    ):
        codes.append("policy_projection_mismatch")
    reported_decision_digest = _BUILTIN_CANONICAL_DIGEST(
        reported_decision
    )
    if reported_decision_digest != mapping["decision_digest"]:
        codes.append("decision_digest_mismatch")
    if (
        reported_decision_digest != expected_decision_digest
        or not _exact_json_equal(
            reported_decision,
            expected_decision_mapping,
        )
    ):
        codes.append("decision_projection_mismatch")

    if not (
        mapping["effect"] == "permit"
        and mapping["derived_permission_class"] == int(permission_class)
        and mapping["decision_current_at_evaluation"] is True
        and mapping["permission_class_matches"] is True
        and mapping["obligations_exact"] is True
        and mapping["shadow_eligible"] is True
    ):
        codes.append("shadow_summary_mismatch")
    if codes:
        return _report(codes, verification_complete=True)
    return _report(
        verification_complete=True,
        verified_variant=f"evaluated_class_{int(permission_class)}",
    )


def _verify_not_evaluated(
    mapping: dict[str, Any],
    *,
    inspection: _InspectionFacts,
) -> RepositoryProposalAdmissionVerificationReport:
    if mapping["run_ref"] != inspection.run_ref:
        return _report(
            ("run_binding_state_mismatch",),
            verification_complete=True,
        )
    if (
        inspection.clean_complete
        or mapping["requested_permission_class"]
        != inspection.permission_class
        or tuple(mapping["block_reason_codes"])
        != ("inspection_not_clean_complete",)
        or not _null_authorization_material(mapping)
    ):
        return _report(
            ("evaluation_state_mismatch",),
            verification_complete=True,
        )
    if not _indeterminate_summary_valid(mapping):
        return _report(
            ("shadow_summary_mismatch",),
            verification_complete=True,
        )
    return _report(
        verification_complete=True,
        verified_variant="not_evaluated",
    )


def _verify_failed(
    mapping: dict[str, Any],
    *,
    inspection: _InspectionFacts,
    inspection_digest: str,
) -> RepositoryProposalAdmissionVerificationReport:
    if (
        mapping["requested_permission_class"] != inspection.permission_class
        or not _null_authorization_material(mapping)
    ):
        return _report(
            ("evaluation_state_mismatch",),
            verification_complete=True,
        )
    blocks = tuple(mapping["block_reason_codes"])
    if blocks == ("inspection_run_binding_mismatch",):
        if mapping["run_ref"] == inspection.run_ref:
            return _report(
                ("run_binding_state_mismatch",),
                verification_complete=True,
            )
        variant = "failed_run_binding"
    elif blocks in {
        ("authorization_evaluation_failed",),
        ("authorization_replay_mismatch",),
    }:
        if mapping["run_ref"] != inspection.run_ref:
            return _report(
                ("run_binding_state_mismatch",),
                verification_complete=True,
            )
        if not inspection.clean_complete:
            return _report(
                ("evaluation_state_mismatch",),
                verification_complete=True,
            )
        if blocks == ("authorization_evaluation_failed",):
            variant = "failed_evaluation"
        else:
            try:
                permission_class = PermissionClass(
                    inspection.permission_class
                )
                request = _build_request(
                    inspection=inspection,
                    inspection_digest=inspection_digest,
                    evaluated_at=mapping["evaluated_at"],
                    permission_class=permission_class,
                )
                policy = _build_policy(permission_class)
                expected = _expected_decision(
                    request,
                    policy,
                    permission_class,
                )
                replayed = _BUILTIN_SHADOW_AUTHORIZATION_EVALUATE(
                    _BUILTIN_SHADOW_AUTHORIZATION_EVALUATOR(),
                    request,
                    policy,
                )
            except Exception:
                return _report(
                    ("evaluation_state_mismatch",),
                    verification_complete=True,
                )
            if (
                _BUILTIN_DERIVE_PERMISSION_CLASS(request)
                is not permission_class
                or type(replayed) is not AuthorizationDecision
                or replayed != expected
            ):
                return _report(
                    ("authorization_replay_mismatch",),
                    verification_complete=True,
                )
            variant = "failed_replay"
    else:
        return _report(
            ("evaluation_state_mismatch",),
            verification_complete=True,
        )
    if not _indeterminate_summary_valid(mapping):
        return _report(
            ("shadow_summary_mismatch",),
            verification_complete=True,
        )
    return _report(
        verification_complete=True,
        verified_variant=variant,
    )


def verify_repository_proposal_admission_shadow_mapping(
    value: object,
) -> RepositoryProposalAdmissionVerificationReport:
    """Independently replay one bounded, untrusted shadow mapping.

    ``contract_valid`` means only that the supplied values are internally
    consistent with the fixed schema and deterministic replay.  The result is
    never proof of origin, durable state, current freshness, or authorization.
    """

    if type(value) is not dict:
        return _report(
            ("input_type_invalid",),
            verification_complete=False,
        )
    try:
        mapping = _snapshot_json_tree(value)
    except _SnapshotFailure as error:
        return _report(
            (error.code,),
            verification_complete=False,
            truncated=error.code == "input_bounds_exceeded",
        )
    except (RecursionError, RuntimeError, UnicodeError):
        return _report(
            ("input_tree_invalid",),
            verification_complete=False,
        )

    try:
        if not _shadow_shape_valid(mapping):
            return _report(
                ("shadow_shape_invalid",),
                verification_complete=True,
            )
        if not _fixed_semantics_valid(mapping):
            return _report(
                ("shadow_fixed_semantics_mismatch",),
                verification_complete=True,
            )
        if not _outer_scalar_semantics_valid(mapping):
            return _report(
                ("evaluation_state_mismatch",),
                verification_complete=True,
            )
        try:
            inspection = _inspection_facts(mapping["inspection"])
        except _ContractFailure as error:
            return _report(
                (error.code,),
                verification_complete=True,
            )

        inspection_digest = _BUILTIN_CANONICAL_DIGEST(inspection.mapping)
        if mapping["inspection_digest"] != inspection_digest:
            return _report(
                ("inspection_digest_mismatch",),
                verification_complete=True,
            )

        if mapping["evaluation_status"] == "evaluated":
            return _verify_evaluated(
                mapping,
                inspection=inspection,
                inspection_digest=inspection_digest,
            )
        if mapping["evaluation_status"] == "not_evaluated":
            return _verify_not_evaluated(mapping, inspection=inspection)
        return _verify_failed(
            mapping,
            inspection=inspection,
            inspection_digest=inspection_digest,
        )
    except Exception:
        return _report(
            ("verification_failed",),
            verification_complete=False,
        )


__all__ = [
    "REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_KIND",
    "REPOSITORY_PROPOSAL_ADMISSION_VERIFICATION_SCHEMA_VERSION",
    "RepositoryProposalAdmissionVerificationFinding",
    "RepositoryProposalAdmissionVerificationReport",
    "verify_repository_proposal_admission_shadow_mapping",
]
