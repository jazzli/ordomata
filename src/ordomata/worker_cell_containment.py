"""Pure contract evidence for the unimplemented repository worker cell.

The repository registration already declares the minimum isolation required for
future repository work.  This module binds that digest-only declaration to
preflight and postflight attestation shapes, but it does not inspect a host,
launch a cell, invoke a process, persist evidence, or authorize dispatch.

The only current backend is a deterministic mock.  It creates no worker cell
and is permanently non-authoritative: even a shape-complete assessment reports
that containment is unproven and worker execution remains disabled.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import math
import re
from typing import Any

from .authorization import canonical_digest, canonical_json
from .errors import ValidationError
from .repository_registration import (
    BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE,
    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE,
    REPOSITORY_REGISTRATION_EVIDENCE_KIND,
)


REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION = 1
REPOSITORY_WORKER_CELL_CONTAINMENT_CONTRACT_KIND = (
    "repository_worker_cell_containment_contract"
)
REPOSITORY_WORKER_CELL_CONTAINMENT_PREFLIGHT_KIND = (
    "repository_worker_cell_containment_preflight"
)
REPOSITORY_WORKER_CELL_CONTAINMENT_POSTFLIGHT_KIND = (
    "repository_worker_cell_containment_postflight"
)
REPOSITORY_WORKER_CELL_CONTAINMENT_ASSESSMENT_KIND = (
    "repository_worker_cell_containment_assessment"
)

_INVALID_CONTRACT_MESSAGE = "repository worker cell containment contract is invalid"
_INVALID_ATTESTATION_MESSAGE = (
    "repository worker cell containment attestation is invalid"
)
_INVALID_ASSESSMENT_MESSAGE = (
    "repository worker cell containment assessment is invalid"
)
_MAX_REGISTRATION_EVIDENCE_BYTES = 16 * 1024
_MAX_REGISTRATION_EVIDENCE_TEXT_BYTES = 512
_MAX_REGISTRATION_EVIDENCE_COUNT = 4_096
_MAX_REGISTRATION_COMMAND_COUNT = 80
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\Z"
)

_REQUIRED_ASSURANCE_NAMES = (
    "effective_user_non_root",
    "base_repository_read_only",
    "root_filesystem_read_only",
    "explicit_mounts_only",
    "git_metadata_hidden",
    "network_disabled",
    "credential_paths_denied",
    "control_sockets_denied",
    "fresh_cell_per_attempt",
    "resource_limits_attested",
)
_REQUIRED_POSTFLIGHT_NAMES = (
    "process_cleanup_verified",
    "filesystem_containment_verified",
    "outside_worktree_writes_absent",
    "network_access_absent",
    "credential_access_absent",
    "control_socket_access_absent",
    "resource_cleanup_verified",
)
_REGISTRATION_EVIDENCE_KEYS = frozenset(
    {
        "authority_granted",
        "baseline_attestation_source",
        "baseline_authenticity_verified",
        "baseline_command_results_digest",
        "baseline_freshness_verified",
        "baseline_result_count",
        "dispatch_enabled",
        "executable_toolchain_attestation_source",
        "executable_toolchain_authenticity_verified",
        "executable_toolchain_content_verified",
        "executable_toolchain_execution_correspondence_verified",
        "executable_toolchain_freshness_verified",
        "executable_toolchain_identities_digest",
        "executable_toolchain_identity_count",
        "executable_toolchain_resolution_verified",
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
        "toolchain_completeness_verified",
        "validation_mode",
        "verification_commands_digest",
    }
)
_REGISTRATION_DIGEST_KEYS = (
    "baseline_command_results_digest",
    "executable_toolchain_identities_digest",
    "filesystem_identity_ref",
    "isolation_requirements_digest",
    "path_policy_digest",
    "registration_digest",
    "registration_ref",
    "repository_ref",
    "resource_limits_digest",
    "review_policy_digest",
    "verification_commands_digest",
)
_REGISTRATION_FALSE_KEYS = (
    "authority_granted",
    "baseline_authenticity_verified",
    "baseline_freshness_verified",
    "dispatch_enabled",
    "executable_toolchain_authenticity_verified",
    "executable_toolchain_content_verified",
    "executable_toolchain_execution_correspondence_verified",
    "executable_toolchain_freshness_verified",
    "executable_toolchain_resolution_verified",
    "toolchain_completeness_verified",
)
_FINDING_ORDER = (
    "preflight_missing",
    "postflight_missing",
    "preflight_contract_mismatch",
    "postflight_contract_mismatch",
    "attestation_backend_mismatch",
    "cell_reference_mismatch",
    "attestation_time_order_invalid",
    "preflight_assurances_incomplete",
    "postflight_assurances_incomplete",
    "deterministic_mock_not_authoritative",
)
_FINDING_CODES = frozenset(_FINDING_ORDER)
_FINDING_RANK = {code: index for index, code in enumerate(_FINDING_ORDER)}


class WorkerCellContainmentBackendKind(StrEnum):
    """Backend identities recognized by the v1 contract."""

    DETERMINISTIC_MOCK = "deterministic_mock_v1"


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _is_timestamp(value: Any) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        timestamp = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(timestamp) and timestamp >= 0.0


def _validate_contract(value: Any) -> "RepositoryWorkerCellContainmentContract":
    if type(value) is not RepositoryWorkerCellContainmentContract:
        raise ValidationError(_INVALID_CONTRACT_MESSAGE)
    try:
        value.__post_init__()
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise ValidationError(_INVALID_CONTRACT_MESSAGE) from None
    return value


def _validate_preflight_attestation(
    value: Any,
) -> "WorkerCellPreflightAttestation":
    if type(value) is not WorkerCellPreflightAttestation:
        raise ValidationError(_INVALID_ATTESTATION_MESSAGE)
    try:
        value.__post_init__()
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise ValidationError(_INVALID_ATTESTATION_MESSAGE) from None
    return value


def _validate_postflight_attestation(
    value: Any,
) -> "WorkerCellPostflightAttestation":
    if type(value) is not WorkerCellPostflightAttestation:
        raise ValidationError(_INVALID_ATTESTATION_MESSAGE)
    try:
        value.__post_init__()
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise ValidationError(_INVALID_ATTESTATION_MESSAGE) from None
    return value


def _registration_snapshot(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValidationError(_INVALID_CONTRACT_MESSAGE)
    if len(value) > len(_REGISTRATION_EVIDENCE_KEYS):
        raise ValidationError(_INVALID_CONTRACT_MESSAGE)
    for item in value.values():
        if type(item) is str:
            try:
                if (
                    len(item.encode("utf-8"))
                    > _MAX_REGISTRATION_EVIDENCE_TEXT_BYTES
                ):
                    raise ValidationError(_INVALID_CONTRACT_MESSAGE)
            except UnicodeError:
                raise ValidationError(_INVALID_CONTRACT_MESSAGE) from None
        elif type(item) is int:
            if not 0 <= item <= _MAX_REGISTRATION_EVIDENCE_COUNT:
                raise ValidationError(_INVALID_CONTRACT_MESSAGE)
        elif type(item) is not bool:
            raise ValidationError(_INVALID_CONTRACT_MESSAGE)
    try:
        encoded = canonical_json(value)
        if len(encoded.encode("utf-8")) > _MAX_REGISTRATION_EVIDENCE_BYTES:
            raise ValueError
        snapshot = json.loads(encoded)
    except (RecursionError, UnicodeError, ValueError, TypeError):
        raise ValidationError(_INVALID_CONTRACT_MESSAGE) from None
    if type(snapshot) is not dict:
        raise ValidationError(_INVALID_CONTRACT_MESSAGE)
    return snapshot


def _validate_registration_evidence(value: dict[str, Any]) -> None:
    if frozenset(value) != _REGISTRATION_EVIDENCE_KEYS:
        raise ValidationError(_INVALID_CONTRACT_MESSAGE)
    if (
        value["schema_version"] != 4
        or value["kind"] != REPOSITORY_REGISTRATION_EVIDENCE_KIND
        or value["validation_mode"] != "read_only"
        or value["baseline_attestation_source"]
        != BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE
        or value["executable_toolchain_attestation_source"]
        != EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE
        or type(value["registration_version"]) is not str
        or _VERSION_PATTERN.fullmatch(value["registration_version"]) is None
        or any(value[name] is not False for name in _REGISTRATION_FALSE_KEYS)
        or any(not _is_digest(value[name]) for name in _REGISTRATION_DIGEST_KEYS)
        or any(
            type(value[name]) is not int
            or not 1 <= value[name] <= _MAX_REGISTRATION_COMMAND_COUNT
            for name in (
                "baseline_result_count",
                "executable_toolchain_identity_count",
            )
        )
    ):
        raise ValidationError(_INVALID_CONTRACT_MESSAGE)


@dataclass(frozen=True, slots=True)
class RepositoryWorkerCellContainmentContract:
    """Digest-only future containment requirements for one v4 registration."""

    registration_ref: str
    repository_ref: str
    registration_digest: str
    registration_evidence_digest: str
    filesystem_identity_ref: str
    isolation_requirements_digest: str
    resource_limits_digest: str
    path_policy_digest: str
    review_policy_digest: str
    verification_commands_digest: str

    def __post_init__(self) -> None:
        if any(
            not _is_digest(getattr(self, name))
            for name in (
                "registration_ref",
                "repository_ref",
                "registration_digest",
                "registration_evidence_digest",
                "filesystem_identity_ref",
                "isolation_requirements_digest",
                "resource_limits_digest",
                "path_policy_digest",
                "review_policy_digest",
                "verification_commands_digest",
            )
        ):
            raise ValidationError(_INVALID_CONTRACT_MESSAGE)

    @property
    def contract_digest(self) -> str:
        return canonical_digest(self.to_contract_mapping())

    def to_contract_mapping(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "filesystem_identity_ref": self.filesystem_identity_ref,
            "isolation_requirements_digest": (
                self.isolation_requirements_digest
            ),
            "kind": REPOSITORY_WORKER_CELL_CONTAINMENT_CONTRACT_KIND,
            "path_policy_digest": self.path_policy_digest,
            "registration_digest": self.registration_digest,
            "registration_evidence_digest": self.registration_evidence_digest,
            "registration_ref": self.registration_ref,
            "repository_ref": self.repository_ref,
            "required_assurances": list(_REQUIRED_ASSURANCE_NAMES),
            "required_backend": "local_container",
            "required_network_mode": "disabled",
            "resource_limits_digest": self.resource_limits_digest,
            "review_policy_digest": self.review_policy_digest,
            "schema_version": REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION,
            "verification_commands_digest": self.verification_commands_digest,
        }

    def to_mapping(self) -> dict[str, Any]:
        mapping = self.to_contract_mapping()
        mapping.update(
            {
                "authority_granted": False,
                "backend_implemented": False,
                "containment_proven": False,
                "dispatch_enabled": False,
                "registration_evidence_revalidated": False,
                "worker_execution_permitted": False,
                "contract_digest": self.contract_digest,
            }
        )
        return mapping


def derive_repository_worker_cell_containment_contract(
    registration_evidence: dict[str, Any],
) -> RepositoryWorkerCellContainmentContract:
    """Bind one untrusted v4 registration-evidence snapshot to requirements.

    The input is deliberately treated as a bounded detached snapshot.  Its
    internal shape is validated, but this function does not revalidate a
    repository, inspect a filesystem, authenticate evidence, or grant any
    execution authority.
    """

    snapshot = _registration_snapshot(registration_evidence)
    _validate_registration_evidence(snapshot)
    return RepositoryWorkerCellContainmentContract(
        registration_ref=snapshot["registration_ref"],
        repository_ref=snapshot["repository_ref"],
        registration_digest=snapshot["registration_digest"],
        registration_evidence_digest=canonical_digest(snapshot),
        filesystem_identity_ref=snapshot["filesystem_identity_ref"],
        isolation_requirements_digest=snapshot[
            "isolation_requirements_digest"
        ],
        resource_limits_digest=snapshot["resource_limits_digest"],
        path_policy_digest=snapshot["path_policy_digest"],
        review_policy_digest=snapshot["review_policy_digest"],
        verification_commands_digest=snapshot["verification_commands_digest"],
    )


@dataclass(frozen=True, slots=True)
class WorkerCellPreflightAttestation:
    """One digest-only preflight observation from a future worker backend."""

    contract_digest: str
    cell_ref: str
    backend_kind: WorkerCellContainmentBackendKind
    observed_at: float
    effective_user_non_root: bool
    base_repository_read_only: bool
    root_filesystem_read_only: bool
    explicit_mounts_only: bool
    git_metadata_hidden: bool
    network_disabled: bool
    credential_paths_denied: bool
    control_sockets_denied: bool
    fresh_cell_per_attempt: bool
    resource_limits_attested: bool

    def __post_init__(self) -> None:
        if (
            not _is_digest(self.contract_digest)
            or not _is_digest(self.cell_ref)
            or type(self.backend_kind) is not WorkerCellContainmentBackendKind
            or not _is_timestamp(self.observed_at)
            or any(
                type(getattr(self, name)) is not bool
                for name in _REQUIRED_ASSURANCE_NAMES
            )
        ):
            raise ValidationError(_INVALID_ATTESTATION_MESSAGE)

    @property
    def assurances_complete(self) -> bool:
        self.__post_init__()
        return all(getattr(self, name) for name in _REQUIRED_ASSURANCE_NAMES)

    def to_mapping(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "backend_kind": self.backend_kind.value,
            "cell_ref": self.cell_ref,
            "contract_digest": self.contract_digest,
            "effective_user_non_root": self.effective_user_non_root,
            "base_repository_read_only": self.base_repository_read_only,
            "root_filesystem_read_only": self.root_filesystem_read_only,
            "explicit_mounts_only": self.explicit_mounts_only,
            "git_metadata_hidden": self.git_metadata_hidden,
            "network_disabled": self.network_disabled,
            "credential_paths_denied": self.credential_paths_denied,
            "control_sockets_denied": self.control_sockets_denied,
            "fresh_cell_per_attempt": self.fresh_cell_per_attempt,
            "resource_limits_attested": self.resource_limits_attested,
            "kind": REPOSITORY_WORKER_CELL_CONTAINMENT_PREFLIGHT_KIND,
            "observed_at": self.observed_at,
            "schema_version": REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class WorkerCellPostflightAttestation:
    """One digest-only postflight observation from a future worker backend."""

    contract_digest: str
    cell_ref: str
    backend_kind: WorkerCellContainmentBackendKind
    observed_at: float
    execution_started: bool
    process_cleanup_verified: bool
    filesystem_containment_verified: bool
    outside_worktree_writes_absent: bool
    network_access_absent: bool
    credential_access_absent: bool
    control_socket_access_absent: bool
    resource_cleanup_verified: bool

    def __post_init__(self) -> None:
        if (
            not _is_digest(self.contract_digest)
            or not _is_digest(self.cell_ref)
            or type(self.backend_kind) is not WorkerCellContainmentBackendKind
            or not _is_timestamp(self.observed_at)
            or type(self.execution_started) is not bool
            or any(
                type(getattr(self, name)) is not bool
                for name in _REQUIRED_POSTFLIGHT_NAMES
            )
        ):
            raise ValidationError(_INVALID_ATTESTATION_MESSAGE)

    @property
    def assurances_complete(self) -> bool:
        self.__post_init__()
        return (
            not self.execution_started
            and all(getattr(self, name) for name in _REQUIRED_POSTFLIGHT_NAMES)
        )

    def to_mapping(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "backend_kind": self.backend_kind.value,
            "cell_ref": self.cell_ref,
            "contract_digest": self.contract_digest,
            "execution_started": self.execution_started,
            "process_cleanup_verified": self.process_cleanup_verified,
            "filesystem_containment_verified": (
                self.filesystem_containment_verified
            ),
            "outside_worktree_writes_absent": (
                self.outside_worktree_writes_absent
            ),
            "network_access_absent": self.network_access_absent,
            "credential_access_absent": self.credential_access_absent,
            "control_socket_access_absent": self.control_socket_access_absent,
            "resource_cleanup_verified": self.resource_cleanup_verified,
            "kind": REPOSITORY_WORKER_CELL_CONTAINMENT_POSTFLIGHT_KIND,
            "observed_at": self.observed_at,
            "schema_version": REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class RepositoryWorkerCellContainmentAssessment:
    """A fail-closed, non-authoritative v1 containment assessment."""

    contract_digest: str
    backend_kind: WorkerCellContainmentBackendKind | None
    cell_ref: str | None
    preflight_present: bool
    postflight_present: bool
    preflight_contract_matched: bool
    postflight_contract_matched: bool
    backend_matched: bool
    cell_ref_matched: bool
    time_ordered: bool
    preflight_assurances_complete: bool
    postflight_assurances_complete: bool
    finding_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not _is_digest(self.contract_digest)
            or self.backend_kind is not None
            and type(self.backend_kind) is not WorkerCellContainmentBackendKind
            or self.cell_ref is not None and not _is_digest(self.cell_ref)
            or any(
                type(getattr(self, name)) is not bool
                for name in (
                    "preflight_present",
                    "postflight_present",
                    "preflight_contract_matched",
                    "postflight_contract_matched",
                    "backend_matched",
                    "cell_ref_matched",
                    "time_ordered",
                    "preflight_assurances_complete",
                    "postflight_assurances_complete",
                )
            )
            or type(self.finding_codes) is not tuple
            or any(code not in _FINDING_CODES for code in self.finding_codes)
            or len(set(self.finding_codes)) != len(self.finding_codes)
            or self.finding_codes
            != tuple(sorted(self.finding_codes, key=_FINDING_RANK.__getitem__))
            or "deterministic_mock_not_authoritative"
            not in self.finding_codes
        ):
            raise ValidationError(_INVALID_ASSESSMENT_MESSAGE)

    @property
    def declared_contract_satisfied(self) -> bool:
        self.__post_init__()
        return all(
            (
                self.preflight_present,
                self.postflight_present,
                self.preflight_contract_matched,
                self.postflight_contract_matched,
                self.backend_matched,
                self.cell_ref_matched,
                self.time_ordered,
                self.preflight_assurances_complete,
                self.postflight_assurances_complete,
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "assessment_scope": "contract_only_no_host_verification",
            "authority_granted": False,
            "backend_implemented": False,
            "backend_kind": (
                None if self.backend_kind is None else self.backend_kind.value
            ),
            "backend_matched": self.backend_matched,
            "cell_ref": self.cell_ref,
            "cell_ref_matched": self.cell_ref_matched,
            "containment_proven": False,
            "contract_digest": self.contract_digest,
            "declared_contract_satisfied": self.declared_contract_satisfied,
            "dispatch_enabled": False,
            "enforcement_enabled": False,
            "finding_codes": list(self.finding_codes),
            "finding_count": len(self.finding_codes),
            "kind": REPOSITORY_WORKER_CELL_CONTAINMENT_ASSESSMENT_KIND,
            "postflight_assurances_complete": (
                self.postflight_assurances_complete
            ),
            "postflight_contract_matched": self.postflight_contract_matched,
            "postflight_present": self.postflight_present,
            "preflight_assurances_complete": (
                self.preflight_assurances_complete
            ),
            "preflight_contract_matched": self.preflight_contract_matched,
            "preflight_present": self.preflight_present,
            "schema_version": REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION,
            "state_persisted": False,
            "time_ordered": self.time_ordered,
            "worker_execution_permitted": False,
        }


@dataclass(frozen=True, slots=True)
class DeterministicWorkerCellContainmentBackend:
    """No-I/O mock that exercises the attestation shape without a worker cell."""

    backend_kind: WorkerCellContainmentBackendKind = (
        WorkerCellContainmentBackendKind.DETERMINISTIC_MOCK
    )

    def __post_init__(self) -> None:
        if self.backend_kind is not WorkerCellContainmentBackendKind.DETERMINISTIC_MOCK:
            raise ValidationError(_INVALID_CONTRACT_MESSAGE)

    def preflight(
        self,
        contract: RepositoryWorkerCellContainmentContract,
        *,
        attempt_ref: str,
        observed_at: float,
    ) -> WorkerCellPreflightAttestation:
        """Return deterministic declarations without inspecting a host or cell."""

        contract = _validate_contract(contract)
        if not _is_digest(attempt_ref) or not _is_timestamp(observed_at):
            raise ValidationError(_INVALID_ATTESTATION_MESSAGE)
        cell_ref = canonical_digest(
            {
                "attempt_ref": attempt_ref,
                "backend_kind": self.backend_kind.value,
                "contract_digest": contract.contract_digest,
                "kind": "deterministic_worker_cell_reference",
                "schema_version": REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION,
            }
        )
        return WorkerCellPreflightAttestation(
            contract_digest=contract.contract_digest,
            cell_ref=cell_ref,
            backend_kind=self.backend_kind,
            observed_at=float(observed_at),
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

    def postflight(
        self,
        preflight: WorkerCellPreflightAttestation,
        *,
        observed_at: float,
    ) -> WorkerCellPostflightAttestation:
        """Return a no-execution postflight declaration without cleanup work."""

        if (
            type(preflight) is not WorkerCellPreflightAttestation
            or not _is_timestamp(observed_at)
        ):
            raise ValidationError(_INVALID_ATTESTATION_MESSAGE)
        preflight = _validate_preflight_attestation(preflight)
        if (
            preflight.backend_kind is not self.backend_kind
            or float(observed_at) < float(preflight.observed_at)
        ):
            raise ValidationError(_INVALID_ATTESTATION_MESSAGE)
        return WorkerCellPostflightAttestation(
            contract_digest=preflight.contract_digest,
            cell_ref=preflight.cell_ref,
            backend_kind=self.backend_kind,
            observed_at=float(observed_at),
            execution_started=False,
            process_cleanup_verified=True,
            filesystem_containment_verified=True,
            outside_worktree_writes_absent=True,
            network_access_absent=True,
            credential_access_absent=True,
            control_socket_access_absent=True,
            resource_cleanup_verified=True,
        )


def assess_repository_worker_cell_containment(
    contract: RepositoryWorkerCellContainmentContract,
    *,
    preflight: WorkerCellPreflightAttestation | None,
    postflight: WorkerCellPostflightAttestation | None,
) -> RepositoryWorkerCellContainmentAssessment:
    """Assess one pair of untrusted declarations without enabling a worker.

    V1 recognizes only the deterministic mock backend.  It always yields a
    non-authoritative assessment, even if its deterministic attestation shape
    is complete.  A future real backend requires a new reviewed contract
    version rather than silently changing this result.
    """

    contract = _validate_contract(contract)
    preflight_valid = type(preflight) is WorkerCellPreflightAttestation
    postflight_valid = type(postflight) is WorkerCellPostflightAttestation
    if preflight_valid:
        preflight = _validate_preflight_attestation(preflight)
    if postflight_valid:
        postflight = _validate_postflight_attestation(postflight)
    findings: list[str] = []

    if not preflight_valid:
        findings.append("preflight_missing")
    if not postflight_valid:
        findings.append("postflight_missing")

    preflight_contract_matched = bool(
        preflight_valid and preflight.contract_digest == contract.contract_digest
    )
    postflight_contract_matched = bool(
        postflight_valid and postflight.contract_digest == contract.contract_digest
    )
    if preflight_valid and not preflight_contract_matched:
        findings.append("preflight_contract_mismatch")
    if postflight_valid and not postflight_contract_matched:
        findings.append("postflight_contract_mismatch")

    backend_matched = bool(
        preflight_valid
        and postflight_valid
        and preflight.backend_kind is postflight.backend_kind
    )
    if preflight_valid and postflight_valid and not backend_matched:
        findings.append("attestation_backend_mismatch")

    cell_ref_matched = bool(
        preflight_valid and postflight_valid and preflight.cell_ref == postflight.cell_ref
    )
    if preflight_valid and postflight_valid and not cell_ref_matched:
        findings.append("cell_reference_mismatch")

    time_ordered = bool(
        preflight_valid
        and postflight_valid
        and float(postflight.observed_at) >= float(preflight.observed_at)
    )
    if preflight_valid and postflight_valid and not time_ordered:
        findings.append("attestation_time_order_invalid")

    preflight_assurances_complete = bool(
        preflight_valid and preflight.assurances_complete
    )
    if preflight_valid and not preflight_assurances_complete:
        findings.append("preflight_assurances_incomplete")

    postflight_assurances_complete = bool(
        postflight_valid and postflight.assurances_complete
    )
    if postflight_valid and not postflight_assurances_complete:
        findings.append("postflight_assurances_incomplete")

    findings.append("deterministic_mock_not_authoritative")
    backend_kind = (
        preflight.backend_kind
        if preflight_valid
        else postflight.backend_kind
        if postflight_valid
        else None
    )
    cell_ref = (
        preflight.cell_ref
        if preflight_valid and postflight_valid and cell_ref_matched
        else None
    )
    return RepositoryWorkerCellContainmentAssessment(
        contract_digest=contract.contract_digest,
        backend_kind=backend_kind,
        cell_ref=cell_ref,
        preflight_present=preflight_valid,
        postflight_present=postflight_valid,
        preflight_contract_matched=preflight_contract_matched,
        postflight_contract_matched=postflight_contract_matched,
        backend_matched=backend_matched,
        cell_ref_matched=cell_ref_matched,
        time_ordered=time_ordered,
        preflight_assurances_complete=preflight_assurances_complete,
        postflight_assurances_complete=postflight_assurances_complete,
        finding_codes=tuple(sorted(set(findings), key=_FINDING_RANK.__getitem__)),
    )


__all__ = [
    "DeterministicWorkerCellContainmentBackend",
    "REPOSITORY_WORKER_CELL_CONTAINMENT_ASSESSMENT_KIND",
    "REPOSITORY_WORKER_CELL_CONTAINMENT_CONTRACT_KIND",
    "REPOSITORY_WORKER_CELL_CONTAINMENT_POSTFLIGHT_KIND",
    "REPOSITORY_WORKER_CELL_CONTAINMENT_PREFLIGHT_KIND",
    "REPOSITORY_WORKER_CELL_CONTAINMENT_SCHEMA_VERSION",
    "RepositoryWorkerCellContainmentAssessment",
    "RepositoryWorkerCellContainmentContract",
    "WorkerCellContainmentBackendKind",
    "WorkerCellPostflightAttestation",
    "WorkerCellPreflightAttestation",
    "assess_repository_worker_cell_containment",
    "derive_repository_worker_cell_containment_contract",
]
