"""Digest-only evidence for dispatch-disabled repository proposals.

This module binds one freshly revalidated repository registration to an
existing controller-created attempt.  It persists two statusless events with
exact readback and never creates a run, changes run status, invokes a command,
creates a worktree, selects an execution profile, or grants authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import re
from typing import Any

from .authorization import canonical_digest, canonical_json
from .errors import ConfigurationError, ValidationError
from .models import PermissionClass, RunStatus
from .repository_registration import (
    REPOSITORY_REGISTRATION_EVIDENCE_KIND,
    REPOSITORY_REGISTRATION_SCHEMA_VERSION,
    RepositoryRegistration,
    fresh_repository_registration_evidence,
)
from .state import (
    RecordNotFoundError,
    RunEventRecord,
    RunRecord,
    RunStateSnapshot,
    SQLiteStateStore,
)


REPOSITORY_PROPOSAL_RUNNER_ID = "repository-proposal-disabled"
REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE = (
    "repository_registration_selection"
)
REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE = (
    "repository_proposal_attempt_binding"
)
REPOSITORY_REGISTRATION_SELECTION_SCHEMA_VERSION = 1
REPOSITORY_PROPOSAL_ATTEMPT_BINDING_SCHEMA_VERSION = 1

_SELECTION_KIND = "repository_registration_selection"
_BINDING_KIND = "repository_proposal_attempt"
_RESULT_KIND = "repository_proposal_attempt_evidence"
_INVALID_MESSAGE = "repository proposal evidence is invalid"
_PERSISTENCE_MESSAGE = "repository proposal evidence persistence is uncertain"
_MAX_CANONICAL_EVIDENCE_CHARACTERS = 131_072
_BUILTIN_FRESH_REPOSITORY_REGISTRATION_EVIDENCE = (
    fresh_repository_registration_evidence
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\Z"
)
_SELECTION_PAYLOAD_KEYS = frozenset(
    {"schema_version", "selection", "selection_digest"}
)
_SELECTION_KEYS = frozenset(
    {
        "kind",
        "proposal_digest",
        "run_ref",
        "selection_mode",
        "selected_registration",
        "selected_registration_evidence_digest",
    }
)
_REGISTRATION_EVIDENCE_KEYS = frozenset(
    {
        "authority_granted",
        "dispatch_enabled",
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
        "validation_mode",
        "verification_commands_digest",
    }
)
_BINDING_PAYLOAD_KEYS = frozenset(
    {"schema_version", "binding", "binding_digest"}
)
_BINDING_KEYS = frozenset(
    {
        "attempt",
        "authority_granted",
        "context_digest",
        "created_at_ref",
        "dispatch_enabled",
        "filesystem_identity_ref",
        "isolation_requirements_digest",
        "kind",
        "path_policy_digest",
        "permission_class",
        "proposal_digest",
        "proposal_ref",
        "proposal_version_ref",
        "registration_digest",
        "registration_evidence_digest",
        "registration_ref",
        "registration_selection_digest",
        "registration_version",
        "repository_ref",
        "resource_limits_digest",
        "review_policy_digest",
        "run_directory_ref",
        "run_ref",
        "runner_ref",
        "timeout_seconds",
        "validation_mode",
        "verification_commands_digest",
        "workspace_ref",
    }
)


class _InvalidRepositoryProposal(ValueError):
    """Private sentinel used to keep validation failures value-free."""


def _load_bounded_json_object(value: Any) -> dict[str, Any]:
    if not _is_bounded_text(value):
        raise _InvalidRepositoryProposal
    try:
        decoded = json.loads(value)
    except (RecursionError, UnicodeError, ValueError):
        raise _InvalidRepositoryProposal from None
    if type(decoded) is not dict:
        raise _InvalidRepositoryProposal
    return decoded


def _is_bounded_text(value: Any) -> bool:
    if type(value) is not str or len(value) > _MAX_CANONICAL_EVIDENCE_CHARACTERS:
        return False
    try:
        return len(value.encode("utf-8")) <= _MAX_CANONICAL_EVIDENCE_CHARACTERS
    except UnicodeError:
        return False


@dataclass(frozen=True, slots=True)
class RepositoryRegistrationSelection:
    """Deeply immutable canonical repository-registration selection."""

    _selection_json: str = field(repr=False)
    selection_digest: str

    @property
    def selection(self) -> dict[str, Any]:
        return _load_bounded_json_object(self._selection_json)

    @property
    def run_ref(self) -> str:
        return self.selection["run_ref"]

    @property
    def selected_registration(self) -> dict[str, Any]:
        selected = self.selection["selected_registration"]
        if type(selected) is not dict:
            raise _InvalidRepositoryProposal
        return selected

    @property
    def selected_registration_evidence_digest(self) -> str:
        return self.selection["selected_registration_evidence_digest"]

    def to_event_payload(self) -> dict[str, Any]:
        return {
            "schema_version": REPOSITORY_REGISTRATION_SELECTION_SCHEMA_VERSION,
            "selection": self.selection,
            "selection_digest": self.selection_digest,
        }


@dataclass(frozen=True, slots=True)
class RepositoryProposalAttemptBinding:
    """Deeply immutable canonical proposal-attempt binding."""

    _binding_json: str = field(repr=False)
    binding_digest: str

    @property
    def binding(self) -> dict[str, Any]:
        return _load_bounded_json_object(self._binding_json)

    @property
    def run_ref(self) -> str:
        return self.binding["run_ref"]

    @property
    def registration_selection_digest(self) -> str:
        return self.binding["registration_selection_digest"]

    def to_event_payload(self) -> dict[str, Any]:
        return {
            "schema_version": REPOSITORY_PROPOSAL_ATTEMPT_BINDING_SCHEMA_VERSION,
            "binding": self.binding,
            "binding_digest": self.binding_digest,
        }


@dataclass(frozen=True, slots=True)
class RepositoryProposalEvidence:
    """Privacy-bounded proof that both inert events read back exactly."""

    run_ref: str
    registration_ref: str
    registration_version: str
    repository_ref: str
    proposal_digest: str
    registration_digest: str
    registration_selection_digest: str
    repository_proposal_binding_digest: str
    selection_sequence: int
    binding_sequence: int

    def to_evidence(self) -> dict[str, Any]:
        return {
            "authority_granted": False,
            "binding_sequence": self.binding_sequence,
            "dispatch_enabled": False,
            "kind": _RESULT_KIND,
            "persistence_mode": "append_only_exact_readback",
            "proposal_digest": self.proposal_digest,
            "registration_digest": self.registration_digest,
            "registration_ref": self.registration_ref,
            "registration_selection_digest": (
                self.registration_selection_digest
            ),
            "registration_version": self.registration_version,
            "repository_proposal_binding_digest": (
                self.repository_proposal_binding_digest
            ),
            "repository_ref": self.repository_ref,
            "run_ref": self.run_ref,
            "run_status_at_readback": RunStatus.CREATED.value,
            "schema_version": (
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_SCHEMA_VERSION
            ),
            "selection_sequence": self.selection_sequence,
        }


@dataclass(frozen=True, slots=True)
class _ProposalHistory:
    selection: RepositoryRegistrationSelection | None
    selection_event: RunEventRecord | None
    binding: RepositoryProposalAttemptBinding | None
    binding_event: RunEventRecord | None
    event_ids: tuple[str, ...]
    event_count: int
    current_status: RunStatus


def _valid_event_record(event: Any, *, run_id: str) -> bool:
    return (
        type(event) is RunEventRecord
        and event.run_id == run_id
        and type(event.event_id) is str
        and bool(event.event_id)
        and type(event.event_type) is str
        and bool(event.event_type)
        and _is_bounded_text(event.payload_json)
        and (event.status is None or type(event.status) is RunStatus)
        and type(event.sequence) is int
        and event.sequence > 0
        and isinstance(event.occurred_at, (int, float))
        and not isinstance(event.occurred_at, bool)
        and math.isfinite(float(event.occurred_at))
        and event.occurred_at >= 0
    )


def _charge_text(value: str, *, bytes_used: list[int]) -> None:
    if not _is_bounded_text(value):
        raise _InvalidRepositoryProposal
    bytes_used[0] += len(value.encode("utf-8"))
    if bytes_used[0] > _MAX_CANONICAL_EVIDENCE_CHARACTERS:
        raise _InvalidRepositoryProposal


def _strict_json_copy(
    value: Any,
    *,
    depth: int,
    nodes: list[int],
    bytes_used: list[int],
) -> Any:
    nodes[0] += 1
    bytes_used[0] += 8
    if (
        depth > 64
        or nodes[0] > 10_000
        or bytes_used[0] > _MAX_CANONICAL_EVIDENCE_CHARACTERS
    ):
        raise _InvalidRepositoryProposal
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > 63:
            raise _InvalidRepositoryProposal
        return value
    if type(value) is str:
        _charge_text(value, bytes_used=bytes_used)
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise _InvalidRepositoryProposal
        return value
    if type(value) is list:
        return [
            _strict_json_copy(
                item,
                depth=depth + 1,
                nodes=nodes,
                bytes_used=bytes_used,
            )
            for item in value
        ]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise _InvalidRepositoryProposal
        for key in value:
            _charge_text(key, bytes_used=bytes_used)
        return {
            key: _strict_json_copy(
                item,
                depth=depth + 1,
                nodes=nodes,
                bytes_used=bytes_used,
            )
            for key, item in value.items()
        }
    raise _InvalidRepositoryProposal


def _object(value: Any, expected_keys: frozenset[str]) -> dict[str, Any]:
    copied = _strict_json_copy(
        value,
        depth=0,
        nodes=[0],
        bytes_used=[0],
    )
    if type(copied) is not dict or frozenset(copied) != expected_keys:
        raise _InvalidRepositoryProposal
    return copied


def _bounded_canonical_json(value: Any) -> str:
    encoded = canonical_json(value)
    if not _is_bounded_text(encoded):
        raise _InvalidRepositoryProposal
    return encoded


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _digest(value: Any) -> str:
    if not isinstance(value, str):
        raise _InvalidRepositoryProposal
    normalized = value if value.startswith("sha256:") else "sha256:" + value
    if not _is_digest(normalized):
        raise _InvalidRepositoryProposal
    return normalized


def _canonical_digest(value: Any) -> str:
    if not _is_digest(value):
        raise _InvalidRepositoryProposal
    return value


def _validate_registration_evidence(value: Any) -> dict[str, Any]:
    evidence = _object(value, _REGISTRATION_EVIDENCE_KEYS)
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"]
        != REPOSITORY_REGISTRATION_SCHEMA_VERSION
        or evidence["kind"] != REPOSITORY_REGISTRATION_EVIDENCE_KIND
        or evidence["validation_mode"] != "read_only"
        or evidence["dispatch_enabled"] is not False
        or evidence["authority_granted"] is not False
        or not isinstance(evidence["registration_version"], str)
        or len(evidence["registration_version"]) > 32
        or _VERSION_PATTERN.fullmatch(evidence["registration_version"]) is None
    ):
        raise _InvalidRepositoryProposal
    for name in _REGISTRATION_EVIDENCE_KEYS - {
        "authority_granted",
        "dispatch_enabled",
        "kind",
        "registration_version",
        "schema_version",
        "validation_mode",
    }:
        if not _is_digest(evidence[name]):
            raise _InvalidRepositoryProposal
    return evidence


def _selection_from_payload(value: Any) -> RepositoryRegistrationSelection:
    payload = _object(value, _SELECTION_PAYLOAD_KEYS)
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"]
        != REPOSITORY_REGISTRATION_SELECTION_SCHEMA_VERSION
    ):
        raise _InvalidRepositoryProposal
    selection = _object(payload["selection"], _SELECTION_KEYS)
    selected = _validate_registration_evidence(
        selection["selected_registration"]
    )
    if (
        selection["kind"] != _SELECTION_KIND
        or selection["selection_mode"] != "controller_owned"
        or not _is_digest(selection["proposal_digest"])
        or not _is_digest(selection["run_ref"])
        or not _is_digest(
            selection["selected_registration_evidence_digest"]
        )
        or not _is_digest(payload["selection_digest"])
        or selection["selected_registration_evidence_digest"]
        != canonical_digest(selected)
    ):
        raise _InvalidRepositoryProposal
    canonical_selection = _bounded_canonical_json(selection)
    if payload["selection_digest"] != canonical_digest(selection):
        raise _InvalidRepositoryProposal
    return RepositoryRegistrationSelection(
        canonical_selection,
        payload["selection_digest"],
    )


def validate_repository_registration_selection_payload(
    value: Any,
) -> RepositoryRegistrationSelection:
    """Strictly validate a persisted selection payload without effects."""

    try:
        return _selection_from_payload(value)
    except (TypeError, ValueError):
        raise ValidationError(_INVALID_MESSAGE) from None


def _binding_from_payload(
    value: Any,
    *,
    selection: RepositoryRegistrationSelection,
) -> RepositoryProposalAttemptBinding:
    if type(selection) is not RepositoryRegistrationSelection:
        raise _InvalidRepositoryProposal
    selection = _selection_from_payload(
        {
            "schema_version": (
                REPOSITORY_REGISTRATION_SELECTION_SCHEMA_VERSION
            ),
            "selection": selection.selection,
            "selection_digest": selection.selection_digest,
        }
    )
    payload = _object(value, _BINDING_PAYLOAD_KEYS)
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"]
        != REPOSITORY_PROPOSAL_ATTEMPT_BINDING_SCHEMA_VERSION
    ):
        raise _InvalidRepositoryProposal
    binding = _object(payload["binding"], _BINDING_KEYS)
    selected = selection.selected_registration
    if (
        binding["kind"] != _BINDING_KIND
        or binding["validation_mode"] != "read_only"
        or binding["dispatch_enabled"] is not False
        or binding["authority_granted"] is not False
        or binding["run_ref"] != selection.run_ref
        or binding["proposal_digest"] != selection.selection["proposal_digest"]
        or binding["registration_selection_digest"]
        != selection.selection_digest
        or binding["registration_evidence_digest"]
        != selection.selected_registration_evidence_digest
        or binding["registration_version"]
        != selected["registration_version"]
        or not _is_digest(payload["binding_digest"])
        or type(binding["attempt"]) is not int
        or not 0 < binding["attempt"] <= (2**63 - 1)
        or type(binding["timeout_seconds"]) is not int
        or not 0 < binding["timeout_seconds"] <= (2**63 - 1)
        or type(binding["permission_class"]) is not int
        or binding["permission_class"] not in (0, 1)
    ):
        raise _InvalidRepositoryProposal
    for name in _BINDING_KEYS - {
        "attempt",
        "authority_granted",
        "dispatch_enabled",
        "kind",
        "permission_class",
        "registration_version",
        "timeout_seconds",
        "validation_mode",
    }:
        if not _is_digest(binding[name]):
            raise _InvalidRepositoryProposal
    for name in (
        "filesystem_identity_ref",
        "isolation_requirements_digest",
        "path_policy_digest",
        "registration_digest",
        "registration_ref",
        "repository_ref",
        "resource_limits_digest",
        "review_policy_digest",
        "verification_commands_digest",
    ):
        if binding[name] != selected[name]:
            raise _InvalidRepositoryProposal
    canonical_binding = _bounded_canonical_json(binding)
    if payload["binding_digest"] != canonical_digest(binding):
        raise _InvalidRepositoryProposal
    return RepositoryProposalAttemptBinding(
        canonical_binding,
        payload["binding_digest"],
    )


def validate_repository_proposal_attempt_binding_payload(
    value: Any,
    *,
    selection: RepositoryRegistrationSelection,
) -> RepositoryProposalAttemptBinding:
    """Strictly validate a binding and all links to its selection."""

    try:
        return _binding_from_payload(value, selection=selection)
    except (TypeError, ValueError):
        raise ValidationError(_INVALID_MESSAGE) from None


def _build_selection(
    run: RunRecord,
    registration_evidence: dict[str, Any],
    *,
    proposal_digest: str,
) -> RepositoryRegistrationSelection:
    evidence = _validate_registration_evidence(registration_evidence)
    selection = {
        "kind": _SELECTION_KIND,
        "proposal_digest": _canonical_digest(proposal_digest),
        "run_ref": canonical_digest({"run_id": run.run_id}),
        "selection_mode": "controller_owned",
        "selected_registration": evidence,
        "selected_registration_evidence_digest": canonical_digest(evidence),
    }
    return _selection_from_payload(
        {
            "schema_version": (
                REPOSITORY_REGISTRATION_SELECTION_SCHEMA_VERSION
            ),
            "selection": selection,
            "selection_digest": canonical_digest(selection),
        }
    )


def _build_binding(
    run: RunRecord,
    selection: RepositoryRegistrationSelection,
    *,
    proposal_digest: str,
) -> RepositoryProposalAttemptBinding:
    selected = selection.selected_registration
    binding = {
        "attempt": run.attempt,
        "authority_granted": False,
        "context_digest": _digest(run.context_digest),
        "created_at_ref": canonical_digest({"created_at": run.created_at}),
        "dispatch_enabled": False,
        "filesystem_identity_ref": selected["filesystem_identity_ref"],
        "isolation_requirements_digest": selected[
            "isolation_requirements_digest"
        ],
        "kind": _BINDING_KIND,
        "path_policy_digest": selected["path_policy_digest"],
        "permission_class": int(run.permission_class),
        "proposal_digest": _canonical_digest(proposal_digest),
        "proposal_ref": canonical_digest({"proposal_id": run.task_id}),
        "proposal_version_ref": canonical_digest(
            {"proposal_version": run.task_version}
        ),
        "registration_digest": selected["registration_digest"],
        "registration_evidence_digest": (
            selection.selected_registration_evidence_digest
        ),
        "registration_ref": selected["registration_ref"],
        "registration_selection_digest": selection.selection_digest,
        "registration_version": selected["registration_version"],
        "repository_ref": selected["repository_ref"],
        "resource_limits_digest": selected["resource_limits_digest"],
        "review_policy_digest": selected["review_policy_digest"],
        "run_directory_ref": canonical_digest(
            {"run_directory": run.run_directory}
        ),
        "run_ref": selection.run_ref,
        "runner_ref": canonical_digest({"runner_id": run.runner_id}),
        "timeout_seconds": run.timeout_seconds,
        "validation_mode": "read_only",
        "verification_commands_digest": selected[
            "verification_commands_digest"
        ],
        "workspace_ref": canonical_digest({"workspace": run.workspace}),
    }
    return _binding_from_payload(
        {
            "schema_version": (
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_SCHEMA_VERSION
            ),
            "binding": binding,
            "binding_digest": canonical_digest(binding),
        },
        selection=selection,
    )


def _validate_run(run: RunRecord) -> None:
    if (
        type(run) is not RunRecord
        or run.runner_id != REPOSITORY_PROPOSAL_RUNNER_ID
        or run.permission_class
        not in (PermissionClass.READ_ONLY, PermissionClass.LOCAL_DRAFT)
        or type(run.permission_class) is not PermissionClass
        or type(run.timeout_seconds) is not int
        or run.timeout_seconds <= 0
        or type(run.attempt) is not int
        or run.attempt <= 0
        or isinstance(run.created_at, bool)
        or not isinstance(run.created_at, (int, float))
        or not math.isfinite(float(run.created_at))
        or run.created_at < 0
    ):
        raise _InvalidRepositoryProposal
    for value in (
        run.run_id,
        run.task_id,
        run.task_version,
        run.runner_id,
        run.workspace,
        run.run_directory,
    ):
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise _InvalidRepositoryProposal
    _digest(run.context_digest)


def _read_run_snapshot_value(
    snapshot: Any,
    run_id: str,
    *,
    expected_run: RunRecord | None = None,
) -> RunStateSnapshot:
    if (
        type(snapshot) is not RunStateSnapshot
        or type(snapshot.run) is not RunRecord
        or snapshot.run.run_id != run_id
        or type(snapshot.events) is not tuple
        or type(snapshot.current_status) is not RunStatus
        or (expected_run is not None and snapshot.run != expected_run)
    ):
        raise _InvalidRepositoryProposal
    _validate_run(snapshot.run)
    return snapshot


def _read_run_snapshot(
    state: SQLiteStateStore,
    run_id: str,
    *,
    expected_run: RunRecord | None = None,
) -> RunStateSnapshot:
    return _read_run_snapshot_value(
        state.get_run_snapshot(run_id),
        run_id,
        expected_run=expected_run,
    )


def _history(
    state: SQLiteStateStore,
    run_id: str,
    *,
    expected_run: RunRecord,
    expected_selection: RepositoryRegistrationSelection,
    expected_binding: RepositoryProposalAttemptBinding,
    snapshot: RunStateSnapshot | None = None,
) -> _ProposalHistory:
    selected_snapshot = (
        _read_run_snapshot(state, run_id, expected_run=expected_run)
        if snapshot is None
        else snapshot
    )
    if snapshot is not None:
        selected_snapshot = _read_run_snapshot_value(
            snapshot,
            run_id=run_id,
            expected_run=expected_run,
        )
    events = selected_snapshot.events
    if any(not _valid_event_record(event, run_id=run_id) for event in events):
        raise _InvalidRepositoryProposal
    if any(
        previous.sequence >= current.sequence
        for previous, current in zip(events, events[1:])
    ):
        raise _InvalidRepositoryProposal
    status_events = tuple(event for event in events if event.event_type == "status")
    allowed_types = {
        "status",
        REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
        REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
    }
    if (
        len(status_events) != 1
        or not events
        or events[0] is not status_events[0]
        or status_events[0].status is not RunStatus.CREATED
        or status_events[0].payload != {}
        or any(event.event_type not in allowed_types for event in events)
        or selected_snapshot.current_status is not RunStatus.CREATED
    ):
        raise _InvalidRepositoryProposal
    selection_events = tuple(
        event
        for event in events
        if event.event_type == REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE
    )
    binding_events = tuple(
        event
        for event in events
        if event.event_type == REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE
    )
    if len(selection_events) > 1 or len(binding_events) > 1:
        raise _InvalidRepositoryProposal
    if binding_events and not selection_events:
        raise _InvalidRepositoryProposal

    selection: RepositoryRegistrationSelection | None = None
    selection_event = selection_events[0] if selection_events else None
    if selection_event is not None:
        if selection_event.status is not None:
            raise _InvalidRepositoryProposal
        selection = _selection_from_payload(selection_event.payload)
        if (
            selection_event.event_id != selection.selection_digest
            or selection.to_event_payload()
            != expected_selection.to_event_payload()
        ):
            raise _InvalidRepositoryProposal

    binding: RepositoryProposalAttemptBinding | None = None
    binding_event = binding_events[0] if binding_events else None
    if binding_event is not None:
        if selection is None:
            raise _InvalidRepositoryProposal
        if binding_event.status is not None:
            raise _InvalidRepositoryProposal
        binding = _binding_from_payload(
            binding_event.payload,
            selection=selection,
        )
        if (
            binding_event.event_id != binding.binding_digest
            or binding.to_event_payload() != expected_binding.to_event_payload()
            or selection_event is None
            or selection_event.sequence >= binding_event.sequence
        ):
            raise _InvalidRepositoryProposal
    return _ProposalHistory(
        selection,
        selection_event,
        binding,
        binding_event,
        tuple(event.event_id for event in events),
        len(events),
        selected_snapshot.current_status,
    )


def _event_readback_state(
    state: SQLiteStateStore,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    event_id: str,
) -> bool | None:
    try:
        events = _read_run_snapshot(state, run_id).events
        if any(
            not _valid_event_record(event, run_id=run_id)
            for event in events
        ):
            return None
        matches = tuple(
            event
            for event in events
            if event.event_type == event_type
        )
    except Exception:
        return None
    if not matches:
        return False
    if len(matches) != 1:
        return None
    event = matches[0]
    if (
        event.event_id == event_id
        and event.status is None
        and event.payload == payload
    ):
        return True
    return None


def _append_required_event_once(
    state: SQLiteStateStore,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    event_id: str,
    required_event_ids: tuple[str, ...],
) -> None:
    try:
        state.append_event_once(
            run_id,
            event_type,
            payload,
            event_id=event_id,
            required_current_status=RunStatus.CREATED,
            required_event_ids=required_event_ids,
        )
    except BaseException as append_error:
        persisted = _event_readback_state(
            state,
            run_id,
            event_type,
            payload,
            event_id=event_id,
        )
        if isinstance(append_error, Exception):
            if persisted is True:
                return
            raise ConfigurationError(_PERSISTENCE_MESSAGE) from None
        raise
    if (
        _event_readback_state(
            state,
            run_id,
            event_type,
            payload,
            event_id=event_id,
        )
        is not True
    ):
        raise ConfigurationError(_PERSISTENCE_MESSAGE)


def bind_repository_proposal_attempt(
    state: SQLiteStateStore,
    *,
    run_id: str,
    proposal_digest: str,
    registration: RepositoryRegistration,
) -> RepositoryProposalEvidence:
    """Persist and exactly read back inert repository-proposal evidence.

    The run must already exist with the fixed non-executable proposal runner.
    Exact retries and an exact selection-only partial history are reconciled;
    every conflicting, ambiguous, or status-bearing history fails closed.
    """

    try:
        if type(state) is not SQLiteStateStore:
            raise _InvalidRepositoryProposal
        initial_snapshot = _read_run_snapshot(state, run_id)
        run = initial_snapshot.run
        if initial_snapshot.current_status is not RunStatus.CREATED:
            raise _InvalidRepositoryProposal
        registration_evidence = (
            _BUILTIN_FRESH_REPOSITORY_REGISTRATION_EVIDENCE(registration)
        )
        selection = _build_selection(
            run,
            registration_evidence,
            proposal_digest=proposal_digest,
        )
        binding = _build_binding(
            run,
            selection,
            proposal_digest=proposal_digest,
        )
        history = _history(
            state,
            run_id,
            expected_run=run,
            expected_selection=selection,
            expected_binding=binding,
            snapshot=initial_snapshot,
        )
        if history.selection is None:
            _append_required_event_once(
                state,
                run_id,
                REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE,
                selection.to_event_payload(),
                event_id=selection.selection_digest,
                required_event_ids=history.event_ids,
            )
            history = _history(
                state,
                run_id,
                expected_run=run,
                expected_selection=selection,
                expected_binding=binding,
            )
        if history.binding is None:
            if history.selection is None:
                raise _InvalidRepositoryProposal
            _append_required_event_once(
                state,
                run_id,
                REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE,
                binding.to_event_payload(),
                event_id=binding.binding_digest,
                required_event_ids=history.event_ids,
            )
            history = _history(
                state,
                run_id,
                expected_run=run,
                expected_selection=selection,
                expected_binding=binding,
            )
        if (
            history.selection is None
            or history.selection_event is None
            or history.binding is None
            or history.binding_event is None
            or history.event_count != 3
            or history.current_status is not RunStatus.CREATED
        ):
            raise _InvalidRepositoryProposal
        selected = history.selection.selected_registration
        return RepositoryProposalEvidence(
            run_ref=history.binding.run_ref,
            registration_ref=selected["registration_ref"],
            registration_version=selected["registration_version"],
            repository_ref=selected["repository_ref"],
            proposal_digest=history.binding.binding["proposal_digest"],
            registration_digest=selected["registration_digest"],
            registration_selection_digest=(
                history.selection.selection_digest
            ),
            repository_proposal_binding_digest=(
                history.binding.binding_digest
            ),
            selection_sequence=history.selection_event.sequence,
            binding_sequence=history.binding_event.sequence,
        )
    except ConfigurationError:
        raise
    except (
        AttributeError,
        RecordNotFoundError,
        TypeError,
        ValueError,
        ValidationError,
    ):
        raise ValidationError(_INVALID_MESSAGE) from None
    except Exception:
        raise ConfigurationError(_PERSISTENCE_MESSAGE) from None


__all__ = [
    "REPOSITORY_PROPOSAL_ATTEMPT_BINDING_EVENT_TYPE",
    "REPOSITORY_PROPOSAL_ATTEMPT_BINDING_SCHEMA_VERSION",
    "REPOSITORY_PROPOSAL_RUNNER_ID",
    "REPOSITORY_REGISTRATION_SELECTION_EVENT_TYPE",
    "REPOSITORY_REGISTRATION_SELECTION_SCHEMA_VERSION",
    "RepositoryProposalAttemptBinding",
    "RepositoryProposalEvidence",
    "RepositoryRegistrationSelection",
    "bind_repository_proposal_attempt",
    "validate_repository_proposal_attempt_binding_payload",
    "validate_repository_registration_selection_payload",
]
