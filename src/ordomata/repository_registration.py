"""Versioned, privacy-bounded repository registration validation.

This module is deliberately read-only.  It validates controller-supplied
repository facts and an immutable registration document, then returns bounded
content-addressed evidence.  It does not create worktrees, invoke commands or
workers, mutate state, grant repository authority, or enable supervisor
dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata
from typing import Any

from .authorization import canonical_digest
from .environment import is_sensitive_environment_name
from .errors import ConfigurationError, ValidationError
from .redaction import contains_credential_material
from .schema import parse_json_document, require_valid


REPOSITORY_REGISTRATION_SCHEMA_VERSION = 4
REPOSITORY_REGISTRATION_SUPPORTED_SCHEMA_VERSIONS = frozenset({1, 2, 3, 4})
REPOSITORY_REGISTRATION_KIND = "repository_registration"
REPOSITORY_REGISTRATION_EVIDENCE_KIND = "repository_registration_validation"
BASELINE_COMMAND_RESULTS_KIND = "repository_baseline_command_results"
BASELINE_COMMAND_RESULTS_SCHEMA_VERSION = 1
BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE = "controller_supplied"
EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND = (
    "repository_executable_toolchain_identities"
)
EXECUTABLE_TOOLCHAIN_IDENTITIES_SCHEMA_VERSION = 1
EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE = "controller_supplied"
DECLARED_EXECUTABLE_KIND = "repository_declared_executable"

_INVALID_MESSAGE = "repository registration is invalid"
_LOAD_MESSAGE = "repository registration could not be loaded"
_SCHEMA_LOAD_MESSAGE = "repository registration schema could not be loaded"
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_REPOSITORY_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._/-]{2,199}")
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})"
)
_WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(r"[A-Za-z]:[\\/]")
_BARE_EXECUTABLE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_MAX_BASELINE_RESULTS = 80
_MAX_EXECUTABLE_TOOLCHAIN_IDENTITIES = 80
_MAX_UNIX_MILLISECONDS = 9_007_199_254_740_991
_MAX_REGISTRATION_DOCUMENT_BYTES = 8 * 1024 * 1024
_MAX_SCHEMA_DOCUMENT_BYTES = 1024 * 1024
_MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
_MAX_SNAPSHOT_INTEGER_BITS = 64
_MANDATORY_PROTECTED_PATHS = frozenset({".agentops", ".git", ".ordomata"})
_EXCLUSION_PATH_NAMES = ("generated_paths", "vendor_paths")
_MAX_EXCLUSION_PATHS_PER_CATEGORY = 64
_MAX_EXCLUSION_PATHS = 128
_MAX_EXCLUSION_PATH_BYTES = 32_768
_EXCLUSION_FORBIDDEN_CHARACTERS = frozenset(
    "*?[]{}$`:%!^~()<>|&;\"'"
)
_WINDOWS_RESERVED_PATH_STEMS = frozenset(
    {"aux", "con", "nul", "prn"}
    | {f"com{suffix}" for suffix in "123456789¹²³"}
    | {f"lpt{suffix}" for suffix in "123456789¹²³"}
)
_SCHEMA_FILENAME_BY_VERSION = {
    1: "repository-registration.schema.json",
    2: "repository-registration-v2.schema.json",
    3: "repository-registration-v3.schema.json",
    4: "repository-registration-v4.schema.json",
}
_SHELL_PROGRAMS = frozenset(
    {
        "ash",
        "bash",
        "bsh",
        "cmd",
        "cmd.exe",
        "csh",
        "dash",
        "elvish",
        "es",
        "env",
        "fish",
        "ion",
        "ksh",
        "mksh",
        "nu",
        "nushell",
        "oil",
        "osh",
        "posh",
        "powershell",
        "pwsh",
        "rc",
        "sh",
        "tcsh",
        "toybox",
        "busybox",
        "wsl",
        "xonsh",
        "yash",
        "zsh",
    }
)
_PROHIBITED_COMMAND_OPTION_FRAGMENTS = (
    "allow_api",
    "api_endpoint",
    "auth_file",
    "auth_path",
    "authfile",
    "base_url",
    "bedrock",
    "billing",
    "cloud_route",
    "credit",
    "credential_file",
    "credential_path",
    "credentials_file",
    "endpoint",
    "foundry",
    "identity_file",
    "key_file",
    "netrc",
    "openrouter",
    "overage",
    "password_file",
    "secret_file",
    "token_file",
    "vertex",
)
_PROHIBITED_CREDENTIAL_PATH_PARTS = frozenset(
    {
        ".aws",
        ".claude",
        ".codex",
        ".docker",
        ".direnv",
        ".env",
        ".envrc",
        ".gnupg",
        ".kube",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".ssh",
    }
)
_LIMIT_BOUNDS: dict[str, tuple[int, int]] = {
    "cpu_count": (1, 64),
    "cpu_seconds": (1, 86_400),
    "memory_bytes": (64 * 1024 * 1024, 64 * 1024 * 1024 * 1024),
    "process_count": (1, 1024),
    "workspace_bytes": (1024 * 1024, 1024 * 1024 * 1024 * 1024),
    "output_bytes": (1024, 1024 * 1024 * 1024),
    "artifact_count": (1, 1024),
    "artifact_bytes": (1024, 1024 * 1024 * 1024),
    "wall_seconds": (1, 86_400),
    "idle_seconds": (1, 3_600),
}
_CONCRETE_PATH_TYPE = type(Path())


class _InvalidRegistration(ValueError):
    """Internal sentinel whose details are never exposed to callers."""


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    """Controller-resolved repository identity with its raw path kept private."""

    repository_id: str = field(repr=False)
    vcs: str
    canonical_root: Path = field(repr=False)
    root_ref: str
    filesystem_identity_ref: str
    repository_ref: str

    def to_canonical(self) -> dict[str, Any]:
        return {
            "filesystem_identity_ref": self.filesystem_identity_ref,
            "repository_id_ref": canonical_digest(
                {"repository_id": self.repository_id}
            ),
            "repository_ref": self.repository_ref,
            "root_ref": self.root_ref,
            "vcs": self.vcs,
        }


@dataclass(frozen=True, slots=True)
class VerificationCommand:
    """One exact argv-array declaration; this type cannot resolve or execute it."""

    command_id: str
    kind: str
    argv: tuple[str, ...] = field(repr=False)
    cwd: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "command_id": self.command_id,
            "cwd": self.cwd,
            "kind": self.kind,
        }


@dataclass(frozen=True, slots=True)
class VerificationCommands:
    format: tuple[VerificationCommand, ...]
    lint: tuple[VerificationCommand, ...]
    type_check: tuple[VerificationCommand, ...]
    test: tuple[VerificationCommand, ...]
    build: tuple[VerificationCommand, ...]

    def to_canonical(self) -> dict[str, Any]:
        return {
            kind: [command.to_canonical() for command in getattr(self, kind)]
            for kind in _COMMAND_KINDS
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class BaselineCommandTermination:
    """One bounded terminal observation without output or diagnostic content."""

    kind: str
    exit_code: int | None = field(default=None, repr=False)
    signal_number: int | None = field(default=None, repr=False)
    timeout_seconds: int | None = field(default=None, repr=False)
    termination_confirmed: bool | None = field(default=None, repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _baseline_termination_projection(self)


@dataclass(frozen=True, slots=True)
class BaselineCommandResult:
    """Controller-supplied result linked to one declared verification command."""

    kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    started_at_unix_ms: int = field(repr=False)
    completed_at_unix_ms: int = field(repr=False)
    termination: BaselineCommandTermination = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _baseline_command_result_projection(self)


@dataclass(frozen=True, slots=True)
class BaselineCommandResults:
    """Unauthenticated baseline observations with controller-derived bindings."""

    kind: str
    schema_version: int
    attestation_source: str
    repository_ref: str = field(repr=False)
    snapshot_digest: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    results: tuple[BaselineCommandResult, ...] = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _baseline_command_results_projection(self)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class ExecutableToolchainIdentity:
    """One opaque controller claim linked to a declared command."""

    kind: str
    command_id: str = field(repr=False)
    command_digest: str = field(repr=False)
    declared_executable_kind: str
    declared_executable_ref: str = field(repr=False)
    executable_identity_digest: str = field(repr=False)
    toolchain_identity_digest: str = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _executable_toolchain_identity_projection(self)


@dataclass(frozen=True, slots=True)
class ExecutableToolchainIdentities:
    """Opaque identity claims with controller-derived context bindings."""

    kind: str
    schema_version: int
    attestation_source: str
    repository_ref: str = field(repr=False)
    verification_commands_digest: str = field(repr=False)
    baseline_command_results_digest: str = field(repr=False)
    identities: tuple[ExecutableToolchainIdentity, ...] = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _executable_toolchain_identities_projection(self)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class RepositoryPathPolicy:
    allowed_paths: tuple[str, ...] = field(repr=False)
    protected_paths: tuple[str, ...] = field(repr=False)
    generated_paths: tuple[str, ...] = field(default=(), repr=False)
    vendor_paths: tuple[str, ...] = field(default=(), repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return _path_policy_projection(self)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class RepositoryResourceLimits:
    cpu_count: int
    cpu_seconds: int
    memory_bytes: int
    process_count: int
    workspace_bytes: int
    output_bytes: int
    artifact_count: int
    artifact_bytes: int
    wall_seconds: int
    idle_seconds: int

    def to_canonical(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in _LIMIT_BOUNDS
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class RepositoryIsolationRequirements:
    backend: str
    network_mode: str
    non_root: bool
    read_only_base_repository: bool
    read_only_root_filesystem: bool
    explicit_mounts_only: bool
    git_metadata_hidden: bool
    credential_paths_denied: bool
    control_sockets_denied: bool
    fresh_cell_per_attempt: bool

    def to_canonical(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "control_sockets_denied": self.control_sockets_denied,
            "credential_paths_denied": self.credential_paths_denied,
            "explicit_mounts_only": self.explicit_mounts_only,
            "fresh_cell_per_attempt": self.fresh_cell_per_attempt,
            "git_metadata_hidden": self.git_metadata_hidden,
            "network_mode": self.network_mode,
            "non_root": self.non_root,
            "read_only_base_repository": self.read_only_base_repository,
            "read_only_root_filesystem": self.read_only_root_filesystem,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class RepositoryReviewPolicy:
    output: str
    branch_creation: bool
    commit: bool
    push: bool
    pull_request: bool
    promotion: bool

    def to_canonical(self) -> dict[str, Any]:
        return {
            "branch_creation": self.branch_creation,
            "commit": self.commit,
            "output": self.output,
            "promotion": self.promotion,
            "pull_request": self.pull_request,
            "push": self.push,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_canonical())


@dataclass(frozen=True, slots=True)
class RepositoryRegistration:
    """Deeply immutable validated registration and safe evidence projection."""

    schema_version: int
    kind: str
    registration_id: str = field(repr=False)
    registration_version: str
    repository: RepositoryIdentity = field(repr=False)
    verification_commands: VerificationCommands = field(repr=False)
    path_policy: RepositoryPathPolicy = field(repr=False)
    resource_limits: RepositoryResourceLimits
    isolation_requirements: RepositoryIsolationRequirements
    review_policy: RepositoryReviewPolicy
    baseline_command_results: BaselineCommandResults | None = field(
        default=None,
        repr=False,
    )
    executable_toolchain_identities: ExecutableToolchainIdentities | None = (
        field(default=None, repr=False)
    )

    @property
    def registration_ref(self) -> str:
        return canonical_digest({"registration_id": self.registration_id})

    def to_canonical(self) -> dict[str, Any]:
        """Return the privacy-bounded canonical preimage used for hashing."""

        return _registration_canonical_projection(self)

    @property
    def registration_digest(self) -> str:
        return canonical_digest(self.to_canonical())

    def to_evidence(self) -> dict[str, Any]:
        """Return digest-only evidence that omits paths, identifiers, and argv."""

        return _registration_evidence_projection(self)


def _require_typed_registration_snapshot(
    registration: RepositoryRegistration,
) -> None:
    if (
        type(registration) is not RepositoryRegistration
        or type(registration.repository) is not RepositoryIdentity
        or type(registration.verification_commands) is not VerificationCommands
        or type(registration.path_policy) is not RepositoryPathPolicy
        or type(registration.resource_limits) is not RepositoryResourceLimits
        or type(registration.isolation_requirements)
        is not RepositoryIsolationRequirements
        or type(registration.review_policy) is not RepositoryReviewPolicy
    ):
        raise _InvalidRegistration
    if (
        type(registration.schema_version) is not int
        or registration.schema_version
        not in REPOSITORY_REGISTRATION_SUPPORTED_SCHEMA_VERSIONS
        or type(registration.kind) is not str
        or type(registration.registration_id) is not str
        or type(registration.registration_version) is not str
    ):
        raise _InvalidRegistration

    repository = registration.repository
    if (
        type(repository.repository_id) is not str
        or type(repository.vcs) is not str
        or type(repository.canonical_root) is not _CONCRETE_PATH_TYPE
        or type(repository.root_ref) is not str
        or type(repository.filesystem_identity_ref) is not str
        or type(repository.repository_ref) is not str
    ):
        raise _InvalidRegistration

    for kind in _COMMAND_KINDS:
        commands = getattr(registration.verification_commands, kind)
        if type(commands) is not tuple:
            raise _InvalidRegistration
        for command in commands:
            if (
                type(command) is not VerificationCommand
                or type(command.command_id) is not str
                or type(command.kind) is not str
                or type(command.argv) is not tuple
                or not command.argv
                or any(type(argument) is not str for argument in command.argv)
                or type(command.cwd) is not str
            ):
                raise _InvalidRegistration

    policy = registration.path_policy
    if (
        type(policy.allowed_paths) is not tuple
        or any(type(path) is not str for path in policy.allowed_paths)
        or type(policy.protected_paths) is not tuple
        or any(type(path) is not str for path in policy.protected_paths)
        or type(policy.generated_paths) is not tuple
        or any(type(path) is not str for path in policy.generated_paths)
        or type(policy.vendor_paths) is not tuple
        or any(type(path) is not str for path in policy.vendor_paths)
        or (
            registration.schema_version == 1
            and (policy.generated_paths or policy.vendor_paths)
        )
    ):
        raise _InvalidRegistration

    if any(
        type(getattr(registration.resource_limits, name)) is not int
        for name in _LIMIT_BOUNDS
    ):
        raise _InvalidRegistration

    isolation = registration.isolation_requirements
    if (
        type(isolation.backend) is not str
        or type(isolation.network_mode) is not str
        or any(
            type(getattr(isolation, name)) is not bool
            for name in (
                "non_root",
                "read_only_base_repository",
                "read_only_root_filesystem",
                "explicit_mounts_only",
                "git_metadata_hidden",
                "credential_paths_denied",
                "control_sockets_denied",
                "fresh_cell_per_attempt",
            )
        )
    ):
        raise _InvalidRegistration

    review = registration.review_policy
    if (
        type(review.output) is not str
        or any(
            type(getattr(review, name)) is not bool
            for name in (
                "branch_creation",
                "commit",
                "push",
                "pull_request",
                "promotion",
            )
        )
    ):
        raise _InvalidRegistration

    if registration.schema_version in {1, 2}:
        if registration.baseline_command_results is not None:
            raise _InvalidRegistration
    else:
        _require_typed_baseline_snapshot(registration)
    if registration.schema_version in {1, 2, 3}:
        if registration.executable_toolchain_identities is not None:
            raise _InvalidRegistration
    else:
        _require_typed_executable_toolchain_snapshot(registration)


def _verification_commands_projection(
    commands: VerificationCommands,
) -> dict[str, list[dict[str, Any]]]:
    return {
        kind: [
            {
                "argv": list(command.argv),
                "command_id": command.command_id,
                "cwd": command.cwd,
                "kind": command.kind,
            }
            for command in getattr(commands, kind)
        ]
        for kind in _COMMAND_KINDS
    }


def _verification_command_projection(
    command: VerificationCommand,
) -> dict[str, Any]:
    return {
        "argv": list(command.argv),
        "command_id": command.command_id,
        "cwd": command.cwd,
        "kind": command.kind,
    }


def _verification_command_digest(command: VerificationCommand) -> str:
    return canonical_digest(
        {
            "command": _verification_command_projection(command),
            "kind": "repository_verification_command",
            "schema_version": 1,
        }
    )


def _baseline_termination_projection(
    termination: BaselineCommandTermination,
) -> dict[str, Any]:
    if termination.kind == "exited":
        return {
            "exit_code": termination.exit_code,
            "kind": "exited",
        }
    if termination.kind == "signaled":
        return {
            "kind": "signaled",
            "signal_number": termination.signal_number,
        }
    if termination.kind == "timed_out":
        return {
            "kind": "timed_out",
            "termination_confirmed": termination.termination_confirmed,
            "timeout_seconds": termination.timeout_seconds,
        }
    raise _InvalidRegistration


def _baseline_command_result_projection(
    result: BaselineCommandResult,
) -> dict[str, Any]:
    return {
        "command_digest": result.command_digest,
        "command_id": result.command_id,
        "completed_at_unix_ms": result.completed_at_unix_ms,
        "kind": result.kind,
        "started_at_unix_ms": result.started_at_unix_ms,
        "termination": _baseline_termination_projection(result.termination),
    }


def _baseline_command_results_projection(
    baseline: BaselineCommandResults,
) -> dict[str, Any]:
    return {
        "attestation_source": baseline.attestation_source,
        "kind": baseline.kind,
        "repository_ref": baseline.repository_ref,
        "results": [
            _baseline_command_result_projection(result)
            for result in baseline.results
        ],
        "schema_version": baseline.schema_version,
        "snapshot_digest": baseline.snapshot_digest,
        "verification_commands_digest": (
            baseline.verification_commands_digest
        ),
    }


def _baseline_command_results_document_projection(
    baseline: BaselineCommandResults,
) -> dict[str, Any]:
    return {
        "attestation_source": baseline.attestation_source,
        "kind": baseline.kind,
        "results": [
            _baseline_command_result_projection(result)
            for result in baseline.results
        ],
        "snapshot_digest": baseline.snapshot_digest,
    }


def _declared_executable_syntax_kind(command: VerificationCommand) -> str:
    if "/" not in command.argv[0]:
        return "path_search"
    return "repository_relative"


def _declared_executable_ref(command: VerificationCommand) -> str:
    return canonical_digest(
        {
            "command_digest": _verification_command_digest(command),
            "declared_executable": command.argv[0],
            "kind": DECLARED_EXECUTABLE_KIND,
            "schema_version": 1,
        }
    )


def _executable_toolchain_identity_projection(
    identity: ExecutableToolchainIdentity,
) -> dict[str, Any]:
    return {
        "command_digest": identity.command_digest,
        "command_id": identity.command_id,
        "declared_executable_kind": identity.declared_executable_kind,
        "declared_executable_ref": identity.declared_executable_ref,
        "executable_identity_digest": identity.executable_identity_digest,
        "kind": identity.kind,
        "toolchain_identity_digest": identity.toolchain_identity_digest,
    }


def _executable_toolchain_identities_projection(
    identities: ExecutableToolchainIdentities,
) -> dict[str, Any]:
    return {
        "attestation_source": identities.attestation_source,
        "baseline_command_results_digest": (
            identities.baseline_command_results_digest
        ),
        "identities": [
            _executable_toolchain_identity_projection(identity)
            for identity in identities.identities
        ],
        "kind": identities.kind,
        "repository_ref": identities.repository_ref,
        "schema_version": identities.schema_version,
        "verification_commands_digest": (
            identities.verification_commands_digest
        ),
    }


def _executable_toolchain_identities_document_projection(
    identities: ExecutableToolchainIdentities,
) -> dict[str, Any]:
    return {
        "attestation_source": identities.attestation_source,
        "identities": [
            {
                "command_digest": identity.command_digest,
                "command_id": identity.command_id,
                "executable_identity_digest": (
                    identity.executable_identity_digest
                ),
                "kind": identity.kind,
                "toolchain_identity_digest": (
                    identity.toolchain_identity_digest
                ),
            }
            for identity in identities.identities
        ],
        "kind": identities.kind,
    }


def _require_typed_baseline_snapshot(
    registration: RepositoryRegistration,
) -> None:
    baseline = registration.baseline_command_results
    if (
        type(baseline) is not BaselineCommandResults
        or type(baseline.kind) is not str
        or baseline.kind != BASELINE_COMMAND_RESULTS_KIND
        or type(baseline.schema_version) is not int
        or baseline.schema_version != BASELINE_COMMAND_RESULTS_SCHEMA_VERSION
        or type(baseline.attestation_source) is not str
        or baseline.attestation_source
        != BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE
        or type(baseline.repository_ref) is not str
        or baseline.repository_ref != registration.repository.repository_ref
        or type(baseline.snapshot_digest) is not str
        or _DIGEST_PATTERN.fullmatch(baseline.snapshot_digest) is None
        or type(baseline.verification_commands_digest) is not str
        or baseline.verification_commands_digest
        != canonical_digest(
            _verification_commands_projection(
                registration.verification_commands
            )
        )
        or type(baseline.results) is not tuple
    ):
        raise _InvalidRegistration
    commands = tuple(
        command
        for kind in _COMMAND_KINDS
        for command in getattr(registration.verification_commands, kind)
    )
    if (
        len(baseline.results) != len(commands)
        or not 1 <= len(baseline.results) <= _MAX_BASELINE_RESULTS
    ):
        raise _InvalidRegistration
    wall_milliseconds = registration.resource_limits.wall_seconds * 1000
    for result, command in zip(baseline.results, commands, strict=True):
        if (
            type(result) is not BaselineCommandResult
            or type(result.kind) is not str
            or result.kind != command.kind
            or type(result.command_id) is not str
            or result.command_id != command.command_id
            or type(result.command_digest) is not str
            or result.command_digest != _verification_command_digest(command)
            or type(result.started_at_unix_ms) is not int
            or not 0 <= result.started_at_unix_ms <= _MAX_UNIX_MILLISECONDS
            or type(result.completed_at_unix_ms) is not int
            or not 0 <= result.completed_at_unix_ms <= _MAX_UNIX_MILLISECONDS
            or result.started_at_unix_ms > result.completed_at_unix_ms
            or result.completed_at_unix_ms - result.started_at_unix_ms
            > wall_milliseconds
            or type(result.termination) is not BaselineCommandTermination
        ):
            raise _InvalidRegistration
        termination = result.termination
        if type(termination.kind) is not str:
            raise _InvalidRegistration
        if termination.kind == "exited":
            if (
                type(termination.exit_code) is not int
                or not 0 <= termination.exit_code <= 255
                or termination.signal_number is not None
                or termination.timeout_seconds is not None
                or termination.termination_confirmed is not None
            ):
                raise _InvalidRegistration
        elif termination.kind == "signaled":
            if (
                termination.exit_code is not None
                or type(termination.signal_number) is not int
                or not 1 <= termination.signal_number <= 64
                or termination.timeout_seconds is not None
                or termination.termination_confirmed is not None
            ):
                raise _InvalidRegistration
        elif termination.kind == "timed_out":
            if (
                termination.exit_code is not None
                or termination.signal_number is not None
                or type(termination.timeout_seconds) is not int
                or not 1
                <= termination.timeout_seconds
                <= registration.resource_limits.wall_seconds
                or termination.termination_confirmed is not True
                or result.completed_at_unix_ms - result.started_at_unix_ms
                < termination.timeout_seconds * 1000
            ):
                raise _InvalidRegistration
        else:
            raise _InvalidRegistration


def _require_typed_executable_toolchain_snapshot(
    registration: RepositoryRegistration,
) -> None:
    identities = registration.executable_toolchain_identities
    baseline = registration.baseline_command_results
    if (
        type(identities) is not ExecutableToolchainIdentities
        or type(identities.kind) is not str
        or identities.kind != EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND
        or type(identities.schema_version) is not int
        or identities.schema_version
        != EXECUTABLE_TOOLCHAIN_IDENTITIES_SCHEMA_VERSION
        or type(identities.attestation_source) is not str
        or identities.attestation_source
        != EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE
        or type(identities.repository_ref) is not str
        or identities.repository_ref != registration.repository.repository_ref
        or type(identities.verification_commands_digest) is not str
        or identities.verification_commands_digest
        != canonical_digest(
            _verification_commands_projection(
                registration.verification_commands
            )
        )
        or type(baseline) is not BaselineCommandResults
        or type(identities.baseline_command_results_digest) is not str
        or identities.baseline_command_results_digest
        != canonical_digest(_baseline_command_results_projection(baseline))
        or type(identities.identities) is not tuple
    ):
        raise _InvalidRegistration
    commands = tuple(
        command
        for kind in _COMMAND_KINDS
        for command in getattr(registration.verification_commands, kind)
    )
    if (
        len(identities.identities) != len(commands)
        or not 1
        <= len(identities.identities)
        <= _MAX_EXECUTABLE_TOOLCHAIN_IDENTITIES
    ):
        raise _InvalidRegistration
    for identity, command in zip(
        identities.identities,
        commands,
        strict=True,
    ):
        if (
            type(identity) is not ExecutableToolchainIdentity
            or type(identity.kind) is not str
            or identity.kind != command.kind
            or type(identity.command_id) is not str
            or identity.command_id != command.command_id
            or type(identity.command_digest) is not str
            or identity.command_digest != _verification_command_digest(command)
            or type(identity.declared_executable_kind) is not str
            or identity.declared_executable_kind
            != _declared_executable_syntax_kind(command)
            or type(identity.declared_executable_ref) is not str
            or identity.declared_executable_ref
            != _declared_executable_ref(command)
            or type(identity.executable_identity_digest) is not str
            or _DIGEST_PATTERN.fullmatch(identity.executable_identity_digest)
            is None
            or type(identity.toolchain_identity_digest) is not str
            or _DIGEST_PATTERN.fullmatch(identity.toolchain_identity_digest)
            is None
        ):
            raise _InvalidRegistration


def _path_policy_projection(policy: RepositoryPathPolicy) -> dict[str, Any]:
    projection: dict[str, Any] = {
        "allowed_paths": list(policy.allowed_paths),
        "protected_paths": list(policy.protected_paths),
    }
    if policy.generated_paths:
        projection["generated_paths"] = list(policy.generated_paths)
    if policy.vendor_paths:
        projection["vendor_paths"] = list(policy.vendor_paths)
    return projection


def _path_policy_document_projection(
    policy: RepositoryPathPolicy,
    *,
    schema_version: int,
) -> dict[str, Any]:
    projection = _path_policy_projection(policy)
    if schema_version == 1:
        if policy.generated_paths or policy.vendor_paths:
            raise _InvalidRegistration
        return projection
    if schema_version in {2, 3, 4}:
        projection.setdefault("generated_paths", [])
        projection.setdefault("vendor_paths", [])
        return projection
    raise _InvalidRegistration


def _resource_limits_projection(
    limits: RepositoryResourceLimits,
) -> dict[str, Any]:
    return {name: getattr(limits, name) for name in _LIMIT_BOUNDS}


def _isolation_requirements_projection(
    requirements: RepositoryIsolationRequirements,
) -> dict[str, Any]:
    return {
        "backend": requirements.backend,
        "control_sockets_denied": requirements.control_sockets_denied,
        "credential_paths_denied": requirements.credential_paths_denied,
        "explicit_mounts_only": requirements.explicit_mounts_only,
        "fresh_cell_per_attempt": requirements.fresh_cell_per_attempt,
        "git_metadata_hidden": requirements.git_metadata_hidden,
        "network_mode": requirements.network_mode,
        "non_root": requirements.non_root,
        "read_only_base_repository": requirements.read_only_base_repository,
        "read_only_root_filesystem": requirements.read_only_root_filesystem,
    }


def _review_policy_projection(policy: RepositoryReviewPolicy) -> dict[str, Any]:
    return {
        "branch_creation": policy.branch_creation,
        "commit": policy.commit,
        "output": policy.output,
        "promotion": policy.promotion,
        "pull_request": policy.pull_request,
        "push": policy.push,
    }


def _registration_canonical_projection(
    registration: RepositoryRegistration,
) -> dict[str, Any]:
    _require_typed_registration_snapshot(registration)
    repository = registration.repository
    projection = {
        "isolation_requirements": _isolation_requirements_projection(
            registration.isolation_requirements
        ),
        "kind": registration.kind,
        "path_policy": _path_policy_projection(registration.path_policy),
        "registration_ref": canonical_digest(
            {"registration_id": registration.registration_id}
        ),
        "registration_version": registration.registration_version,
        "repository": {
            "filesystem_identity_ref": repository.filesystem_identity_ref,
            "repository_id_ref": canonical_digest(
                {"repository_id": repository.repository_id}
            ),
            "repository_ref": repository.repository_ref,
            "root_ref": repository.root_ref,
            "vcs": repository.vcs,
        },
        "resource_limits": _resource_limits_projection(
            registration.resource_limits
        ),
        "review_policy": _review_policy_projection(registration.review_policy),
        "schema_version": registration.schema_version,
        "verification_commands": _verification_commands_projection(
            registration.verification_commands
        ),
    }
    if registration.schema_version in {3, 4}:
        baseline = registration.baseline_command_results
        if baseline is None:
            raise _InvalidRegistration
        projection["baseline_command_results"] = (
            _baseline_command_results_projection(baseline)
        )
    if registration.schema_version == 4:
        identities = registration.executable_toolchain_identities
        if identities is None:
            raise _InvalidRegistration
        projection["executable_toolchain_identities"] = (
            _executable_toolchain_identities_projection(identities)
        )
    return projection


def _registration_evidence_projection(
    registration: RepositoryRegistration,
) -> dict[str, Any]:
    canonical = _registration_canonical_projection(registration)
    repository = registration.repository
    projection = {
        "authority_granted": False,
        "dispatch_enabled": False,
        "filesystem_identity_ref": repository.filesystem_identity_ref,
        "isolation_requirements_digest": canonical_digest(
            canonical["isolation_requirements"]
        ),
        "kind": REPOSITORY_REGISTRATION_EVIDENCE_KIND,
        "path_policy_digest": canonical_digest(canonical["path_policy"]),
        "registration_digest": canonical_digest(canonical),
        "registration_ref": canonical["registration_ref"],
        "registration_version": registration.registration_version,
        "repository_ref": repository.repository_ref,
        "resource_limits_digest": canonical_digest(canonical["resource_limits"]),
        "review_policy_digest": canonical_digest(canonical["review_policy"]),
        "schema_version": registration.schema_version,
        "validation_mode": "read_only",
        "verification_commands_digest": canonical_digest(
            canonical["verification_commands"]
        ),
    }
    if registration.schema_version in {3, 4}:
        baseline = registration.baseline_command_results
        if baseline is None:
            raise _InvalidRegistration
        projection.update(
            {
                "baseline_attestation_source": (
                    BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE
                ),
                "baseline_authenticity_verified": False,
                "baseline_command_results_digest": canonical_digest(
                    _baseline_command_results_projection(baseline)
                ),
                "baseline_freshness_verified": False,
                "baseline_result_count": len(baseline.results),
            }
        )
    if registration.schema_version == 4:
        identities = registration.executable_toolchain_identities
        if identities is None:
            raise _InvalidRegistration
        projection.update(
            {
                "executable_toolchain_attestation_source": (
                    EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE
                ),
                "executable_toolchain_authenticity_verified": False,
                "executable_toolchain_content_verified": False,
                "executable_toolchain_execution_correspondence_verified": (
                    False
                ),
                "executable_toolchain_freshness_verified": False,
                "executable_toolchain_identities_digest": canonical_digest(
                    _executable_toolchain_identities_projection(identities)
                ),
                "executable_toolchain_identity_count": len(
                    identities.identities
                ),
                "executable_toolchain_resolution_verified": False,
                "toolchain_completeness_verified": False,
            }
        )
    return projection


def _require_exact_keys(value: Any, expected: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != expected:
        raise _InvalidRegistration
    return value


def _require_identifier(value: Any) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise _InvalidRegistration
    return value


def _require_repository_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _REPOSITORY_ID_PATTERN.fullmatch(value) is None
        or "//" in value
        or value.endswith(("/", ".", "-", "_"))
    ):
        raise _InvalidRegistration
    return value


def _contains_controls(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _canonical_filesystem_spelling(path: Path) -> Path:
    """Recover stored directory-entry spelling for one resolved absolute path."""

    if not path.is_absolute() or not path.anchor:
        raise _InvalidRegistration
    current = Path(path.anchor)
    for supplied_name in path.parts[1:]:
        try:
            with os.scandir(current) as entries:
                names = [entry.name for entry in entries]
        except OSError:
            raise _InvalidRegistration from None
        if supplied_name in names:
            stored_name = supplied_name
        else:
            folded = unicodedata.normalize("NFC", supplied_name).casefold()
            matches = [
                name
                for name in names
                if unicodedata.normalize("NFC", name).casefold() == folded
            ]
            if len(matches) != 1:
                raise _InvalidRegistration
            stored_name = matches[0]
        if not stored_name:
            raise _InvalidRegistration
        current /= stored_name
    return current


def _resolve_repository_root(repository_root: str | Path) -> tuple[Path, os.stat_result, os.stat_result]:
    if isinstance(repository_root, bool):
        raise _InvalidRegistration
    supplied = Path(repository_root)
    if supplied.is_symlink():
        raise _InvalidRegistration
    try:
        root = _canonical_filesystem_spelling(supplied.resolve(strict=True))
        root_stat = root.lstat()
        git_stat = (root / ".git").lstat()
    except (OSError, RuntimeError, ValueError):
        raise _InvalidRegistration from None
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise _InvalidRegistration
    if not stat.S_ISDIR(git_stat.st_mode) or stat.S_ISLNK(git_stat.st_mode):
        raise _InvalidRegistration
    return root, root_stat, git_stat


def _validate_existing_components(root: Path, parts: tuple[str, ...]) -> None:
    current = root
    missing = False
    for part in parts:
        if missing:
            current /= part
            continue
        try:
            with os.scandir(current) as entries:
                names = {entry.name for entry in entries}
        except OSError:
            raise _InvalidRegistration from None
        current /= part
        if part not in names:
            try:
                current.lstat()
            except FileNotFoundError:
                missing = True
                continue
            except OSError:
                raise _InvalidRegistration from None
            raise _InvalidRegistration
        try:
            entry = current.lstat()
        except OSError:
            raise _InvalidRegistration from None
        if stat.S_ISLNK(entry.st_mode):
            raise _InvalidRegistration


def _canonical_relative_path(
    value: Any,
    *,
    root: Path,
    allow_root: bool,
    require_directory: bool = False,
    require_regular_file: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 500
        or _contains_controls(value)
        or unicodedata.normalize("NFC", value) != value
        or "\\" in value
        or _WINDOWS_ABSOLUTE_PATH_PATTERN.match(value) is not None
    ):
        raise _InvalidRegistration
    path = PurePosixPath(value)
    if path.is_absolute():
        raise _InvalidRegistration
    if value == ".":
        if not allow_root:
            raise _InvalidRegistration
        parts: tuple[str, ...] = ()
    else:
        parts = path.parts
        if (
            not parts
            or any(part in {"", ".", ".."} for part in parts)
            or str(path) != value
        ):
            raise _InvalidRegistration
    _validate_existing_components(root, parts)
    candidate = root.joinpath(*parts)
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        raise _InvalidRegistration from None
    if require_directory or require_regular_file:
        try:
            candidate_stat = candidate.lstat()
        except OSError:
            raise _InvalidRegistration from None
        if stat.S_ISLNK(candidate_stat.st_mode):
            raise _InvalidRegistration
        if require_directory and not stat.S_ISDIR(candidate_stat.st_mode):
            raise _InvalidRegistration
        if require_regular_file and (
            not stat.S_ISREG(candidate_stat.st_mode)
            or candidate_stat.st_mode & 0o111 == 0
        ):
            raise _InvalidRegistration
    return value


def _is_at_or_below(path: str, parent: str) -> bool:
    candidate = PurePosixPath(path)
    ancestor = PurePosixPath(parent)
    return candidate == ancestor or ancestor in candidate.parents


def _is_at_or_below_casefold(path: str, parent: str) -> bool:
    return _is_at_or_below(path.casefold(), parent.casefold())


def _reject_overlapping_paths(paths: tuple[str, ...]) -> None:
    for index, path in enumerate(paths):
        for other in paths[index + 1 :]:
            if _is_at_or_below_casefold(
                path, other
            ) or _is_at_or_below_casefold(other, path):
                raise _InvalidRegistration


def _exclusion_path_is_literal(value: str) -> bool:
    if any(
        character in value
        for character in _EXCLUSION_FORBIDDEN_CHARACTERS
    ):
        return False
    for part in PurePosixPath(value).parts:
        folded = part.casefold()
        windows_stem = folded.split(".", 1)[0].rstrip(" .")
        if (
            part.endswith((" ", "."))
            or windows_stem in _WINDOWS_RESERVED_PATH_STEMS
            or folded in _MANDATORY_PROTECTED_PATHS
            or folded in _PROHIBITED_CREDENTIAL_PATH_PARTS
            or folded.startswith(".env.")
            or folded.startswith(".envrc.")
            or any(
                unicodedata.category(character).startswith("C")
                for character in part
            )
        ):
            return False
    return True


def _validate_exclusion_endpoint(root: Path, value: str) -> None:
    candidate = root.joinpath(*PurePosixPath(value).parts)
    try:
        candidate_stat = candidate.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise _InvalidRegistration from None
    if not (
        stat.S_ISDIR(candidate_stat.st_mode)
        or stat.S_ISREG(candidate_stat.st_mode)
    ):
        raise _InvalidRegistration


def _validate_exclusion_component_spelling(root: Path, value: str) -> None:
    current = root
    for part in PurePosixPath(value).parts:
        try:
            with os.scandir(current) as entries:
                names = [entry.name for entry in entries]
        except OSError:
            raise _InvalidRegistration from None
        folded = unicodedata.normalize("NFC", part).casefold()
        matches = [
            name
            for name in names
            if unicodedata.normalize("NFC", name).casefold() == folded
        ]
        if part not in names:
            if matches:
                raise _InvalidRegistration
            return
        if matches != [part]:
            raise _InvalidRegistration
        current /= part


def _build_exclusion_paths(raw: Any, *, root: Path) -> tuple[str, ...]:
    if (
        type(raw) is not list
        or len(raw) > _MAX_EXCLUSION_PATHS_PER_CATEGORY
    ):
        raise _InvalidRegistration
    paths = tuple(
        sorted(
            _canonical_relative_path(
                value,
                root=root,
                allow_root=False,
            )
            for value in raw
        )
    )
    if (
        any(not _exclusion_path_is_literal(path) for path in paths)
        or len(paths) != len(set(paths))
    ):
        raise _InvalidRegistration
    for path in paths:
        _validate_exclusion_component_spelling(root, path)
        _validate_exclusion_endpoint(root, path)
    _reject_overlapping_paths(paths)
    return paths


def _validate_exclusion_relationships(
    *,
    allowed: tuple[str, ...],
    protected: tuple[str, ...],
    generated: tuple[str, ...],
    vendor: tuple[str, ...],
) -> None:
    exclusions = (*generated, *vendor)
    if len(exclusions) > _MAX_EXCLUSION_PATHS:
        raise _InvalidRegistration
    try:
        total_bytes = sum(len(path.encode("utf-8")) for path in exclusions)
    except UnicodeError:
        raise _InvalidRegistration from None
    if total_bytes > _MAX_EXCLUSION_PATH_BYTES:
        raise _InvalidRegistration
    _reject_overlapping_paths(exclusions)
    for exclusion in exclusions:
        containing_allowed = 0
        for allowed_path in allowed:
            casefold_related = _is_at_or_below_casefold(
                exclusion, allowed_path
            ) or _is_at_or_below_casefold(allowed_path, exclusion)
            exactly_related = _is_at_or_below(
                exclusion, allowed_path
            ) or _is_at_or_below(allowed_path, exclusion)
            if casefold_related and not exactly_related:
                raise _InvalidRegistration
            if _is_at_or_below(allowed_path, exclusion):
                raise _InvalidRegistration
            if _is_at_or_below(exclusion, allowed_path):
                containing_allowed += 1
        if containing_allowed != 1:
            raise _InvalidRegistration
        if any(
            _is_at_or_below_casefold(exclusion, protected_path)
            or _is_at_or_below_casefold(protected_path, exclusion)
            for protected_path in protected
        ):
            raise _InvalidRegistration


def _build_repository_identity(
    raw: Any,
    *,
    root: Path,
    root_stat: os.stat_result,
    git_stat: os.stat_result,
) -> RepositoryIdentity:
    repository = _require_exact_keys(
        raw,
        frozenset({"repository_id", "root", "vcs"}),
    )
    repository_id = _require_repository_id(repository["repository_id"])
    if repository["root"] != "." or repository["vcs"] != "git":
        raise _InvalidRegistration
    root_ref = canonical_digest(
        {
            "root_device": root_stat.st_dev,
            "root_inode": root_stat.st_ino,
        }
    )
    filesystem_identity_ref = canonical_digest(
        {
            "git_device": git_stat.st_dev,
            "git_inode": git_stat.st_ino,
            "root_device": root_stat.st_dev,
            "root_inode": root_stat.st_ino,
            "root_ref": root_ref,
        }
    )
    repository_ref = canonical_digest(
        {
            "filesystem_identity_ref": filesystem_identity_ref,
            "repository_id_ref": canonical_digest(
                {"repository_id": repository_id}
            ),
            "root_ref": root_ref,
            "vcs": "git",
        }
    )
    return RepositoryIdentity(
        repository_id=repository_id,
        vcs="git",
        canonical_root=root,
        root_ref=root_ref,
        filesystem_identity_ref=filesystem_identity_ref,
        repository_ref=repository_ref,
    )


def _argument_has_host_absolute_path(value: str) -> bool:
    candidates = [value]
    if "=" in value:
        candidates.append(value.split("=", 1)[1])
    return any(
        candidate.startswith(("/", "~"))
        or _WINDOWS_ABSOLUTE_PATH_PATTERN.match(candidate) is not None
        for candidate in candidates
        if candidate
    )


def _argument_has_prohibited_option_name(value: str) -> bool:
    option_name: str | None = None
    if value.startswith("-"):
        option_name = value.lstrip("-").split("=", 1)[0]
    elif "=" in value:
        option_name = value.split("=", 1)[0]
    elif re.fullmatch(r"[A-Z][A-Z0-9_-]{2,}", value):
        option_name = value
    if not option_name:
        return False
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", option_name).strip("_")
    return is_sensitive_environment_name(normalized) or any(
        fragment in normalized.casefold()
        for fragment in _PROHIBITED_COMMAND_OPTION_FRAGMENTS
    )


def _argument_references_credential_path(value: str) -> bool:
    candidate = value.split("=", 1)[1] if "=" in value else value
    parts = PurePosixPath(candidate.replace("\\", "/")).parts
    return any(
        part.casefold() in _PROHIBITED_CREDENTIAL_PATH_PARTS
        or part.casefold().startswith(".env.")
        or part.casefold().startswith(".envrc.")
        for part in parts
    )


def _validate_executable(value: str, *, root: Path) -> None:
    executable = PurePosixPath(value).name.casefold()
    normalized_executable = executable.removesuffix(".exe")
    if (
        executable in _SHELL_PROGRAMS
        or normalized_executable in _SHELL_PROGRAMS
    ):
        raise _InvalidRegistration
    if "/" not in value:
        if _BARE_EXECUTABLE_PATTERN.fullmatch(value) is None:
            raise _InvalidRegistration
        return
    canonical = _canonical_relative_path(
        value,
        root=root,
        allow_root=False,
        require_regular_file=True,
    )
    if any(
        _is_at_or_below_casefold(canonical, protected)
        for protected in _MANDATORY_PROTECTED_PATHS
    ):
        raise _InvalidRegistration


def _build_verification_commands(raw: Any, *, root: Path) -> VerificationCommands:
    groups = _require_exact_keys(raw, frozenset(_COMMAND_KINDS))
    built: dict[str, tuple[VerificationCommand, ...]] = {}
    command_ids: set[str] = set()
    total_commands = 0
    private_root = str(root)
    for kind in _COMMAND_KINDS:
        entries = groups[kind]
        if not isinstance(entries, list) or len(entries) > 16:
            raise _InvalidRegistration
        if kind == "test" and not entries:
            raise _InvalidRegistration
        commands: list[VerificationCommand] = []
        for entry in entries:
            command = _require_exact_keys(
                entry,
                frozenset({"argv", "command_id", "cwd"}),
            )
            command_id = _require_identifier(command["command_id"])
            if command_id in command_ids:
                raise _InvalidRegistration
            command_ids.add(command_id)
            argv = command["argv"]
            if not isinstance(argv, list) or not 1 <= len(argv) <= 64:
                raise _InvalidRegistration
            if contains_credential_material(argv):
                raise _InvalidRegistration
            exact_argv: list[str] = []
            total_bytes = 0
            for argument in argv:
                if (
                    not isinstance(argument, str)
                    or not argument.strip()
                    or len(argument) > 1024
                    or _contains_controls(argument)
                    or _argument_has_host_absolute_path(argument)
                    or _argument_has_prohibited_option_name(argument)
                    or _argument_references_credential_path(argument)
                    or private_root in argument
                ):
                    raise _InvalidRegistration
                total_bytes += len(argument.encode("utf-8"))
                exact_argv.append(argument)
            if total_bytes > 16_384:
                raise _InvalidRegistration
            _validate_executable(exact_argv[0], root=root)
            cwd = _canonical_relative_path(
                command["cwd"],
                root=root,
                allow_root=True,
                require_directory=True,
            )
            if any(
                _is_at_or_below_casefold(cwd, protected)
                for protected in _MANDATORY_PROTECTED_PATHS
            ):
                raise _InvalidRegistration
            commands.append(
                VerificationCommand(
                    command_id=command_id,
                    kind=kind,
                    argv=tuple(exact_argv),
                    cwd=cwd,
                )
            )
        total_commands += len(commands)
        built[kind] = tuple(commands)
    if total_commands == 0:
        raise _InvalidRegistration
    return VerificationCommands(**built)


def _require_digest(value: Any) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise _InvalidRegistration
    return value


def _build_baseline_termination(
    raw: Any,
    *,
    elapsed_milliseconds: int,
    wall_seconds: int,
) -> BaselineCommandTermination:
    if type(raw) is not dict or type(raw.get("kind")) is not str:
        raise _InvalidRegistration
    kind = raw["kind"]
    if kind == "exited":
        termination = _require_exact_keys(
            raw,
            frozenset({"kind", "exit_code"}),
        )
        exit_code = termination["exit_code"]
        if type(exit_code) is not int or not 0 <= exit_code <= 255:
            raise _InvalidRegistration
        return BaselineCommandTermination(
            kind="exited",
            exit_code=exit_code,
        )
    if kind == "signaled":
        termination = _require_exact_keys(
            raw,
            frozenset({"kind", "signal_number"}),
        )
        signal_number = termination["signal_number"]
        if (
            type(signal_number) is not int
            or not 1 <= signal_number <= 64
        ):
            raise _InvalidRegistration
        return BaselineCommandTermination(
            kind="signaled",
            signal_number=signal_number,
        )
    if kind == "timed_out":
        termination = _require_exact_keys(
            raw,
            frozenset(
                {
                    "kind",
                    "termination_confirmed",
                    "timeout_seconds",
                }
            ),
        )
        timeout_seconds = termination["timeout_seconds"]
        if (
            type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= wall_seconds
            or termination["termination_confirmed"] is not True
            or elapsed_milliseconds < timeout_seconds * 1000
        ):
            raise _InvalidRegistration
        return BaselineCommandTermination(
            kind="timed_out",
            timeout_seconds=timeout_seconds,
            termination_confirmed=True,
        )
    raise _InvalidRegistration


def _build_baseline_command_results(
    raw: Any,
    *,
    repository: RepositoryIdentity,
    commands: VerificationCommands,
    resource_limits: RepositoryResourceLimits,
) -> BaselineCommandResults:
    baseline = _require_exact_keys(
        raw,
        frozenset(
            {
                "attestation_source",
                "kind",
                "results",
                "snapshot_digest",
            }
        ),
    )
    if (
        baseline["kind"] != BASELINE_COMMAND_RESULTS_KIND
        or baseline["attestation_source"]
        != BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE
    ):
        raise _InvalidRegistration
    snapshot_digest = _require_digest(baseline["snapshot_digest"])
    declared_commands = tuple(
        command
        for kind in _COMMAND_KINDS
        for command in getattr(commands, kind)
    )
    raw_results = baseline["results"]
    if (
        type(raw_results) is not list
        or len(raw_results) != len(declared_commands)
        or not 1 <= len(raw_results) <= _MAX_BASELINE_RESULTS
    ):
        raise _InvalidRegistration
    command_by_key = {
        (command.kind, command.command_id): command
        for command in declared_commands
    }
    result_by_key: dict[tuple[str, str], BaselineCommandResult] = {}
    wall_milliseconds = resource_limits.wall_seconds * 1000
    for raw_result in raw_results:
        result = _require_exact_keys(
            raw_result,
            frozenset(
                {
                    "command_digest",
                    "command_id",
                    "completed_at_unix_ms",
                    "kind",
                    "started_at_unix_ms",
                    "termination",
                }
            ),
        )
        kind = result["kind"]
        command_id = result["command_id"]
        if type(kind) is not str or type(command_id) is not str:
            raise _InvalidRegistration
        key = (kind, command_id)
        if key in result_by_key or key not in command_by_key:
            raise _InvalidRegistration
        command = command_by_key[key]
        if _require_digest(result["command_digest"]) != (
            _verification_command_digest(command)
        ):
            raise _InvalidRegistration
        started = result["started_at_unix_ms"]
        completed = result["completed_at_unix_ms"]
        if (
            type(started) is not int
            or not 0 <= started <= _MAX_UNIX_MILLISECONDS
            or type(completed) is not int
            or not 0 <= completed <= _MAX_UNIX_MILLISECONDS
            or started > completed
            or completed - started > wall_milliseconds
        ):
            raise _InvalidRegistration
        result_by_key[key] = BaselineCommandResult(
            kind=kind,
            command_id=command_id,
            command_digest=_verification_command_digest(command),
            started_at_unix_ms=started,
            completed_at_unix_ms=completed,
            termination=_build_baseline_termination(
                result["termination"],
                elapsed_milliseconds=completed - started,
                wall_seconds=resource_limits.wall_seconds,
            ),
        )
    if frozenset(result_by_key) != frozenset(command_by_key):
        raise _InvalidRegistration
    ordered_results = tuple(
        result_by_key[(command.kind, command.command_id)]
        for command in declared_commands
    )
    return BaselineCommandResults(
        kind=BASELINE_COMMAND_RESULTS_KIND,
        schema_version=BASELINE_COMMAND_RESULTS_SCHEMA_VERSION,
        attestation_source=BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE,
        repository_ref=repository.repository_ref,
        snapshot_digest=snapshot_digest,
        verification_commands_digest=canonical_digest(
            _verification_commands_projection(commands)
        ),
        results=ordered_results,
    )


def _build_executable_toolchain_identities(
    raw: Any,
    *,
    repository: RepositoryIdentity,
    commands: VerificationCommands,
    baseline: BaselineCommandResults,
) -> ExecutableToolchainIdentities:
    supplied = _require_exact_keys(
        raw,
        frozenset({"attestation_source", "identities", "kind"}),
    )
    if (
        supplied["kind"] != EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND
        or supplied["attestation_source"]
        != EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE
    ):
        raise _InvalidRegistration
    declared_commands = tuple(
        command
        for kind in _COMMAND_KINDS
        for command in getattr(commands, kind)
    )
    raw_identities = supplied["identities"]
    if (
        type(raw_identities) is not list
        or len(raw_identities) != len(declared_commands)
        or not 1
        <= len(raw_identities)
        <= _MAX_EXECUTABLE_TOOLCHAIN_IDENTITIES
    ):
        raise _InvalidRegistration
    command_by_key = {
        (command.kind, command.command_id): command
        for command in declared_commands
    }
    identity_by_key: dict[
        tuple[str, str], ExecutableToolchainIdentity
    ] = {}
    for raw_identity in raw_identities:
        supplied_identity = _require_exact_keys(
            raw_identity,
            frozenset(
                {
                    "command_digest",
                    "command_id",
                    "executable_identity_digest",
                    "kind",
                    "toolchain_identity_digest",
                }
            ),
        )
        kind = supplied_identity["kind"]
        command_id = supplied_identity["command_id"]
        if type(kind) is not str or type(command_id) is not str:
            raise _InvalidRegistration
        key = (kind, command_id)
        if key in identity_by_key or key not in command_by_key:
            raise _InvalidRegistration
        command = command_by_key[key]
        command_digest = _verification_command_digest(command)
        if _require_digest(supplied_identity["command_digest"]) != (
            command_digest
        ):
            raise _InvalidRegistration
        identity_by_key[key] = ExecutableToolchainIdentity(
            kind=kind,
            command_id=command_id,
            command_digest=command_digest,
            declared_executable_kind=_declared_executable_syntax_kind(
                command
            ),
            declared_executable_ref=_declared_executable_ref(command),
            executable_identity_digest=_require_digest(
                supplied_identity["executable_identity_digest"]
            ),
            toolchain_identity_digest=_require_digest(
                supplied_identity["toolchain_identity_digest"]
            ),
        )
    if frozenset(identity_by_key) != frozenset(command_by_key):
        raise _InvalidRegistration
    return ExecutableToolchainIdentities(
        kind=EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND,
        schema_version=EXECUTABLE_TOOLCHAIN_IDENTITIES_SCHEMA_VERSION,
        attestation_source=(
            EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE
        ),
        repository_ref=repository.repository_ref,
        verification_commands_digest=canonical_digest(
            _verification_commands_projection(commands)
        ),
        baseline_command_results_digest=canonical_digest(
            _baseline_command_results_projection(baseline)
        ),
        identities=tuple(
            identity_by_key[(command.kind, command.command_id)]
            for command in declared_commands
        ),
    )


def _build_path_policy(
    raw: Any,
    *,
    root: Path,
    schema_version: int,
) -> RepositoryPathPolicy:
    expected_keys = {"allowed_paths", "protected_paths"}
    if schema_version in {2, 3, 4}:
        expected_keys.update(_EXCLUSION_PATH_NAMES)
    elif schema_version != 1:
        raise _InvalidRegistration
    policy = _require_exact_keys(raw, frozenset(expected_keys))
    normalized: dict[str, tuple[str, ...]] = {}
    for name in ("allowed_paths", "protected_paths"):
        values = policy[name]
        if not isinstance(values, list) or not values or len(values) > 128:
            raise _InvalidRegistration
        paths = tuple(
            sorted(
                _canonical_relative_path(
                    value,
                    root=root,
                    allow_root=False,
                )
                for value in values
            )
        )
        if len(paths) != len(set(paths)):
            raise _InvalidRegistration
        _reject_overlapping_paths(paths)
        normalized[name] = paths
    allowed = normalized["allowed_paths"]
    protected = normalized["protected_paths"]
    if not _MANDATORY_PROTECTED_PATHS.issubset(protected):
        raise _InvalidRegistration
    for allowed_path in allowed:
        for protected_path in protected:
            casefold_related = _is_at_or_below_casefold(
                allowed_path, protected_path
            ) or _is_at_or_below_casefold(protected_path, allowed_path)
            exactly_related = _is_at_or_below(
                allowed_path, protected_path
            ) or _is_at_or_below(protected_path, allowed_path)
            if casefold_related and not exactly_related:
                raise _InvalidRegistration
    if any(
        _is_at_or_below_casefold(path, mandatory)
        for path in allowed
        for mandatory in _MANDATORY_PROTECTED_PATHS
    ):
        raise _InvalidRegistration
    generated: tuple[str, ...] = ()
    vendor: tuple[str, ...] = ()
    if schema_version in {2, 3, 4}:
        generated = _build_exclusion_paths(
            policy["generated_paths"],
            root=root,
        )
        vendor = _build_exclusion_paths(
            policy["vendor_paths"],
            root=root,
        )
        _validate_exclusion_relationships(
            allowed=allowed,
            protected=protected,
            generated=generated,
            vendor=vendor,
        )
    return RepositoryPathPolicy(
        allowed_paths=allowed,
        protected_paths=protected,
        generated_paths=generated,
        vendor_paths=vendor,
    )


def _build_resource_limits(raw: Any) -> RepositoryResourceLimits:
    limits = _require_exact_keys(raw, frozenset(_LIMIT_BOUNDS))
    checked: dict[str, int] = {}
    for name, (minimum, maximum) in _LIMIT_BOUNDS.items():
        value = limits[name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise _InvalidRegistration
        checked[name] = value
    if checked["idle_seconds"] > checked["wall_seconds"]:
        raise _InvalidRegistration
    if checked["cpu_seconds"] > checked["cpu_count"] * checked["wall_seconds"]:
        raise _InvalidRegistration
    if checked["output_bytes"] > checked["workspace_bytes"]:
        raise _InvalidRegistration
    if checked["artifact_bytes"] > checked["workspace_bytes"]:
        raise _InvalidRegistration
    return RepositoryResourceLimits(**checked)


def _build_isolation_requirements(raw: Any) -> RepositoryIsolationRequirements:
    boolean_names = (
        "non_root",
        "read_only_base_repository",
        "read_only_root_filesystem",
        "explicit_mounts_only",
        "git_metadata_hidden",
        "credential_paths_denied",
        "control_sockets_denied",
        "fresh_cell_per_attempt",
    )
    requirements = _require_exact_keys(
        raw,
        frozenset({"backend", "network_mode", *boolean_names}),
    )
    if (
        requirements["backend"] != "local_container"
        or requirements["network_mode"] != "disabled"
    ):
        raise _InvalidRegistration
    if any(requirements[name] is not True for name in boolean_names):
        raise _InvalidRegistration
    return RepositoryIsolationRequirements(
        backend="local_container",
        network_mode="disabled",
        **{name: True for name in boolean_names},
    )


def _build_review_policy(raw: Any) -> RepositoryReviewPolicy:
    boolean_names = (
        "branch_creation",
        "commit",
        "push",
        "pull_request",
        "promotion",
    )
    policy = _require_exact_keys(
        raw,
        frozenset({"output", *boolean_names}),
    )
    if policy["output"] != "patch_only":
        raise _InvalidRegistration
    if any(policy[name] is not False for name in boolean_names):
        raise _InvalidRegistration
    return RepositoryReviewPolicy(
        output="patch_only",
        **{name: False for name in boolean_names},
    )


def _consume_snapshot_text(value: str, *, bytes_seen: list[int]) -> None:
    if len(value) > _MAX_SNAPSHOT_BYTES:
        raise _InvalidRegistration
    bytes_seen[0] += len(value.encode("utf-8"))
    if bytes_seen[0] > _MAX_SNAPSHOT_BYTES:
        raise _InvalidRegistration


def _snapshot_json_value(
    value: Any,
    *,
    depth: int,
    nodes: list[int],
    bytes_seen: list[int],
) -> Any:
    """Copy strict JSON data without invoking caller-defined conversion hooks."""

    nodes[0] += 1
    bytes_seen[0] += 1
    if depth > 64 or nodes[0] > 10_000:
        raise _InvalidRegistration
    if bytes_seen[0] > _MAX_SNAPSHOT_BYTES:
        raise _InvalidRegistration
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > _MAX_SNAPSHOT_INTEGER_BITS:
            raise _InvalidRegistration
        return value
    if type(value) is str:
        _consume_snapshot_text(value, bytes_seen=bytes_seen)
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise _InvalidRegistration
        return value
    if type(value) is list:
        return [
            _snapshot_json_value(
                child,
                depth=depth + 1,
                nodes=nodes,
                bytes_seen=bytes_seen,
            )
            for child in value
        ]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise _InvalidRegistration
        for key in value:
            _consume_snapshot_text(key, bytes_seen=bytes_seen)
        return {
            key: _snapshot_json_value(
                child,
                depth=depth + 1,
                nodes=nodes,
                bytes_seen=bytes_seen,
            )
            for key, child in value.items()
        }
    raise _InvalidRegistration


def _snapshot_registration(value: Any) -> dict[str, Any]:
    decoded = _snapshot_json_value(
        value,
        depth=0,
        nodes=[0],
        bytes_seen=[0],
    )
    if not isinstance(decoded, dict):
        raise _InvalidRegistration
    return decoded


def _validate_repository_registration(
    value: Any,
    *,
    repository_root: str | Path,
) -> RepositoryRegistration:
    raw = _snapshot_registration(value)
    schema_version = raw.get("schema_version")
    if (
        type(schema_version) is not int
        or schema_version
        not in REPOSITORY_REGISTRATION_SUPPORTED_SCHEMA_VERSIONS
    ):
        raise _InvalidRegistration
    expected_keys = {
        "schema_version",
        "kind",
        "registration_id",
        "registration_version",
        "repository",
        "verification_commands",
        "path_policy",
        "resource_limits",
        "isolation_requirements",
        "review_policy",
    }
    if schema_version in {3, 4}:
        expected_keys.add("baseline_command_results")
    if schema_version == 4:
        expected_keys.add("executable_toolchain_identities")
    registration = _require_exact_keys(raw, frozenset(expected_keys))
    if registration["kind"] != REPOSITORY_REGISTRATION_KIND:
        raise _InvalidRegistration
    registration_id = _require_identifier(registration["registration_id"])
    registration_version = registration["registration_version"]
    if (
        not isinstance(registration_version, str)
        or len(registration_version) > 32
        or _VERSION_PATTERN.fullmatch(registration_version) is None
    ):
        raise _InvalidRegistration
    root, root_stat, git_stat = _resolve_repository_root(repository_root)
    repository = _build_repository_identity(
        registration["repository"],
        root=root,
        root_stat=root_stat,
        git_stat=git_stat,
    )
    verification_commands = _build_verification_commands(
        registration["verification_commands"],
        root=root,
    )
    resource_limits = _build_resource_limits(registration["resource_limits"])
    baseline_command_results = None
    if schema_version in {3, 4}:
        baseline_command_results = _build_baseline_command_results(
            registration["baseline_command_results"],
            repository=repository,
            commands=verification_commands,
            resource_limits=resource_limits,
        )
    executable_toolchain_identities = None
    if schema_version == 4:
        if baseline_command_results is None:
            raise _InvalidRegistration
        executable_toolchain_identities = (
            _build_executable_toolchain_identities(
                registration["executable_toolchain_identities"],
                repository=repository,
                commands=verification_commands,
                baseline=baseline_command_results,
            )
        )
    return RepositoryRegistration(
        schema_version=schema_version,
        kind=REPOSITORY_REGISTRATION_KIND,
        registration_id=registration_id,
        registration_version=registration_version,
        repository=repository,
        verification_commands=verification_commands,
        path_policy=_build_path_policy(
            registration["path_policy"],
            root=root,
            schema_version=schema_version,
        ),
        resource_limits=resource_limits,
        isolation_requirements=_build_isolation_requirements(
            registration["isolation_requirements"]
        ),
        review_policy=_build_review_policy(registration["review_policy"]),
        baseline_command_results=baseline_command_results,
        executable_toolchain_identities=executable_toolchain_identities,
    )


def validate_repository_registration(
    value: Any,
    *,
    repository_root: str | Path,
) -> RepositoryRegistration:
    """Validate one registration without executing or mutating anything."""

    try:
        return _validate_repository_registration(
            value,
            repository_root=repository_root,
        )
    except (OSError, TypeError, ValueError, ValidationError):
        raise ValidationError(_INVALID_MESSAGE) from None


def revalidate_repository_registration(
    registration: RepositoryRegistration,
) -> RepositoryRegistration:
    """Revalidate one typed snapshot against fresh repository facts.

    ``RepositoryRegistration`` is intentionally constructible for transparent
    controller code and tests, so its Python type alone is not validation
    provenance.  Reconstructing the source document and running the strict
    validator again rejects forged dataclass instances and repository drift
    before durable evidence is created.
    """

    try:
        _require_typed_registration_snapshot(registration)
        verification_commands = {
            kind: [
                {
                    "argv": list(command.argv),
                    "command_id": command.command_id,
                    "cwd": command.cwd,
                }
                for command in getattr(registration.verification_commands, kind)
            ]
            for kind in _COMMAND_KINDS
        }
        document = {
            "schema_version": registration.schema_version,
            "kind": registration.kind,
            "registration_id": registration.registration_id,
            "registration_version": registration.registration_version,
            "repository": {
                "repository_id": registration.repository.repository_id,
                "vcs": registration.repository.vcs,
                "root": ".",
            },
            "verification_commands": verification_commands,
            "path_policy": _path_policy_document_projection(
                registration.path_policy,
                schema_version=registration.schema_version,
            ),
            "resource_limits": _resource_limits_projection(
                registration.resource_limits
            ),
            "isolation_requirements": _isolation_requirements_projection(
                registration.isolation_requirements
            ),
            "review_policy": _review_policy_projection(
                registration.review_policy
            ),
        }
        if registration.schema_version in {3, 4}:
            baseline = registration.baseline_command_results
            if baseline is None:
                raise _InvalidRegistration
            document["baseline_command_results"] = (
                _baseline_command_results_document_projection(baseline)
            )
        if registration.schema_version == 4:
            identities = registration.executable_toolchain_identities
            if identities is None:
                raise _InvalidRegistration
            document["executable_toolchain_identities"] = (
                _executable_toolchain_identities_document_projection(
                    identities
                )
            )
        refreshed = _validate_repository_registration(
            document,
            repository_root=registration.repository.canonical_root,
        )
        if _registration_canonical_projection(
            refreshed
        ) != _registration_canonical_projection(registration):
            raise _InvalidRegistration
        return refreshed
    except (AttributeError, OSError, TypeError, ValueError, ValidationError):
        raise ValidationError(_INVALID_MESSAGE) from None


_BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION = (
    revalidate_repository_registration
)


def fresh_repository_registration_evidence(
    registration: RepositoryRegistration,
) -> dict[str, Any]:
    """Return a freshly revalidated, explicitly projected evidence copy."""

    refreshed = _BUILTIN_REVALIDATE_REPOSITORY_REGISTRATION(registration)
    return _registration_evidence_projection(refreshed)


def _load_json_object(
    path: Path,
    *,
    failure_message: str,
    maximum_bytes: int,
) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            encoded = source.read(maximum_bytes + 1)
        if len(encoded) > maximum_bytes:
            raise ValueError
        document = parse_json_document(encoded.decode("utf-8"))
    except (OSError, RecursionError, UnicodeError, ValueError, ValidationError):
        raise ConfigurationError(failure_message) from None
    if not isinstance(document, dict):
        raise ConfigurationError(failure_message)
    return document


def load_repository_registration(
    path: str | Path,
    *,
    repository_root: str | Path,
    definition_schema_path: str | Path | None = None,
) -> RepositoryRegistration:
    """Load and strictly validate a repository registration without effects."""

    try:
        registration_path = Path(path)
    except (TypeError, ValueError):
        raise ConfigurationError(_LOAD_MESSAGE) from None
    raw = _load_json_object(
        registration_path,
        failure_message=_LOAD_MESSAGE,
        maximum_bytes=_MAX_REGISTRATION_DOCUMENT_BYTES,
    )
    if definition_schema_path is None:
        schema_version = raw.get("schema_version")
        if (
            type(schema_version) is not int
            or schema_version not in _SCHEMA_FILENAME_BY_VERSION
        ):
            raise ConfigurationError(_INVALID_MESSAGE)
        definition_schema_path = (
            registration_path.parent.parent
            / "schemas"
            / _SCHEMA_FILENAME_BY_VERSION[schema_version]
        )
    try:
        schema_path = Path(definition_schema_path)
    except (TypeError, ValueError):
        raise ConfigurationError(_SCHEMA_LOAD_MESSAGE) from None
    schema = _load_json_object(
        schema_path,
        failure_message=_SCHEMA_LOAD_MESSAGE,
        maximum_bytes=_MAX_SCHEMA_DOCUMENT_BYTES,
    )
    try:
        require_valid(raw, schema)
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise ConfigurationError(_INVALID_MESSAGE) from None
    try:
        return validate_repository_registration(
            raw,
            repository_root=repository_root,
        )
    except ValidationError:
        raise ConfigurationError(_INVALID_MESSAGE) from None


__all__ = [
    "BASELINE_COMMAND_RESULTS_ATTESTATION_SOURCE",
    "BASELINE_COMMAND_RESULTS_KIND",
    "BASELINE_COMMAND_RESULTS_SCHEMA_VERSION",
    "DECLARED_EXECUTABLE_KIND",
    "EXECUTABLE_TOOLCHAIN_IDENTITIES_ATTESTATION_SOURCE",
    "EXECUTABLE_TOOLCHAIN_IDENTITIES_KIND",
    "EXECUTABLE_TOOLCHAIN_IDENTITIES_SCHEMA_VERSION",
    "REPOSITORY_REGISTRATION_EVIDENCE_KIND",
    "REPOSITORY_REGISTRATION_KIND",
    "REPOSITORY_REGISTRATION_SCHEMA_VERSION",
    "REPOSITORY_REGISTRATION_SUPPORTED_SCHEMA_VERSIONS",
    "BaselineCommandResult",
    "BaselineCommandResults",
    "BaselineCommandTermination",
    "ExecutableToolchainIdentities",
    "ExecutableToolchainIdentity",
    "RepositoryIdentity",
    "RepositoryIsolationRequirements",
    "RepositoryPathPolicy",
    "RepositoryRegistration",
    "RepositoryResourceLimits",
    "RepositoryReviewPolicy",
    "VerificationCommand",
    "VerificationCommands",
    "fresh_repository_registration_evidence",
    "load_repository_registration",
    "revalidate_repository_registration",
    "validate_repository_registration",
]
