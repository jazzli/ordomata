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


REPOSITORY_REGISTRATION_SCHEMA_VERSION = 1
REPOSITORY_REGISTRATION_KIND = "repository_registration"
REPOSITORY_REGISTRATION_EVIDENCE_KIND = "repository_registration_validation"

_INVALID_MESSAGE = "repository registration is invalid"
_LOAD_MESSAGE = "repository registration could not be loaded"
_SCHEMA_LOAD_MESSAGE = "repository registration schema could not be loaded"
_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,119}")
_REPOSITORY_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._/-]{2,199}")
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})\."
    r"(?:0|[1-9][0-9]{0,9})"
)
_WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(r"[A-Za-z]:[\\/]")
_BARE_EXECUTABLE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
_COMMAND_KINDS = ("format", "lint", "type_check", "test", "build")
_MANDATORY_PROTECTED_PATHS = frozenset({".agentops", ".git", ".ordomata"})
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
class RepositoryPathPolicy:
    allowed_paths: tuple[str, ...] = field(repr=False)
    protected_paths: tuple[str, ...] = field(repr=False)

    def to_canonical(self) -> dict[str, Any]:
        return {
            "allowed_paths": list(self.allowed_paths),
            "protected_paths": list(self.protected_paths),
        }

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

    @property
    def registration_ref(self) -> str:
        return canonical_digest({"registration_id": self.registration_id})

    def to_canonical(self) -> dict[str, Any]:
        """Return the privacy-bounded canonical preimage used for hashing."""

        return {
            "isolation_requirements": self.isolation_requirements.to_canonical(),
            "kind": self.kind,
            "path_policy": self.path_policy.to_canonical(),
            "registration_ref": self.registration_ref,
            "registration_version": self.registration_version,
            "repository": self.repository.to_canonical(),
            "resource_limits": self.resource_limits.to_canonical(),
            "review_policy": self.review_policy.to_canonical(),
            "schema_version": self.schema_version,
            "verification_commands": self.verification_commands.to_canonical(),
        }

    @property
    def registration_digest(self) -> str:
        return canonical_digest(self.to_canonical())

    def to_evidence(self) -> dict[str, Any]:
        """Return digest-only evidence that omits paths, identifiers, and argv."""

        return {
            "authority_granted": False,
            "dispatch_enabled": False,
            "filesystem_identity_ref": self.repository.filesystem_identity_ref,
            "isolation_requirements_digest": self.isolation_requirements.digest,
            "kind": REPOSITORY_REGISTRATION_EVIDENCE_KIND,
            "path_policy_digest": self.path_policy.digest,
            "registration_digest": self.registration_digest,
            "registration_ref": self.registration_ref,
            "registration_version": self.registration_version,
            "repository_ref": self.repository.repository_ref,
            "resource_limits_digest": self.resource_limits.digest,
            "review_policy_digest": self.review_policy.digest,
            "schema_version": self.schema_version,
            "validation_mode": "read_only",
            "verification_commands_digest": self.verification_commands.digest,
        }


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


def _build_path_policy(raw: Any, *, root: Path) -> RepositoryPathPolicy:
    policy = _require_exact_keys(
        raw,
        frozenset({"allowed_paths", "protected_paths"}),
    )
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
    return RepositoryPathPolicy(
        allowed_paths=allowed,
        protected_paths=protected,
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


def _snapshot_json_value(value: Any, *, depth: int, nodes: list[int]) -> Any:
    """Copy strict JSON data without invoking caller-defined conversion hooks."""

    nodes[0] += 1
    if depth > 64 or nodes[0] > 10_000:
        raise _InvalidRegistration
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise _InvalidRegistration
        return value
    if type(value) is list:
        return [
            _snapshot_json_value(child, depth=depth + 1, nodes=nodes)
            for child in value
        ]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise _InvalidRegistration
        return {
            key: _snapshot_json_value(child, depth=depth + 1, nodes=nodes)
            for key, child in value.items()
        }
    raise _InvalidRegistration


def _snapshot_registration(value: Any) -> dict[str, Any]:
    decoded = _snapshot_json_value(value, depth=0, nodes=[0])
    if not isinstance(decoded, dict):
        raise _InvalidRegistration
    return decoded


def _validate_repository_registration(
    value: Any,
    *,
    repository_root: str | Path,
) -> RepositoryRegistration:
    raw = _snapshot_registration(value)
    registration = _require_exact_keys(
        raw,
        frozenset(
            {
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
        ),
    )
    if (
        type(registration["schema_version"]) is not int
        or registration["schema_version"] != REPOSITORY_REGISTRATION_SCHEMA_VERSION
        or registration["kind"] != REPOSITORY_REGISTRATION_KIND
    ):
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
    return RepositoryRegistration(
        schema_version=REPOSITORY_REGISTRATION_SCHEMA_VERSION,
        kind=REPOSITORY_REGISTRATION_KIND,
        registration_id=registration_id,
        registration_version=registration_version,
        repository=repository,
        verification_commands=_build_verification_commands(
            registration["verification_commands"],
            root=root,
        ),
        path_policy=_build_path_policy(
            registration["path_policy"],
            root=root,
        ),
        resource_limits=_build_resource_limits(registration["resource_limits"]),
        isolation_requirements=_build_isolation_requirements(
            registration["isolation_requirements"]
        ),
        review_policy=_build_review_policy(registration["review_policy"]),
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


def _load_json_object(path: Path, *, failure_message: str) -> dict[str, Any]:
    try:
        document = parse_json_document(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValidationError):
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
    raw = _load_json_object(registration_path, failure_message=_LOAD_MESSAGE)
    if definition_schema_path is None:
        definition_schema_path = (
            registration_path.parent.parent
            / "schemas"
            / "repository-registration.schema.json"
        )
    try:
        schema_path = Path(definition_schema_path)
    except (TypeError, ValueError):
        raise ConfigurationError(_SCHEMA_LOAD_MESSAGE) from None
    schema = _load_json_object(schema_path, failure_message=_SCHEMA_LOAD_MESSAGE)
    try:
        require_valid(raw, schema)
    except ValidationError:
        raise ConfigurationError(_INVALID_MESSAGE) from None
    try:
        return validate_repository_registration(
            raw,
            repository_root=repository_root,
        )
    except ValidationError:
        raise ConfigurationError(_INVALID_MESSAGE) from None


__all__ = [
    "REPOSITORY_REGISTRATION_EVIDENCE_KIND",
    "REPOSITORY_REGISTRATION_KIND",
    "REPOSITORY_REGISTRATION_SCHEMA_VERSION",
    "RepositoryIdentity",
    "RepositoryIsolationRequirements",
    "RepositoryPathPolicy",
    "RepositoryRegistration",
    "RepositoryResourceLimits",
    "RepositoryReviewPolicy",
    "VerificationCommand",
    "VerificationCommands",
    "load_repository_registration",
    "validate_repository_registration",
]
