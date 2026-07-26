"""Safe environment inspection and child-process environment construction."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

from .billing import (
    LEGACY_LIVE_RUN_ENVIRONMENT_NAME,
    LIVE_RUN_ENVIRONMENT_NAME,
)
from .models import EnvironmentValidation


# Names are compared case-insensitively.  Code may inspect whether these names
# exist, but must never include their values in diagnostics.
RISKY_MODEL_ENVIRONMENT_NAMES = frozenset(
    {
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "AZURE_OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENROUTER_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_API_KEY",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
    }
)

CLOUD_ROUTE_ENVIRONMENT_NAMES = frozenset(
    {
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    }
)

CONTROL_PLANE_ENVIRONMENT_NAMES = frozenset(
    {LIVE_RUN_ENVIRONMENT_NAME, LEGACY_LIVE_RUN_ENVIRONMENT_NAME}
)

# Deliberately small.  Authentication is reached through the harness's files
# under HOME/XDG directories, never through inherited model credentials.
SAFE_BASE_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SHELL",
        "USER",
        "LOGNAME",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "FORCE_COLOR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
    }
)

_SENSITIVE_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:API_?KEY|AUTH_?TOKEN|ACCESS_?TOKEN|TOKEN|PASSWORD|PASSWD|SECRET|"
    r"CREDENTIALS?|PRIVATE_?KEY)(?:$|_)",
    re.IGNORECASE,
)

_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)(?:-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|"
    r"\bbearer\s+[a-z0-9._~+/=-]{12,}|"
    r"\b(?:sk-|sk-ant-|gh[pousr]_|xox[baprs]-)[A-Za-z0-9_-]{12,}|"
    r"\b(?:api[_-]?key|password|client[_-]?secret|token)\s*[:=]\s*\S{8,})"
)


def _canonical_name(name: str) -> str:
    return name.upper()


def is_sensitive_environment_name(name: str) -> bool:
    """Return whether a name appears capable of carrying credential material."""

    canonical = _canonical_name(name)
    return (
        canonical in RISKY_MODEL_ENVIRONMENT_NAMES
        or _SENSITIVE_NAME_PATTERN.search(canonical) is not None
    )


def is_sensitive_environment_value(value: str) -> bool:
    """Detect common credential material without retaining or reporting it."""

    return _SENSITIVE_VALUE_PATTERN.search(value) is not None


def inspect_risky_environment(
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return risky variable *names* that are present, never their values."""

    source = os.environ if environment is None else environment
    names = {
        name
        for name in source
        if is_sensitive_environment_name(name)
    }
    return tuple(sorted(names, key=str.upper))


def build_child_environment(
    parent: Mapping[str, str] | None = None,
    *,
    approved: Mapping[str, str] | None = None,
) -> EnvironmentValidation:
    """Construct a new, narrowly allowlisted child environment.

    ``parent`` is never mutated.  ``approved`` permits repository-specific,
    non-secret configuration, but credential-shaped names are rejected even if
    a caller tries to approve them.
    """

    source = os.environ if parent is None else parent
    child: dict[str, str] = {}
    retained: set[str] = set()
    excluded: set[str] = set()
    errors: list[str] = []
    warnings: list[str] = []

    for name, value in source.items():
        if _canonical_name(name) in SAFE_BASE_ENVIRONMENT_NAMES:
            child[name] = value
            retained.add(name)
        else:
            excluded.add(name)

    risky = inspect_risky_environment(source)
    if risky:
        warnings.append(
            "Excluded risky parent environment variables by name: "
            + ", ".join(risky)
        )

    for name, value in (approved or {}).items():
        if not isinstance(name, str) or not isinstance(value, str):
            errors.append("Approved environment entries must be string pairs.")
            continue
        if _canonical_name(name) in CONTROL_PLANE_ENVIRONMENT_NAMES:
            errors.append(
                f"Approved environment variable {name!r} was rejected because "
                "live-run gates are controller-only."
            )
            excluded.add(name)
            continue
        if is_sensitive_environment_name(name):
            errors.append(
                f"Approved environment variable {name!r} was rejected because "
                "its name may contain credentials."
            )
            excluded.add(name)
            continue
        if is_sensitive_environment_value(value):
            errors.append(
                f"Approved environment variable {name!r} was rejected because "
                "its value resembles credential material."
            )
            excluded.add(name)
            continue
        child[name] = value
        retained.add(name)
        excluded.discard(name)

    return EnvironmentValidation(
        valid=not errors,
        sanitized_environment=dict(child),
        retained_names=tuple(sorted(retained, key=str.upper)),
        excluded_names=tuple(sorted(excluded, key=str.upper)),
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


__all__ = [
    "CLOUD_ROUTE_ENVIRONMENT_NAMES",
    "CONTROL_PLANE_ENVIRONMENT_NAMES",
    "RISKY_MODEL_ENVIRONMENT_NAMES",
    "SAFE_BASE_ENVIRONMENT_NAMES",
    "build_child_environment",
    "inspect_risky_environment",
    "is_sensitive_environment_name",
    "is_sensitive_environment_value",
]
