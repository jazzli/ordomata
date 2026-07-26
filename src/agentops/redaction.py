"""Best-effort redaction for normalized diagnostics and runner events."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .environment import is_sensitive_environment_name


REDACTED = "[REDACTED]"

_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s,;]+"
)
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([A-Z][A-Z0-9_]*(?:API_KEY|AUTH_TOKEN|ACCESS_TOKEN|PASSWORD|"
    r"TOKEN|SECRET|PRIVATE_KEY)\s*[:=]\s*)([^\s,;]+)"
)
_COMMON_TOKEN_PATTERN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|"
    r"gh[pousr]_[A-Za-z0-9_]{16,})\b"
)


class Redactor:
    """Redact known secret values and common credential-shaped strings."""

    def __init__(self, secret_values: Iterable[str] = ()) -> None:
        self._secret_values = tuple(
            sorted(
                {value for value in secret_values if isinstance(value, str) and value},
                key=len,
                reverse=True,
            )
        )

    def redact_text(self, text: str) -> str:
        result = text
        for value in self._secret_values:
            result = result.replace(value, REDACTED)
        result = _AUTHORIZATION_PATTERN.sub(r"\1" + REDACTED, result)
        result = _ASSIGNMENT_PATTERN.sub(r"\1" + REDACTED, result)
        return _COMMON_TOKEN_PATTERN.sub(REDACTED, result)

    def redact(self, value: Any) -> Any:
        """Recursively redact mappings and sequences without mutating input."""

        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            return {
                str(key): (
                    REDACTED
                    if is_sensitive_environment_name(str(key))
                    else self.redact(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        return value


DEFAULT_REDACTOR = Redactor()


def contains_credential_material(value: Any) -> bool:
    """Return whether the default scanner would alter a structured value."""

    return DEFAULT_REDACTOR.redact(value) != value


def redact_text(text: str, secret_values: Iterable[str] = ()) -> str:
    return Redactor(secret_values).redact_text(text)


def redact_value(value: Any, secret_values: Iterable[str] = ()) -> Any:
    return Redactor(secret_values).redact(value)


__all__ = [
    "DEFAULT_REDACTOR",
    "REDACTED",
    "Redactor",
    "contains_credential_material",
    "redact_text",
    "redact_value",
]
