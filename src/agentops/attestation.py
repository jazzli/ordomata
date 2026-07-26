"""Interactive, fail-closed billing-attestation lifecycle tooling.

This module deliberately cannot execute a model.  It asks an unadorned runner
adapter for its current, sanitized billing assessment, requires an operator to
type a provider-specific statement in a terminal, and writes only the strict
semantic record accepted by :class:`FileBillingAttestationLoader`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import errno
import json
import math
import os
from pathlib import Path
import secrets
import stat
import sys
import time
from typing import Any, Protocol, TextIO

from .billing import (
    MAX_BILLING_ATTESTATION_LIFETIME_SECONDS,
    _parse_file_attestation,
)
from .errors import ConfigurationError
from .models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    PaidContinuationProtection,
    PaidCreditBalance,
)


ATTESTATION_RELATIVE_PATH = Path(".agentops") / "billing-attestations.json"
CODEX_ATTESTATION_TTL_SECONDS = 60 * 60
CLAUDE_ATTESTATION_TTL_SECONDS = 15 * 60
ATTESTATION_FILE_MAX_BYTES = 64 * 1024
CONFIRMATION_PHRASES = {
    "codex": "I CONFIRM CODEX AUTOMATIC RECHARGE IS DISABLED",
    "claude": (
        "I CONFIRM CLAUDE EXTRA USAGE IS DISABLED AND INCLUDED CAPACITY "
        "IS AVAILABLE"
    ),
}
_EVIDENCE_CODES = {
    "codex": ("provider_ui_auto_top_up_disabled",),
    "claude": (
        "provider_ui_extra_usage_disabled",
        "provider_ui_included_capacity_available",
    ),
}
_FINGERPRINT_LENGTH = 64
_MAX_CONFIRMATION_BYTES = 256


class BillingAssessmentProbe(Protocol):
    """The one read-only runner operation used by the operator workflow."""

    @property
    def runner_id(self) -> str: ...

    async def inspect_billing_route(self) -> BillingRouteAssessment: ...


@dataclass(frozen=True, slots=True)
class BillingAttestationRefresh:
    """Safe operator-facing result; it contains no account or balance data."""

    runner_id: str
    path: Path
    maximum_validity_seconds: int

    def to_mapping(self) -> dict[str, Any]:
        return {
            "runner_id": self.runner_id,
            "path": str(self.path),
            "refreshed": True,
            "maximum_validity_seconds": self.maximum_validity_seconds,
        }


async def refresh_billing_attestation(
    project_root: str | Path,
    runner: BillingAssessmentProbe,
    *,
    clock=time.time,
) -> BillingAttestationRefresh:
    """Create a short-lived attestation after machine and human checks.

    The runner must not have a file attestation loader configured.  To make
    that invariant independently enforceable, any assessment already carrying
    an attestation is rejected rather than being used to refresh itself.
    """

    source = sys.stdin
    destination = sys.stdout
    _require_interactive_terminal(source, destination)

    runner_id = runner.runner_id
    if runner_id not in CONFIRMATION_PHRASES:
        raise ConfigurationError("billing attest supports only codex or claude")

    try:
        assessment = await runner.inspect_billing_route()
    except Exception as exc:
        raise ConfigurationError(
            f"{runner_id} billing attestation blocked: machine inspection failed"
        ) from exc
    _validate_common_machine_evidence(assessment, runner_id=runner_id)
    if runner_id == "codex":
        _validate_codex_machine_evidence(assessment, now=float(clock()))
    else:
        _validate_claude_machine_evidence(assessment)

    phrase = CONFIRMATION_PHRASES[runner_id]
    destination.write(_confirmation_prompt(runner_id, phrase))
    destination.flush()
    typed = source.readline(_MAX_CONFIRMATION_BYTES + 1)
    if len(typed.encode("utf-8", errors="ignore")) > _MAX_CONFIRMATION_BYTES:
        raise ConfigurationError("billing attestation confirmation was not accepted")
    if typed.endswith("\n"):
        typed = typed[:-1]
    if typed.endswith("\r"):
        typed = typed[:-1]
    if typed != phrase:
        raise ConfigurationError("billing attestation confirmation was not accepted")

    # Re-check time-sensitive evidence after the operator has used the UI.
    observed_at = float(clock())
    if runner_id == "codex":
        _validate_codex_machine_evidence(
            assessment,
            now=observed_at,
        )
        # Capacity and paid-credit balance are machine-probed again before
        # every dispatch.  This longer window applies only to the operator's
        # observation that automatic recharge is disabled.
        expires_at = observed_at + CODEX_ATTESTATION_TTL_SECONDS
        protection = (
            PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
        )
    else:
        _validate_claude_machine_evidence(assessment)
        expires_at = observed_at + CLAUDE_ATTESTATION_TTL_SECONDS
        protection = PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED

    if expires_at <= observed_at:
        raise ConfigurationError(
            f"{runner_id} billing attestation blocked: machine evidence expired"
        )
    attestation = BillingSafetyAttestation(
        runner_id=runner_id,
        account_identity_fingerprint=(
            assessment.account_identity_fingerprint or ""
        ),
        billing_route=BillingRoute.SUBSCRIPTION_INCLUDED,
        capacity_state=CapacityState.AVAILABLE,
        paid_continuation_protection=protection,
        observed_at=observed_at,
        expires_at=expires_at,
        confidence=AssessmentConfidence.HIGH,
        evidence=tuple(
            f"operator_attestation:{code}" for code in _EVIDENCE_CODES[runner_id]
        ),
    )
    path = _write_private_attestation(project_root, attestation, now=observed_at)
    return BillingAttestationRefresh(
        runner_id=runner_id,
        path=path,
        maximum_validity_seconds=max(0, int(expires_at - observed_at)),
    )


def _require_interactive_terminal(source: TextIO, destination: TextIO) -> None:
    try:
        interactive = source.isatty() and destination.isatty()
    except (AttributeError, OSError):
        interactive = False
    if not interactive:
        raise ConfigurationError(
            "billing attest requires an interactive terminal; piped input and "
            "noninteractive confirmation are prohibited"
        )


def _confirmation_prompt(runner_id: str, phrase: str) -> str:
    if runner_id == "codex":
        claim = (
            "For the same account currently authenticated in this harness, "
            "verify in the official provider UI that automatic recharge is "
            "disabled."
        )
    else:
        claim = (
            "For the same account currently authenticated in this harness, "
            "verify in the official provider UI that extra usage is disabled "
            "and included subscription capacity is currently available."
        )
    return f"{claim}\nType exactly:\n{phrase}\n> "


def _validate_common_machine_evidence(
    assessment: BillingRouteAssessment,
    *,
    runner_id: str,
) -> None:
    if assessment.runner_id != runner_id:
        raise ConfigurationError(
            f"{runner_id} billing attestation blocked: runner identity mismatch"
        )
    if assessment.attestation is not None:
        raise ConfigurationError(
            f"{runner_id} billing attestation blocked: inspection was not independent"
        )
    if (
        assessment.route is not BillingRoute.SUBSCRIPTION_INCLUDED
        or assessment.confidence is not AssessmentConfidence.HIGH
    ):
        raise ConfigurationError(
            f"{runner_id} billing attestation blocked: paid subscription route "
            "was not machine verified"
        )
    if not _valid_fingerprint(assessment.account_identity_fingerprint):
        raise ConfigurationError(
            f"{runner_id} billing attestation blocked: account identity was not "
            "machine verified"
        )
    if assessment.paid_continuation_protection is PaidContinuationProtection.ENABLED:
        raise ConfigurationError(
            f"{runner_id} billing attestation blocked: paid continuation is enabled"
        )


def _validate_codex_machine_evidence(
    assessment: BillingRouteAssessment,
    *,
    now: float,
) -> float:
    if not _valid_time(now):
        raise ConfigurationError("codex billing attestation blocked: invalid clock")
    if (
        assessment.capacity_state is not CapacityState.AVAILABLE
        or assessment.paid_credit_balance is not PaidCreditBalance.ZERO
    ):
        raise ConfigurationError(
            "codex billing attestation blocked: current capacity and zero paid "
            "credits were not machine verified"
        )
    observed = assessment.capacity_observed_at
    expires = assessment.capacity_expires_at
    if (
        not _valid_time(observed)
        or not _valid_time(expires)
        or float(observed) > now
        or now >= float(expires)
        or float(expires) <= float(observed)
    ):
        raise ConfigurationError(
            "codex billing attestation blocked: capacity evidence is not current"
        )
    return float(expires)


def _validate_claude_machine_evidence(
    assessment: BillingRouteAssessment,
) -> None:
    if assessment.capacity_state in {
        CapacityState.LIMIT_REACHED,
        CapacityState.BLOCKED_UNTIL_RESET,
        CapacityState.COOLDOWN,
    }:
        raise ConfigurationError(
            "claude billing attestation blocked: machine evidence contradicts "
            "available included capacity"
        )
    if assessment.paid_credit_balance not in {
        PaidCreditBalance.NOT_APPLICABLE,
        PaidCreditBalance.ZERO,
    }:
        raise ConfigurationError(
            "claude billing attestation blocked: paid-capacity evidence is unsafe"
        )


def _valid_fingerprint(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _FINGERPRINT_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_time(value: float | None) -> bool:
    return (
        value is not None
        and not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _write_private_attestation(
    project_root: str | Path,
    attestation: BillingSafetyAttestation,
    *,
    now: float,
) -> Path:
    root = Path(project_root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise ConfigurationError(
            "project root must be an existing non-symlink directory"
        )

    root_descriptor: int | None = None
    parent_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        root_descriptor = _open_directory(root)
        _require_owner(os.fstat(root_descriptor), role="project root")
        try:
            os.mkdir(".agentops", mode=0o700, dir_fd=root_descriptor)
        except FileExistsError:
            pass
        parent_descriptor = _open_directory(".agentops", dir_fd=root_descriptor)
        parent_metadata = os.fstat(parent_descriptor)
        _require_owner(parent_metadata, role="attestation directory")
        os.fchmod(parent_descriptor, 0o700)
        if stat.S_IMODE(os.fstat(parent_descriptor).st_mode) != 0o700:
            raise ConfigurationError("attestation directory is not owner-private")

        retained = _read_retained_records(parent_descriptor, now=now)
        retained = [
            record
            for record in retained
            if record["runner_id"] != attestation.runner_id
        ]
        retained.append(_attestation_record(attestation))
        retained.sort(
            key=lambda record: (
                str(record["runner_id"]),
                str(record["account_identity_fingerprint"]),
            )
        )
        document = {"schema_version": 1, "attestations": retained}
        payload = (
            json.dumps(
                document,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        if len(payload) > ATTESTATION_FILE_MAX_BYTES:
            raise ConfigurationError("billing attestation file exceeds its size limit")

        temporary_name = (
            f".billing-attestations.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temporary_descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            _write_all(temporary_descriptor, payload)
            os.fchmod(temporary_descriptor, 0o600)
            os.fsync(temporary_descriptor)
        finally:
            os.close(temporary_descriptor)
        os.replace(
            temporary_name,
            "billing-attestations.json",
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        os.fsync(parent_descriptor)
    except ConfigurationError:
        raise
    except OSError as exc:
        raise ConfigurationError(
            "billing attestation could not be stored safely"
        ) from exc
    finally:
        if temporary_name is not None and parent_descriptor is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
    return root / ATTESTATION_RELATIVE_PATH


def _open_directory(path: str | Path, *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ConfigurationError(
                "attestation path contains a symlink or non-directory"
            ) from exc
        raise


def _require_owner(metadata: os.stat_result, *, role: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConfigurationError(f"{role} is not a directory")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ConfigurationError(f"{role} is not owned by the current operator")


def _read_retained_records(
    parent_descriptor: int,
    *,
    now: float,
) -> list[dict[str, Any]]:
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                "billing-attestations.json",
                flags,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            return []
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigurationError(
                "existing billing attestation is not a regular file"
            )
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ConfigurationError(
                "existing billing attestation is not owned by the current operator"
            )
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ConfigurationError("existing billing attestation is not mode 0600")
        if metadata.st_size > ATTESTATION_FILE_MAX_BYTES:
            raise ConfigurationError("existing billing attestation is too large")
        raw = _read_bounded(descriptor, maximum_bytes=ATTESTATION_FILE_MAX_BYTES)
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ConfigurationError(
                "existing billing attestation is not strict valid JSON"
            ) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ConfigurationError(
                "existing billing attestation must not be a symlink"
            ) from exc
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if (
        not isinstance(document, Mapping)
        or set(document) != {"schema_version", "attestations"}
        or document.get("schema_version") != 1
        or not isinstance(document.get("attestations"), list)
    ):
        raise ConfigurationError("existing billing attestation schema is invalid")

    retained: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_record in document["attestations"]:
        parsed = _parse_file_attestation(raw_record)
        if parsed is None:
            raise ConfigurationError("existing billing attestation record is invalid")
        key = (parsed.runner_id, parsed.account_identity_fingerprint)
        if key in seen:
            raise ConfigurationError(
                "existing billing attestation records are ambiguous"
            )
        seen.add(key)
        if parsed.expires_at <= now:
            continue
        if (
            parsed.observed_at > now
            or parsed.expires_at <= parsed.observed_at
            or parsed.expires_at - parsed.observed_at
            > MAX_BILLING_ATTESTATION_LIFETIME_SECONDS
        ):
            raise ConfigurationError("existing billing attestation window is invalid")
        retained.append(_attestation_record(parsed))
    return retained


def _read_bounded(descriptor: int, *, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    observed = 0
    while True:
        chunk = os.read(descriptor, min(8_192, maximum_bytes + 1 - observed))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        observed += len(chunk)
        if observed > maximum_bytes:
            raise ConfigurationError("existing billing attestation is too large")


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _attestation_record(
    attestation: BillingSafetyAttestation,
) -> dict[str, Any]:
    codes = []
    for evidence in attestation.evidence:
        prefix = "operator_attestation:"
        if not evidence.startswith(prefix):
            raise ConfigurationError("billing attestation evidence is not semantic")
        codes.append(evidence[len(prefix) :])
    expected_codes = list(_EVIDENCE_CODES.get(attestation.runner_id, ()))
    if len(codes) != len(set(codes)) or set(codes) != set(expected_codes):
        raise ConfigurationError("billing attestation evidence is not authorized")
    if not _valid_fingerprint(attestation.account_identity_fingerprint):
        raise ConfigurationError("billing attestation identity fingerprint is invalid")
    if (
        attestation.billing_route is not BillingRoute.SUBSCRIPTION_INCLUDED
        or attestation.capacity_state is not CapacityState.AVAILABLE
        or attestation.confidence is not AssessmentConfidence.HIGH
    ):
        raise ConfigurationError("billing attestation fields are not subscription-safe")
    expected_protection = (
        PaidContinuationProtection.VERIFIED_ZERO_BALANCE_AND_AUTO_TOP_UP_DISABLED
        if attestation.runner_id == "codex"
        else PaidContinuationProtection.PROVIDER_ENFORCED_DISABLED
    )
    if attestation.paid_continuation_protection is not expected_protection:
        raise ConfigurationError("billing attestation protection is invalid")
    return {
        "runner_id": attestation.runner_id,
        "account_identity_fingerprint": attestation.account_identity_fingerprint,
        "billing_route": attestation.billing_route.value,
        "capacity_state": attestation.capacity_state.value,
        "paid_continuation_protection": (
            attestation.paid_continuation_protection.value
        ),
        "observed_at": attestation.observed_at,
        "expires_at": attestation.expires_at,
        "confidence": attestation.confidence.value,
        "evidence_codes": expected_codes,
    }


__all__ = [
    "ATTESTATION_RELATIVE_PATH",
    "BillingAttestationRefresh",
    "CONFIRMATION_PHRASES",
    "refresh_billing_attestation",
]
