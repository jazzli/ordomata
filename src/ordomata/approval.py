"""Deterministic human-control boundaries."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import ValidationError
from .models import PermissionClass


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    permission_class: PermissionClass
    executable_now: bool
    human_approval_required: bool
    reason: str


class ApprovalPolicy:
    """Current-stage policy: only read-only and local-draft work is executable."""

    enabled_classes = frozenset(
        {PermissionClass.READ_ONLY, PermissionClass.LOCAL_DRAFT}
    )

    def classify(self, permission_class: PermissionClass) -> ApprovalDecision:
        if permission_class in self.enabled_classes:
            return ApprovalDecision(
                permission_class=permission_class,
                executable_now=True,
                human_approval_required=False,
                reason=(
                    "read-only analysis may run unattended"
                    if permission_class is PermissionClass.READ_ONLY
                    else "local drafts may run unattended but must remain local"
                ),
            )
        return ApprovalDecision(
            permission_class=permission_class,
            executable_now=False,
            human_approval_required=True,
            reason="current-stage policy disables classes 2 and 3",
        )

    def assert_executable(self, permission_class: PermissionClass) -> None:
        decision = self.classify(permission_class)
        if not decision.executable_now:
            raise ValidationError(decision.reason)
