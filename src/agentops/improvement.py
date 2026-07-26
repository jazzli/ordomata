"""Regression-safe scaffolding for proposal-based self-improvement."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping


PROTECTED_TARGETS = frozenset(
    {
        PurePosixPath("AGENTS.md"),
        PurePosixPath("docs/subscription-only-policy.md"),
        PurePosixPath("src/agentops/billing.py"),
        PurePosixPath("src/agentops/environment.py"),
        PurePosixPath("src/agentops/approval.py"),
    }
)
PROTECTED_PREFIXES = (
    PurePosixPath("fixtures/held_out"),
    PurePosixPath("tests/held_out"),
)


@dataclass(frozen=True, slots=True)
class BenchmarkOutcome:
    benchmark_id: str
    schema_valid_rate: float
    assertion_pass_rate: float
    safety_failures: int
    accepted_rate: float | None = None


@dataclass(frozen=True, slots=True)
class ImprovementProposal:
    proposal_id: str
    baseline_version: str
    candidate_version: str
    changed_paths: tuple[str, ...]
    development_outcomes: tuple[BenchmarkOutcome, ...]
    held_out_outcomes: tuple[BenchmarkOutcome, ...]
    rollback_version: str


@dataclass(frozen=True, slots=True)
class PromotionAssessment:
    promotable: bool
    operator_approval_required: bool
    reasons: tuple[str, ...]
    metrics: Mapping[str, float | int]


class ImprovementPolicy:
    """Reject unsafe targets and regressions; never self-promote."""

    def assess(
        self,
        proposal: ImprovementProposal,
        baseline_held_out: Mapping[str, BenchmarkOutcome],
    ) -> PromotionAssessment:
        reasons: list[str] = []
        for raw_path in proposal.changed_paths:
            path = PurePosixPath(raw_path)
            if path in PROTECTED_TARGETS or any(
                path == prefix or prefix in path.parents
                for prefix in PROTECTED_PREFIXES
            ):
                reasons.append(f"protected target cannot be self-modified: {path}")

        if not proposal.held_out_outcomes:
            reasons.append("held-out benchmark results are required")

        for candidate in proposal.held_out_outcomes:
            baseline = baseline_held_out.get(candidate.benchmark_id)
            if baseline is None:
                reasons.append(
                    f"missing baseline for held-out benchmark {candidate.benchmark_id}"
                )
                continue
            if candidate.safety_failures > baseline.safety_failures:
                reasons.append(
                    f"safety regression in {candidate.benchmark_id}: "
                    f"{baseline.safety_failures} -> {candidate.safety_failures}"
                )
            if candidate.schema_valid_rate < baseline.schema_valid_rate:
                reasons.append(
                    f"schema-valid regression in {candidate.benchmark_id}"
                )
            if candidate.assertion_pass_rate < baseline.assertion_pass_rate:
                reasons.append(
                    f"assertion regression in {candidate.benchmark_id}"
                )

        metrics = {
            "development_benchmarks": len(proposal.development_outcomes),
            "held_out_benchmarks": len(proposal.held_out_outcomes),
            "candidate_safety_failures": sum(
                outcome.safety_failures for outcome in proposal.held_out_outcomes
            ),
        }
        return PromotionAssessment(
            promotable=not reasons,
            operator_approval_required=True,
            reasons=tuple(reasons),
            metrics=metrics,
        )
