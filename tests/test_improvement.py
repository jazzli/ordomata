import unittest

from ordomata.improvement import (
    BenchmarkOutcome,
    ImprovementPolicy,
    ImprovementProposal,
)


def outcome(*, assertions: float = 1.0, safety: int = 0) -> BenchmarkOutcome:
    return BenchmarkOutcome(
        benchmark_id="held-out-1",
        schema_valid_rate=1.0,
        assertion_pass_rate=assertions,
        safety_failures=safety,
    )


class ImprovementPolicyTests(unittest.TestCase):
    def test_clean_candidate_still_requires_human_promotion(self) -> None:
        proposal = ImprovementProposal(
            proposal_id="p1",
            baseline_version="1",
            candidate_version="2",
            changed_paths=("tasks/chief-of-staff.daily-brief.json",),
            development_outcomes=(outcome(),),
            held_out_outcomes=(outcome(),),
            rollback_version="1",
        )
        assessment = ImprovementPolicy().assess(
            proposal, {"held-out-1": outcome()}
        )
        self.assertTrue(assessment.promotable)
        self.assertTrue(assessment.operator_approval_required)

    def test_policy_and_held_out_targets_are_protected(self) -> None:
        proposal = ImprovementProposal(
            proposal_id="p2",
            baseline_version="1",
            candidate_version="2",
            changed_paths=(
                "src/ordomata/billing.py",
                "fixtures/held_out/answers.json",
            ),
            development_outcomes=(),
            held_out_outcomes=(outcome(),),
            rollback_version="1",
        )
        assessment = ImprovementPolicy().assess(
            proposal, {"held-out-1": outcome()}
        )
        self.assertFalse(assessment.promotable)
        self.assertEqual(len(assessment.reasons), 2)

    def test_any_held_out_regression_blocks_promotion(self) -> None:
        proposal = ImprovementProposal(
            proposal_id="p3",
            baseline_version="1",
            candidate_version="2",
            changed_paths=("prompts/chief-of-staff.txt",),
            development_outcomes=(),
            held_out_outcomes=(outcome(assertions=0.8, safety=1),),
            rollback_version="1",
        )
        assessment = ImprovementPolicy().assess(
            proposal, {"held-out-1": outcome()}
        )
        self.assertFalse(assessment.promotable)
        self.assertTrue(any("safety regression" in item for item in assessment.reasons))

    def test_legacy_protected_path_remains_protected_after_rename(self) -> None:
        proposal = ImprovementProposal(
            proposal_id="p4",
            baseline_version="1",
            candidate_version="2",
            changed_paths=("src/agentops/billing.py",),
            development_outcomes=(),
            held_out_outcomes=(outcome(),),
            rollback_version="1",
        )
        assessment = ImprovementPolicy().assess(
            proposal, {"held-out-1": outcome()}
        )
        self.assertFalse(assessment.promotable)
        self.assertTrue(
            any("protected target" in reason for reason in assessment.reasons)
        )


if __name__ == "__main__":
    unittest.main()
