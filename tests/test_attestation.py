from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from agentops.attestation import (
    CONFIRMATION_PHRASES,
    BillingAttestationRefresh,
    refresh_billing_attestation,
)
from agentops.billing import FileBillingAttestationLoader
from agentops.cli import build_parser, main
from agentops.errors import ConfigurationError
from agentops.models import (
    AssessmentConfidence,
    BillingRoute,
    BillingRouteAssessment,
    BillingSafetyAttestation,
    CapacityState,
    PaidContinuationProtection,
    PaidCreditBalance,
)


NOW = 1_000_000.0
CODEX_FINGERPRINT = "a" * 64
CLAUDE_FINGERPRINT = "b" * 64


class TTYStringIO(StringIO):
    def isatty(self) -> bool:
        return True


class FakeBillingRunner:
    def __init__(
        self,
        runner_id: str,
        assessment: BillingRouteAssessment,
    ) -> None:
        self._runner_id = runner_id
        self.assessment = assessment
        self.inspections = 0

    @property
    def runner_id(self) -> str:
        return self._runner_id

    async def inspect_billing_route(self) -> BillingRouteAssessment:
        self.inspections += 1
        return self.assessment


def codex_assessment(**changes) -> BillingRouteAssessment:
    assessment = BillingRouteAssessment(
        runner_id="codex",
        route=BillingRoute.SUBSCRIPTION_INCLUDED,
        confidence=AssessmentConfidence.HIGH,
        evidence=("provider diagnostic free text must not be persisted",),
        capacity_state=CapacityState.AVAILABLE,
        paid_continuation_protection=PaidContinuationProtection.UNKNOWN,
        paid_credit_balance=PaidCreditBalance.ZERO,
        account_identity_fingerprint=CODEX_FINGERPRINT,
        capacity_observed_at=NOW - 1,
        capacity_expires_at=NOW + 300,
    )
    return replace(assessment, **changes)


def claude_assessment(**changes) -> BillingRouteAssessment:
    assessment = BillingRouteAssessment(
        runner_id="claude",
        route=BillingRoute.SUBSCRIPTION_INCLUDED,
        confidence=AssessmentConfidence.HIGH,
        evidence=("another provider-authored diagnostic sentence",),
        capacity_state=CapacityState.UNKNOWN,
        paid_continuation_protection=PaidContinuationProtection.UNKNOWN,
        paid_credit_balance=PaidCreditBalance.NOT_APPLICABLE,
        account_identity_fingerprint=CLAUDE_FINGERPRINT,
    )
    return replace(assessment, **changes)


class BillingAttestationWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def _refresh(
        self,
        root: Path,
        runner: FakeBillingRunner,
        phrase: str,
    ) -> tuple[BillingAttestationRefresh, str]:
        output = TTYStringIO()
        with (
            patch("agentops.attestation.sys.stdin", TTYStringIO(phrase + "\n")),
            patch("agentops.attestation.sys.stdout", output),
        ):
            result = await refresh_billing_attestation(
                root,
                runner,
                clock=lambda: NOW,
            )
        return result, output.getvalue()

    async def test_codex_writes_only_canonical_private_semantic_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = FakeBillingRunner("codex", codex_assessment())

            result, prompt = await self._refresh(
                root,
                runner,
                CONFIRMATION_PHRASES["codex"],
            )

            path = root / ".agentops" / "billing-attestations.json"
            self.assertEqual(result.path, path)
            self.assertEqual(result.maximum_validity_seconds, 3600)
            self.assertEqual(runner.inspections, 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(set(document), {"schema_version", "attestations"})
            self.assertEqual(document["schema_version"], 1)
            [record] = document["attestations"]
            self.assertEqual(
                record["paid_continuation_protection"],
                "verified_zero_balance_and_auto_top_up_disabled",
            )
            self.assertEqual(
                record["evidence_codes"],
                ["provider_ui_auto_top_up_disabled"],
            )
            self.assertNotIn("balance", record)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("provider diagnostic free text", raw)
            self.assertNotIn(CODEX_FINGERPRINT, prompt)
            self.assertNotIn(CODEX_FINGERPRINT, result.to_mapping().values())
            self.assertIsNotNone(
                FileBillingAttestationLoader(path).load(
                    "codex",
                    CODEX_FINGERPRINT,
                )
            )

    async def test_claude_confirmation_sets_both_required_codes_and_preserves_codex(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            await self._refresh(
                root,
                FakeBillingRunner("codex", codex_assessment()),
                CONFIRMATION_PHRASES["codex"],
            )

            result, prompt = await self._refresh(
                root,
                FakeBillingRunner("claude", claude_assessment()),
                CONFIRMATION_PHRASES["claude"],
            )

            self.assertEqual(result.maximum_validity_seconds, 900)
            self.assertIn("extra usage is disabled", prompt)
            self.assertIn("included subscription capacity", prompt)
            path = root / ".agentops" / "billing-attestations.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                {record["runner_id"] for record in document["attestations"]},
                {"codex", "claude"},
            )
            claude = next(
                record
                for record in document["attestations"]
                if record["runner_id"] == "claude"
            )
            self.assertEqual(
                claude["paid_continuation_protection"],
                "provider_enforced_disabled",
            )
            self.assertEqual(
                claude["evidence_codes"],
                [
                    "provider_ui_extra_usage_disabled",
                    "provider_ui_included_capacity_available",
                ],
            )
            self.assertNotIn(
                "another provider-authored diagnostic sentence",
                path.read_text(encoding="utf-8"),
            )

    async def test_non_tty_is_rejected_before_machine_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = FakeBillingRunner("codex", codex_assessment())
            with (
                patch(
                    "agentops.attestation.sys.stdin",
                    StringIO(CONFIRMATION_PHRASES["codex"] + "\n"),
                ),
                patch("agentops.attestation.sys.stdout", TTYStringIO()),
                self.assertRaisesRegex(ConfigurationError, "interactive terminal"),
            ):
                await refresh_billing_attestation(
                    root,
                    runner,
                    clock=lambda: NOW,
                )
            self.assertEqual(runner.inspections, 0)
            self.assertFalse((root / ".agentops").exists())

    async def test_confirmation_must_match_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = FakeBillingRunner("codex", codex_assessment())
            with (
                patch(
                    "agentops.attestation.sys.stdin",
                    TTYStringIO(CONFIRMATION_PHRASES["codex"] + " \n"),
                ),
                patch("agentops.attestation.sys.stdout", TTYStringIO()),
                self.assertRaisesRegex(ConfigurationError, "was not accepted"),
            ):
                await refresh_billing_attestation(
                    root,
                    runner,
                    clock=lambda: NOW,
                )
            self.assertEqual(runner.inspections, 1)
            self.assertFalse((root / ".agentops").exists())

    async def test_codex_machine_evidence_fails_closed_before_prompt(self) -> None:
        unsafe_assessments = (
            codex_assessment(route=BillingRoute.PURCHASED_PRODUCT_CREDIT),
            codex_assessment(confidence=AssessmentConfidence.LOW),
            codex_assessment(capacity_state=CapacityState.UNKNOWN),
            codex_assessment(paid_credit_balance=PaidCreditBalance.POSITIVE),
            codex_assessment(account_identity_fingerprint=None),
            codex_assessment(capacity_expires_at=NOW),
        )
        for assessment in unsafe_assessments:
            with self.subTest(assessment=assessment):
                with tempfile.TemporaryDirectory() as temporary:
                    output = TTYStringIO()
                    with (
                        patch(
                            "agentops.attestation.sys.stdin",
                            TTYStringIO(
                                CONFIRMATION_PHRASES["codex"] + "\n"
                            ),
                        ),
                        patch("agentops.attestation.sys.stdout", output),
                        self.assertRaises(ConfigurationError),
                    ):
                        await refresh_billing_attestation(
                            temporary,
                            FakeBillingRunner("codex", assessment),
                            clock=lambda: NOW,
                        )
                    self.assertEqual(output.getvalue(), "")
                    self.assertFalse((Path(temporary) / ".agentops").exists())

    async def test_claude_requires_paid_route_identity_and_no_contradiction(
        self,
    ) -> None:
        unsafe_assessments = (
            claude_assessment(route=BillingRoute.UNKNOWN),
            claude_assessment(account_identity_fingerprint=None),
            claude_assessment(capacity_state=CapacityState.LIMIT_REACHED),
            claude_assessment(
                paid_continuation_protection=PaidContinuationProtection.ENABLED
            ),
            claude_assessment(paid_credit_balance=PaidCreditBalance.POSITIVE),
        )
        for assessment in unsafe_assessments:
            with self.subTest(assessment=assessment):
                with tempfile.TemporaryDirectory() as temporary:
                    with (
                        patch(
                            "agentops.attestation.sys.stdin",
                            TTYStringIO(
                                CONFIRMATION_PHRASES["claude"] + "\n"
                            ),
                        ),
                        patch(
                            "agentops.attestation.sys.stdout",
                            TTYStringIO(),
                        ),
                        self.assertRaises(ConfigurationError),
                    ):
                        await refresh_billing_attestation(
                            temporary,
                            FakeBillingRunner("claude", assessment),
                            clock=lambda: NOW,
                        )
                    self.assertFalse((Path(temporary) / ".agentops").exists())

    async def test_assessment_loaded_from_an_attestation_cannot_self_refresh(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assessment = codex_assessment()
            # Construct a non-None marker with the same strict shape.
            loaded = replace(
                assessment,
                attestation=BillingSafetyAttestation(
                    runner_id="codex",
                    account_identity_fingerprint=CODEX_FINGERPRINT,
                ),
            )
            with (
                patch(
                    "agentops.attestation.sys.stdin",
                    TTYStringIO(CONFIRMATION_PHRASES["codex"] + "\n"),
                ),
                patch("agentops.attestation.sys.stdout", TTYStringIO()),
                self.assertRaisesRegex(ConfigurationError, "not independent"),
            ):
                await refresh_billing_attestation(
                    temporary,
                    FakeBillingRunner("codex", loaded),
                    clock=lambda: NOW,
                )

    async def test_symlinked_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "private-target"
            target.mkdir()
            (root / ".agentops").symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ConfigurationError, "symlink"):
                await self._refresh(
                    root,
                    FakeBillingRunner("codex", codex_assessment()),
                    CONFIRMATION_PHRASES["codex"],
                )
            self.assertFalse((target / "billing-attestations.json").exists())

    async def test_atomic_replace_failure_preserves_previous_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            await self._refresh(
                root,
                FakeBillingRunner("codex", codex_assessment()),
                CONFIRMATION_PHRASES["codex"],
            )
            path = root / ".agentops" / "billing-attestations.json"
            previous = path.read_bytes()
            with patch(
                "agentops.attestation.os.replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaisesRegex(ConfigurationError, "stored safely"):
                    await self._refresh(
                        root,
                        FakeBillingRunner("claude", claude_assessment()),
                        CONFIRMATION_PHRASES["claude"],
                    )
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(
                list(path.parent.glob(".billing-attestations.*.tmp")),
                [],
            )


class BillingAttestationParserTests(unittest.TestCase):
    def test_command_has_no_noninteractive_yes_override(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["billing-attest", "--runner", "codex", "--yes"]
            )

    def test_cli_dispatches_an_unadorned_runner_and_safe_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BillingAttestationRefresh(
                runner_id="codex",
                path=root / ".agentops" / "billing-attestations.json",
                maximum_validity_seconds=300,
            )
            refresh = AsyncMock(return_value=result)
            stdout = StringIO()
            stderr = StringIO()
            with (
                patch(
                    "agentops.cli.refresh_billing_attestation",
                    new=refresh,
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = main(
                    (
                        "--project-root",
                        str(root),
                        "billing-attest",
                        "--runner",
                        "codex",
                    )
                )

            self.assertEqual(status, 0, stderr.getvalue())
            refresh.assert_awaited_once()
            called_root, runner = refresh.await_args.args
            self.assertEqual(called_root, root.resolve())
            self.assertEqual(runner.runner_id, "codex")
            self.assertIsNone(runner._billing_attestation)
            self.assertIsNone(runner._billing_attestation_loader)
            self.assertNotIn(CODEX_FINGERPRINT, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
