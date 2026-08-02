from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import inspect
import json
import os
import socket
import subprocess
import unittest
from unittest.mock import patch

import ordomata.repository_executable_native_loader_nested_target_chain_guard as guard_module
import ordomata.repository_executable_native_loader_nested_target_resolution as nested_module
import ordomata.repository_executable_shebang_nested_target_resolution as nofollow_module
from ordomata.errors import ValidationError
from ordomata.repository_executable_native_loader_nested_target_chain_guard import (
    GUARD_SCOPE,
    INSPECTION_SOURCE,
    MAXIMUM_RESOLUTION_DEPTH,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_KIND,
    REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION,
    RESOLUTION_DEPTH,
    RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt,
    inspect_staged_executable_native_loader_nested_target_chain_guard,
)

if __package__:
    from . import (
        test_repository_executable_native_loader_nested_target_resolution
        as nested_test_module,
    )
else:
    import test_repository_executable_native_loader_nested_target_resolution \
        as nested_test_module


FIXED_ERROR = (
    "repository executable native loader nested target chain guard is invalid"
)


@unittest.skipUnless(os.name == "posix", "native-loader chain guard requires POSIX")
class RepositoryExecutableNativeLoaderNestedTargetChainGuardTests(
    unittest.TestCase
):
    nested_fixture = (
        nested_test_module
        .RepositoryExecutableNativeLoaderNestedTargetResolutionTests
    )
    fixture = nested_fixture.fixture

    def _chain(self, **kwargs: object) -> dict[str, object]:
        return self.nested_fixture._chain(self, **kwargs)

    def _nested(self, chain: dict[str, object]):
        return self.nested_fixture._inspect(self, chain)

    @staticmethod
    def _source_lease_snapshot(lease: object) -> tuple[object, ...]:
        return (
            lease.state,
            lease.receipt,
            lease.cleanup_receipt,
            lease._receipt_digest_anchor,
            lease._receipt_staged_file_refs_anchor,
            lease._owner_pid,
            id(lease._files),
            lease._root_descriptor,
            lease._root_metadata,
            lease._pending_name,
            lease._pending_identity,
            lease._pending_descriptors,
            lease._descriptor_release_unverifiable,
        )

    def _guard(
        self,
        chain: dict[str, object],
        nested: object,
        **overrides: object,
    ):
        arguments = {
            "expected_target_requirements": chain["target_requirements"],
            "expected_target_runtime": chain["target_runtime"],
            "expected_target_staging": chain["target_staging"],
            "expected_target_resolution": chain["first_resolution"],
            "target_lease": chain["target_lease"],
            "expected_source_staging": chain["source_staging"],
            "source_lease": chain["source_lease"],
            "expected_loader_paths": chain["first_paths"],
            "expected_nested_loader_paths": chain["nested_paths"],
        }
        arguments.update(overrides)
        return inspect_staged_executable_native_loader_nested_target_chain_guard(
            nested,
            **arguments,
        )

    def _assert_invalid(
        self,
        chain: dict[str, object],
        nested: object,
        **overrides: object,
    ) -> None:
        with self.assertRaises(ValidationError) as caught:
            self._guard(chain, nested, **overrides)
        self.assertEqual(str(caught.exception), FIXED_ERROR)
        self.assertIsNone(caught.exception.__cause__)

    def test_happy_correspondence_privacy_and_immutability(self) -> None:
        chain = self._chain()
        nested = self._nested(chain)
        receipt = self._guard(chain, nested)
        repeated = self._guard(chain, nested)

        self.assertEqual(receipt, repeated)
        self.assertIsInstance(
            receipt,
            RepositoryExecutableNativeLoaderNestedTargetChainGuardReceipt,
        )
        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.lineage_count, 2)
        self.assertEqual(receipt.command_count, 2)
        self.assertEqual(receipt.known_chain_guard_verified_count, 2)
        self.assertEqual(receipt.guarded_measurement_count, 2)
        self.assertEqual(receipt.known_source_identity_count, 4)
        self.assertEqual(receipt.known_target_identity_count, 4)
        self.assertEqual(receipt.protected_staging_root_identity_count, 2)
        self.assertEqual(
            receipt.nested_target_resolution_receipt_digest,
            nested.receipt_digest,
        )
        self.assertEqual(
            receipt.target_loader_requirements_receipt_digest,
            chain["target_requirements"].receipt_digest,
        )
        canonical = receipt.to_canonical()
        evidence = receipt.to_evidence()
        self.assertEqual(evidence["receipt_digest"], receipt.receipt_digest)
        self.assertEqual(evidence["guard_scope"], GUARD_SCOPE)
        self.assertEqual(evidence["effect_class"], 0)
        self.assertTrue(
            evidence["known_source_original_identity_reentry_excluded"]
        )
        self.assertTrue(
            evidence["known_source_staged_identity_reentry_excluded"]
        )
        self.assertTrue(
            evidence["source_staging_root_identity_ancestor_excluded"]
        )
        self.assertFalse(evidence["execution_enabled"])
        self.assertFalse(evidence["harness_invoked"])
        self.assertFalse(evidence["model_invoked"])
        for private_path in (
            str(chain["root"]),
            str(chain["nested_one"]),
            str(chain["target_stage_root"]),
        ):
            self.assertNotIn(private_path, json.dumps(canonical, sort_keys=True))
            self.assertNotIn(private_path, json.dumps(evidence, sort_keys=True))
            self.assertNotIn(private_path, repr(receipt))
        with self.assertRaises(FrozenInstanceError):
            receipt.requirement_count = 99

    def test_shared_nested_target_has_one_guarded_measurement(self) -> None:
        chain = self._chain(same_nested_target=True)
        nested = self._nested(chain)
        receipt = self._guard(chain, nested)

        self.assertEqual(receipt.requirement_count, 2)
        self.assertEqual(receipt.guarded_measurement_count, 1)
        self.assertEqual(
            len(
                {
                    item.guarded_measurement_ref
                    for item in receipt.requirements
                }
            ),
            1,
        )

    def test_non_declared_and_no_target_outcomes_do_not_read_candidates(self) -> None:
        cases = (
            ("elf_absent", "loader_declaration_absent"),
            ("mach_absent", "loader_declaration_absent"),
            ("unsupported", "unsupported_native_layout"),
            ("non_native", "non_native_not_applicable"),
        )
        for content_kind, expected in cases:
            with self.subTest(content_kind=content_kind):
                chain = self._chain(
                    same_first_target=True,
                    first_content_kind=content_kind,
                )
                nested = self._nested(chain)
                with patch.object(
                    nofollow_module,
                    "_BUILTIN_READ",
                    side_effect=AssertionError("candidate read"),
                ):
                    receipt = self._guard(chain, nested)
                self.assertEqual(receipt.guarded_measurement_count, 0)
                self.assertEqual(receipt.requirements[0].disposition, expected)

        chain = self._chain(no_first_targets=True)
        nested = self._nested(chain)
        with patch.object(
            nofollow_module,
            "_BUILTIN_READ",
            side_effect=AssertionError("candidate read"),
        ):
            receipt = self._guard(chain, nested)
        self.assertEqual(receipt.requirement_count, 0)
        self.assertEqual(receipt.guarded_measurement_count, 0)
        self.assertEqual(receipt.known_target_identity_count, 0)
        self.assertEqual(receipt.protected_staging_root_identity_count, 1)
        self.assertTrue(
            all(
                item.disposition != "guard_requirement_bound"
                for item in receipt.lineages
            )
        )

    def test_original_source_identity_and_hardlink_alias_fail_before_read(self) -> None:
        cases = (
            {"nested_source_reentry": True},
            {"nested_source_hardlink_alias": True},
        )
        for parameters in cases:
            with self.subTest(parameters=parameters):
                chain = self._chain(same_first_target=True, **parameters)
                nested = self._nested(chain)
                with patch.object(
                    nofollow_module,
                    "_BUILTIN_READ",
                    side_effect=AssertionError("leaf bytes read"),
                ):
                    self._assert_invalid(chain, nested)

    def test_source_staging_root_descendant_fails_before_read(self) -> None:
        chain = self._chain(
            same_first_target=True,
            nested_under_source_stage_root=True,
        )
        nested = self._nested(chain)
        with patch.object(
            nofollow_module,
            "_BUILTIN_READ",
            side_effect=AssertionError("leaf bytes read"),
        ):
            self._assert_invalid(chain, nested)

    def test_forged_inputs_and_closed_leases_fail_fixed_and_redacted(self) -> None:
        chain = self._chain(same_first_target=True)
        nested = self._nested(chain)
        forged_nested = replace(
            nested,
            registration_digest="sha256:" + "0" * 64,
        )
        self._assert_invalid(chain, forged_nested)
        self._assert_invalid(
            chain,
            nested,
            expected_source_staging=replace(
                chain["source_staging"],
                registration_digest="sha256:" + "0" * 64,
            ),
        )
        self._assert_invalid(
            chain,
            nested,
            expected_target_resolution=replace(
                chain["first_resolution"],
                registration_digest="sha256:" + "0" * 64,
            ),
        )

        chain["source_lease"].close()
        self._assert_invalid(chain, nested)

        chain = self._chain(same_first_target=True)
        nested = self._nested(chain)
        chain["target_lease"].close()
        self._assert_invalid(chain, nested)

    def test_two_guarded_reproductions_and_closing_source_anchor(self) -> None:
        chain = self._chain(same_first_target=True)
        nested = self._nested(chain)
        inspect_action = guard_module._BUILTIN_INSPECT_NESTED_TARGETS
        source_snapshot = guard_module._BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT
        namespace_matches = (
            nested_module._BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES
        )
        calls: list[dict[str, object]] = []

        def observe(*args: object, **kwargs: object):
            calls.append(dict(kwargs))
            return inspect_action(*args, **kwargs)

        with patch.object(
            guard_module,
            "_BUILTIN_INSPECT_NESTED_TARGETS",
            side_effect=observe,
        ), patch.object(
            guard_module,
            "_BUILTIN_ACTIVE_SOURCE_STAGE_SNAPSHOT",
            wraps=source_snapshot,
        ) as source_mock:
            with patch.object(
                nested_module,
                "_BUILTIN_NESTED_TARGET_NAMESPACE_MATCHES",
                wraps=namespace_matches,
            ) as namespace_mock:
                self._guard(chain, nested)

        self.assertEqual(len(calls), 2)
        self.assertNotIn("expected_receipt_canonical", calls[0])
        self.assertNotIn("closing_guard_anchor", calls[0])
        self.assertEqual(calls[1]["expected_receipt_canonical"], nested.to_canonical())
        self.assertTrue(inspect.isfunction(calls[1]["closing_guard_anchor"]))
        self.assertGreaterEqual(source_mock.call_count, 4)
        self.assertEqual(namespace_mock.call_count, 2)

    def test_receipt_projection_rejects_set_lineage_and_count_forgery(self) -> None:
        chain = self._chain(same_first_target=True)
        receipt = self._guard(chain, self._nested(chain))
        digest = "sha256:" + "0" * 64
        for forged in (
            replace(receipt, requirement_count=999),
            replace(receipt, guarded_measurement_count=999),
            replace(receipt, known_source_identity_set_digest=digest),
            replace(receipt, total_guarded_bytes=999),
            replace(
                receipt,
                lineages=(
                    replace(receipt.lineages[0], chain_guard_lineage_ref=digest),
                ),
            ),
        ):
            with self.subTest(forged=type(forged).__name__):
                with self.assertRaises(ValueError):
                    forged.to_canonical()

    def test_frozen_proof_graph_ignores_public_helper_monkeypatches(self) -> None:
        chain = self._chain(same_first_target=True)
        nested = self._nested(chain)
        expected = self._guard(chain, nested)
        with patch.object(
            guard_module,
            "_active_source_stage_snapshot",
            side_effect=AssertionError("public source helper"),
        ), patch.object(
            guard_module,
            "_nested_resolution_projection_v1",
            side_effect=AssertionError("public nested projection"),
        ), patch.object(
            guard_module,
            "_inspect_staged_executable_native_loader_nested_targets",
            side_effect=AssertionError("public nested resolver"),
        ):
            self.assertEqual(self._guard(chain, nested), expected)

    def test_no_process_network_or_lease_mutation_effects(self) -> None:
        chain = self._chain(same_first_target=True)
        nested = self._nested(chain)
        source_before = self._source_lease_snapshot(chain["source_lease"])
        target_before = self.nested_fixture._lease_snapshot(
            chain["target_lease"]
        )
        with patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("subprocess invoked"),
        ), patch.object(
            socket,
            "socket",
            side_effect=AssertionError("network invoked"),
        ), patch.object(
            os,
            "system",
            side_effect=AssertionError("shell invoked"),
        ):
            self._guard(chain, nested)
        self.assertEqual(
            source_before,
            self._source_lease_snapshot(chain["source_lease"]),
        )
        self.assertEqual(
            target_before,
            self.nested_fixture._lease_snapshot(chain["target_lease"]),
        )

    def test_keyboard_interrupt_and_system_exit_are_preserved(self) -> None:
        chain = self._chain(same_first_target=True)
        nested = self._nested(chain)
        for signal in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(signal=type(signal).__name__):
                with patch.object(
                    guard_module,
                    "_BUILTIN_INSPECT_NESTED_TARGETS",
                    side_effect=signal,
                ):
                    with self.assertRaises(type(signal)):
                        self._guard(chain, nested)

    def test_exports_signature_and_public_surface_are_exact(self) -> None:
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_KIND,
            "repository_executable_native_loader_nested_target_chain_guard",
        )
        self.assertEqual(
            REPOSITORY_EXECUTABLE_NATIVE_LOADER_NESTED_TARGET_CHAIN_GUARD_SCHEMA_VERSION,
            1,
        )
        self.assertEqual(INSPECTION_SOURCE, "controller_inspected")
        self.assertEqual(
            GUARD_SCOPE,
            "known_native_loader_source_chain_identity_and_staging_root_identity_v1",
        )
        self.assertEqual(RESOLUTION_DEPTH, 2)
        self.assertEqual(MAXIMUM_RESOLUTION_DEPTH, 2)
        signature = inspect.signature(
            inspect_staged_executable_native_loader_nested_target_chain_guard
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "expected_nested_resolution",
                "expected_target_requirements",
                "expected_target_runtime",
                "expected_target_staging",
                "expected_target_resolution",
                "target_lease",
                "expected_source_staging",
                "source_lease",
                "expected_loader_paths",
                "expected_nested_loader_paths",
            ),
        )
        self.assertEqual(
            guard_module.__all__[-1],
            "inspect_staged_executable_native_loader_nested_target_chain_guard",
        )
        for name in tuple(signature.parameters)[1:]:
            self.assertEqual(
                signature.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )


if __name__ == "__main__":
    unittest.main()
