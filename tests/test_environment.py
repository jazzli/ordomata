from __future__ import annotations

import unittest

from ordomata.environment import (
    build_child_environment,
    inspect_risky_environment,
    is_sensitive_environment_name,
)
from ordomata.billing import (
    LEGACY_LIVE_RUN_ENVIRONMENT_NAME,
    LIVE_RUN_ENVIRONMENT_NAME,
)
from ordomata.redaction import REDACTED, Redactor


class EnvironmentTests(unittest.TestCase):
    def test_inspection_returns_names_only(self) -> None:
        secret = "must-never-appear"
        parent = {
            "PATH": "/bin",
            "OPENAI_API_KEY": secret,
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "UNRELATED": "value",
        }
        names = inspect_risky_environment(parent)
        self.assertEqual(
            names, ("CLAUDE_CODE_USE_BEDROCK", "OPENAI_API_KEY")
        )
        self.assertNotIn(secret, repr(names))

    def test_child_environment_is_narrow_and_parent_is_not_mutated(self) -> None:
        parent = {
            "PATH": "/bin",
            "HOME": "/safe/home",
            "TERM": "xterm",
            "OPENAI_API_KEY": "openai-secret",
            "ANTHROPIC_API_KEY": "anthropic-secret",
            "PROJECT_MODE": "parent-value",
        }
        original = dict(parent)
        result = build_child_environment(
            parent,
            approved={"PROJECT_MODE": "approved-value"},
        )

        self.assertTrue(result.valid)
        self.assertEqual(parent, original)
        self.assertEqual(result.sanitized_environment["PATH"], "/bin")
        self.assertEqual(result.sanitized_environment["HOME"], "/safe/home")
        self.assertEqual(
            result.sanitized_environment["PROJECT_MODE"], "approved-value"
        )
        self.assertNotIn("OPENAI_API_KEY", result.sanitized_environment)
        self.assertNotIn("ANTHROPIC_API_KEY", result.sanitized_environment)
        self.assertNotIn("openai-secret", repr(result))
        self.assertNotIn("anthropic-secret", repr(result))

    def test_approved_credential_shaped_name_is_rejected(self) -> None:
        result = build_child_environment(
            {"PATH": "/bin", "HOME": "/home"},
            approved={"SOME_SERVICE_API_KEY": "secret"},
        )
        self.assertFalse(result.valid)
        self.assertNotIn("SOME_SERVICE_API_KEY", result.sanitized_environment)
        self.assertNotIn("secret", " ".join(result.errors))
        self.assertTrue(is_sensitive_environment_name("database_password"))
        self.assertTrue(is_sensitive_environment_name("MODEL_TOKEN"))

    def test_approved_credential_shaped_value_is_rejected(self) -> None:
        result = build_child_environment(
            {"PATH": "/bin", "HOME": "/home"},
            approved={"PROJECT_HEADER": "Bearer abcdefghijklmnop"},
        )
        self.assertFalse(result.valid)
        self.assertNotIn("PROJECT_HEADER", result.sanitized_environment)
        self.assertNotIn("abcdefghijklmnop", " ".join(result.errors))

    def test_live_gate_names_cannot_enter_child_environment(self) -> None:
        for name in (
            LIVE_RUN_ENVIRONMENT_NAME,
            LEGACY_LIVE_RUN_ENVIRONMENT_NAME,
        ):
            with self.subTest(name=name):
                result = build_child_environment(
                    {"PATH": "/bin", "HOME": "/home"},
                    approved={name: "1"},
                )
                self.assertFalse(result.valid)
                self.assertNotIn(name, result.sanitized_environment)

    def test_generic_token_name_is_reported_without_value(self) -> None:
        secret = "opaque-value-that-must-not-appear"
        names = inspect_risky_environment({"MODEL_TOKEN": secret})
        self.assertEqual(names, ("MODEL_TOKEN",))
        self.assertNotIn(secret, repr(names))

    def test_redactor_handles_known_values_headers_and_nested_keys(self) -> None:
        redactor = Redactor(["literal-secret"])
        source = {
            "message": "Authorization: Bearer literal-secret",
            "OPENAI_API_KEY": "another-secret",
            "nested": ["value=literal-secret", "safe"],
        }
        redacted = redactor.redact(source)
        self.assertNotIn("literal-secret", repr(redacted))
        self.assertNotIn("another-secret", repr(redacted))
        self.assertEqual(redacted["OPENAI_API_KEY"], REDACTED)
        self.assertEqual(redactor.redact({"token": "opaque"})["token"], REDACTED)


if __name__ == "__main__":
    unittest.main()
