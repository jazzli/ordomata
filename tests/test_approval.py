import unittest

from ordomata.approval import ApprovalPolicy
from ordomata.errors import ValidationError
from ordomata.models import PermissionClass


class ApprovalPolicyTests(unittest.TestCase):
    def test_only_classes_zero_and_one_are_enabled(self) -> None:
        policy = ApprovalPolicy()
        self.assertTrue(policy.classify(PermissionClass.READ_ONLY).executable_now)
        self.assertTrue(policy.classify(PermissionClass.LOCAL_DRAFT).executable_now)
        self.assertFalse(
            policy.classify(PermissionClass.REVERSIBLE_INTERNAL_WRITE).executable_now
        )
        with self.assertRaises(ValidationError):
            policy.assert_executable(PermissionClass.EXTERNAL_CONSEQUENTIAL)


if __name__ == "__main__":
    unittest.main()
