"""Unit tests for the shared IAM password helpers."""

import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

SCRIPT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPT_ROOT / "lambda"))

from common import iam_passwords  # noqa: E402


class TestIAMPasswordHelpers(unittest.TestCase):
    def test_generate_password_meets_requirements(self):
        mock_client = Mock()
        mock_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 12,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        }
        password = iam_passwords.generate_temporary_password(mock_client, min_length=14)
        self.assertGreaterEqual(len(password), 14)
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in iam_passwords.DEFAULT_SYMBOLS for c in password))

    def test_validates_password_policy_failures(self):
        policy = {
            "MinimumPasswordLength": 10,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
        }

        errors = iam_passwords.validate_password_against_policy("short", policy)
        self.assertIn("Password must be at least 10 characters long", errors[0])
        errors = iam_passwords.validate_password_against_policy(
            "onlylowercase1!", policy
        )
        self.assertIn("Password must contain uppercase letters", errors)

    @patch("common.iam_passwords.secrets.SystemRandom")
    def test_generate_password_retries_when_policy_violated(self, mock_random):
        mock_client = Mock()
        mock_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 8}
        }
        mock_random().shuffle.side_effect = lambda seq: None
        password = iam_passwords.generate_temporary_password(mock_client, min_length=8)
        self.assertEqual(len(password), 8)


if __name__ == "__main__":
    unittest.main()
