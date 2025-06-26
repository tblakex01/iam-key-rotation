#!/usr/bin/env python3
"""
Unit tests for AWS IAM Admin Password Reset Tool
"""

import unittest
from unittest.mock import Mock, patch, call
import sys
import os

# Add the scripts directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Import after path modification  # noqa: E402
import aws_iam_user_password_reset as admin_reset  # noqa: E402


class TestPasswordGeneration(unittest.TestCase):
    """Test admin password generation functionality"""

    def test_passwordgen_meets_requirements(self):
        """Test that generated passwords meet AWS requirements"""
        import string

        for _ in range(10):
            password = admin_reset.passwordgen()

            # Check length
            self.assertEqual(len(password), 20)

            # Check for required character classes
            self.assertTrue(any(c in string.ascii_uppercase for c in password))
            self.assertTrue(any(c in string.ascii_lowercase for c in password))
            self.assertTrue(any(c in string.digits for c in password))
            self.assertTrue(any(c in string.punctuation for c in password))


class TestErrorHandling(unittest.TestCase):
    """Test error handling for IAM operations"""

    @patch("aws_iam_user_password_reset.client")
    @patch("sys.exit")
    def test_reset_user_not_found(self, mock_exit, mock_client):
        """Test reset command when user doesn't exist"""
        from botocore.exceptions import ClientError

        # Mock user not found
        error_response = {
            "Error": {"Code": "NoSuchEntity", "Message": "User not found"}
        }
        mock_client.get_user.side_effect = ClientError(error_response, "GetUser")

        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "nonexistent"]):
            admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)

    @patch("aws_iam_user_password_reset.client")
    @patch("sys.exit")
    def test_reset_no_login_profile(self, mock_exit, mock_client):
        """Test reset command when user has no login profile"""
        from botocore.exceptions import ClientError

        # Mock successful get_user
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}

        # Mock no login profile
        error_response = {
            "Error": {"Code": "NoSuchEntity", "Message": "No login profile"}
        }
        mock_client.get_login_profile.side_effect = ClientError(
            error_response, "GetLoginProfile"
        )

        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "testuser"]):
            admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)

    @patch("aws_iam_user_password_reset.client")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_reset_password_policy_violation(self, mock_print, mock_exit, mock_client):
        """Test reset command with password policy violation"""
        from botocore.exceptions import ClientError

        # Mock successful get_user and get_login_profile
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}
        mock_client.get_login_profile.return_value = {"LoginProfile": {}}

        # Mock password policy violation
        error_response = {
            "Error": {
                "Code": "PasswordPolicyViolation",
                "Message": "Password does not meet policy requirements",
            }
        }
        mock_client.update_login_profile.side_effect = ClientError(
            error_response, "UpdateLoginProfile"
        )

        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "testuser"]):
            admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)
        # Check that policy violation message was printed
        mock_print.assert_any_call(
            "Error: Generated password violates account password policy."
        )

    @patch("aws_iam_user_password_reset.client")
    @patch("sys.exit")
    def test_profile_already_exists(self, mock_exit, mock_client):
        """Test profile command when login profile already exists"""
        # Mock successful get_user
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}

        # Mock existing login profile
        mock_client.get_login_profile.return_value = {"LoginProfile": {}}

        # Mock command line args
        with patch("sys.argv", ["script", "profile", "-u", "testuser"]):
            admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)

    @patch("aws_iam_user_password_reset.client")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_access_denied_error(self, mock_print, mock_exit, mock_client):
        """Test handling of access denied errors"""
        from botocore.exceptions import ClientError

        # Mock access denied
        error_response = {
            "Error": {"Code": "AccessDenied", "Message": "User is not authorized"}
        }
        mock_client.get_user.side_effect = ClientError(error_response, "GetUser")

        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "testuser"]):
            admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)
        mock_print.assert_any_call(
            "Error: Access denied. You need IAM user administration permissions."
        )

    @patch("aws_iam_user_password_reset.client")
    @patch("builtins.print")
    def test_successful_password_reset(self, mock_print, mock_client):
        """Test successful password reset"""
        # Mock successful operations
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}
        mock_client.get_login_profile.return_value = {"LoginProfile": {}}
        mock_client.update_login_profile.return_value = {}

        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "testuser"]):
            admin_reset.main()

        # Verify success message
        mock_print.assert_any_call("✓ Password has been reset for: testuser")

    @patch("aws_iam_user_password_reset.client")
    @patch("builtins.print")
    def test_successful_profile_creation(self, mock_print, mock_client):
        """Test successful profile creation"""
        from botocore.exceptions import ClientError

        # Mock successful get_user
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}

        # Mock no existing login profile
        error_response = {"Error": {"Code": "NoSuchEntity"}}
        mock_client.get_login_profile.side_effect = ClientError(
            error_response, "GetLoginProfile"
        )

        # Mock successful profile creation
        mock_client.create_login_profile.return_value = {}

        # Mock command line args
        with patch("sys.argv", ["script", "profile", "-u", "testuser"]):
            admin_reset.main()

        # Verify success message
        mock_print.assert_any_call("✓ New login profile has been created for: testuser")


class TestListUsers(unittest.TestCase):
    """Test list users functionality"""

    @patch("aws_iam_user_password_reset.client")
    @patch("builtins.print")
    def test_list_users_success(self, mock_print, mock_client):
        """Test successful user listing"""
        # Mock IAM response
        mock_client.list_users.return_value = {
            "Users": [
                {"UserName": "user1"},
                {"UserName": "user2"},
                {"UserName": "user3"},
            ]
        }

        # Mock command line args
        with patch("sys.argv", ["script", "list-users"]):
            admin_reset.main()

        # Verify output
        mock_print.assert_any_call("Found 3 IAM users:")
        mock_print.assert_any_call("  - user1")
        mock_print.assert_any_call("  - user2")
        mock_print.assert_any_call("  - user3")

    @patch("aws_iam_user_password_reset.client")
    @patch("builtins.print")
    def test_list_users_empty(self, mock_print, mock_client):
        """Test listing when no users exist"""
        # Mock empty response
        mock_client.list_users.return_value = {"Users": []}

        # Mock command line args
        with patch("sys.argv", ["script", "list-users"]):
            admin_reset.main()

        # Verify output
        mock_print.assert_any_call("No IAM users found.")


if __name__ == "__main__":
    unittest.main()
