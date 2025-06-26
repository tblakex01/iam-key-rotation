#!/usr/bin/env python3
"""
Unit tests for AWS IAM Admin Password Reset Tool
"""

import unittest
from unittest.mock import Mock, patch
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


class TestClientCreation(unittest.TestCase):
    """Test IAM client creation functionality"""

    @patch("aws_iam_user_password_reset.boto3.Session")
    def test_get_iam_client_default(self, mock_session_class):
        """Test client creation with default parameters"""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_client = Mock()
        mock_session.client.return_value = mock_client

        result = admin_reset.get_iam_client()

        # Verify session created without profile/region
        mock_session_class.assert_called_once_with()
        mock_session.client.assert_called_once_with('iam')
        self.assertEqual(result, mock_client)

    @patch("aws_iam_user_password_reset.boto3.Session")
    def test_get_iam_client_with_profile(self, mock_session_class):
        """Test client creation with profile"""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_client = Mock()
        mock_session.client.return_value = mock_client

        result = admin_reset.get_iam_client(profile="test-profile")

        # Verify session created with profile
        mock_session_class.assert_called_once_with(profile_name="test-profile")
        mock_session.client.assert_called_once_with('iam')
        self.assertEqual(result, mock_client)

    @patch("aws_iam_user_password_reset.boto3.Session")
    def test_get_iam_client_with_region(self, mock_session_class):
        """Test client creation with region"""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_client = Mock()
        mock_session.client.return_value = mock_client

        result = admin_reset.get_iam_client(region="us-west-2")

        # Verify session created with region
        mock_session_class.assert_called_once_with(region_name="us-west-2")
        mock_session.client.assert_called_once_with('iam', region_name="us-west-2")
        self.assertEqual(result, mock_client)


class TestErrorHandling(unittest.TestCase):
    """Test error handling for IAM operations"""

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("sys.exit")
    def test_reset_user_not_found(self, mock_exit, mock_get_client):
        """Test reset command when user doesn't exist"""
        from botocore.exceptions import ClientError

        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        # Mock user not found
        error_response = {
            "Error": {"Code": "NoSuchEntity", "Message": "User not found"}
        }
        mock_client.get_user.side_effect = ClientError(error_response, "GetUser")

        # Mock sys.exit to raise an exception to stop execution
        mock_exit.side_effect = SystemExit(1)
        
        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "nonexistent"]):
            with self.assertRaises(SystemExit):
                admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("sys.exit")
    def test_reset_no_login_profile(self, mock_exit, mock_get_client):
        """Test reset command when user has no login profile"""
        from botocore.exceptions import ClientError

        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        # Mock successful get_user
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}

        # Mock no login profile
        error_response = {
            "Error": {"Code": "NoSuchEntity", "Message": "No login profile"}
        }
        mock_client.get_login_profile.side_effect = ClientError(
            error_response, "GetLoginProfile"
        )

        # Mock sys.exit to raise an exception to stop execution
        mock_exit.side_effect = SystemExit(1)
        
        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "testuser"]):
            with self.assertRaises(SystemExit):
                admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_reset_password_policy_violation(self, mock_print, mock_exit, mock_get_client):
        """Test reset command with password policy violation"""
        from botocore.exceptions import ClientError

        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
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

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("sys.exit")
    def test_profile_already_exists(self, mock_exit, mock_get_client):
        """Test profile command when login profile already exists"""
        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        # Mock successful get_user
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}

        # Mock existing login profile
        mock_client.get_login_profile.return_value = {"LoginProfile": {}}

        # Mock command line args
        with patch("sys.argv", ["script", "profile", "-u", "testuser"]):
            admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_access_denied_error(self, mock_print, mock_exit, mock_get_client):
        """Test handling of access denied errors"""
        from botocore.exceptions import ClientError

        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
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

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("builtins.print")
    def test_successful_password_reset(self, mock_print, mock_get_client):
        """Test successful password reset"""
        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        # Mock successful operations
        mock_client.get_user.return_value = {"User": {"UserName": "testuser"}}
        mock_client.get_login_profile.return_value = {"LoginProfile": {}}
        mock_client.update_login_profile.return_value = {}

        # Mock command line args
        with patch("sys.argv", ["script", "reset", "-u", "testuser"]):
            admin_reset.main()

        # Verify success message
        mock_print.assert_any_call("✓ Password has been reset for: testuser")

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("builtins.print")
    def test_successful_profile_creation(self, mock_print, mock_get_client):
        """Test successful profile creation"""
        from botocore.exceptions import ClientError

        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
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

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("sys.exit")
    @patch("builtins.print")
    def test_client_initialization_error(self, mock_print, mock_exit, mock_get_client):
        """Test error during client initialization"""
        # Mock client initialization failure
        mock_get_client.side_effect = Exception("AWS configuration error")
        
        # Mock sys.exit to raise an exception to stop execution
        mock_exit.side_effect = SystemExit(1)

        # Mock command line args
        with patch("sys.argv", ["script", "list-users"]):
            with self.assertRaises(SystemExit):
                admin_reset.main()

        # Verify error handling
        mock_exit.assert_called_with(1)
        mock_print.assert_any_call("Error initializing AWS client: AWS configuration error")


class TestListUsers(unittest.TestCase):
    """Test list users functionality"""

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("builtins.print")
    def test_list_users_success(self, mock_print, mock_get_client):
        """Test successful user listing"""
        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
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

    @patch("aws_iam_user_password_reset.get_iam_client")
    @patch("builtins.print")
    def test_list_users_empty(self, mock_print, mock_get_client):
        """Test listing when no users exist"""
        # Setup mock client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        # Mock empty response
        mock_client.list_users.return_value = {"Users": []}

        # Mock command line args
        with patch("sys.argv", ["script", "list-users"]):
            admin_reset.main()

        # Verify output
        mock_print.assert_any_call("No IAM users found.")


class TestArgumentParsing(unittest.TestCase):
    """Test command line argument parsing"""

    def test_parse_args_with_profile_and_region(self):
        """Test parsing arguments with profile and region"""
        with patch("sys.argv", ["script", "--profile", "test-profile", "--region", "us-west-2", "list-users"]):
            args = admin_reset.parse_args()
            
        self.assertEqual(args.profile, "test-profile")
        self.assertEqual(args.region, "us-west-2")
        self.assertEqual(args.command, "list-users")

    def test_parse_args_reset_command(self):
        """Test parsing reset command arguments"""
        with patch("sys.argv", ["script", "reset", "-u", "testuser"]):
            args = admin_reset.parse_args()
            
        self.assertEqual(args.command, "reset")
        self.assertEqual(args.username, "testuser")
        self.assertIsNone(args.profile)
        self.assertIsNone(args.region)


if __name__ == "__main__":
    unittest.main()