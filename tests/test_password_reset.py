#!/usr/bin/env python3
"""
Unit tests for AWS IAM Self-Service Password Reset Tool
"""

import unittest
from unittest.mock import Mock, patch, mock_open
import sys
import os

# Add the scripts directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Import after path modification  # noqa: E402
import aws_iam_self_service_password_reset as pwd_reset  # noqa: E402


class TestAWSConnectionValidation(unittest.TestCase):
    """Test AWS connection validation"""

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_validate_aws_connection_success(self, mock_boto_client):
        """Test successful AWS connection validation"""
        # Mock STS client and response
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::123456789012:user/testuser"
        }

        result = pwd_reset.validate_aws_connection()
        self.assertTrue(result)

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_validate_aws_connection_no_credentials(self, mock_boto_client):
        """Test AWS connection validation with no credentials"""
        from botocore.exceptions import NoCredentialsError

        # Mock STS client to raise NoCredentialsError
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()

        result = pwd_reset.validate_aws_connection()
        self.assertFalse(result)

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_validate_aws_connection_partial_credentials(self, mock_boto_client):
        """Test AWS connection validation with partial credentials"""
        from botocore.exceptions import PartialCredentialsError

        # Mock STS client to raise PartialCredentialsError
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = PartialCredentialsError(
            provider="test", cred_var="test"
        )

        result = pwd_reset.validate_aws_connection()
        self.assertFalse(result)


class TestCurrentUserRetrieval(unittest.TestCase):
    """Test current user information retrieval"""

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_get_current_user_success(self, mock_boto_client):
        """Test successful current user retrieval"""
        # Mock IAM client and response
        mock_iam = Mock()
        mock_boto_client.return_value = mock_iam
        mock_iam.get_user.return_value = {
            "User": {
                "UserName": "testuser",
                "UserId": "AIDACKCEVSQ6C2EXAMPLE",
                "Arn": "arn:aws:iam::123456789012:user/testuser",
            }
        }

        user = pwd_reset.get_current_user()
        self.assertIsNotNone(user)
        self.assertEqual(user["UserName"], "testuser")

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_get_current_user_not_found(self, mock_boto_client):
        """Test current user retrieval when user not found"""
        from botocore.exceptions import ClientError

        # Mock IAM client to raise NoSuchEntity error
        mock_iam = Mock()
        mock_boto_client.return_value = mock_iam
        error_response = {"Error": {"Code": "NoSuchEntity"}}
        mock_iam.get_user.side_effect = ClientError(error_response, "GetUser")

        user = pwd_reset.get_current_user()
        self.assertIsNone(user)


class TestAuditLogging(unittest.TestCase):
    """Test audit logging functionality"""

    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_log_password_reset(self, mock_open):
        """Test password reset logging"""
        username = "testuser"

        pwd_reset.log_password_reset(username)

        # Verify file was opened for append
        mock_open.assert_called_with("password_reset_audit.log", "a", encoding="utf-8")

        # Verify log entry was written
        handle = mock_open()
        handle.write.assert_called_once()

        # Check that the log entry contains the username
        args, kwargs = handle.write.call_args
        log_entry = args[0]
        self.assertIn(username, log_entry)
        self.assertIn("password_reset", log_entry)
        self.assertIn("success", log_entry)


class TestPasswordDisplay(unittest.TestCase):
    """Test secure password display functionality"""

    @patch("aws_iam_self_service_password_reset.Prompt.ask")
    @patch("aws_iam_self_service_password_reset.console")
    def test_secure_password_display_no_repeat(self, mock_console, mock_prompt):
        """Test secure password display without repeat"""
        mock_prompt.return_value = "n"

        test_password = "TestPassword123!"
        pwd_reset.secure_password_display(test_password)

        # Verify password was printed once
        mock_console.print.assert_called()

        # Verify prompt was asked
        mock_prompt.assert_called_once()

    @patch("aws_iam_self_service_password_reset.Prompt.ask")
    @patch("aws_iam_self_service_password_reset.console")
    def test_secure_password_display_with_repeat(self, mock_console, mock_prompt):
        """Test secure password display with repeat"""
        mock_prompt.return_value = "y"

        test_password = "TestPassword123!"
        pwd_reset.secure_password_display(test_password)

        # Verify password was printed twice (initial + repeat)
        self.assertEqual(mock_console.print.call_count, 2)


class TestMainFlow(unittest.TestCase):
    """Regression tests that exercise the interactive main workflow."""

    @patch("aws_iam_self_service_password_reset.log_password_reset")
    @patch("aws_iam_self_service_password_reset.secure_password_display")
    @patch(
        "aws_iam_self_service_password_reset.getpass.getpass",
        return_value="old-password",
    )
    @patch(
        "aws_iam_self_service_password_reset.generate_temporary_password",
        return_value="NewPassw0rd!",
    )
    @patch("aws_iam_self_service_password_reset.boto3.client")
    @patch(
        "aws_iam_self_service_password_reset.get_current_user",
        return_value={"UserName": "cli-user"},
    )
    @patch(
        "aws_iam_self_service_password_reset.validate_aws_connection", return_value=True
    )
    def test_main_successful_reset(
        self,
        mock_validate,
        mock_get_user,
        mock_boto_client,
        mock_generate_temporary_password,
        mock_getpass,
        mock_display,
        mock_log,
    ):
        iam_client = Mock()
        mock_boto_client.return_value = iam_client
        iam_client.get_login_profile.return_value = {}

        with patch("aws_iam_self_service_password_reset.rprint"):
            pwd_reset.main()

        iam_client.change_password.assert_called_once_with(
            OldPassword="old-password", NewPassword="NewPassw0rd!"
        )
        mock_display.assert_called_once_with("NewPassw0rd!")
        mock_log.assert_called_once_with("cli-user")

    @patch("aws_iam_self_service_password_reset.sys.exit", side_effect=SystemExit)
    @patch("aws_iam_self_service_password_reset.boto3.client")
    @patch(
        "aws_iam_self_service_password_reset.get_current_user",
        return_value={"UserName": "cli-user"},
    )
    @patch(
        "aws_iam_self_service_password_reset.validate_aws_connection", return_value=True
    )
    def test_main_missing_login_profile_triggers_exit(
        self, mock_validate, mock_get_user, mock_boto_client, mock_exit
    ):
        from botocore.exceptions import ClientError

        iam_client = Mock()
        mock_boto_client.return_value = iam_client
        iam_client.get_login_profile.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "missing"}},
            "GetLoginProfile",
        )

        with patch("aws_iam_self_service_password_reset.rprint"):
            with self.assertRaises(SystemExit):
                pwd_reset.main()

        mock_exit.assert_called_with(1)

    @patch("aws_iam_self_service_password_reset.sys.exit", side_effect=SystemExit)
    @patch(
        "aws_iam_self_service_password_reset.validate_aws_connection",
        return_value=False,
    )
    def test_main_exits_when_connection_invalid(self, mock_validate, mock_exit):
        with patch("aws_iam_self_service_password_reset.rprint"):
            with self.assertRaises(SystemExit):
                pwd_reset.main()

        mock_exit.assert_called_with(1)

    @patch("aws_iam_self_service_password_reset.sys.exit", side_effect=SystemExit)
    @patch("aws_iam_self_service_password_reset.get_current_user", return_value=None)
    @patch(
        "aws_iam_self_service_password_reset.validate_aws_connection", return_value=True
    )
    def test_main_exits_when_user_missing(
        self, mock_validate, mock_get_user, mock_exit
    ):
        with patch("aws_iam_self_service_password_reset.rprint"):
            with self.assertRaises(SystemExit):
                pwd_reset.main()

        mock_exit.assert_called_with(1)

    @patch("builtins.open", new_callable=mock_open)
    @patch("aws_iam_self_service_password_reset.sys.exit", side_effect=SystemExit)
    @patch("aws_iam_self_service_password_reset.getpass.getpass", return_value="old")
    @patch(
        "aws_iam_self_service_password_reset.generate_temporary_password",
        return_value="NewPass!1",
    )
    @patch("aws_iam_self_service_password_reset.boto3.client")
    @patch(
        "aws_iam_self_service_password_reset.get_current_user",
        return_value={"UserName": "cli-user"},
    )
    @patch(
        "aws_iam_self_service_password_reset.validate_aws_connection", return_value=True
    )
    def test_main_handles_policy_violation(
        self,
        mock_validate,
        mock_get_user,
        mock_boto_client,
        mock_generate_temporary_password,
        mock_getpass,
        mock_exit,
        mock_file,
    ):
        from botocore.exceptions import ClientError

        iam_client = Mock()
        mock_boto_client.return_value = iam_client
        iam_client.get_login_profile.return_value = {}
        iam_client.change_password.side_effect = ClientError(
            {"Error": {"Code": "PasswordPolicyViolation", "Message": "too short"}},
            "ChangePassword",
        )

        with patch("aws_iam_self_service_password_reset.rprint"):
            with self.assertRaises(SystemExit):
                pwd_reset.main()

        mock_exit.assert_called_with(1)
        mock_file().write.assert_called()

    @patch("builtins.open", new_callable=mock_open)
    @patch("aws_iam_self_service_password_reset.sys.exit", side_effect=SystemExit)
    @patch("aws_iam_self_service_password_reset.getpass.getpass", return_value="old")
    @patch(
        "aws_iam_self_service_password_reset.generate_temporary_password",
        return_value="NewPass!1",
    )
    @patch("aws_iam_self_service_password_reset.boto3.client")
    @patch(
        "aws_iam_self_service_password_reset.get_current_user",
        return_value={"UserName": "cli-user"},
    )
    @patch(
        "aws_iam_self_service_password_reset.validate_aws_connection", return_value=True
    )
    def test_main_handles_unexpected_exception(
        self,
        mock_validate,
        mock_get_user,
        mock_boto_client,
        mock_generate_temporary_password,
        mock_getpass,
        mock_exit,
        mock_file,
    ):
        iam_client = Mock()
        mock_boto_client.return_value = iam_client
        iam_client.get_login_profile.return_value = {}
        iam_client.change_password.side_effect = RuntimeError("boom")

        with patch("aws_iam_self_service_password_reset.rprint"):
            with self.assertRaises(SystemExit):
                pwd_reset.main()

        mock_exit.assert_called_with(1)
        mock_file().write.assert_called()


if __name__ == "__main__":
    # Create a test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestAWSConnectionValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestCurrentUserRetrieval))
    suite.addTests(loader.loadTestsFromTestCase(TestAuditLogging))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordDisplay))

    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with appropriate code
    if result.wasSuccessful():
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print(
            f"\n❌ Tests failed: {len(result.failures)} failures, "
            f"{len(result.errors)} errors"
        )
        sys.exit(1)
