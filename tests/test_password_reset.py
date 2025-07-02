#!/usr/bin/env python3
"""
Unit tests for AWS IAM Self-Service Password Reset Tool
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add the scripts directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Import after path modification  # noqa: E402
import aws_iam_self_service_password_reset as pwd_reset  # noqa: E402


class TestPasswordGeneration(unittest.TestCase):
    """Test password generation functionality"""

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_passwordgen_length(self, mock_boto_client):
        """Test that generated passwords have correct length"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        mock_client.get_account_password_policy.return_value = {"PasswordPolicy": {}}

        password = pwd_reset.passwordgen(20)
        self.assertEqual(len(password), 20)

        password = pwd_reset.passwordgen(30)
        self.assertEqual(len(password), 30)

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_passwordgen_character_requirements(self, mock_boto_client):
        """Test that generated passwords meet character requirements"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        mock_client.get_account_password_policy.return_value = {"PasswordPolicy": {}}

        password = pwd_reset.passwordgen(20)

        # Check for uppercase letters
        self.assertTrue(any(c.isupper() for c in password))

        # Check for lowercase letters
        self.assertTrue(any(c.islower() for c in password))

        # Check for digits
        self.assertTrue(any(c.isdigit() for c in password))

        # Check for symbols
        self.assertTrue(any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password))

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_passwordgen_excludes_ambiguous(self, mock_boto_client):
        """Test that ambiguous characters are excluded when requested"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        mock_client.get_account_password_policy.return_value = {"PasswordPolicy": {}}

        password = pwd_reset.passwordgen(50, exclude_ambiguous=True)
        ambiguous = "0O1lI"

        for char in ambiguous:
            self.assertNotIn(char, password)

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_passwordgen_uniqueness(self, mock_boto_client):
        """Test that multiple calls generate different passwords"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        mock_client.get_account_password_policy.return_value = {"PasswordPolicy": {}}

        passwords = [pwd_reset.passwordgen(20) for _ in range(10)]

        # All passwords should be unique
        self.assertEqual(len(passwords), len(set(passwords)))


class TestPasswordPolicyValidation(unittest.TestCase):
    """Test password policy validation"""

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_validate_password_policy_success(self, mock_boto_client):
        """Test successful password policy validation"""
        # Mock IAM client and response
        mock_iam = Mock()
        mock_boto_client.return_value = mock_iam
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 8,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        }

        # Test valid password
        password = "ValidPass123!"
        errors = pwd_reset.validate_password_policy(password)
        self.assertEqual(errors, [])

    @patch("aws_iam_self_service_password_reset.boto3.client")
    def test_validate_password_policy_failures(self, mock_boto_client):
        """Test password policy validation failures"""
        # Mock IAM client and response
        mock_iam = Mock()
        mock_boto_client.return_value = mock_iam
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 12,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        }

        # Test password that's too short
        password = "Short1!"
        errors = pwd_reset.validate_password_policy(password)
        self.assertIn("Password must be at least 12 characters long", errors[0])

        # Test password without uppercase
        password = "nouppercase123!"
        errors = pwd_reset.validate_password_policy(password)
        self.assertIn("Password must contain uppercase letters", errors[0])


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


if __name__ == "__main__":
    # Create a test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordPolicyValidation))
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
