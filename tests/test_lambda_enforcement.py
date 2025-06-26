#!/usr/bin/env python3
"""
Unit tests for AWS IAM Access Key Enforcement Lambda
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os
import json
from datetime import datetime, timedelta

# Add the lambda directory to the path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "lambda", "access_key_enforcement")
)

# Import after path modification  # noqa: E402
import access_key_enforcement  # noqa: E402


class TestLambdaHandler(unittest.TestCase):
    """Test the main Lambda handler"""

    @patch.dict(
        os.environ,
        {
            "WARNING_THRESHOLD": "75",
            "URGENT_THRESHOLD": "85",
            "DISABLE_THRESHOLD": "90",
            "AUTO_DISABLE": "false",
            "SENDER_EMAIL": "test@example.com",
        },
    )
    @patch("access_key_enforcement.iam_client")
    @patch("access_key_enforcement.ses_client")
    @patch("access_key_enforcement.cloudwatch")
    def test_lambda_handler_success(self, mock_cloudwatch, mock_ses, mock_iam):
        """Test successful Lambda execution"""
        # Mock credential report generation
        mock_iam.generate_credential_report.return_value = {}
        credential_report_data = (
            "user,arn,user_creation_time,password_enabled,password_last_used,"
            "password_last_changed,password_next_rotation,mfa_active,"
            "access_key_1_active,access_key_1_last_rotated,"
            "access_key_1_last_used_date,access_key_1_last_used_region,"
            "access_key_1_last_used_service,access_key_2_active,"
            "access_key_2_last_rotated\n"
            "testuser,arn:aws:iam::123456789012:user/testuser,"
            "2023-01-01T00:00:00+00:00,true,N/A,2023-01-01T00:00:00+00:00,"
            "N/A,false,true,2023-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A"
        )
        mock_iam.get_credential_report.return_value = {
            "Content": credential_report_data.encode()
        }

        # Mock user tags (no exemption)
        mock_iam.list_user_tags.return_value = {
            "Tags": [{"Key": "email", "Value": "test@example.com"}]
        }

        # Mock access keys
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE123456789"}]
        }

        # Mock successful SES send
        mock_ses.send_email.return_value = {"MessageId": "test-message-id"}

        # Mock CloudWatch put_metric_data
        mock_cloudwatch.put_metric_data.return_value = {}

        # Test event and context
        event = {}
        context = Mock()
        context.function_name = "test-function"

        # Execute handler
        result = access_key_enforcement.lambda_handler(event, context)

        # Verify response
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("message", json.loads(result["body"]))

    @patch.dict(
        os.environ,
        {
            "WARNING_THRESHOLD": "75",
            "URGENT_THRESHOLD": "85", 
            "DISABLE_THRESHOLD": "90",
            "AUTO_DISABLE": "false",
            "SENDER_EMAIL": "test@example.com",
        },
    )
    @patch("access_key_enforcement.iam_client")
    def test_lambda_handler_credential_report_timeout(self, mock_iam):
        """Test Lambda execution when credential report generation times out"""
        # Mock credential report generation
        mock_iam.generate_credential_report.return_value = {}
        
        # Mock get_credential_report to never return Content (simulating timeout)
        mock_iam.get_credential_report.return_value = {"State": "INPROGRESS"}
        
        # Test event and context
        event = {}
        context = Mock()
        context.function_name = "test-function"

        # Execute handler - should raise an exception due to timeout
        with self.assertRaises(Exception) as cm:
            access_key_enforcement.lambda_handler(event, context)
        
        # Verify the timeout exception message
        self.assertIn("Credential report generation timed out", str(cm.exception))
        self.assertIn("60 seconds", str(cm.exception))

    @patch.dict(
        os.environ,
        {
            "WARNING_THRESHOLD": "75",
            "URGENT_THRESHOLD": "85",
            "DISABLE_THRESHOLD": "90", 
            "AUTO_DISABLE": "false",
            "SENDER_EMAIL": "test@example.com",
        },
    )
    @patch("access_key_enforcement.iam_client")
    @patch("access_key_enforcement.ses_client")
    @patch("access_key_enforcement.cloudwatch")
    @patch("access_key_enforcement.time.sleep")  # Mock sleep to speed up test
    def test_lambda_handler_credential_report_retry_success(self, mock_sleep, mock_cloudwatch, mock_ses, mock_iam):
        """Test Lambda execution when credential report succeeds after retries"""
        # Mock credential report generation
        mock_iam.generate_credential_report.return_value = {}
        
        # Mock get_credential_report to succeed on third attempt
        mock_iam.get_credential_report.side_effect = [
            {"State": "INPROGRESS"},  # First attempt - still in progress
            {"State": "INPROGRESS"},  # Second attempt - still in progress  
            {  # Third attempt - success
                "Content": b"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated\ntestuser,arn:aws:iam::123456789012:user/testuser,2023-01-01T00:00:00+00:00,true,N/A,2023-01-01T00:00:00+00:00,N/A,false,false,N/A,N/A,N/A,N/A,false,N/A"
            }
        ]

        # Mock other required services
        mock_iam.list_user_tags.return_value = {"Tags": []}  # No exemption tags
        mock_cloudwatch.put_metric_data.return_value = {}

        # Test event and context
        event = {}
        context = Mock()
        context.function_name = "test-function"

        # Execute handler
        result = access_key_enforcement.lambda_handler(event, context)

        # Verify response
        self.assertEqual(result["statusCode"], 200)
        
        # Verify sleep was called twice (for the retry attempts)
        self.assertEqual(mock_sleep.call_count, 3)

    @patch.dict(
        os.environ,
        {
            "WARNING_THRESHOLD": "75",
            "URGENT_THRESHOLD": "85",
            "DISABLE_THRESHOLD": "90",
            "AUTO_DISABLE": "false", 
            "SENDER_EMAIL": "test@example.com",
            "CREDENTIAL_REPORT_TIMEOUT": "10",  # Custom short timeout for testing
        },
    )
    @patch("access_key_enforcement.iam_client")
    def test_lambda_handler_custom_timeout(self, mock_iam):
        """Test Lambda execution with custom credential report timeout"""
        # Mock credential report generation
        mock_iam.generate_credential_report.return_value = {}
        
        # Mock get_credential_report to never return Content (simulating timeout)
        mock_iam.get_credential_report.return_value = {"State": "INPROGRESS"}
        
        # Test event and context
        event = {}
        context = Mock()
        context.function_name = "test-function"

        # Execute handler - should raise an exception due to timeout
        with self.assertRaises(Exception) as cm:
            access_key_enforcement.lambda_handler(event, context)
        
        # Verify the timeout exception message reflects custom timeout
        self.assertIn("Credential report generation timed out", str(cm.exception))
        self.assertIn("10 seconds", str(cm.exception))


class TestUserExemption(unittest.TestCase):
    """Test user exemption functionality"""

    @patch("access_key_enforcement.iam_client")
    def test_is_user_exempt_true(self, mock_iam):
        """Test user exemption when user has exemption tag"""
        mock_iam.list_user_tags.return_value = {
            "Tags": [
                {"Key": "key-rotation-exempt", "Value": "true"},
                {"Key": "email", "Value": "test@example.com"},
            ]
        }

        result = access_key_enforcement.is_user_exempt("testuser")
        self.assertTrue(result)

    @patch("access_key_enforcement.iam_client")
    def test_is_user_exempt_false(self, mock_iam):
        """Test user exemption when user has no exemption tag"""
        mock_iam.list_user_tags.return_value = {
            "Tags": [{"Key": "email", "Value": "test@example.com"}]
        }

        result = access_key_enforcement.is_user_exempt("testuser")
        self.assertFalse(result)

    @patch("access_key_enforcement.iam_client")
    def test_is_user_exempt_false_value(self, mock_iam):
        """Test user exemption when exemption tag is false"""
        mock_iam.list_user_tags.return_value = {
            "Tags": [
                {"Key": "key-rotation-exempt", "Value": "false"},
                {"Key": "email", "Value": "test@example.com"},
            ]
        }

        result = access_key_enforcement.is_user_exempt("testuser")
        self.assertFalse(result)


class TestAccessKeyProcessing(unittest.TestCase):
    """Test access key processing logic"""

    @patch.dict(
        os.environ,
        {
            "WARNING_THRESHOLD": "75",
            "URGENT_THRESHOLD": "85",
            "DISABLE_THRESHOLD": "90",
        },
    )
    @patch("access_key_enforcement.get_user_email")
    def test_process_key_warning(self, mock_get_email):
        """Test key processing for warning threshold"""
        mock_get_email.return_value = "test@example.com"

        # Create a key that's 80 days old (warning range)
        old_date = datetime.now() - timedelta(days=80)
        last_rotated = old_date.isoformat()

        notifications = []
        metrics = {
            "total_keys": 0,
            "warning_keys": 0,
            "urgent_keys": 0,
            "disabled_keys": 0,
            "expired_keys": 0,
        }

        access_key_enforcement.process_key(
            "testuser", "AKIAEXAMPLE", last_rotated, notifications, metrics
        )

        # Verify metrics updated
        self.assertEqual(metrics["total_keys"], 1)
        self.assertEqual(metrics["warning_keys"], 1)

        # Verify notification created
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["action"], "warning")

    @patch.dict(
        os.environ,
        {
            "WARNING_THRESHOLD": "75",
            "URGENT_THRESHOLD": "85",
            "DISABLE_THRESHOLD": "90",
        },
    )
    @patch("access_key_enforcement.get_user_email")
    def test_process_key_urgent(self, mock_get_email):
        """Test key processing for urgent threshold"""
        mock_get_email.return_value = "test@example.com"

        # Create a key that's 87 days old (urgent range)
        old_date = datetime.now() - timedelta(days=87)
        last_rotated = old_date.isoformat()

        notifications = []
        metrics = {
            "total_keys": 0,
            "warning_keys": 0,
            "urgent_keys": 0,
            "disabled_keys": 0,
            "expired_keys": 0,
        }

        access_key_enforcement.process_key(
            "testuser", "AKIAEXAMPLE", last_rotated, notifications, metrics
        )

        # Verify metrics updated
        self.assertEqual(metrics["total_keys"], 1)
        self.assertEqual(metrics["urgent_keys"], 1)

        # Verify notification created
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["action"], "urgent")

    @patch.dict(
        os.environ,
        {
            "WARNING_THRESHOLD": "75",
            "URGENT_THRESHOLD": "85",
            "DISABLE_THRESHOLD": "90",
        },
    )
    @patch("access_key_enforcement.get_user_email")
    def test_process_key_expired(self, mock_get_email):
        """Test key processing for expired threshold"""
        mock_get_email.return_value = "test@example.com"

        # Create a key that's 95 days old (expired)
        old_date = datetime.now() - timedelta(days=95)
        last_rotated = old_date.isoformat()

        notifications = []
        metrics = {
            "total_keys": 0,
            "warning_keys": 0,
            "urgent_keys": 0,
            "disabled_keys": 0,
            "expired_keys": 0,
        }

        access_key_enforcement.process_key(
            "testuser", "AKIAEXAMPLE", last_rotated, notifications, metrics
        )

        # Verify metrics updated
        self.assertEqual(metrics["total_keys"], 1)
        self.assertEqual(metrics["expired_keys"], 1)

        # Verify notification created
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["action"], "expired")


class TestEmailRetrieval(unittest.TestCase):
    """Test user email retrieval from tags"""

    @patch("access_key_enforcement.iam_client")
    def test_get_user_email_success(self, mock_iam):
        """Test successful email retrieval"""
        mock_iam.list_user_tags.return_value = {
            "Tags": [
                {"Key": "email", "Value": "test@example.com"},
                {"Key": "department", "Value": "IT"},
            ]
        }

        email = access_key_enforcement.get_user_email("testuser")
        self.assertEqual(email, "test@example.com")

    @patch("access_key_enforcement.iam_client")
    def test_get_user_email_not_found(self, mock_iam):
        """Test email retrieval when no email tag exists"""
        mock_iam.list_user_tags.return_value = {
            "Tags": [{"Key": "department", "Value": "IT"}]
        }

        email = access_key_enforcement.get_user_email("testuser")
        self.assertIsNone(email)


class TestKeyDisabling(unittest.TestCase):
    """Test access key disabling functionality"""

    @patch("access_key_enforcement.iam_client")
    def test_disable_key_success(self, mock_iam):
        """Test successful key disabling"""
        mock_iam.update_access_key.return_value = {}

        # Should not raise exception
        access_key_enforcement.disable_key("testuser", "AKIAEXAMPLE")

        # Verify IAM call was made
        mock_iam.update_access_key.assert_called_once_with(
            UserName="testuser", AccessKeyId="AKIAEXAMPLE", Status="Inactive"
        )

    @patch("access_key_enforcement.iam_client")
    def test_disable_key_error(self, mock_iam):
        """Test key disabling with error"""
        from botocore.exceptions import ClientError

        error_response = {"Error": {"Code": "NoSuchEntity"}}
        mock_iam.update_access_key.side_effect = ClientError(
            error_response, "UpdateAccessKey"
        )

        # Should not raise exception (error is logged)
        access_key_enforcement.disable_key("testuser", "AKIAEXAMPLE")


class TestNotificationSending(unittest.TestCase):
    """Test notification sending functionality"""

    @patch("access_key_enforcement.ses_client")
    def test_send_notification_warning(self, mock_ses):
        """Test sending warning notification"""
        mock_ses.send_email.return_value = {"MessageId": "test-message-id"}

        notification = {
            "username": "testuser",
            "email": "test@example.com",
            "key_id": "AKIAEXAMPLE",
            "age": 80,
            "action": "warning",
            "severity": "medium",
        }

        access_key_enforcement.send_notification(notification)

        # Verify SES call was made
        mock_ses.send_email.assert_called_once()

        # Verify email content
        call_args = mock_ses.send_email.call_args
        self.assertIn("test@example.com", call_args[1]["Destination"]["ToAddresses"])
        self.assertIn("WARNING", call_args[1]["Message"]["Subject"]["Data"])

    @patch("access_key_enforcement.ses_client")
    def test_send_notification_disabled(self, mock_ses):
        """Test sending disabled notification"""
        mock_ses.send_email.return_value = {"MessageId": "test-message-id"}

        notification = {
            "username": "testuser",
            "email": "test@example.com",
            "key_id": "AKIAEXAMPLE",
            "age": 95,
            "action": "disabled",
            "severity": "critical",
        }

        access_key_enforcement.send_notification(notification)

        # Verify SES call was made
        mock_ses.send_email.assert_called_once()

        # Verify email content
        call_args = mock_ses.send_email.call_args
        self.assertIn("CRITICAL", call_args[1]["Message"]["Subject"]["Data"])


class TestMetricsPublishing(unittest.TestCase):
    """Test CloudWatch metrics publishing"""

    @patch("access_key_enforcement.cloudwatch")
    def test_publish_metrics_success(self, mock_cloudwatch):
        """Test successful metrics publishing"""
        mock_cloudwatch.put_metric_data.return_value = {}

        metrics = {
            "total_keys": 10,
            "warning_keys": 2,
            "urgent_keys": 1,
            "disabled_keys": 0,
            "expired_keys": 1,
        }

        access_key_enforcement.publish_metrics(metrics)

        # Verify CloudWatch calls were made
        self.assertEqual(mock_cloudwatch.put_metric_data.call_count, 5)


if __name__ == "__main__":
    # Create a test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestLambdaHandler))
    suite.addTests(loader.loadTestsFromTestCase(TestUserExemption))
    suite.addTests(loader.loadTestsFromTestCase(TestAccessKeyProcessing))
    suite.addTests(loader.loadTestsFromTestCase(TestEmailRetrieval))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyDisabling))
    suite.addTests(loader.loadTestsFromTestCase(TestNotificationSending))
    suite.addTests(loader.loadTestsFromTestCase(TestMetricsPublishing))

    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with appropriate code
    if result.wasSuccessful():
        print("\n✅ All Lambda tests passed!")
        sys.exit(0)
    else:
        print(
            f"\n❌ Lambda tests failed: {len(result.failures)} failures, "
            f"{len(result.errors)} errors"
        )
        sys.exit(1)
