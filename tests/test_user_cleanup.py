#!/usr/bin/env python3
"""
Unit tests for AWS IAM User Cleanup Tool
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add the scripts directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Import after path modification  # noqa: E402
import aws_iam_user_cleanup as cleanup  # noqa: E402


class TestCheckUsername(unittest.TestCase):
    """Test username validation functionality"""

    @patch("aws_iam_user_cleanup.client")
    @patch("sys.argv", ["script.py", "testuser"])
    def test_check_username_exists(self, mock_client):
        """Test checking username when user exists"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "testuser"}, {"UserName": "otheruser"}]}
        ]

        result = cleanup.check_username()
        self.assertEqual(result, "testuser")

    @patch("aws_iam_user_cleanup.client")
    @patch("sys.argv", ["script.py", "nonexistent"])
    @patch("builtins.print")
    def test_check_username_not_exists(self, mock_print, mock_client):
        """Test checking username when user doesn't exist"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "testuser"}, {"UserName": "otheruser"}]}
        ]

        result = cleanup.check_username()
        self.assertIsNone(result)
        mock_print.assert_called_with("The user 'nonexistent' does not exist.")

    @patch("sys.argv", ["script.py"])
    @patch("builtins.print")
    def test_check_username_no_args(self, mock_print):
        """Test checking username with no arguments"""
        result = cleanup.check_username()
        self.assertIsNone(result)
        mock_print.assert_called_with(
            "Usage: python aws_iam_user_cleanup.py <username>"
        )

    @patch("sys.argv", ["script.py", "--help"])
    @patch("builtins.print")
    def test_check_username_help(self, mock_print):
        """Test checking username with help flag"""
        result = cleanup.check_username()
        self.assertIsNone(result)
        mock_print.assert_called_with(
            "Usage: python aws_iam_user_cleanup.py <username>"
        )

    @patch("aws_iam_user_cleanup.client")
    @patch("sys.argv", ["script.py", "testuser"])
    def test_check_username_multiple_pages(self, mock_client):
        """Test checking username with paginated results"""
        # Mock paginator with multiple pages
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "user1"}, {"UserName": "user2"}]},
            {"Users": [{"UserName": "testuser"}, {"UserName": "user3"}]},
            {"Users": [{"UserName": "user4"}]},
        ]

        result = cleanup.check_username()
        self.assertEqual(result, "testuser")


class TestDeleteLoginProfile(unittest.TestCase):
    """Test login profile deletion"""

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_login_profile_success(self, mock_print, mock_client):
        """Test successful login profile deletion"""
        mock_client.delete_login_profile.return_value = {}

        result = cleanup.delete_login_profile("testuser")

        self.assertTrue(result)
        mock_client.delete_login_profile.assert_called_once_with(UserName="testuser")
        mock_print.assert_called_with("Deleting login profile for testuser")

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_login_profile_not_exists(self, mock_print, mock_client):
        """Test deleting non-existent login profile"""
        mock_client.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )
        mock_client.delete_login_profile.side_effect = (
            mock_client.exceptions.NoSuchEntityException()
        )

        result = cleanup.delete_login_profile("testuser")

        self.assertTrue(result)  # Should return True as it's not an error
        mock_print.assert_called_with("No login profile found for testuser")

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_login_profile_error(self, mock_print, mock_client):
        """Test login profile deletion with error"""
        mock_client.delete_login_profile.side_effect = Exception("Access denied")

        result = cleanup.delete_login_profile("testuser")

        self.assertFalse(result)
        mock_print.assert_called_with(
            "Error deleting login profile for testuser: Access denied"
        )


class TestDeleteMFADevices(unittest.TestCase):
    """Test MFA device deletion"""

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_mfa_devices_none(self, mock_print, mock_client):
        """Test deleting MFA devices when none exist"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"MFADevices": []}]

        result = cleanup.delete_mfa_devices("testuser")

        self.assertTrue(result)
        mock_print.assert_called_with("No MFA devices found for testuser")

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_mfa_devices_success(self, mock_print, mock_client):
        """Test successful MFA device deletion"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "MFADevices": [
                    {"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser"},
                    {"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser-backup"},
                ]
            }
        ]

        mock_client.deactivate_mfa_device.return_value = {}

        result = cleanup.delete_mfa_devices("testuser")

        self.assertTrue(result)
        self.assertEqual(mock_client.deactivate_mfa_device.call_count, 2)

        # Verify both devices were deactivated
        calls = mock_client.deactivate_mfa_device.call_args_list
        self.assertEqual(calls[0][1]["UserName"], "testuser")
        self.assertEqual(
            calls[0][1]["SerialNumber"], "arn:aws:iam::123456789012:mfa/testuser"
        )
        self.assertEqual(calls[1][1]["UserName"], "testuser")
        self.assertEqual(
            calls[1][1]["SerialNumber"], "arn:aws:iam::123456789012:mfa/testuser-backup"
        )

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_mfa_devices_partial_failure(self, mock_print, mock_client):
        """Test MFA device deletion with partial failure"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "MFADevices": [
                    {"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser"},
                    {"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser-backup"},
                ]
            }
        ]

        # First deactivation succeeds, second fails
        mock_client.deactivate_mfa_device.side_effect = [{}, Exception("Access denied")]

        result = cleanup.delete_mfa_devices("testuser")

        self.assertFalse(result)  # Should return False due to partial failure

        # Verify error message was printed
        error_printed = False
        for call in mock_print.call_args_list:
            if "Error deleting MFA device" in str(call) and "Access denied" in str(
                call
            ):
                error_printed = True
                break
        self.assertTrue(error_printed)

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_mfa_devices_list_error(self, mock_print, mock_client):
        """Test MFA device deletion with listing error"""
        # Mock paginator to raise exception
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = Exception("Network error")

        result = cleanup.delete_mfa_devices("testuser")

        self.assertFalse(result)
        mock_print.assert_called_with(
            "Error listing MFA devices for testuser: Network error"
        )


class TestDeleteAccessKeys(unittest.TestCase):
    """Test access key deletion"""

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_access_keys_none(self, mock_print, mock_client):
        """Test deleting access keys when none exist"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"AccessKeyMetadata": []}]

        result = cleanup.delete_access_keys("testuser")

        self.assertTrue(result)
        mock_print.assert_called_with("No access keys found for testuser")

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_access_keys_success(self, mock_print, mock_client):
        """Test successful access key deletion"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "AccessKeyMetadata": [
                    {"AccessKeyId": "AKIAEXAMPLE123"},
                    {"AccessKeyId": "AKIAEXAMPLE456"},
                ]
            }
        ]

        mock_client.delete_access_key.return_value = {}

        result = cleanup.delete_access_keys("testuser")

        self.assertTrue(result)
        self.assertEqual(mock_client.delete_access_key.call_count, 2)

        # Verify both keys were deleted
        calls = mock_client.delete_access_key.call_args_list
        self.assertEqual(calls[0][1]["UserName"], "testuser")
        self.assertEqual(calls[0][1]["AccessKeyId"], "AKIAEXAMPLE123")
        self.assertEqual(calls[1][1]["UserName"], "testuser")
        self.assertEqual(calls[1][1]["AccessKeyId"], "AKIAEXAMPLE456")

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_access_keys_partial_failure(self, mock_print, mock_client):
        """Test access key deletion with partial failure"""
        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "AccessKeyMetadata": [
                    {"AccessKeyId": "AKIAEXAMPLE123"},
                    {"AccessKeyId": "AKIAEXAMPLE456"},
                ]
            }
        ]

        # First deletion succeeds, second fails
        mock_client.delete_access_key.side_effect = [{}, Exception("Key not found")]

        result = cleanup.delete_access_keys("testuser")

        self.assertFalse(result)  # Should return False due to partial failure

        # Verify error message was printed
        error_printed = False
        for call in mock_print.call_args_list:
            if "Error deleting access key AKIAEXAMPLE456" in str(call):
                error_printed = True
                break
        self.assertTrue(error_printed)

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_access_keys_list_error(self, mock_print, mock_client):
        """Test access key deletion with listing error"""
        # Mock paginator to raise exception
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = Exception("Permission denied")

        result = cleanup.delete_access_keys("testuser")

        self.assertFalse(result)
        mock_print.assert_called_with(
            "Error listing access keys for testuser: Permission denied"
        )

    @patch("aws_iam_user_cleanup.client")
    @patch("builtins.print")
    def test_delete_access_keys_multiple_pages(self, mock_print, mock_client):
        """Test deleting access keys across multiple pages"""
        # Mock paginator with multiple pages
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE123"}]},
            {"AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE456"}]},
            {"AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE789"}]},
        ]

        mock_client.delete_access_key.return_value = {}

        result = cleanup.delete_access_keys("testuser")

        self.assertTrue(result)
        self.assertEqual(mock_client.delete_access_key.call_count, 3)


class TestMainFunction(unittest.TestCase):
    """Test main function integration"""

    @patch("aws_iam_user_cleanup.check_username")
    @patch("aws_iam_user_cleanup.delete_login_profile")
    @patch("aws_iam_user_cleanup.delete_mfa_devices")
    @patch("aws_iam_user_cleanup.delete_access_keys")
    @patch("builtins.print")
    @patch("sys.exit")
    def test_main_success(
        self,
        mock_exit,
        mock_print,
        mock_delete_keys,
        mock_delete_mfa,
        mock_delete_profile,
        mock_check_username,
    ):
        """Test successful cleanup of all resources"""
        mock_check_username.return_value = "testuser"
        mock_delete_profile.return_value = True
        mock_delete_mfa.return_value = True
        mock_delete_keys.return_value = True

        cleanup.main()

        mock_delete_profile.assert_called_once_with("testuser")
        mock_delete_mfa.assert_called_once_with("testuser")
        mock_delete_keys.assert_called_once_with("testuser")
        mock_print.assert_called_with(
            "Successfully cleaned up all resources for testuser"
        )
        mock_exit.assert_called_with(0)

    @patch("aws_iam_user_cleanup.check_username")
    @patch("aws_iam_user_cleanup.delete_login_profile")
    @patch("aws_iam_user_cleanup.delete_mfa_devices")
    @patch("aws_iam_user_cleanup.delete_access_keys")
    @patch("builtins.print")
    @patch("sys.exit")
    def test_main_partial_failure(
        self,
        mock_exit,
        mock_print,
        mock_delete_keys,
        mock_delete_mfa,
        mock_delete_profile,
        mock_check_username,
    ):
        """Test cleanup with some operations failing"""
        mock_check_username.return_value = "testuser"
        mock_delete_profile.return_value = True
        mock_delete_mfa.return_value = False  # MFA deletion fails
        mock_delete_keys.return_value = True

        cleanup.main()

        # All operations should be attempted
        mock_delete_profile.assert_called_once_with("testuser")
        mock_delete_mfa.assert_called_once_with("testuser")
        mock_delete_keys.assert_called_once_with("testuser")

        mock_print.assert_called_with("Some cleanup operations failed for testuser")
        mock_exit.assert_called_with(1)

    @patch("aws_iam_user_cleanup.check_username")
    def test_main_invalid_username(self, mock_check_username):
        """Test main with invalid username"""
        mock_check_username.return_value = None

        # Should exit early without calling other functions
        cleanup.main()

        # No assertions needed - just verify it doesn't crash

    @patch("aws_iam_user_cleanup.check_username")
    @patch("aws_iam_user_cleanup.delete_login_profile")
    @patch("aws_iam_user_cleanup.delete_mfa_devices")
    @patch("aws_iam_user_cleanup.delete_access_keys")
    @patch("builtins.print")
    @patch("sys.exit")
    def test_main_all_failures(
        self,
        mock_exit,
        mock_print,
        mock_delete_keys,
        mock_delete_mfa,
        mock_delete_profile,
        mock_check_username,
    ):
        """Test cleanup with all operations failing"""
        mock_check_username.return_value = "testuser"
        mock_delete_profile.return_value = False
        mock_delete_mfa.return_value = False
        mock_delete_keys.return_value = False

        cleanup.main()

        # All operations should be attempted despite failures
        mock_delete_profile.assert_called_once_with("testuser")
        mock_delete_mfa.assert_called_once_with("testuser")
        mock_delete_keys.assert_called_once_with("testuser")

        mock_print.assert_called_with("Some cleanup operations failed for testuser")
        mock_exit.assert_called_with(1)


if __name__ == "__main__":
    unittest.main()
