#!/usr/bin/env python3
"""
Unit tests for AWS IAM Self-Service Key Rotation Tool
"""

import unittest
from unittest.mock import Mock, patch, mock_open
import sys
import os
import json
from datetime import datetime, timedelta, timezone

# Add the scripts directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Import after path modification  # noqa: E402
import aws_iam_self_service_key_rotation as key_rotation  # noqa: E402


class TestIAMClient(unittest.TestCase):
    """Test IAM client creation and session caching"""

    def setUp(self):
        """Reset global session before each test"""
        key_rotation._session = None

    @patch("aws_iam_self_service_key_rotation.boto3.Session")
    def test_get_iam_client_creates_session(self, mock_session_class):
        """Test that IAM client creates and caches session"""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_client = Mock()
        mock_session.client.return_value = mock_client

        # First call should create session
        client1 = key_rotation.get_iam_client()
        self.assertEqual(client1, mock_client)
        mock_session_class.assert_called_once()

        # Second call should reuse session
        client2 = key_rotation.get_iam_client()
        self.assertEqual(client2, mock_client)
        # Still only called once
        self.assertEqual(mock_session_class.call_count, 1)


class TestArgumentParsing(unittest.TestCase):
    """Test command line argument parsing"""

    def test_parse_args_create(self):
        """Test parsing create argument"""
        with patch("sys.argv", ["script", "-c"]):
            args = key_rotation.parse_args()
        self.assertTrue(args.create)
        self.assertFalse(args.list)

    def test_parse_args_create_with_backup(self):
        """Test parsing create with backup argument"""
        with patch("sys.argv", ["script", "-c", "--backup"]):
            args = key_rotation.parse_args()
        self.assertTrue(args.create)
        self.assertTrue(args.backup)

    def test_parse_args_list(self):
        """Test parsing list argument"""
        with patch("sys.argv", ["script", "-l"]):
            args = key_rotation.parse_args()
        self.assertTrue(args.list)
        self.assertFalse(args.json)

    def test_parse_args_list_json(self):
        """Test parsing list with json argument"""
        with patch("sys.argv", ["script", "-l", "--json"]):
            args = key_rotation.parse_args()
        self.assertTrue(args.list)
        self.assertTrue(args.json)

    def test_parse_args_update(self):
        """Test parsing update argument"""
        with patch("sys.argv", ["script", "-u", "AKIAEXAMPLE", "active"]):
            args = key_rotation.parse_args()
        self.assertEqual(args.update, ["AKIAEXAMPLE", "active"])

    def test_parse_args_delete(self):
        """Test parsing delete argument"""
        with patch("sys.argv", ["script", "-d", "AKIAEXAMPLE"]):
            args = key_rotation.parse_args()
        self.assertEqual(args.delete, ["AKIAEXAMPLE"])


class TestKeyAgeCalculation(unittest.TestCase):
    """Test key age calculation functionality"""

    def test_calculate_key_age_with_datetime(self):
        """Test age calculation with datetime object"""
        # Create a key that's 30 days old
        create_date = datetime.now(timezone.utc) - timedelta(days=30)
        age = key_rotation.calculate_key_age(create_date)
        self.assertEqual(age, 30)

    def test_calculate_key_age_with_string(self):
        """Test age calculation with string (invalid input)"""
        age = key_rotation.calculate_key_age("2023-01-01")
        self.assertEqual(age, "N/A")

    def test_calculate_key_age_today(self):
        """Test age calculation for key created today"""
        create_date = datetime.now(timezone.utc)
        age = key_rotation.calculate_key_age(create_date)
        self.assertEqual(age, 0)

    def test_get_age_color_green(self):
        """Test color for new key (green)"""
        self.assertEqual(key_rotation.get_age_color(30), "green")

    def test_get_age_color_orange(self):
        """Test color for medium age key (orange)"""
        self.assertEqual(key_rotation.get_age_color(65), "orange")

    def test_get_age_color_yellow(self):
        """Test color for old key (yellow)"""
        self.assertEqual(key_rotation.get_age_color(80), "yellow")

    def test_get_age_color_red(self):
        """Test color for very old key (red)"""
        self.assertEqual(key_rotation.get_age_color(95), "red")

    def test_get_age_color_string(self):
        """Test color for string age (white)"""
        self.assertEqual(key_rotation.get_age_color("N/A"), "white")


class TestBackupFunctionality(unittest.TestCase):
    """Test credentials backup functionality"""

    @patch("aws_iam_self_service_key_rotation.path")
    @patch("aws_iam_self_service_key_rotation.datetime")
    @patch("aws_iam_self_service_key_rotation.rprint")
    def test_backup_credentials_success(self, mock_rprint, mock_datetime, mock_path):
        """Test successful credentials backup"""
        # Mock path existence and content
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "test credentials content"

        # Mock datetime for consistent backup filename
        mock_now = Mock()
        mock_now.strftime.return_value = "20231201_120000"
        mock_datetime.now.return_value = mock_now

        # Mock backup path
        mock_backup_path = Mock()
        mock_path.with_suffix.return_value = mock_backup_path

        result = key_rotation.backup_credentials()

        self.assertEqual(result, mock_backup_path)
        mock_backup_path.write_text.assert_called_once_with("test credentials content")
        mock_rprint.assert_called_once()

    @patch("aws_iam_self_service_key_rotation.path")
    def test_backup_credentials_no_file(self, mock_path):
        """Test backup when credentials file doesn't exist"""
        mock_path.exists.return_value = False

        result = key_rotation.backup_credentials()

        self.assertIsNone(result)


class TestListKeysJSON(unittest.TestCase):
    """Test JSON listing functionality"""

    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("builtins.print")
    def test_list_keys_json_success(self, mock_print, mock_get_client):
        """Test successful JSON key listing"""
        # Mock IAM client and response
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        create_date = datetime.now(timezone.utc) - timedelta(days=45)
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Active",
                    "CreateDate": create_date,
                }
            ]
        }

        key_rotation.list_keys_json()

        # Verify JSON output
        mock_print.assert_called_once()
        output = mock_print.call_args[0][0]
        data = json.loads(output)

        self.assertIn("AccessKeys", data)
        self.assertEqual(len(data["AccessKeys"]), 1)
        self.assertEqual(data["AccessKeys"][0]["AccessKeyId"], "AKIAEXAMPLE123")
        self.assertEqual(data["AccessKeys"][0]["Age"], 45)

    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.logger")
    @patch("aws_iam_self_service_key_rotation.rprint")
    def test_list_keys_json_error(self, mock_rprint, mock_logger, mock_get_client):
        """Test JSON listing with client error"""
        from botocore.exceptions import ClientError

        mock_client = Mock()
        mock_get_client.return_value = mock_client

        error_response = {"Error": {"Code": "AccessDenied"}}
        mock_client.list_access_keys.side_effect = ClientError(
            error_response, "ListAccessKeys"
        )

        key_rotation.list_keys_json()

        mock_logger.error.assert_called_once()
        mock_rprint.assert_called_once()


class TestListKeysTable(unittest.TestCase):
    """Test table listing functionality"""

    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.console")
    @patch("aws_iam_self_service_key_rotation.rprint")
    def test_list_keys_table_empty(self, mock_rprint, mock_console, mock_get_client):
        """Test table listing with no keys"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}

        key_rotation.list_keys_table()

        mock_rprint.assert_called_with("[yellow]No access keys found.[/yellow]")

    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.console")
    @patch("aws_iam_self_service_key_rotation.Table")
    @patch("aws_iam_self_service_key_rotation.rprint")
    def test_list_keys_table_with_old_key(
        self, mock_rprint, mock_table_class, mock_console, mock_get_client
    ):
        """Test table listing with old key warning"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        # Create a key that's 95 days old
        create_date = datetime.now(timezone.utc) - timedelta(days=95)
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Active",
                    "CreateDate": create_date,
                }
            ]
        }

        mock_table = Mock()
        mock_table_class.return_value = mock_table

        key_rotation.list_keys_table()

        # Verify table was created and populated
        mock_table_class.assert_called_once_with(title="AWS Access Keys")
        mock_table.add_row.assert_called_once()

        # Verify warning was printed for old key
        warning_printed = False
        for call in mock_rprint.call_args_list:
            if "95 days old and should be rotated immediately" in str(call):
                warning_printed = True
                break
        self.assertTrue(warning_printed)


class TestMainFunction(unittest.TestCase):
    """Test main function with different command combinations"""

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.list_keys_table")
    @patch("aws_iam_self_service_key_rotation.list_keys_json")
    def test_main_list_json(self, mock_list_json, mock_list_table, mock_parse_args):
        """Test main with list and json flags"""
        mock_args = Mock()
        mock_args.list = True
        mock_args.json = True
        mock_args.create = False
        mock_args.update = None
        mock_args.delete = None
        mock_parse_args.return_value = mock_args

        key_rotation.main()

        mock_list_json.assert_called_once()
        mock_list_table.assert_not_called()

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.list_keys_table")
    def test_main_list_table(self, mock_list_table, mock_parse_args):
        """Test main with list flag only"""
        mock_args = Mock()
        mock_args.list = True
        mock_args.json = False
        mock_args.create = False
        mock_args.update = None
        mock_args.delete = None
        mock_parse_args.return_value = mock_args

        key_rotation.main()

        mock_list_table.assert_called_once()

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.rprint")
    def test_main_update_invalid_status(
        self, mock_rprint, mock_get_client, mock_parse_args
    ):
        """Test main with invalid update status"""
        mock_args = Mock()
        mock_args.update = ["AKIAEXAMPLE", "invalid"]
        mock_args.create = False
        mock_args.list = False
        mock_args.delete = None
        mock_parse_args.return_value = mock_args

        key_rotation.main()

        # Verify error message for invalid status
        error_printed = False
        for call in mock_rprint.call_args_list:
            if "Status 'invalid' is not valid" in str(call):
                error_printed = True
                break
        self.assertTrue(error_printed)

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.list_keys_table")
    @patch("aws_iam_self_service_key_rotation.rprint")
    def test_main_update_success(
        self, mock_rprint, mock_list_table, mock_get_client, mock_parse_args
    ):
        """Test successful key update"""
        mock_args = Mock()
        mock_args.update = ["AKIAEXAMPLE", "inactive"]
        mock_args.create = False
        mock_args.list = False
        mock_args.delete = None
        mock_parse_args.return_value = mock_args

        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.update_access_key.return_value = {}

        key_rotation.main()

        mock_client.update_access_key.assert_called_once_with(
            AccessKeyId="AKIAEXAMPLE", Status="Inactive"
        )

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.list_keys_table")
    @patch("aws_iam_self_service_key_rotation.rprint")
    @patch("builtins.input")
    def test_main_delete_cancelled(
        self, mock_input, mock_rprint, mock_list_table, mock_get_client, mock_parse_args
    ):
        """Test delete operation cancelled by user"""
        mock_args = Mock()
        mock_args.delete = ["AKIAEXAMPLE"]
        mock_args.create = False
        mock_args.list = False
        mock_args.update = None
        mock_parse_args.return_value = mock_args

        mock_input.return_value = "no"

        key_rotation.main()

        # Verify cancellation message
        cancelled = False
        for call in mock_rprint.call_args_list:
            if "Delete operation cancelled" in str(call):
                cancelled = True
                break
        self.assertTrue(cancelled)

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.list_keys_table")
    @patch("aws_iam_self_service_key_rotation.rprint")
    @patch("builtins.input")
    def test_main_delete_confirmed(
        self, mock_input, mock_rprint, mock_list_table, mock_get_client, mock_parse_args
    ):
        """Test successful delete operation"""
        mock_args = Mock()
        mock_args.delete = ["AKIAEXAMPLE"]
        mock_args.create = False
        mock_args.list = False
        mock_args.update = None
        mock_parse_args.return_value = mock_args

        mock_input.return_value = "yes"

        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.delete_access_key.return_value = {}

        key_rotation.main()

        mock_client.delete_access_key.assert_called_once_with(AccessKeyId="AKIAEXAMPLE")

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.list_keys_table")
    @patch("aws_iam_self_service_key_rotation.rprint")
    @patch("builtins.input")
    def test_main_create_limit_exceeded(
        self, mock_input, mock_rprint, mock_list_table, mock_get_client, mock_parse_args
    ):
        """Test create with key limit exceeded"""
        from botocore.exceptions import ClientError

        mock_args = Mock()
        mock_args.create = True
        mock_args.backup = False
        mock_args.list = False
        mock_args.update = None
        mock_args.delete = None
        mock_parse_args.return_value = mock_args

        mock_client = Mock()
        mock_get_client.return_value = mock_client

        error_response = {"Error": {"Code": "LimitExceeded"}}
        mock_client.create_access_key.side_effect = ClientError(
            error_response, "CreateAccessKey"
        )

        key_rotation.main()

        # Verify limit exceeded message
        limit_msg = False
        for call in mock_rprint.call_args_list:
            if "Access key limit exceeded" in str(call):
                limit_msg = True
                break
        self.assertTrue(limit_msg)

    @patch("aws_iam_self_service_key_rotation.parse_args")
    @patch("aws_iam_self_service_key_rotation.get_iam_client")
    @patch("aws_iam_self_service_key_rotation.list_keys_table")
    @patch("aws_iam_self_service_key_rotation.rprint")
    @patch("aws_iam_self_service_key_rotation.path")
    @patch("builtins.input")
    @patch("builtins.open", new_callable=mock_open)
    @patch("aws_iam_self_service_key_rotation.configparser.ConfigParser")
    def test_main_create_update_credentials(
        self,
        mock_configparser,
        mock_file,
        mock_input,
        mock_path,
        mock_rprint,
        mock_list_table,
        mock_get_client,
        mock_parse_args,
    ):
        """Test create with credentials file update"""
        mock_args = Mock()
        mock_args.create = True
        mock_args.backup = False
        mock_args.list = False
        mock_args.update = None
        mock_args.delete = None
        mock_parse_args.return_value = mock_args

        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.create_access_key.return_value = {
            "AccessKey": {
                "AccessKeyId": "AKIANEWKEY123",
                "SecretAccessKey": "newsecretkey456",
            }
        }

        mock_input.return_value = "y"
        mock_path.exists.return_value = True

        # Mock ConfigParser
        mock_config = Mock()
        mock_configparser.return_value = mock_config
        mock_config.__contains__ = Mock(return_value=True)
        mock_config.__getitem__ = Mock(return_value={})

        key_rotation.main()

        # Verify key was created
        mock_client.create_access_key.assert_called_once()

        # Verify config was updated
        mock_config.__setitem__.assert_called()
        mock_config.write.assert_called_once()


if __name__ == "__main__":
    unittest.main()
