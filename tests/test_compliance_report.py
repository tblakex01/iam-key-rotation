#!/usr/bin/env python3
"""
Unit tests for AWS IAM Compliance Report Generator
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys
import os
import json
from datetime import datetime, timedelta, timezone

# Import ClientError at the top
from botocore.exceptions import ClientError

# Add the scripts directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

# Import after path modification  # noqa: E402
import aws_iam_compliance_report as compliance  # noqa: E402


class TestIAMComplianceReport(unittest.TestCase):
    """Test IAMComplianceReport class initialization and methods"""

    def test_init_default_thresholds(self):
        """Test default threshold initialization"""
        report = compliance.IAMComplianceReport()

        self.assertEqual(report.KEY_WARNING_THRESHOLD, 75)
        self.assertEqual(report.KEY_NON_COMPLIANT_THRESHOLD, 90)
        self.assertEqual(report.PASSWORD_WARNING_THRESHOLD, 75)
        self.assertEqual(report.PASSWORD_NON_COMPLIANT_THRESHOLD, 90)

        # Check initial stats
        self.assertEqual(report.summary_stats["total_users"], 0)
        self.assertEqual(report.users_data, [])

    @patch.dict(
        os.environ,
        {
            "KEY_WARNING_THRESHOLD": "60",
            "KEY_NON_COMPLIANT_THRESHOLD": "80",
            "PASSWORD_WARNING_THRESHOLD": "70",
            "PASSWORD_NON_COMPLIANT_THRESHOLD": "85",
        },
    )
    def test_init_custom_thresholds(self):
        """Test custom threshold initialization from environment"""
        report = compliance.IAMComplianceReport()

        self.assertEqual(report.KEY_WARNING_THRESHOLD, 60)
        self.assertEqual(report.KEY_NON_COMPLIANT_THRESHOLD, 80)
        self.assertEqual(report.PASSWORD_WARNING_THRESHOLD, 70)
        self.assertEqual(report.PASSWORD_NON_COMPLIANT_THRESHOLD, 85)

    @patch("aws_iam_compliance_report.iam_client")
    @patch("aws_iam_compliance_report.time.sleep")
    @patch("aws_iam_compliance_report.Progress")
    @patch("aws_iam_compliance_report.rprint")
    def test_generate_credential_report_success(
        self, mock_rprint, mock_progress_class, mock_sleep, mock_iam_client
    ):
        """Test successful credential report generation"""
        report = compliance.IAMComplianceReport()

        # Mock successful report generation
        mock_iam_client.generate_credential_report.return_value = {}
        mock_iam_client.get_credential_report.side_effect = [
            ClientError({"Error": {"Code": "ReportNotReady"}}, "GetCredentialReport"),
            {"Content": b"test,content"},
        ]

        # Mock progress bar
        mock_progress = MagicMock()
        mock_progress_class.return_value.__enter__.return_value = mock_progress

        # Call the method
        content = report.generate_credential_report()

        self.assertEqual(content, b"test,content")
        mock_iam_client.generate_credential_report.assert_called_once()
        self.assertEqual(mock_iam_client.get_credential_report.call_count, 2)

    @patch("aws_iam_compliance_report.iam_client")
    @patch("aws_iam_compliance_report.time.sleep")
    @patch("aws_iam_compliance_report.Progress")
    def test_generate_credential_report_timeout(
        self, mock_progress_class, mock_sleep, mock_iam_client
    ):
        """Test credential report generation timeout"""
        report = compliance.IAMComplianceReport()

        # Mock report not ready for all attempts
        mock_iam_client.generate_credential_report.return_value = {}
        mock_iam_client.get_credential_report.side_effect = ClientError(
            {"Error": {"Code": "ReportNotReady"}}, "GetCredentialReport"
        )

        # Mock progress bar
        mock_progress = MagicMock()
        mock_progress_class.return_value.__enter__.return_value = mock_progress

        # Should raise TimeoutError
        with self.assertRaises(TimeoutError) as cm:
            report.generate_credential_report()

        self.assertIn("60 seconds", str(cm.exception))

    def test_calculate_compliance_status_compliant(self):
        """Test compliance status calculation for compliant user"""
        report = compliance.IAMComplianceReport()

        user_data = {
            "has_access_keys": True,
            "key_1_age": 30,
            "key_2_age": None,
            "has_password": True,
            "password_age": 45,
            "mfa_active": True,
        }

        status = report.calculate_compliance_status(user_data)

        self.assertEqual(status["status"], "Compliant")
        self.assertEqual(status["level"], "compliant")
        self.assertEqual(len(status["issues"]), 0)

    def test_calculate_compliance_status_warning(self):
        """Test compliance status calculation for user with warnings"""
        report = compliance.IAMComplianceReport()

        user_data = {
            "has_access_keys": True,
            "key_1_age": 80,  # Warning level
            "key_2_age": None,
            "has_password": True,
            "password_age": 45,
            "mfa_active": True,
        }

        status = report.calculate_compliance_status(user_data)

        self.assertEqual(status["status"], "Warning")
        self.assertEqual(status["level"], "warning")
        self.assertIn("Access key 1 is 80 days old", status["issues"][0])

    def test_calculate_compliance_status_non_compliant(self):
        """Test compliance status calculation for non-compliant user"""
        report = compliance.IAMComplianceReport()

        user_data = {
            "has_access_keys": True,
            "key_1_age": 95,  # Non-compliant
            "key_2_age": 100,  # Non-compliant
            "has_password": True,
            "password_age": 95,  # Non-compliant
            "mfa_active": False,  # Non-compliant
        }

        status = report.calculate_compliance_status(user_data)

        self.assertEqual(status["status"], "Non-Compliant")
        self.assertEqual(status["level"], "non_compliant")
        self.assertEqual(len(status["issues"]), 4)  # All 4 issues

    def test_parse_date_valid(self):
        """Test date parsing with valid date"""
        report = compliance.IAMComplianceReport()

        date_str = "2023-01-15T10:30:00+00:00"
        result = report.parse_date(date_str)

        self.assertIsInstance(result, datetime)
        self.assertEqual(result.year, 2023)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_parse_date_na(self):
        """Test date parsing with N/A"""
        report = compliance.IAMComplianceReport()

        result = report.parse_date("N/A")
        self.assertIsNone(result)

    def test_parse_date_not_supported(self):
        """Test date parsing with not_supported"""
        report = compliance.IAMComplianceReport()

        result = report.parse_date("not_supported")
        self.assertIsNone(result)

    def test_calculate_age_days_valid(self):
        """Test age calculation with valid date"""
        report = compliance.IAMComplianceReport()

        # Date 30 days ago
        date = datetime.now(timezone.utc) - timedelta(days=30)
        age = report.calculate_age_days(date)

        self.assertEqual(age, 30)

    def test_calculate_age_days_none(self):
        """Test age calculation with None date"""
        report = compliance.IAMComplianceReport()

        age = report.calculate_age_days(None)
        self.assertIsNone(age)

    @patch("aws_iam_compliance_report.Progress")
    def test_process_users_data(self, mock_progress_class):
        """Test processing users data from credential report"""
        report = compliance.IAMComplianceReport()

        # Mock CSV data
        csv_content = (
            "user,arn,user_creation_time,password_enabled,password_last_used,"
            "password_last_changed,password_next_rotation,mfa_active,"
            "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
            "access_key_1_last_used_region,access_key_1_last_used_service,"
            "access_key_2_active,access_key_2_last_rotated\n"
            "testuser1,arn:aws:iam::123456789012:user/testuser1,2023-01-01T00:00:00+00:00,"
            "true,2023-12-01T00:00:00+00:00,2023-10-01T00:00:00+00:00,N/A,true,true,"
            "2023-09-01T00:00:00+00:00,2023-12-01T00:00:00+00:00,us-east-1,s3,false,N/A\n"
            "testuser2,arn:aws:iam::123456789012:user/testuser2,2023-01-01T00:00:00+00:00,"
            "false,N/A,N/A,N/A,false,true,2023-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A"
        )

        # Mock progress bar
        mock_progress = MagicMock()
        mock_progress_class.return_value.__enter__.return_value = mock_progress

        # Process data
        report.process_users_data(csv_content.encode())

        # Verify results
        self.assertEqual(len(report.users_data), 2)
        self.assertEqual(report.summary_stats["total_users"], 2)
        self.assertEqual(report.summary_stats["users_with_keys"], 2)
        self.assertEqual(report.summary_stats["users_with_passwords"], 1)
        self.assertEqual(report.summary_stats["users_with_mfa"], 1)

    def test_export_json(self):
        """Test JSON export functionality"""
        report = compliance.IAMComplianceReport()

        # Add sample data
        report.users_data = [{"username": "testuser", "compliance_status": "Compliant"}]
        report.summary_stats = {"total_users": 1}

        # Mock file operations
        m = mock_open()
        with patch("builtins.open", m):
            with patch("aws_iam_compliance_report.rprint"):
                report.export_json("test_report.json")

        # Verify file was written
        m.assert_called_once_with("test_report.json", "w", encoding="utf-8")
        handle = m()

        # Verify JSON structure was written
        written_data = "".join(call[0][0] for call in handle.write.call_args_list)
        data = json.loads(written_data)

        self.assertIn("report_date", data)
        self.assertIn("summary", data)
        self.assertIn("users", data)
        self.assertEqual(len(data["users"]), 1)

    def test_export_csv(self):
        """Test CSV export functionality"""
        report = compliance.IAMComplianceReport()

        # Add sample data
        report.users_data = [
            {
                "username": "testuser",
                "has_password": True,
                "password_age": 30,
                "has_access_keys": True,
                "key_1_age": 45,
                "key_2_age": None,
                "mfa_active": True,
                "compliance_status": "Compliant",
            }
        ]

        # Mock file operations
        m = mock_open()
        with patch("builtins.open", m):
            with patch("aws_iam_compliance_report.rprint"):
                report.export_csv("test_report.csv")

        # Verify file was written
        m.assert_called_once_with("test_report.csv", "w", newline="", encoding="utf-8")

    @patch("aws_iam_compliance_report.Table")
    @patch("aws_iam_compliance_report.console")
    def test_display_summary(self, mock_console, mock_table_class):
        """Test summary display"""
        report = compliance.IAMComplianceReport()

        # Set sample stats
        report.summary_stats = {
            "total_users": 10,
            "users_with_keys": 8,
            "users_with_passwords": 7,
            "users_with_mfa": 5,
            "expired_keys": 2,
            "expired_passwords": 1,
            "compliant_users": 6,
        }

        mock_table = Mock()
        mock_table_class.return_value = mock_table

        report.display_summary()

        # Verify table was created and displayed
        mock_table_class.assert_called_once_with(title="IAM Compliance Summary")
        mock_console.print.assert_called_with(mock_table)


class TestArgumentParsing(unittest.TestCase):
    """Test command line argument parsing"""

    def test_parse_args_defaults(self):
        """Test default argument values"""
        with patch("sys.argv", ["script"]):
            args = compliance.parse_args()

        self.assertEqual(args.format, "table")
        self.assertIsNone(args.export)
        self.assertFalse(args.json)
        self.assertFalse(args.csv)

    def test_parse_args_json_format(self):
        """Test JSON format argument"""
        with patch("sys.argv", ["script", "--json"]):
            args = compliance.parse_args()

        self.assertTrue(args.json)
        self.assertFalse(args.csv)

    def test_parse_args_export(self):
        """Test export argument"""
        with patch("sys.argv", ["script", "--export", "report.json"]):
            args = compliance.parse_args()

        self.assertEqual(args.export, "report.json")

    def test_parse_args_format_and_export(self):
        """Test combined format and export arguments"""
        with patch(
            "sys.argv", ["script", "--format", "csv", "--export", "report.csv"]
        ):
            args = compliance.parse_args()

        self.assertEqual(args.format, "csv")
        self.assertEqual(args.export, "report.csv")


class TestMainFunction(unittest.TestCase):
    """Test main function execution"""

    @patch("aws_iam_compliance_report.IAMComplianceReport")
    @patch("aws_iam_compliance_report.parse_args")
    def test_main_table_display(self, mock_parse_args, mock_report_class):
        """Test main with table display"""
        # Mock arguments
        mock_args = Mock()
        mock_args.format = "table"
        mock_args.json = False
        mock_args.csv = False
        mock_args.export = None
        mock_parse_args.return_value = mock_args

        # Mock report instance
        mock_report = Mock()
        mock_report_class.return_value = mock_report
        mock_report.generate_credential_report.return_value = b"test"

        compliance.main()

        # Verify methods were called
        mock_report.generate_credential_report.assert_called_once()
        mock_report.process_users_data.assert_called_once_with(b"test")
        mock_report.display_summary.assert_called_once()
        mock_report.display_users_table.assert_called_once()

    @patch("aws_iam_compliance_report.IAMComplianceReport")
    @patch("aws_iam_compliance_report.parse_args")
    def test_main_json_export(self, mock_parse_args, mock_report_class):
        """Test main with JSON export"""
        # Mock arguments
        mock_args = Mock()
        mock_args.format = "json"
        mock_args.json = True
        mock_args.csv = False
        mock_args.export = "report.json"
        mock_parse_args.return_value = mock_args

        # Mock report instance
        mock_report = Mock()
        mock_report_class.return_value = mock_report
        mock_report.generate_credential_report.return_value = b"test"

        compliance.main()

        # Verify export was called
        mock_report.export_json.assert_called_once_with("report.json")

    @patch("aws_iam_compliance_report.IAMComplianceReport")
    @patch("aws_iam_compliance_report.parse_args")
    @patch("aws_iam_compliance_report.logger")
    @patch("aws_iam_compliance_report.rprint")
    def test_main_error_handling(
        self, mock_rprint, mock_logger, mock_parse_args, mock_report_class
    ):
        """Test main with error handling"""
        # Mock arguments
        mock_args = Mock()
        mock_args.format = "table"
        mock_args.json = False
        mock_args.csv = False
        mock_args.export = None
        mock_parse_args.return_value = mock_args

        # Mock report instance to raise error
        mock_report = Mock()
        mock_report_class.return_value = mock_report
        mock_report.generate_credential_report.side_effect = Exception("Test error")

        compliance.main()

        # Verify error was logged
        mock_logger.error.assert_called_once()
        mock_rprint.assert_called_with("[red]Error generating report: Test error[/red]")


if __name__ == "__main__":
    unittest.main()
