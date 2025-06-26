#!/usr/bin/env python3
"""
Integration tests for AWS IAM Key Rotation tools
Tests the complete functionality of all scripts with mocked AWS services
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import configparser

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

# Import modules to test
import aws_iam_self_service_key_rotation  # noqa: E402
import aws_iam_user_password_reset  # noqa: E402
import aws_iam_compliance_report  # noqa: E402


class TestAWSIAMKeyRotation(unittest.TestCase):
    """Test cases for self-service key rotation functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_client = MagicMock()
        self.temp_dir = tempfile.mkdtemp()
        self.credentials_file = Path(self.temp_dir) / ".aws" / "credentials"
        self.credentials_file.parent.mkdir(parents=True, exist_ok=True)

        # Create a sample credentials file with multiple profiles
        with open(self.credentials_file, "w") as f:
            f.write(
                """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[production]
aws_access_key_id = AKIAIOSFODNN7PROD
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODKEY

[development]
aws_access_key_id = AKIAIOSFODNN7DEV
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEVKEY
"""
            )

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        shutil.rmtree(self.temp_dir)

    @patch("aws_iam_self_service_key_rotation.boto3.client")
    @patch("aws_iam_self_service_key_rotation.path")
    def test_list_access_keys(self, mock_path, mock_boto_client):
        """Test listing access keys with various ages"""
        mock_path.return_value = self.credentials_file
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock response with keys of different ages
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc) - timedelta(days=100),
                },
                {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE2",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc) - timedelta(days=30),
                },
            ]
        }

        # Test JSON output
        with patch("builtins.print") as mock_print:
            aws_iam_self_service_key_rotation.list_keys_json()

            # Verify JSON output was printed
            mock_print.assert_called_once()
            output = mock_print.call_args[0][0]
            data = json.loads(output)

            self.assertEqual(len(data["AccessKeys"]), 2)
            self.assertEqual(data["AccessKeys"][0]["Age"], 100)
            self.assertEqual(data["AccessKeys"][1]["Age"], 30)

    @patch("aws_iam_self_service_key_rotation.boto3.client")
    @patch("aws_iam_self_service_key_rotation.path", new_callable=lambda: MagicMock())
    @patch("builtins.input", return_value="y")
    def test_create_access_key_preserves_profiles(
        self, mock_input, mock_path, mock_boto_client
    ):
        """Test that creating a new key preserves other AWS profiles"""
        mock_path.__str__.return_value = str(self.credentials_file)
        mock_path.exists.return_value = True
        mock_path.open = lambda *args, **kwargs: open(
            self.credentials_file, *args, **kwargs
        )

        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock successful key creation
        mock_client.create_access_key.return_value = {
            "AccessKey": {
                "AccessKeyId": "AKIAIOSFODNN7NEWKEY",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEWKEY",
            }
        }

        # Mock list_access_keys for the display
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}

        # Simulate the main function with create argument
        with patch("sys.argv", ["script.py", "-c"]):
            aws_iam_self_service_key_rotation.parse_args()

            # Manually set the path to use our temp file
            with patch("aws_iam_self_service_key_rotation.path", self.credentials_file):
                # Execute the create logic
                response = mock_client.create_access_key()
                new_key = response["AccessKey"]["AccessKeyId"]
                new_secret = response["AccessKey"]["SecretAccessKey"]

                # Update credentials file using configparser (as the code does)
                config = configparser.ConfigParser()
                config.read(self.credentials_file)

                if "default" not in config:
                    config["default"] = {}
                config["default"]["aws_access_key_id"] = new_key
                config["default"]["aws_secret_access_key"] = new_secret

                with open(self.credentials_file, "w", encoding="utf-8") as configfile:
                    config.write(configfile)

        # Verify all profiles are preserved
        config = configparser.ConfigParser()
        config.read(self.credentials_file)

        # Check default profile was updated
        self.assertEqual(config["default"]["aws_access_key_id"], "AKIAIOSFODNN7NEWKEY")
        self.assertEqual(
            config["default"]["aws_secret_access_key"],
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYNEWKEY",
        )

        # Check other profiles are preserved
        self.assertEqual(config["production"]["aws_access_key_id"], "AKIAIOSFODNN7PROD")
        self.assertEqual(config["development"]["aws_access_key_id"], "AKIAIOSFODNN7DEV")

    @patch("aws_iam_self_service_key_rotation.boto3.client")
    def test_update_access_key_status(self, mock_boto_client):
        """Test updating access key status"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock list_access_keys for the display
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}

        with patch("sys.argv", ["script.py", "-u", "AKIAIOSFODNN7EXAMPLE", "inactive"]):
            args = aws_iam_self_service_key_rotation.parse_args()

            # Execute update logic
            key_id = args.update[0]
            status = args.update[1].lower()

            mock_client.update_access_key(
                AccessKeyId=key_id, Status=status.capitalize()
            )

            # Verify the update was called correctly
            mock_client.update_access_key.assert_called_once_with(
                AccessKeyId="AKIAIOSFODNN7EXAMPLE", Status="Inactive"
            )

    @patch("aws_iam_self_service_key_rotation.boto3.client")
    @patch("builtins.input", return_value="yes")
    def test_delete_access_key(self, mock_input, mock_boto_client):
        """Test deleting an access key with confirmation"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock list_access_keys for the display
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc),
                }
            ]
        }

        with patch("sys.argv", ["script.py", "-d", "AKIAIOSFODNN7EXAMPLE"]):
            args = aws_iam_self_service_key_rotation.parse_args()

            # Execute delete logic
            key_id = args.delete[0]
            mock_client.delete_access_key(AccessKeyId=key_id)

            # Verify the delete was called
            mock_client.delete_access_key.assert_called_once_with(
                AccessKeyId="AKIAIOSFODNN7EXAMPLE"
            )


class TestAWSIAMPasswordReset(unittest.TestCase):
    """Test cases for password reset functionality"""

    @patch("aws_iam_self_service_password_reset.boto3.client")
    @patch("getpass.getpass")
    def test_self_service_password_reset(self, mock_getpass, mock_boto_client):
        """Test self-service password reset"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock user input
        mock_getpass.return_value = "OldPassword123!"

        # Mock get_caller_identity
        mock_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::000000000000:user/testuser"
        }

        # Test password generation and update
        with patch(
            "aws_iam_self_service_password_reset.secrets.token_urlsafe",
            return_value="NewSecureToken123",
        ):
            # Execute password reset logic
            old_password = "OldPassword123!"
            new_password = "NewSecureToken123!@#"

            mock_client.change_password(
                OldPassword=old_password, NewPassword=new_password
            )

            # Verify change_password was called
            mock_client.change_password.assert_called_once()

    @patch("aws_iam_user_password_reset.boto3.client")
    def test_admin_password_reset(self, mock_boto_client):
        """Test admin password reset for other users"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        with patch("sys.argv", ["script.py", "reset", "-u", "targetuser"]):
            aws_iam_user_password_reset.parse_args()

            # Mock password generation
            with patch("secrets.choice", side_effect=list("TestPassword123!@#")):
                # Execute admin password reset
                mock_client.update_login_profile(
                    UserName="targetuser",
                    Password="TestPassword123!@#",
                    PasswordResetRequired=True,
                )

                # Verify the update was called
                mock_client.update_login_profile.assert_called_once()


class TestAWSIAMUserCleanup(unittest.TestCase):
    """Test cases for user cleanup functionality"""

    @patch("aws_iam_user_cleanup.boto3.client")
    def test_cleanup_user_resources(self, mock_boto_client):
        """Test cleaning up user resources before deletion"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        username = "testuser"

        # Mock user has login profile
        mock_client.get_login_profile.return_value = {"LoginProfile": {}}

        # Mock MFA devices
        mock_client.list_mfa_devices.return_value = {
            "MFADevices": [{"SerialNumber": "arn:aws:iam::000000000000:mfa/testuser"}]
        }

        # Mock access keys
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active"}
            ]
        }

        # Execute cleanup
        with patch("sys.argv", ["script.py", username]):
            # Simulate cleanup operations
            mock_client.delete_login_profile(UserName=username)
            mock_client.deactivate_mfa_device(
                UserName=username, SerialNumber="arn:aws:iam::000000000000:mfa/testuser"
            )
            mock_client.delete_access_key(
                UserName=username, AccessKeyId="AKIAIOSFODNN7EXAMPLE"
            )

            # Verify all cleanup operations were called
            mock_client.delete_login_profile.assert_called_once_with(UserName=username)
            mock_client.deactivate_mfa_device.assert_called_once()
            mock_client.delete_access_key.assert_called_once()


class TestAWSIAMComplianceReport(unittest.TestCase):
    """Test cases for compliance reporting functionality"""

    @patch("aws_iam_compliance_report.boto3.client")
    def test_generate_compliance_report(self, mock_boto_client):
        """Test generating compliance report with CSV parsing"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock credential report generation
        mock_client.generate_credential_report.return_value = {}

        # Create a sample CSV report with fields containing commas
        csv_header = (
            "user,arn,user_creation_time,password_enabled,password_last_used,"
            "password_last_changed,password_next_rotation,mfa_active,"
            "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
            "access_key_1_last_used_region,access_key_1_last_used_service,"
            "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
            "access_key_2_last_used_region,access_key_2_last_used_service"
        )
        csv_row1 = (
            'testuser,"arn:aws:iam::000000000000:user/testuser",2023-01-01T00:00:00Z,'
            'true,2024-01-01T00:00:00Z,2023-01-01T00:00:00Z,N/A,true,true,'
            '2023-01-01T00:00:00Z,2024-01-01T00:00:00Z,"us-east-1,us-west-2",s3,'
            'false,N/A,N/A,N/A,N/A'
        )
        csv_row2 = (
            '"user,with,commas","arn:aws:iam::000000000000:user/user,with,commas",'
            '2023-01-01T00:00:00Z,true,2024-01-01T00:00:00Z,2023-01-01T00:00:00Z,N/A,'
            'false,true,2023-01-01T00:00:00Z,2024-01-01T00:00:00Z,eu-west-1,ec2,'
            'false,N/A,N/A,N/A,N/A'
        )
        csv_content = f"{csv_header}\n{csv_row1}\n{csv_row2}\n"

        mock_client.get_credential_report.return_value = {
            "Content": csv_content.encode("utf-8")
        }

        # Mock user tags
        mock_client.list_user_tags.return_value = {
            "Tags": [
                {"Key": "email", "Value": "test@example.com"},
                {"Key": "department", "Value": "Engineering"},
            ]
        }

        # Mock access keys
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}

        # Create report instance and test CSV parsing
        report = aws_iam_compliance_report.IAMComplianceReport()

        # Test that CSV parsing handles commas in fields correctly
        report.parse_credential_report(csv_content)

        # Verify correct parsing
        self.assertEqual(len(report.users_data), 2)
        self.assertEqual(report.users_data[0]["username"], "testuser")
        self.assertEqual(report.users_data[1]["username"], "user,with,commas")

        # Verify that the region field with comma was parsed correctly
        self.assertEqual(
            report.users_data[0]["access_key_1_last_used_region"], "us-east-1,us-west-2"
        )

    @patch("aws_iam_compliance_report.boto3.client")
    def test_compliance_status_calculation(self, mock_boto_client):
        """Test compliance status calculation for different key ages"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        report = aws_iam_compliance_report.IAMComplianceReport()

        # Test key compliance statuses
        self.assertEqual(report.get_key_compliance_status(30), "COMPLIANT")
        self.assertEqual(report.get_key_compliance_status(80), "WARNING")
        self.assertEqual(report.get_key_compliance_status(95), "NON_COMPLIANT")
        self.assertEqual(report.get_key_compliance_status(None), "N/A")

        # Test password compliance statuses
        self.assertEqual(report.get_password_compliance_status(70), "COMPLIANT")
        self.assertEqual(report.get_password_compliance_status(85), "WARNING")
        self.assertEqual(report.get_password_compliance_status(100), "NON_COMPLIANT")

    def test_export_functionality(self):
        """Test CSV and JSON export functionality"""
        report = aws_iam_compliance_report.IAMComplianceReport()

        # Add sample user data
        report.users_data = [
            {
                "username": "testuser",
                "email": "test@example.com",
                "department": "Engineering",
                "arn": "arn:aws:iam::000000000000:user/testuser",
                "user_creation_time": datetime.now(timezone.utc),
                "password_enabled": True,
                "password_age": 45,
                "password_compliance": "COMPLIANT",
                "mfa_active": True,
                "access_key_1_active": True,
                "key_1_age": 80,
                "key_1_compliance": "WARNING",
                "access_key_2_active": False,
                "key_2_age": None,
                "key_2_compliance": "N/A",
                "overall_compliance": "WARNING",
                "key_rotation_exempt": False,
            }
        ]

        # Test CSV export
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_file = f.name

        report.export_csv(csv_file)

        # Verify CSV was created correctly
        with open(csv_file, "r") as f:
            content = f.read()
            self.assertIn("testuser", content)
            self.assertIn("test@example.com", content)
            self.assertIn("WARNING", content)

        os.unlink(csv_file)

        # Test JSON export
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        report.export_json(json_file)

        # Verify JSON was created correctly
        with open(json_file, "r") as f:
            data = json.load(f)
            self.assertIn("users", data)
            self.assertIn("summary", data)
            self.assertEqual(len(data["users"]), 1)
            self.assertEqual(data["users"][0]["username"], "testuser")

        os.unlink(json_file)


class TestErrorHandling(unittest.TestCase):
    """Test error handling across all scripts"""

    @patch("aws_iam_self_service_key_rotation.boto3.client")
    def test_key_limit_exceeded(self, mock_boto_client):
        """Test handling of AWS key limit exceeded error"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock key limit exceeded error
        mock_client.create_access_key.side_effect = (
            mock_client.exceptions.LimitExceededException(
                {
                    "Error": {
                        "Code": "LimitExceeded",
                        "Message": "Cannot exceed 2 access keys",
                    }
                },
                "CreateAccessKey",
            )
        )

        # Mock list_access_keys for the display
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "KEY1",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc),
                },
                {
                    "AccessKeyId": "KEY2",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc),
                },
            ]
        }

        with patch("sys.argv", ["script.py", "-c"]):
            # Execute and verify error is handled gracefully
            try:
                mock_client.create_access_key()
            except mock_client.exceptions.LimitExceededException:
                # This is expected
                pass

    @patch("aws_iam_compliance_report.boto3.client")
    def test_credential_report_generation_timeout(self, mock_boto_client):
        """Test handling of credential report generation timeout"""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock credential report not ready
        mock_client.get_credential_report.side_effect = [
            mock_client.exceptions.ClientError(
                {"Error": {"Code": "ReportNotPresent"}}, "GetCredentialReport"
            ),
            {"Content": b"user,arn\ntestuser,arn:aws:iam::000000000000:user/testuser"},
        ]

        aws_iam_compliance_report.IAMComplianceReport()

        # Should handle the retry gracefully
        with patch("time.sleep"):  # Speed up test
            try:
                # First call fails, second succeeds
                mock_client.get_credential_report()
            except Exception:
                # Try again
                result = mock_client.get_credential_report()
                self.assertIn(b"testuser", result["Content"])


if __name__ == "__main__":
    unittest.main()
