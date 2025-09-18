#!/usr/bin/env python3
"""Unit tests for secret key rotation and S3 storage."""

import os
import runpy
import sys
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import ANY, Mock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import aws_iam_secret_key_rotation_s3 as rotate  # noqa: E402


class TestRotateAndStoreCredentials(unittest.TestCase):
    """Test credential rotation and S3 upload."""

    @patch("aws_iam_secret_key_rotation_s3.uuid4")
    @patch("aws_iam_secret_key_rotation_s3.get_s3_client")
    @patch("aws_iam_secret_key_rotation_s3.get_iam_client")
    def test_rotate_and_store(self, mock_iam_client, mock_s3_client, mock_uuid):
        iam = Mock()
        s3 = Mock()
        mock_iam_client.return_value = iam
        mock_s3_client.return_value = s3
        mock_uuid.return_value.hex = "abc123"

        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{"AccessKeyId": "OLD"}]
        }
        iam.create_access_key.return_value = {
            "AccessKey": {
                "AccessKeyId": "NEW",
                "SecretAccessKey": "SECRET",
                "CreateDate": datetime(2024, 1, 1),
            }
        }
        s3.generate_presigned_url.return_value = "https://example.com/url"

        url = rotate.rotate_and_store_credentials("test")

        self.assertEqual(url, "https://example.com/url")
        bucket = "iam-creds-abc123"
        s3.create_bucket.assert_called_once_with(Bucket=bucket)
        s3.put_public_access_block.assert_called_once()
        s3.put_object.assert_called_once_with(
            Bucket=bucket,
            Key="NEW.json",
            Body=ANY,
            ServerSideEncryption="AES256",
        )
        iam.update_access_key.assert_called_once_with(
            UserName="test", AccessKeyId="OLD", Status="Inactive"
        )

    def test_rotate_and_store_with_moto(self):
        rotate._iam_client = None
        rotate._s3_client = None

        with mock_aws():
            iam = boto3.client("iam", region_name="us-east-1")
            s3 = boto3.client("s3", region_name="us-east-1")

            iam.create_user(UserName="demo-user")
            iam.create_access_key(UserName="demo-user")

            with patch("builtins.print"):
                url = rotate.rotate_and_store_credentials("demo-user")

            buckets = s3.list_buckets()["Buckets"]
            self.assertTrue(buckets)
            self.assertTrue(url.startswith("https://"))

    def test_cli_invocation_executes_rotation(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "aws_iam_secret_key_rotation_s3.py"
        )

        class _FakeIAM:
            def __init__(self):
                self.calls = []

            def list_access_keys(self, UserName):
                self.calls.append(("list", UserName))
                return {"AccessKeyMetadata": []}

            def create_access_key(self, UserName):
                self.calls.append(("create", UserName))
                return {
                    "AccessKey": {
                        "AccessKeyId": "FAKE",
                        "SecretAccessKey": "SECRET",
                        "CreateDate": datetime(2024, 1, 1),
                    }
                }

            def update_access_key(self, **kwargs):
                self.calls.append(("update", kwargs))

        class _FakeS3:
            def create_bucket(self, **kwargs):
                pass

            def put_public_access_block(self, **kwargs):
                pass

            def put_object(self, **kwargs):
                pass

            def generate_presigned_url(self, *_, **__):
                return "https://example.com"

        class _FakeBoto3:
            def __init__(self):
                self.iam = _FakeIAM()
                self.s3 = _FakeS3()

            def client(self, name, **_):
                return self.iam if name == "iam" else self.s3

        fake_boto3 = _FakeBoto3()
        fake_module = types.ModuleType("boto3")
        fake_module.client = fake_boto3.client

        with patch.object(sys, "argv", [script.name, "demo"]):
            with patch("builtins.print"):
                with patch.dict(sys.modules, {"boto3": fake_module}):
                    runpy.run_path(script, run_name="__main__")

        self.assertIn(("list", "demo"), fake_boto3.iam.calls)
        self.assertTrue(any(call[0] == "create" for call in fake_boto3.iam.calls))

    def test_cli_propagates_client_errors(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "aws_iam_secret_key_rotation_s3.py"
        )

        class _ErroringIAM:
            def list_access_keys(self, UserName):
                return {"AccessKeyMetadata": []}

            def create_access_key(self, UserName):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    "CreateAccessKey",
                )

        class _NoopS3:
            def create_bucket(self, **kwargs):
                pass

            def put_public_access_block(self, **kwargs):
                pass

        class _FakeBoto3:
            def __init__(self):
                self.iam = _ErroringIAM()
                self.s3 = _NoopS3()

            def client(self, name, **_):
                return self.iam if name == "iam" else self.s3

        fake_boto3 = _FakeBoto3()
        fake_module = types.ModuleType("boto3")
        fake_module.client = fake_boto3.client

        with patch.object(sys, "argv", [script.name, "demo"]):
            with patch.dict(sys.modules, {"boto3": fake_module}):
                with self.assertLogs(level="ERROR") as logs:
                    with self.assertRaises(ClientError):
                        runpy.run_path(script, run_name="__main__")

        self.assertTrue(any("AWS error" in message for message in logs.output))


if __name__ == "__main__":
    unittest.main()
