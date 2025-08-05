#!/usr/bin/env python3
"""Unit tests for secret key rotation and S3 storage."""

import unittest
from unittest.mock import Mock, patch, ANY
from datetime import datetime

# Add scripts directory to path
import os
import sys

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


if __name__ == "__main__":
    unittest.main()
