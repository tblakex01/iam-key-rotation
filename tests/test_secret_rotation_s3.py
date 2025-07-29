#!/usr/bin/env python3
"""Unit tests for secret rotation S3 storage script."""

import unittest
from unittest.mock import Mock, patch

# Add scripts directory to path
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import aws_iam_secret_rotation_s3 as rot  # noqa: E402


class TestRotateAndStore(unittest.TestCase):
    """Test rotate_and_store_credentials function."""

    @patch("aws_iam_secret_rotation_s3.create_secure_bucket")
    @patch("aws_iam_secret_rotation_s3.get_s3_client")
    @patch("aws_iam_secret_rotation_s3.get_iam_client")
    def test_rotate_and_store_success(self, mock_get_iam, mock_get_s3, mock_bucket):
        iam_client = Mock()
        s3_client = Mock()
        mock_get_iam.return_value = iam_client
        mock_get_s3.return_value = s3_client
        mock_bucket.return_value = "test-bucket"

        iam_client.get_user.return_value = {"User": {"UserName": "test"}}
        iam_client.create_access_key.return_value = {
            "AccessKey": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret",
            }
        }
        s3_client.generate_presigned_url.return_value = "https://example.com/url"

        url = rot.rotate_and_store_credentials("OLDKEY")

        iam_client.update_access_key.assert_called_once_with(
            UserName="test", AccessKeyId="OLDKEY", Status="Inactive"
        )
        s3_client.put_object.assert_called_once()
        mock_bucket.assert_called_once()
        self.assertEqual(url, "https://example.com/url")


if __name__ == "__main__":
    unittest.main()
