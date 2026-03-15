#!/usr/bin/env python3
"""Additional coverage for access key enforcement edge cases."""

import os
import sys
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from access_key_enforcement import access_key_enforcement  # noqa: E402


class TestLambdaEnforcementAdditional(unittest.TestCase):
    @patch.dict(
        os.environ,
        {
            "SENDER_EMAIL": "test@example.com",
            "S3_BUCKET": "rotation-bucket",
            "DYNAMODB_TABLE": "rotation-table",
            "NEW_KEY_RETENTION_DAYS": "45",
            "OLD_KEY_RETENTION_DAYS": "30",
        },
    )
    @patch("access_key_enforcement.access_key_enforcement.dynamodb")
    @patch("access_key_enforcement.access_key_enforcement.iam_client")
    def test_create_and_store_new_key_skips_existing_rotation(
        self, mock_iam, mock_dynamodb
    ):
        mock_table = Mock()
        mock_table.get_item.return_value = {"Item": {"status": "pending_download"}}
        mock_dynamodb.Table.return_value = mock_table

        result = access_key_enforcement.create_and_store_new_key(
            "alice", "OLDKEY", "alice@example.com"
        )

        self.assertIsNone(result)
        mock_iam.create_access_key.assert_not_called()

    @patch("access_key_enforcement.access_key_enforcement.get_s3_client")
    @patch("access_key_enforcement.access_key_enforcement.get_iam_client")
    def test_cleanup_failed_rotation_rolls_back_artifacts(
        self, mock_iam_client, mock_s3_client
    ):
        access_key_enforcement.cleanup_failed_rotation(
            "alice", "NEWKEY", "rotation-bucket", "credentials/alice/OLDKEY.json"
        )

        mock_iam_client.return_value.delete_access_key.assert_called_once()
        mock_s3_client.return_value.delete_object.assert_called_once()


if __name__ == "__main__":
    unittest.main()
