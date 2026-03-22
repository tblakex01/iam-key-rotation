#!/usr/bin/env python3
"""Unit tests for cleanup and S3 cleanup Lambdas."""

import json
import os
import sys
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from common.rotation_common import isoformat, utc_now  # noqa: E402
from cleanup import cleanup  # noqa: E402
from s3_cleanup import s3_cleanup  # noqa: E402


class TestCleanupLambdas(unittest.TestCase):
    @patch.dict(
        os.environ,
        {
            "SENDER_EMAIL": "security@example.com",
            "S3_BUCKET": "rotation-bucket",
            "DYNAMODB_TABLE": "rotation-table",
            "NEW_KEY_RETENTION_DAYS": "45",
            "OLD_KEY_RETENTION_DAYS": "30",
        },
    )
    @patch("cleanup.cleanup.cloudwatch")
    @patch("cleanup.cleanup.send_html_email")
    @patch("cleanup.cleanup.s3")
    @patch("cleanup.cleanup.iam")
    @patch("cleanup.cleanup.dynamodb")
    def test_cleanup_deletes_old_key_and_preserves_pending_download(
        self, mock_dynamodb, mock_iam, mock_s3, mock_send_html_email, mock_cloudwatch
    ):
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.query.side_effect = [
            {
                "Items": [
                    {
                        "PK": "USER#alice",
                        "SK": "ROTATION#OLDKEY",
                        "username": "alice",
                        "email": "alice@example.com",
                        "old_key_id": "OLDKEY",
                        "s3_key": "credentials/alice/OLDKEY.json",
                        "rotation_initiated": isoformat(utc_now() - timedelta(days=31)),
                        "old_key_deletion_date": int(
                            (utc_now() - timedelta(days=1)).timestamp()
                        ),
                        "downloaded": False,
                        "old_key_warning_sent": True,
                        "status": "pending_download",
                    }
                ]
            },
            {"Items": []},
        ]
        mock_s3.generate_presigned_url.return_value = "https://example.com/download"

        result = cleanup.lambda_handler({}, None)

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(json.loads(result["body"])["deleted"], 1)
        update_values = mock_table.update_item.call_args.kwargs[
            "ExpressionAttributeValues"
        ]
        self.assertEqual(update_values[":status"], "old_key_deleted_pending_download")
        mock_iam.delete_access_key.assert_called_once()
        mock_send_html_email.assert_called_once()

    @patch.dict(
        os.environ,
        {
            "SENDER_EMAIL": "security@example.com",
            "S3_BUCKET": "rotation-bucket",
            "DYNAMODB_TABLE": "rotation-table",
            "NEW_KEY_RETENTION_DAYS": "45",
            "OLD_KEY_RETENTION_DAYS": "30",
        },
    )
    @patch("s3_cleanup.s3_cleanup.cloudwatch")
    @patch("s3_cleanup.s3_cleanup.send_html_email")
    @patch("s3_cleanup.s3_cleanup.s3")
    @patch("s3_cleanup.s3_cleanup.dynamodb")
    def test_s3_cleanup_expires_pending_credentials(
        self, mock_dynamodb, mock_s3, mock_send_html_email, mock_cloudwatch
    ):
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.query.side_effect = [
            {
                "Items": [
                    {
                        "PK": "USER#alice",
                        "SK": "ROTATION#OLDKEY",
                        "username": "alice",
                        "email": "alice@example.com",
                        "old_key_id": "OLDKEY",
                        "s3_key": "credentials/alice/OLDKEY.json",
                        "rotation_initiated": isoformat(utc_now() - timedelta(days=46)),
                        "status": "old_key_deleted_pending_download",
                    }
                ]
            },
            {"Items": []},
        ]

        result = s3_cleanup.lambda_handler({}, None)

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(json.loads(result["body"])["expired"], 1)
        mock_s3.delete_object.assert_called_once()
        update_values = mock_table.update_item.call_args.kwargs[
            "ExpressionAttributeValues"
        ]
        self.assertEqual(update_values[":status"], "expired_no_download")
        mock_send_html_email.assert_called_once()


if __name__ == "__main__":
    unittest.main()
