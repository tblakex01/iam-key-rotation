#!/usr/bin/env python3
"""Unit tests for the URL regenerator Lambda."""

import json
import os
import sys
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from common.rotation_common import isoformat, utc_now  # noqa: E402
from url_regenerator import url_regenerator  # noqa: E402


class TestUrlRegenerator(unittest.TestCase):
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
    @patch("url_regenerator.url_regenerator.ses")
    @patch("url_regenerator.url_regenerator.s3")
    @patch("url_regenerator.url_regenerator.dynamodb")
    def test_sends_due_reminder_once(self, mock_dynamodb, mock_s3, mock_ses):
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
                        "rotation_initiated": isoformat(utc_now() - timedelta(days=7)),
                        "last_reminder_day": 0,
                        "status": "pending_download",
                    }
                ]
            },
            {"Items": []},
        ]
        mock_s3.generate_presigned_url.return_value = "https://example.com/download"

        result = url_regenerator.lambda_handler({}, None)

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(json.loads(result["body"])["reminded"], 1)
        mock_table.update_item.assert_called_once()
        mock_ses.send_email.assert_called_once()


if __name__ == "__main__":
    unittest.main()
