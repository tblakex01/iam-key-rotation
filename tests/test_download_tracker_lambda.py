#!/usr/bin/env python3
"""Unit tests for the download tracker Lambda."""

import json
import os
import sys
import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from download_tracker import download_tracker  # noqa: E402


class TestDownloadTracker(unittest.TestCase):
    @patch.dict(os.environ, {"DYNAMODB_TABLE": "rotation-table"})
    @patch("download_tracker.download_tracker.dynamodb")
    @patch("download_tracker.download_tracker.s3")
    def test_tracks_download_by_exact_s3_key(self, mock_s3, mock_dynamodb):
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.query.return_value = {
            "Items": [{"PK": "USER#alice", "SK": "ROTATION#OLDKEY"}]
        }

        result = download_tracker.lambda_handler(
            {
                "detail": {
                    "eventTime": "2026-03-15T12:00:00Z",
                    "sourceIPAddress": "10.0.0.1",
                    "requestParameters": {
                        "bucketName": "rotation-bucket",
                        "key": "credentials/alice/OLDKEY.json",
                    },
                }
            },
            None,
        )

        self.assertEqual(result["statusCode"], 200)
        mock_s3.delete_object.assert_called_once_with(
            Bucket="rotation-bucket", Key="credentials/alice/OLDKEY.json"
        )
        self.assertEqual(mock_table.query.call_args.kwargs["IndexName"], "s3-key-index")
        self.assertEqual(json.loads(result["body"])["updated"], True)

    @patch.dict(os.environ, {"DYNAMODB_TABLE": "rotation-table"})
    @patch("download_tracker.download_tracker.dynamodb")
    @patch("download_tracker.download_tracker.s3")
    def test_treats_replayed_event_as_idempotent(self, mock_s3, mock_dynamodb):
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.query.return_value = {
            "Items": [{"PK": "USER#alice", "SK": "ROTATION#OLDKEY"}]
        }
        mock_table.update_item.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ConditionalCheckFailedException",
                    "Message": "already downloaded",
                }
            },
            "UpdateItem",
        )

        result = download_tracker.lambda_handler(
            {
                "detail": {
                    "requestParameters": {
                        "bucketName": "rotation-bucket",
                        "key": "credentials/alice/OLDKEY.json",
                    }
                }
            },
            None,
        )

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(json.loads(result["body"])["updated"], False)


if __name__ == "__main__":
    unittest.main()
