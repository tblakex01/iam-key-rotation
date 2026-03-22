#!/usr/bin/env python3
"""Unit tests for the access-key recovery request Lambda."""

from __future__ import annotations

import base64
import json
import os
import sys
import unittest
from datetime import timedelta
from unittest.mock import ANY, Mock, patch

from boto3.dynamodb.conditions import And, BeginsWith, Equals
from botocore.exceptions import ClientError

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from password_recovery_request import password_recovery_request  # noqa: E402


class FakeTable:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.update_calls = []

    def query(self, **kwargs):
        condition = kwargs.get("KeyConditionExpression")
        return {
            "Items": [
                dict(item)
                for item in self.items
                if self._matches_condition(item, condition)
            ]
        }

    def get_item(self, Key=None, ConsistentRead=False):  # noqa: N803
        for item in self.items:
            if item["PK"] == Key["PK"] and item["SK"] == Key["SK"]:
                return {"Item": dict(item)}
        return {}

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        key = kwargs["Key"]
        values = kwargs.get("ExpressionAttributeValues", {})
        item = next(
            (
                existing
                for existing in self.items
                if existing["PK"] == key["PK"] and existing["SK"] == key["SK"]
            ),
            None,
        )
        expected_version = values.get(":expected_version")
        current_version = None if item is None else item.get("reissue_version")
        if expected_version is not None and current_version not in {
            None,
            expected_version,
        }:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem"
            )

        if item is None:
            item = {"PK": key["PK"], "SK": key["SK"]}
            self.items.append(item)

        if ":email" in values:
            item["email"] = values[":email"]
        if ":email_lookup" in values:
            item["email_lookup"] = values[":email_lookup"]
        if ":timestamp" in values:
            item["last_self_service_reissue_at"] = values[":timestamp"]
            if item["SK"].startswith("ROTATION#"):
                item["last_email_sent_at"] = values[":timestamp"]
        if ":last_reissue" in values:
            item["last_self_service_reissue_at"] = values[":last_reissue"]
        if ":ip" in values:
            item["last_reissue_request_ip"] = values[":ip"]
        if ":last_ip" in values:
            item["last_reissue_request_ip"] = values[":last_ip"]
        if ":recent" in values:
            item["recent_self_service_reissues"] = list(values[":recent"])
        if ":new_version" in values:
            item["reissue_version"] = values[":new_version"]
        if ":rollback_version" in values:
            item["reissue_version"] = values[":rollback_version"]
        if item["SK"].startswith("ROTATION#"):
            item["email_sent_count"] = item.get("email_sent_count", 0) + values.get(
                ":one", 0
            )
            item["self_service_reissue_count"] = item.get(
                "self_service_reissue_count", 0
            ) + values.get(":one", 0)
        return {}

    def _matches_condition(self, item, condition) -> bool:
        if condition is None:
            return True
        if isinstance(condition, And):
            return all(
                self._matches_condition(item, part) for part in condition._values
            )
        if isinstance(condition, Equals):
            key, expected = condition._values
            return item.get(key.name) == expected
        if isinstance(condition, BeginsWith):
            key, prefix = condition._values
            value = item.get(key.name)
            return isinstance(value, str) and value.startswith(prefix)
        raise AssertionError(f"Unsupported DynamoDB condition: {condition!r}")


class FakeResource:
    def __init__(self, table):
        self._table = table

    def Table(self, name):  # noqa: N802
        return self._table


class FakePaginator:
    def __init__(self, users):
        self._users = users

    def paginate(self):
        return [{"Users": self._users}]


class FakeIAMClient:
    def __init__(self, users, tags):
        self.users = users
        self.tags = tags
        self.list_users_requested = False

    def get_user(self, UserName=None):
        if UserName not in self.users:
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetUser")
        return {"User": {"UserName": UserName}}

    def list_user_tags(self, UserName=None):
        return {"Tags": self.tags.get(UserName, [])}

    def get_paginator(self, name):
        assert name == "list_users"
        self.list_users_requested = True
        return FakePaginator([{"UserName": username} for username in self.users])


class FakeS3Client:
    def __init__(self, *, existing_keys=None):
        self.existing_keys = set(existing_keys or [])
        self.generate_calls = []
        self.head_calls = []

    def head_object(self, Bucket=None, Key=None):
        self.head_calls.append({"Bucket": Bucket, "Key": Key})
        if Key not in self.existing_keys:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {}

    def generate_presigned_url(self, operation_name, Params=None, ExpiresIn=None):
        self.generate_calls.append(
            {
                "operation_name": operation_name,
                "Params": Params,
                "ExpiresIn": ExpiresIn,
            }
        )
        return f"https://example.com/download/{Params['Key']}"


class PaginatedQueryTable:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages.pop(0)


BASE_ENV = {
    "SENDER_EMAIL": "security@example.com",
    "SUPPORT_EMAIL": "support@example.com",
    "DYNAMODB_TABLE": "rotation-table",
    "S3_BUCKET": "rotation-bucket",
    "ACCESS_KEY_RECOVERY_REQUEST_COOLDOWN_MINUTES": "30",
    "ACCESS_KEY_RECOVERY_MAX_REQUESTS_PER_DAY": "3",
}


def build_rotation_item(
    *,
    username: str = "alice",
    status: str = "pending_download",
    rotation_started_at: str | None = None,
    s3_key: str = "credentials/alice/OLDKEY.json",
    old_key_id: str = "OLDKEY",
    email: str = "alice@example.com",
    last_self_service_reissue_at: str | None = None,
) -> dict[str, object]:
    return {
        "PK": f"USER#{username}",
        "SK": f"ROTATION#{old_key_id}",
        "username": username,
        "email": email,
        "email_lookup": email.lower(),
        "old_key_id": old_key_id,
        "s3_key": s3_key,
        "status": status,
        "rotation_initiated": rotation_started_at
        or password_recovery_request.isoformat(password_recovery_request.utc_now()),
        "email_sent_count": 1,
        "last_self_service_reissue_at": last_self_service_reissue_at,
    }


def build_recovery_state(
    *,
    username: str = "alice",
    email: str = "alice@example.com",
    recent_self_service_reissues: list[str] | None = None,
    last_self_service_reissue_at: str | None = None,
    reissue_version: int = 1,
) -> dict[str, object]:
    recent = list(recent_self_service_reissues or [])
    if last_self_service_reissue_at and not recent:
        recent = [last_self_service_reissue_at]
    return {
        "PK": f"USER#{username}",
        "SK": "RECOVERY#STATE",
        "email": email,
        "email_lookup": email.lower(),
        "last_self_service_reissue_at": last_self_service_reissue_at,
        "recent_self_service_reissues": recent,
        "reissue_version": reissue_version,
    }


class TestAccessKeyRecoveryRequest(unittest.TestCase):
    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_reissues_pending_download_credentials(self, mock_send_html_email):
        table = FakeTable([build_rotation_item()])
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        fake_s3 = FakeS3Client(existing_keys={"credentials/alice/OLDKEY.json"})
        password_recovery_request.s3 = fake_s3

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "alice"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        self.assertEqual(len(fake_s3.generate_calls), 1)
        self.assertEqual(len(table.update_calls), 2)
        mock_send_html_email.assert_called_once()
        self.assertEqual(
            mock_send_html_email.call_args.kwargs["to_addresses"],
            ["alice@example.com"],
        )

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_reissues_after_old_key_deleted_if_secret_still_exists(
        self, mock_send_html_email
    ):
        table = FakeTable(
            [
                build_rotation_item(
                    status="old_key_deleted_pending_download",
                    s3_key="credentials/alice/OLDKEY2.json",
                    old_key_id="OLDKEY2",
                )
            ]
        )
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY2.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "alice"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        self.assertEqual(len(table.update_calls), 2)
        self.assertTrue(mock_send_html_email.call_args.kwargs["html_body"])

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_downloaded_credentials_are_not_reissued(self, mock_send_html_email):
        table = FakeTable([build_rotation_item(status="downloaded")])
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "alice"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        self.assertEqual(len(table.update_calls), 0)
        mock_send_html_email.assert_not_called()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_missing_s3_object_blocks_reissue(self, mock_send_html_email):
        table = FakeTable([build_rotation_item()])
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(existing_keys=set())

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "alice"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        self.assertEqual(len(table.update_calls), 0)
        mock_send_html_email.assert_not_called()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_reissue_cooldown_blocks_repeat_requests(self, mock_send_html_email):
        recent_reissue = password_recovery_request.isoformat(
            password_recovery_request.utc_now() - timedelta(minutes=5)
        )
        table = FakeTable(
            [
                build_rotation_item(),
                build_recovery_state(last_self_service_reissue_at=recent_reissue),
            ]
        )
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "alice"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        self.assertEqual(len(table.update_calls), 0)
        mock_send_html_email.assert_not_called()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_reissue_daily_limit_blocks_repeat_requests(self, mock_send_html_email):
        now = password_recovery_request.utc_now()
        recent = [
            password_recovery_request.isoformat(now - timedelta(hours=1)),
            password_recovery_request.isoformat(now - timedelta(hours=2)),
            password_recovery_request.isoformat(now - timedelta(hours=3)),
        ]
        table = FakeTable(
            [
                build_rotation_item(),
                build_recovery_state(
                    recent_self_service_reissues=recent,
                    last_self_service_reissue_at=recent[0],
                ),
            ]
        )
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "alice"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        self.assertEqual(len(table.update_calls), 0)
        mock_send_html_email.assert_not_called()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_unknown_username_returns_generic_success(self, mock_send_html_email):
        password_recovery_request.iam = FakeIAMClient(users=set(), tags={})
        password_recovery_request.dynamodb = FakeResource(FakeTable())
        password_recovery_request.s3 = FakeS3Client(existing_keys=set())

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "missing"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        mock_send_html_email.assert_not_called()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_email_lookup_uses_tracking_table_index(self, mock_send_html_email):
        table = FakeTable([build_rotation_item(email="Alice@Example.com")])
        fake_iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "Alice@Example.com"}]},
        )
        password_recovery_request.iam = fake_iam
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"email": "alice@example.com"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        self.assertFalse(fake_iam.list_users_requested)
        mock_send_html_email.assert_called_once()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_email_lookup_falls_back_for_legacy_rows_without_email_lookup(
        self, mock_send_html_email
    ):
        legacy_item = build_rotation_item(email="alice@example.com")
        legacy_item.pop("email_lookup")
        table = FakeTable([legacy_item])
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"email": "alice@example.com"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        mock_send_html_email.assert_called_once()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_email_lookup_revalidates_current_iam_email(self, mock_send_html_email):
        table = FakeTable([build_rotation_item(email="alice@example.com")])
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "new-address@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"email": "alice@example.com"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        mock_send_html_email.assert_not_called()

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_failed_send_rolls_back_reissue_reservation(self, mock_send_html_email):
        table = FakeTable([build_rotation_item()])
        mock_send_html_email.side_effect = RuntimeError("ses down")
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"},
            tags={"alice": [{"Key": "email", "Value": "alice@example.com"}]},
        )
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(
            existing_keys={"credentials/alice/OLDKEY.json"}
        )

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"username": "alice"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        recovery_state = next(
            item for item in table.items if item["SK"] == "RECOVERY#STATE"
        )
        self.assertIsNone(recovery_state["last_self_service_reissue_at"])
        self.assertEqual(recovery_state["recent_self_service_reissues"], [])
        self.assertEqual(recovery_state["reissue_version"], 0)
        self.assertEqual(len(table.update_calls), 2)

    @patch.dict(os.environ, BASE_ENV, clear=False)
    @patch("password_recovery_request.password_recovery_request.send_html_email")
    def test_duplicate_email_matches_return_generic_success(self, mock_send_html_email):
        table = FakeTable(
            [
                build_rotation_item(
                    username="alice",
                    email="shared@example.com",
                    s3_key="credentials/alice/OLDKEY.json",
                ),
                build_rotation_item(
                    username="bob",
                    email="shared@example.com",
                    old_key_id="OLDKEY2",
                    s3_key="credentials/bob/OLDKEY2.json",
                ),
            ]
        )
        password_recovery_request.iam = FakeIAMClient(users=set(), tags={})
        password_recovery_request.dynamodb = FakeResource(table)
        password_recovery_request.s3 = FakeS3Client(existing_keys=set())

        result = password_recovery_request.lambda_handler(
            {"body": json.dumps({"email": "shared@example.com"})}, None
        )

        self.assertEqual(result["statusCode"], 202)
        mock_send_html_email.assert_not_called()


class TestAccessKeyRecoveryRequestHelpers(unittest.TestCase):
    def test_parse_request_payload_handles_missing_invalid_and_dict_bodies(self):
        self.assertIsNone(password_recovery_request.parse_request_payload({}))
        self.assertIsNone(
            password_recovery_request.parse_request_payload(
                {
                    "body": base64.b64encode(b"\xff").decode("utf-8"),
                    "isBase64Encoded": True,
                }
            )
        )
        self.assertEqual(
            password_recovery_request.parse_request_payload(
                {"body": {"username": "alice"}}
            ),
            {"username": "alice"},
        )
        self.assertIsNone(
            password_recovery_request.parse_request_payload({"body": "not-json"})
        )

    def test_validate_identifier_payload_rejects_invalid_combinations(self):
        self.assertIsNone(
            password_recovery_request.validate_identifier_payload(
                {"username": "alice", "email": "alice@example.com"}
            )
        )
        self.assertEqual(
            password_recovery_request.validate_identifier_payload(
                {"username": " alice "}
            ),
            {"username": "alice"},
        )
        self.assertIsNone(
            password_recovery_request.validate_identifier_payload({"email": "invalid"})
        )

    def test_resolve_user_by_username_returns_none_when_email_missing(self):
        password_recovery_request.iam = FakeIAMClient(
            users={"alice"}, tags={"alice": []}
        )
        self.assertIsNone(password_recovery_request.resolve_user_by_username("alice"))

    def test_resolve_user_by_username_returns_none_for_missing_user(self):
        password_recovery_request.iam = FakeIAMClient(users=set(), tags={})
        self.assertIsNone(password_recovery_request.resolve_user_by_username("alice"))

    def test_resolve_user_by_username_reraises_unexpected_iam_errors(self):
        password_recovery_request.iam = Mock()
        password_recovery_request.iam.get_user.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "GetUser",
        )

        with self.assertRaises(ClientError):
            password_recovery_request.resolve_user_by_username("alice")

    @patch(
        "password_recovery_request.password_recovery_request.legacy_recoverable_items_for_email"
    )
    @patch("password_recovery_request.password_recovery_request.query_all_items")
    def test_list_rotation_items_by_email_falls_back_when_index_unavailable(
        self, mock_query_all_items, mock_legacy_lookup
    ):
        mock_query_all_items.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}},
            "Query",
        )
        mock_legacy_lookup.return_value = [{"username": "alice"}]

        result = password_recovery_request.list_rotation_items_by_email(
            FakeTable(), "alice@example.com"
        )

        self.assertEqual(result, [{"username": "alice"}])
        mock_legacy_lookup.assert_called_once_with(ANY, "alice@example.com")

    def test_query_all_items_handles_pagination(self):
        table = PaginatedQueryTable(
            [
                {"Items": [{"PK": "one"}], "LastEvaluatedKey": {"PK": "one"}},
                {"Items": [{"PK": "two"}]},
            ]
        )

        result = password_recovery_request.query_all_items(
            table, {"IndexName": "status-index"}
        )

        self.assertEqual(result, [{"PK": "one"}, {"PK": "two"}])
        self.assertIn("ExclusiveStartKey", table.calls[1])

    @patch(
        "password_recovery_request.password_recovery_request.find_latest_recoverable_rotation"
    )
    @patch(
        "password_recovery_request.password_recovery_request.list_rotation_items_by_email"
    )
    def test_resolve_user_by_email_returns_none_when_no_latest_rotation(
        self, mock_list_items, mock_find_latest
    ):
        mock_list_items.return_value = [
            {"username": "alice", "status": "pending_download", "s3_key": "key"}
        ]
        mock_find_latest.return_value = None

        self.assertIsNone(
            password_recovery_request.resolve_user_by_email(
                FakeTable(), "alice@example.com"
            )
        )

    def test_resolve_user_by_email_returns_none_when_current_user_is_missing(self):
        table = FakeTable([build_rotation_item(email="alice@example.com")])
        password_recovery_request.iam = FakeIAMClient(users=set(), tags={})

        self.assertIsNone(
            password_recovery_request.resolve_user_by_email(table, "alice@example.com")
        )

    def test_get_user_email_returns_none_when_tag_lookup_fails(self):
        password_recovery_request.iam = Mock()
        password_recovery_request.iam.list_user_tags.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListUserTags",
        )

        self.assertIsNone(password_recovery_request.get_user_email("alice"))

    def test_list_user_rotation_items_handles_pagination(self):
        table = PaginatedQueryTable(
            [
                {
                    "Items": [{"PK": "USER#alice", "SK": "ROTATION#one"}],
                    "LastEvaluatedKey": {"PK": "USER#alice", "SK": "ROTATION#one"},
                },
                {"Items": [{"PK": "USER#alice", "SK": "ROTATION#two"}]},
            ]
        )

        result = password_recovery_request.list_user_rotation_items(table, "alice")

        self.assertEqual(len(result), 2)
        self.assertIn("ExclusiveStartKey", table.calls[1])

    @patch("password_recovery_request.password_recovery_request.query_all_items")
    def test_list_rotation_items_by_email_reraises_unexpected_query_errors(
        self, mock_query_all_items
    ):
        mock_query_all_items.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "Query",
        )

        with self.assertRaises(ClientError):
            password_recovery_request.list_rotation_items_by_email(
                FakeTable(), "alice@example.com"
            )

    def test_parse_rotation_time_defaults_to_epoch_for_missing_values(self):
        self.assertEqual(
            password_recovery_request.parse_rotation_time(None),
            password_recovery_request.parse_iso8601("1970-01-01T00:00:00+00:00"),
        )

    def test_reserve_reissue_slot_returns_none_on_conditional_conflict(self):
        table = Mock()
        table.get_item.return_value = {"Item": {"reissue_version": 2}}
        table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}},
            "UpdateItem",
        )

        self.assertIsNone(
            password_recovery_request.reserve_reissue_slot(
                table,
                username="alice",
                email="alice@example.com",
                source_ip="203.0.113.5",
                cooldown_minutes=0,
                max_requests_per_day=5,
            )
        )

    def test_release_reissue_slot_ignores_conditional_conflict(self):
        table = Mock()
        table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}},
            "UpdateItem",
        )

        password_recovery_request.release_reissue_slot(
            table,
            username="alice",
            reservation={
                "last_reissue": None,
                "last_reissue_request_ip": None,
                "recent_reissues": [],
                "reserved_version": 2,
                "current_version": 1,
            },
        )

        table.update_item.assert_called_once()

    def test_release_reissue_slot_reraises_unexpected_errors(self):
        table = Mock()
        table.update_item.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "UpdateItem",
        )

        with self.assertRaises(ClientError):
            password_recovery_request.release_reissue_slot(
                table,
                username="alice",
                reservation={
                    "last_reissue": None,
                    "last_reissue_request_ip": None,
                    "recent_reissues": [],
                    "reserved_version": 2,
                    "current_version": 1,
                },
            )

    def test_credential_object_exists_handles_not_found_and_raises_other_errors(self):
        missing_s3 = FakeS3Client(existing_keys=set())
        password_recovery_request.s3 = missing_s3
        self.assertFalse(
            password_recovery_request.credential_object_exists("bucket", "missing.json")
        )

        erroring_s3 = Mock()
        erroring_s3.head_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "HeadObject",
        )
        password_recovery_request.s3 = erroring_s3
        with self.assertRaises(ClientError):
            password_recovery_request.credential_object_exists("bucket", "blocked.json")

    def test_extract_source_ip_prefers_forwarded_header(self):
        self.assertEqual(
            password_recovery_request.extract_source_ip(
                {
                    "headers": {"x-forwarded-for": "198.51.100.10, 203.0.113.5"},
                    "requestContext": {"http": {"sourceIp": "203.0.113.5"}},
                }
            ),
            "198.51.100.10",
        )
        self.assertEqual(
            password_recovery_request.extract_source_ip(
                {"requestContext": {"http": {"sourceIp": "203.0.113.5"}}}
            ),
            "203.0.113.5",
        )


if __name__ == "__main__":
    unittest.main()
