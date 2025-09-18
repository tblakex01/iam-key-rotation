#!/usr/bin/env python3
"""Tests for the password notification Lambda using moto-backed AWS services."""

import importlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import boto3
import pytest
from moto import mock_aws


@pytest.fixture()
def password_notification_module() -> Iterator[object]:
    """Load the Lambda module with moto-backed boto3 clients."""

    module_path = (
        Path(__file__).resolve().parent.parent / "lambda" / "password_notification"
    )
    sys.path.insert(0, str(module_path))

    with mock_aws():
        os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
        os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

        module = importlib.import_module("password_notification")
        module = importlib.reload(module)

        # Replace the global clients with moto-backed instances for deterministic tests
        module.iam_client = boto3.client("iam", region_name="us-east-1")
        module.ses_client = boto3.client("ses", region_name="us-east-1")
        module.ses_client.verify_email_identity(
            EmailAddress="cloud-admins@jennasrunbooks.com"
        )

        try:
            yield module
        finally:
            sys.path.remove(str(module_path))
            sys.modules.pop("password_notification", None)


def _credential_report_for(users: list[tuple[str, datetime]]):
    """Generate a credential report CSV for the provided users."""

    rows = [
        "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed",
    ]
    for username, changed_at in users:
        rows.append(
            ",".join(
                [
                    username,
                    f"arn:aws:iam::123456789012:user/{username}",
                    "2023-01-01T00:00:00+00:00",
                    "true",
                    "N/A",
                    changed_at.astimezone(timezone.utc).isoformat(),
                ]
            )
        )
    return "\n".join(rows).encode("utf-8")


def test_lambda_sends_notifications_for_expiring_passwords(
    password_notification_module,
):
    """Verify that users beyond the warning threshold receive an email."""

    module = password_notification_module
    iam_client = module.iam_client

    iam_client.create_user(UserName="alice")
    iam_client.tag_user(
        UserName="alice", Tags=[{"Key": "email", "Value": "alice@example.com"}]
    )

    iam_client.create_user(UserName="bob")
    iam_client.tag_user(
        UserName="bob", Tags=[{"Key": "email", "Value": "bob@example.com"}]
    )

    expiring = datetime.now(timezone.utc) - timedelta(days=80)
    recent = datetime.now(timezone.utc) - timedelta(days=5)
    credential_data = _credential_report_for([("alice", expiring), ("bob", recent)])

    # First call during the wait loop and second call when processing
    responses = [{"Content": credential_data}, {"Content": credential_data}]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(module.time, "sleep", lambda *_: None)
        mp.setattr(module.iam_client, "get_credential_report", lambda: responses.pop(0))

        with pytest.MonkeyPatch.context() as nested_mp:
            original_send = module.ses_client.send_email
            send_calls = []

            def _send_email(**kwargs):
                send_calls.append(kwargs)
                return original_send(**kwargs)

            nested_mp.setattr(module.ses_client, "send_email", _send_email)

            result = module.lambda_handler({}, None)

    assert result == "Password expiry notifications sent."
    assert len(send_calls) == 1
    assert send_calls[0]["Destination"]["ToAddresses"] == ["alice@example.com"]


def test_lambda_skips_users_without_emails(password_notification_module):
    """Ensure the Lambda tolerates users without email tags gracefully."""

    module = password_notification_module
    iam_client = module.iam_client

    iam_client.create_user(UserName="no-email-user")

    aged = datetime.now(timezone.utc) - timedelta(days=120)
    credential_data = _credential_report_for([("no-email-user", aged)])
    responses = [{"Content": credential_data}, {"Content": credential_data}]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(module.time, "sleep", lambda *_: None)
        mp.setattr(module.iam_client, "get_credential_report", lambda: responses.pop(0))

        with pytest.MonkeyPatch.context() as nested_mp:
            nested_mp.setattr(
                module.ses_client,
                "send_email",
                lambda **_: pytest.fail("Email should not be sent"),
            )

            result = module.lambda_handler({}, None)

    assert result == "Password expiry notifications sent."
