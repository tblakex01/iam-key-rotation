#!/usr/bin/env python3
"""End-to-end style CLI tests executed against moto-backed AWS services."""

import io
import json
import os
import runpy
import sys
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws


def _scripts_path(script_name: str) -> Path:
    return Path(__file__).resolve().parents[2] / "scripts" / script_name


@pytest.mark.integration
def test_key_rotation_list_json_cli():
    """Invoke the key rotation CLI and validate the JSON payload it prints."""

    script = _scripts_path("aws_iam_self_service_key_rotation.py")

    class _FakeIAM:
        def list_access_keys(self):
            return {
                "AccessKeyMetadata": [
                    {
                        "AccessKeyId": "AKIAFAKE1234567890",
                        "Status": "Active",
                        "CreateDate": datetime.now(timezone.utc),
                    }
                ]
            }

    stdout = io.StringIO()
    argv = [script.name, "--list", "--json"]

    with patch.object(sys, "argv", argv):
        with patch("boto3.client", return_value=_FakeIAM()):
            with redirect_stdout(stdout):
                runpy.run_path(script, run_name="__main__")

    payload = json.loads(stdout.getvalue())
    assert payload["AccessKeys"][0]["AccessKeyId"] == "AKIAFAKE1234567890"


@pytest.mark.integration
def test_password_reset_list_users_cli():
    """Ensure the password reset CLI lists users without raising errors."""

    script = _scripts_path("aws_iam_user_password_reset.py")

    with mock_aws():
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
        os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
        os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="cli-user-one")
        iam.create_user(UserName="cli-user-two")

        stdout = io.StringIO()
        argv = [script.name, "list-users"]

        with patch.object(sys, "argv", argv):
            with redirect_stdout(stdout):
                runpy.run_path(script, run_name="__main__")

    output = stdout.getvalue().splitlines()
    assert "Found 2 IAM users:" in output[0]
    assert any(line.strip().endswith("cli-user-one") for line in output)
    assert any(line.strip().endswith("cli-user-two") for line in output)
