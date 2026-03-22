#!/usr/bin/env python3
"""Unit tests for shared key-rotation helpers."""

import os
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from common.rotation_common import (  # noqa: E402
    PENDING_DOWNLOAD,
    build_rotation_record,
    credential_s3_key,
    load_runtime_config,
    normalize_email,
    recovery_state_key,
    reminder_day_due,
    rotation_item_key,
    utc_now,
    validate_runtime_config,
)


class TestRotationCommon(unittest.TestCase):
    def test_rotation_item_key_and_s3_key(self):
        self.assertEqual(
            rotation_item_key("alice", "OLDKEY"),
            {"PK": "USER#alice", "SK": "ROTATION#OLDKEY"},
        )
        self.assertEqual(
            credential_s3_key("alice", "OLDKEY"), "credentials/alice/OLDKEY.json"
        )
        self.assertEqual(
            recovery_state_key("alice"),
            {"PK": "USER#alice", "SK": "RECOVERY#STATE"},
        )
        self.assertEqual(normalize_email(" Alice@Example.COM "), "alice@example.com")

    def test_reminder_day_due_on_exact_interval(self):
        started = (utc_now() - timedelta(days=14)).isoformat()
        self.assertEqual(reminder_day_due(started), 14)

    def test_build_rotation_record_sets_canonical_defaults(self):
        config = load_runtime_config_from_env()
        record = build_rotation_record(
            username="alice",
            email="alice@example.com",
            old_key_id="OLDKEY",
            new_key_id="NEWKEY",
            s3_key="credentials/alice/OLDKEY.json",
            rotation_started_at=utc_now(),
            config=config,
        )
        self.assertEqual(record["status"], PENDING_DOWNLOAD)
        self.assertFalse(record["downloaded"])
        self.assertFalse(record["old_key_deleted"])
        self.assertEqual(record["email_lookup"], "alice@example.com")

    def test_validate_runtime_config_rejects_partial_store_config(self):
        config = load_runtime_config_from_env()
        broken = config.__class__(
            **{**config.__dict__, "s3_bucket": "bucket", "dynamodb_table": None}
        )
        with self.assertRaises(RuntimeError):
            validate_runtime_config(broken)


def load_runtime_config_from_env():
    env = {
        "SENDER_EMAIL": "security@example.com",
        "S3_BUCKET": "rotation-bucket",
        "DYNAMODB_TABLE": "rotation-table",
        "NEW_KEY_RETENTION_DAYS": "45",
        "OLD_KEY_RETENTION_DAYS": "30",
    }
    previous = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        return load_runtime_config(require_rotation_store=True)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
