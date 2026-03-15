"""Shared runtime policy and state helpers for IAM key rotation Lambdas."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

PENDING_DOWNLOAD = "pending_download"
DOWNLOADED = "downloaded"
OLD_KEY_DELETED_PENDING_DOWNLOAD = "old_key_deleted_pending_download"
COMPLETED = "completed"
EXPIRED_NO_DOWNLOAD = "expired_no_download"

ACTIVE_ROTATION_STATUSES = (
    PENDING_DOWNLOAD,
    DOWNLOADED,
    OLD_KEY_DELETED_PENDING_DOWNLOAD,
)
PENDING_REMINDER_STATUSES = (
    PENDING_DOWNLOAD,
    OLD_KEY_DELETED_PENDING_DOWNLOAD,
)

REMINDER_INTERVAL_DAYS = 7
PRESIGNED_URL_TTL_SECONDS = 7 * 24 * 60 * 60
TRACKING_TTL_DAYS = 90
ROTATION_NAMESPACE = "IAM/KeyRotation"


@dataclass(frozen=True)
class RuntimeConfig:
    warning_threshold: int
    urgent_threshold: int
    disable_threshold: int
    auto_disable: bool
    sender_email: str
    support_email: str
    exemption_tag: str
    s3_bucket: str | None
    dynamodb_table: str | None
    new_key_retention_days: int
    old_key_retention_days: int

    @property
    def auto_rotation_enabled(self) -> bool:
        return bool(self.s3_bucket and self.dynamodb_table)


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def isoformat(value: datetime) -> str:
    """Return a stable ISO 8601 UTC string."""
    return value.astimezone(UTC).replace(microsecond=0).isoformat()


def parse_iso8601(value: str) -> datetime:
    """Parse an ISO 8601 string into a timezone-aware UTC datetime."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def rotation_partition_key(username: str) -> str:
    return f"USER#{username}"


def rotation_sort_key(old_key_id: str) -> str:
    return f"ROTATION#{old_key_id}"


def rotation_item_key(username: str, old_key_id: str) -> dict[str, str]:
    return {"PK": rotation_partition_key(username), "SK": rotation_sort_key(old_key_id)}


def credential_s3_key(username: str, old_key_id: str) -> str:
    return f"credentials/{username}/{old_key_id}.json"


def seconds_to_epoch(value: datetime) -> int:
    return int(value.timestamp())


def days_since(rotation_started_at: str, *, now: datetime | None = None) -> int:
    current = now or utc_now()
    return max((current - parse_iso8601(rotation_started_at)).days, 0)


def reminder_day_due(
    rotation_started_at: str, *, now: datetime | None = None
) -> int | None:
    elapsed_days = days_since(rotation_started_at, now=now)
    if elapsed_days <= 0 or elapsed_days % REMINDER_INTERVAL_DAYS != 0:
        return None
    return elapsed_days


def build_rotation_record(
    *,
    username: str,
    email: str,
    old_key_id: str,
    new_key_id: str,
    s3_key: str,
    rotation_started_at: datetime,
    config: RuntimeConfig,
) -> dict[str, Any]:
    old_key_deletion_at = rotation_started_at.timestamp() + (
        config.old_key_retention_days * 86400
    )
    credential_expires_at = rotation_started_at.timestamp() + (
        config.new_key_retention_days * 86400
    )
    return {
        **rotation_item_key(username, old_key_id),
        "username": username,
        "email": email,
        "old_key_id": old_key_id,
        "new_key_id": new_key_id,
        "rotation_initiated": isoformat(rotation_started_at),
        "s3_key": s3_key,
        "downloaded": False,
        "download_timestamp": None,
        "download_ip": None,
        "s3_file_deleted": False,
        "s3_file_deletion_timestamp": None,
        "old_key_deleted": False,
        "old_key_deletion_timestamp": None,
        "old_key_deletion_date": int(old_key_deletion_at),
        "credential_expires_at": int(credential_expires_at),
        "email_sent_count": 1,
        "last_reminder_day": 0,
        "old_key_warning_sent": False,
        "status": PENDING_DOWNLOAD,
        "TTL": int(rotation_started_at.timestamp() + (TRACKING_TTL_DAYS * 86400)),
    }


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def load_runtime_config(*, require_rotation_store: bool = False) -> RuntimeConfig:
    sender_email = require_env("SENDER_EMAIL")
    support_email = os.environ.get("SUPPORT_EMAIL", sender_email)
    config = RuntimeConfig(
        warning_threshold=int(os.environ.get("WARNING_THRESHOLD", "75")),
        urgent_threshold=int(os.environ.get("URGENT_THRESHOLD", "85")),
        disable_threshold=int(os.environ.get("DISABLE_THRESHOLD", "90")),
        auto_disable=os.environ.get("AUTO_DISABLE", "false").lower() == "true",
        sender_email=sender_email,
        support_email=support_email,
        exemption_tag=os.environ.get("EXEMPTION_TAG", "key-rotation-exempt"),
        s3_bucket=os.environ.get("S3_BUCKET"),
        dynamodb_table=os.environ.get("DYNAMODB_TABLE"),
        new_key_retention_days=int(os.environ.get("NEW_KEY_RETENTION_DAYS", "45")),
        old_key_retention_days=int(os.environ.get("OLD_KEY_RETENTION_DAYS", "30")),
    )
    validate_runtime_config(config, require_rotation_store=require_rotation_store)
    return config


def validate_runtime_config(
    config: RuntimeConfig, *, require_rotation_store: bool = False
) -> None:
    if config.warning_threshold <= 0:
        raise RuntimeError("WARNING_THRESHOLD must be greater than 0")
    if config.urgent_threshold < config.warning_threshold:
        raise RuntimeError("URGENT_THRESHOLD must be >= WARNING_THRESHOLD")
    if config.disable_threshold < config.urgent_threshold:
        raise RuntimeError("DISABLE_THRESHOLD must be >= URGENT_THRESHOLD")
    if config.old_key_retention_days <= 0:
        raise RuntimeError("OLD_KEY_RETENTION_DAYS must be greater than 0")
    if config.new_key_retention_days <= config.old_key_retention_days:
        raise RuntimeError(
            "NEW_KEY_RETENTION_DAYS must be greater than OLD_KEY_RETENTION_DAYS"
        )
    if bool(config.s3_bucket) != bool(config.dynamodb_table):
        raise RuntimeError(
            "S3_BUCKET and DYNAMODB_TABLE must both be set together for rotation tracking"
        )
    if require_rotation_store and not config.auto_rotation_enabled:
        raise RuntimeError("S3_BUCKET and DYNAMODB_TABLE are required for this Lambda")
