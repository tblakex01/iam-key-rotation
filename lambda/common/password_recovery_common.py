"""Shared configuration and time helpers for access-key recovery requests."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

__all__ = [
    "AccessKeyRecoveryConfig",
    "load_access_key_recovery_config",
    "utc_now",
    "isoformat",
    "parse_iso8601",
]


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class AccessKeyRecoveryConfig:
    sender_email: str
    support_email: str
    ses_region: str | None
    ses_configuration_set: str | None
    dynamodb_table: str
    s3_bucket: str
    recovery_request_cooldown_minutes: int
    recovery_max_requests_per_day: int

    @classmethod
    def load(cls) -> "AccessKeyRecoveryConfig":
        config = cls(
            sender_email=require_env("SENDER_EMAIL"),
            support_email=os.environ.get("SUPPORT_EMAIL", require_env("SENDER_EMAIL")),
            ses_region=os.environ.get("SES_REGION"),
            ses_configuration_set=os.environ.get("SES_CONFIGURATION_SET") or None,
            dynamodb_table=require_env("DYNAMODB_TABLE"),
            s3_bucket=require_env("S3_BUCKET"),
            recovery_request_cooldown_minutes=int(
                os.environ.get("ACCESS_KEY_RECOVERY_REQUEST_COOLDOWN_MINUTES", "15")
            ),
            recovery_max_requests_per_day=int(
                os.environ.get("ACCESS_KEY_RECOVERY_MAX_REQUESTS_PER_DAY", "5")
            ),
        )
        validate_access_key_recovery_config(config)
        return config

    def to_email_config(self):
        from common.email import EmailConfig

        return EmailConfig(
            sender_email=self.sender_email,
            support_email=self.support_email,
            ses_region=self.ses_region,
            ses_configuration_set=self.ses_configuration_set,
        )


def load_access_key_recovery_config() -> AccessKeyRecoveryConfig:
    return AccessKeyRecoveryConfig.load()


def validate_access_key_recovery_config(config: AccessKeyRecoveryConfig) -> None:
    if config.recovery_request_cooldown_minutes < 0:
        raise RuntimeError(
            "ACCESS_KEY_RECOVERY_REQUEST_COOLDOWN_MINUTES must be greater than or equal to 0"
        )
    if config.recovery_max_requests_per_day < 0:
        raise RuntimeError(
            "ACCESS_KEY_RECOVERY_MAX_REQUESTS_PER_DAY must be greater than or equal to 0"
        )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso8601(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
