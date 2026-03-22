"""Shared SES email helpers and runtime configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Sequence

import boto3
from botocore.exceptions import BotoCoreError, ClientError

__all__ = [
    "EmailConfig",
    "send_html_email",
]

_ses_client = None


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class EmailConfig:
    sender_email: str
    support_email: str
    ses_region: str | None
    ses_configuration_set: str | None

    @classmethod
    def load(cls) -> "EmailConfig":
        sender_email = require_env("SENDER_EMAIL")
        support_email = os.environ.get("SUPPORT_EMAIL", sender_email)
        return cls(
            sender_email=sender_email,
            support_email=support_email,
            ses_region=os.environ.get("SES_REGION"),
            ses_configuration_set=os.environ.get("SES_CONFIGURATION_SET") or None,
        )


def get_sesv2_client(config: EmailConfig):
    global _ses_client
    if _ses_client is None:
        _ses_client = boto3.client("sesv2", region_name=config.ses_region)
    return _ses_client


def send_html_email(
    *,
    config: EmailConfig,
    to_addresses: Sequence[str],
    subject: str,
    html_body: str,
    text_body: str | None = None,
    reply_to: Sequence[str] | None = None,
) -> dict:
    """Send an HTML email through SESv2."""

    if not to_addresses:
        raise ValueError("to_addresses must include at least one recipient")

    content: dict = {"Simple": {"Subject": {"Data": subject}, "Body": {}}}
    content["Simple"]["Body"]["Html"] = {"Data": html_body}
    if text_body:
        content["Simple"]["Body"]["Text"] = {"Data": text_body}

    destination: dict[str, list[str]] = {"ToAddresses": list(to_addresses)}

    kwargs: dict[str, object] = {
        "FromEmailAddress": config.sender_email,
        "Destination": destination,
        "Content": content,
        "ReplyToAddresses": list(reply_to or (config.support_email,)),
    }
    if config.ses_configuration_set:
        kwargs["ConfigurationSetName"] = config.ses_configuration_set

    try:
        return get_sesv2_client(config).send_email(**kwargs)
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError("failed to send SES email") from exc
