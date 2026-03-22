"""AWS IAM Access Key Enforcement Lambda."""

from __future__ import annotations

import os
import csv
import io
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from common.email import EmailConfig, send_html_email
from common.notifications import render_enforcement_email
from common.rotation_common import (
    ACTIVE_ROTATION_STATUSES,
    PRESIGNED_URL_TTL_SECONDS,
    ROTATION_NAMESPACE,
    build_rotation_record,
    credential_s3_key,
    isoformat,
    load_runtime_config,
    parse_iso8601,
    rotation_item_key,
    utc_now,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam_client = None
cloudwatch = None
s3_client = None
dynamodb = None


def get_runtime_config() -> dict[str, Any]:
    """Return validated runtime configuration as a plain dict for compatibility."""
    return load_runtime_config().__dict__.copy()


def get_iam_client():
    global iam_client
    if iam_client is None:
        iam_client = boto3.client("iam")
    return iam_client


def get_cloudwatch_client():
    global cloudwatch
    if cloudwatch is None:
        cloudwatch = boto3.client("cloudwatch")
    return cloudwatch


def get_s3_client():
    global s3_client
    if s3_client is None:
        s3_client = boto3.client("s3")
    return s3_client


def get_dynamodb_resource():
    global dynamodb
    if dynamodb is None:
        dynamodb = boto3.resource("dynamodb")
    return dynamodb


def build_notification(
    username: str,
    email: str,
    key_id: str,
    age: int,
    action: str,
    severity: str,
    key_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    notification = {
        "username": username,
        "email": email,
        "old_key_id": key_id,
        "key_id": key_id,
        "age": age,
        "action": action,
        "severity": severity,
    }
    if key_data:
        notification.update(key_data)
    return notification


def can_auto_rotate() -> bool:
    return load_runtime_config().auto_rotation_enabled


def lambda_handler(event, context):  # noqa: ARG001
    """Main Lambda handler."""
    logger.info("Starting IAM access key enforcement run")
    config = load_runtime_config()
    iam = get_iam_client()

    try:
        credential_report = generate_credential_report(iam)
    except ClientError:
        logger.exception("Failed to generate credential report")
        raise

    metrics = {
        "total_keys": 0,
        "warning_keys": 0,
        "urgent_keys": 0,
        "disabled_keys": 0,
        "expired_keys": 0,
    }
    notifications: list[dict[str, Any]] = []

    csv_reader = csv.reader(io.StringIO(credential_report))
    next(csv_reader, None)

    for fields in csv_reader:
        if not fields:
            continue
        username = fields[0]
        if is_user_exempt(username):
            logger.info("Skipping exempt user %s", username)
            continue
        evaluate_report_slot(username, fields, 8, 9, notifications, metrics, config)
        evaluate_report_slot(username, fields, 13, 14, notifications, metrics, config)

    for notification in notifications:
        send_notification(notification)

    publish_metrics(metrics)
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Access key enforcement completed",
                "metrics": metrics,
                "notifications_sent": len(notifications),
            }
        ),
    }


def generate_credential_report(iam) -> str:
    """Generate and return the credential report CSV."""
    iam.generate_credential_report()
    timeout_seconds = int(os.environ.get("CREDENTIAL_REPORT_TIMEOUT", "60"))
    max_attempts = max(timeout_seconds // 2, 1)

    for _ in range(max_attempts + 1):
        time.sleep(0.1)
        response = iam.get_credential_report()
        if "Content" in response:
            return response["Content"].decode("utf-8")

    raise RuntimeError(
        f"Credential report generation timed out after {timeout_seconds} seconds"
    )


def evaluate_report_slot(
    username: str,
    fields: list[str],
    active_index: int,
    rotated_index: int,
    notifications: list[dict[str, Any]],
    metrics: dict[str, int],
    config,
) -> None:
    """Process a single access-key slot from the credential report."""
    if fields[active_index] != "true":
        return
    last_rotated = fields[rotated_index]
    if last_rotated in {"N/A", "not_supported"}:
        return
    key_index = 0 if active_index == 8 else 1
    key_id = get_access_key_id(username, key_index)
    process_key(username, key_id, last_rotated, notifications, metrics, config)


def is_user_exempt(username: str) -> bool:
    exemption_tag = os.environ.get("EXEMPTION_TAG", "key-rotation-exempt")
    try:
        response = get_iam_client().list_user_tags(UserName=username)
    except ClientError:
        logger.exception("Unable to read user tags for %s", username)
        return False
    return any(
        tag["Key"] == exemption_tag and tag["Value"].lower() == "true"
        for tag in response.get("Tags", [])
    )


def get_access_key_id(username: str, key_index: int) -> str | None:
    try:
        response = get_iam_client().list_access_keys(UserName=username)
    except ClientError:
        logger.exception("Unable to list access keys for %s", username)
        return None
    keys = sorted(
        response.get("AccessKeyMetadata", []),
        key=lambda entry: entry.get("CreateDate", datetime.now(UTC)),
    )
    if key_index < len(keys):
        return keys[key_index]["AccessKeyId"]
    return None


def process_key(
    username: str,
    key_id: str | None,
    last_rotated: str,
    notifications: list[dict[str, Any]],
    metrics: dict[str, int],
    config=None,
) -> None:
    """Process a single access key against the configured thresholds."""
    if not key_id:
        return
    runtime_config = config or load_runtime_config()
    metrics["total_keys"] += 1
    key_age = (utc_now() - parse_iso8601(last_rotated)).days
    email = get_user_email(username)
    if not email:
        logger.warning("Skipping %s because no email tag was found", username)
        return

    if key_age >= runtime_config.disable_threshold:
        metrics["expired_keys"] += 1
        action, severity = "expired", "critical"
    elif key_age >= runtime_config.urgent_threshold:
        metrics["urgent_keys"] += 1
        action, severity = "urgent", "high"
    elif key_age >= runtime_config.warning_threshold:
        metrics["warning_keys"] += 1
        action, severity = "warning", "medium"
    else:
        return

    if runtime_config.auto_rotation_enabled:
        new_key_data = create_and_store_new_key(username, key_id, email, runtime_config)
        if new_key_data:
            notifications.append(
                build_notification(
                    username,
                    email,
                    key_id,
                    key_age,
                    "rotated",
                    severity,
                    new_key_data,
                )
            )
        return

    if action == "expired" and runtime_config.auto_disable:
        disable_key(username, key_id)
        metrics["disabled_keys"] += 1
        action = "disabled"
    notifications.append(
        build_notification(username, email, key_id, key_age, action, severity)
    )


def get_user_email(username: str) -> str | None:
    try:
        response = get_iam_client().list_user_tags(UserName=username)
    except ClientError:
        logger.exception("Unable to load email tag for %s", username)
        return None
    for tag in response.get("Tags", []):
        if tag["Key"] == "email":
            return tag["Value"]
    return None


def create_and_store_new_key(username: str, old_key_id: str, email: str, config=None):
    """Create an idempotent rotation record and return notification data."""
    runtime_config = config or load_runtime_config(require_rotation_store=True)
    table = get_dynamodb_resource().Table(runtime_config.dynamodb_table)
    existing = table.get_item(Key=rotation_item_key(username, old_key_id)).get("Item")
    if existing and existing.get("status") in ACTIVE_ROTATION_STATUSES:
        logger.info("Skipping duplicate rotation for %s/%s", username, old_key_id)
        return None

    iam = get_iam_client()
    s3 = get_s3_client()
    created_key_id = None
    s3_key = credential_s3_key(username, old_key_id)

    try:
        response = iam.create_access_key(UserName=username)
        new_key = response["AccessKey"]
        created_key_id = new_key["AccessKeyId"]
        rotation_started_at = utc_now()
        old_key_deletion_date = int(
            rotation_started_at.timestamp()
            + (runtime_config.old_key_retention_days * 86400)
        )
        credentials = {
            "AccessKeyId": created_key_id,
            "SecretAccessKey": new_key["SecretAccessKey"],
            "Username": username,
            "CreatedAt": isoformat(rotation_started_at),
            "OldKeyId": old_key_id,
        }
        s3.put_object(
            Bucket=runtime_config.s3_bucket,
            Key=s3_key,
            Body=json.dumps(credentials, indent=2).encode("utf-8"),
            ServerSideEncryption="AES256",
            ContentType="application/json",
        )

        record = build_rotation_record(
            username=username,
            email=email,
            old_key_id=old_key_id,
            new_key_id=created_key_id,
            s3_key=s3_key,
            rotation_started_at=rotation_started_at,
            config=runtime_config,
        )
        table.put_item(
            Item=record,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )

        url_expires_at = int(
            rotation_started_at.timestamp() + PRESIGNED_URL_TTL_SECONDS
        )
        return {
            "download_url": s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": runtime_config.s3_bucket, "Key": s3_key},
                ExpiresIn=PRESIGNED_URL_TTL_SECONDS,
            ),
            "url_expires": datetime.fromtimestamp(url_expires_at, tz=UTC).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            "new_key_id": created_key_id,
            "old_key_deletion_date": old_key_deletion_date,
        }
    except ClientError as exc:
        cleanup_failed_rotation(
            username, created_key_id, runtime_config.s3_bucket, s3_key
        )
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info(
                "Another invocation already created the rotation for %s/%s",
                username,
                old_key_id,
            )
            return None
        logger.exception("Failed to create rotation for %s", username)
        return None


def cleanup_failed_rotation(
    username: str, created_key_id: str | None, bucket: str | None, s3_key: str
) -> None:
    """Delete partially created artifacts after a failed rotation attempt."""
    if created_key_id:
        try:
            get_iam_client().delete_access_key(
                UserName=username, AccessKeyId=created_key_id
            )
        except ClientError:
            logger.exception(
                "Failed to roll back new access key %s for %s", created_key_id, username
            )
    if bucket:
        try:
            get_s3_client().delete_object(Bucket=bucket, Key=s3_key)
        except ClientError:
            logger.exception("Failed to roll back S3 object %s", s3_key)


def send_notification(notification: dict[str, Any]) -> None:
    """Send an SES notification for an enforcement event."""
    config = load_runtime_config()
    subject, html_body = render_enforcement_email(notification, config)
    try:
        send_html_email(
            config=EmailConfig.load(),
            to_addresses=[notification["email"]],
            subject=subject,
            html_body=html_body,
        )
    except RuntimeError:
        logger.exception("Failed to send notification to %s", notification["email"])


def disable_key(username: str, key_id: str) -> None:
    try:
        get_iam_client().update_access_key(
            UserName=username, AccessKeyId=key_id, Status="Inactive"
        )
    except ClientError:
        logger.exception("Failed to disable key %s for %s", key_id, username)


def publish_metrics(metrics: dict[str, int]) -> None:
    try:
        cw = get_cloudwatch_client()
        for metric_name, value in metrics.items():
            cw.put_metric_data(
                Namespace=ROTATION_NAMESPACE,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Value": value,
                        "Unit": "Count",
                        "Timestamp": utc_now(),
                    }
                ],
            )
    except ClientError:
        logger.exception("Failed to publish CloudWatch metrics")
