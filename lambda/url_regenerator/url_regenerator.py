"""IAM key URL reminder Lambda."""

from __future__ import annotations

import json
import logging
from datetime import timedelta

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from common.email import EmailConfig, send_html_email
from common.notifications import render_reminder_email
from common.rotation_common import (
    OLD_KEY_DELETED_PENDING_DOWNLOAD,
    PENDING_REMINDER_STATUSES,
    PRESIGNED_URL_TTL_SECONDS,
    isoformat,
    load_runtime_config,
    reminder_day_due,
    utc_now,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = None
s3 = None


def get_dynamodb_resource():
    global dynamodb
    if dynamodb is None:
        dynamodb = boto3.resource("dynamodb")
    return dynamodb


def get_s3_client():
    global s3
    if s3 is None:
        s3 = boto3.client("s3")
    return s3


def lambda_handler(event, context):  # noqa: ARG001
    """Send reminder emails for credentials still pending download."""
    config = load_runtime_config(require_rotation_store=True)
    table = get_dynamodb_resource().Table(config.dynamodb_table)
    reminded = 0
    checked = 0
    skipped = 0

    for item in list_pending_reminder_items(table):
        checked += 1
        reminder_day = reminder_day_due(item["rotation_initiated"])
        if (
            reminder_day is None
            or reminder_day >= config.new_key_retention_days
            or int(item.get("last_reminder_day", 0)) >= reminder_day
        ):
            skipped += 1
            continue
        if not credential_object_exists(config.s3_bucket, item["s3_key"]):
            logger.warning("Skipping reminder for missing object %s", item["s3_key"])
            skipped += 1
            continue
        if regenerate_url_and_notify(table, config, item, reminder_day):
            reminded += 1
        else:
            skipped += 1

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "URL regeneration completed",
                "checked": checked,
                "reminded": reminded,
                "skipped": skipped,
            }
        ),
    }


def list_pending_reminder_items(table) -> list[dict]:
    """Query all active reminder-eligible statuses."""
    items: list[dict] = []
    for status in PENDING_REMINDER_STATUSES:
        query_args = {
            "IndexName": "status-index",
            "KeyConditionExpression": Key("status").eq(status),
        }
        while True:
            response = table.query(**query_args)
            items.extend(response.get("Items", []))
            if "LastEvaluatedKey" not in response:
                break
            query_args["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    return items


def credential_object_exists(bucket: str, s3_key: str) -> bool:
    try:
        get_s3_client().head_object(Bucket=bucket, Key=s3_key)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"404", "NoSuchKey", "NotFound"}:
            return False
        logger.exception("Failed to verify S3 object %s", s3_key)
        raise


def regenerate_url_and_notify(table, config, item: dict, reminder_day: int) -> bool:
    """Generate a fresh URL, persist reminder state, and send an email."""
    try:
        presigned_url = get_s3_client().generate_presigned_url(
            "get_object",
            Params={"Bucket": config.s3_bucket, "Key": item["s3_key"]},
            ExpiresIn=PRESIGNED_URL_TTL_SECONDS,
        )
        url_expires = isoformat(
            utc_now() + timedelta(seconds=PRESIGNED_URL_TTL_SECONDS)
        ).replace("+00:00", "Z")
        table.update_item(
            Key={"PK": item["PK"], "SK": item["SK"]},
            UpdateExpression=(
                "SET last_reminder_day = :day, "
                "email_sent_count = email_sent_count + :one"
            ),
            ConditionExpression="attribute_not_exists(last_reminder_day) OR last_reminder_day < :day",
            ExpressionAttributeValues={":day": reminder_day, ":one": 1},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info(
                "Reminder day %s already recorded for %s", reminder_day, item["PK"]
            )
            return False
        logger.exception("Failed to update reminder state for %s", item["PK"])
        raise

    subject, html = render_reminder_email(
        username=item["username"],
        old_key_id=item["old_key_id"],
        presigned_url=presigned_url,
        url_expires=url_expires,
        old_key_deleted=item["status"] == OLD_KEY_DELETED_PENDING_DOWNLOAD,
        support_email=config.support_email,
        reminder_day=reminder_day,
    )
    send_html_email(
        config=EmailConfig.load(),
        to_addresses=[item["email"]],
        subject=subject,
        html_body=html,
    )
    return True
