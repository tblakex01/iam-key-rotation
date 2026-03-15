"""IAM key cleanup Lambda."""

from __future__ import annotations

import json
import logging
from datetime import datetime

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from common.notifications import (
    render_old_key_deleted_email,
    render_old_key_warning_email,
)
from common.rotation_common import (
    COMPLETED,
    DOWNLOADED,
    OLD_KEY_DELETED_PENDING_DOWNLOAD,
    PENDING_DOWNLOAD,
    PRESIGNED_URL_TTL_SECONDS,
    ROTATION_NAMESPACE,
    days_since,
    isoformat,
    load_runtime_config,
    utc_now,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = None
iam = None
ses = None
cloudwatch = None
s3 = None


def get_dynamodb_resource():
    global dynamodb
    if dynamodb is None:
        dynamodb = boto3.resource("dynamodb")
    return dynamodb


def get_iam_client():
    global iam
    if iam is None:
        iam = boto3.client("iam")
    return iam


def get_ses_client():
    global ses
    if ses is None:
        ses = boto3.client("ses")
    return ses


def get_cloudwatch_client():
    global cloudwatch
    if cloudwatch is None:
        cloudwatch = boto3.client("cloudwatch")
    return cloudwatch


def get_s3_client():
    global s3
    if s3 is None:
        s3 = boto3.client("s3")
    return s3


def lambda_handler(event, context):  # noqa: ARG001
    """Handle warning and deletion milestones for rotated keys."""
    config = load_runtime_config(require_rotation_store=True)
    table = get_dynamodb_resource().Table(config.dynamodb_table)
    warnings_sent = 0
    deleted = 0
    skipped = 0
    warning_day = config.old_key_retention_days - 7

    for item in list_cleanup_candidates(table):
        elapsed_days = days_since(item["rotation_initiated"])
        if (
            warning_day > 0
            and elapsed_days >= warning_day
            and not item.get("old_key_warning_sent", False)
        ):
            if send_deletion_warning(table, config, item):
                warnings_sent += 1
                continue
        if elapsed_days >= config.old_key_retention_days:
            if delete_old_key_and_notify(table, config, item):
                deleted += 1
            else:
                skipped += 1
            continue
        skipped += 1

    publish_cleanup_metrics(warnings_sent, deleted)
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Old key cleanup completed",
                "warnings_sent": warnings_sent,
                "deleted": deleted,
                "skipped": skipped,
            }
        ),
    }


def list_cleanup_candidates(table) -> list[dict]:
    items: list[dict] = []
    for status in (PENDING_DOWNLOAD, DOWNLOADED):
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


def send_deletion_warning(table, config, item: dict) -> bool:
    deletion_date = datetime.fromtimestamp(item["old_key_deletion_date"]).strftime(
        "%B %d, %Y"
    )
    subject, html = render_old_key_warning_email(
        username=item["username"],
        old_key_id=item["old_key_id"],
        deletion_date=deletion_date,
        support_email=config.support_email,
    )
    table.update_item(
        Key={"PK": item["PK"], "SK": item["SK"]},
        UpdateExpression=(
            "SET old_key_warning_sent = :true, "
            "old_key_warning_sent_at = :sent_at, "
            "email_sent_count = email_sent_count + :one"
        ),
        ConditionExpression="attribute_not_exists(old_key_warning_sent) OR old_key_warning_sent = :false",
        ExpressionAttributeValues={
            ":true": True,
            ":false": False,
            ":sent_at": isoformat(utc_now()),
            ":one": 1,
        },
    )
    get_ses_client().send_email(
        Source=config.sender_email,
        Destination={"ToAddresses": [item["email"]]},
        Message={"Subject": {"Data": subject}, "Body": {"Html": {"Data": html}}},
    )
    return True


def delete_old_key_and_notify(table, config, item: dict) -> bool:
    """Delete the old key and persist the resulting state."""
    try:
        get_iam_client().delete_access_key(
            UserName=item["username"], AccessKeyId=item["old_key_id"]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            logger.exception("Failed to delete old key %s", item["old_key_id"])
            raise

    downloaded = bool(item.get("downloaded"))
    new_status = COMPLETED if downloaded else OLD_KEY_DELETED_PENDING_DOWNLOAD
    try:
        table.update_item(
            Key={"PK": item["PK"], "SK": item["SK"]},
            UpdateExpression=(
                "SET old_key_deleted = :true, "
                "old_key_deletion_timestamp = :timestamp, "
                "#status = :status"
            ),
            ConditionExpression="attribute_not_exists(old_key_deleted) OR old_key_deleted = :false",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":true": True,
                ":false": False,
                ":timestamp": isoformat(utc_now()),
                ":status": new_status,
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info("Old key %s was already deleted", item["old_key_id"])
            return False
        raise

    presigned_url = None
    url_expires = None
    if not downloaded and credential_object_exists(config.s3_bucket, item["s3_key"]):
        presigned_url = get_s3_client().generate_presigned_url(
            "get_object",
            Params={"Bucket": config.s3_bucket, "Key": item["s3_key"]},
            ExpiresIn=PRESIGNED_URL_TTL_SECONDS,
        )
        url_expires = datetime.fromtimestamp(
            utc_now().timestamp() + PRESIGNED_URL_TTL_SECONDS
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject, html = render_old_key_deleted_email(
        username=item["username"],
        old_key_id=item["old_key_id"],
        downloaded=downloaded,
        support_email=config.support_email,
        presigned_url=presigned_url,
        url_expires=url_expires,
    )
    get_ses_client().send_email(
        Source=config.sender_email,
        Destination={"ToAddresses": [item["email"]]},
        Message={"Subject": {"Data": subject}, "Body": {"Html": {"Data": html}}},
    )
    return True


def credential_object_exists(bucket: str, s3_key: str) -> bool:
    try:
        get_s3_client().head_object(Bucket=bucket, Key=s3_key)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"404", "NoSuchKey", "NotFound"}:
            return False
        raise


def publish_cleanup_metrics(warnings: int, deleted: int) -> None:
    try:
        get_cloudwatch_client().put_metric_data(
            Namespace=ROTATION_NAMESPACE,
            MetricData=[
                {
                    "MetricName": "deletion_warnings_sent",
                    "Value": warnings,
                    "Unit": "Count",
                    "Timestamp": utc_now(),
                },
                {
                    "MetricName": "old_keys_deleted",
                    "Value": deleted,
                    "Unit": "Count",
                    "Timestamp": utc_now(),
                },
            ],
        )
    except ClientError:
        logger.exception("Failed to publish cleanup metrics")
