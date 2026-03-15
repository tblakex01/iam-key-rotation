"""IAM credential S3 cleanup Lambda."""

from __future__ import annotations

import json
import logging

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from common.notifications import render_credentials_expired_email
from common.rotation_common import (
    EXPIRED_NO_DOWNLOAD,
    OLD_KEY_DELETED_PENDING_DOWNLOAD,
    PENDING_DOWNLOAD,
    ROTATION_NAMESPACE,
    days_since,
    isoformat,
    load_runtime_config,
    utc_now,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = None
s3 = None
ses = None
cloudwatch = None


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


def lambda_handler(event, context):  # noqa: ARG001
    """Delete expired credential objects and send final notices."""
    config = load_runtime_config(require_rotation_store=True)
    table = get_dynamodb_resource().Table(config.dynamodb_table)
    expired = 0
    skipped = 0

    for item in list_expiration_candidates(table):
        if days_since(item["rotation_initiated"]) < config.new_key_retention_days:
            skipped += 1
            continue
        if expire_credentials(table, config, item):
            expired += 1
        else:
            skipped += 1

    publish_s3_cleanup_metrics(expired)
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "S3 cleanup completed",
                "expired": expired,
                "skipped": skipped,
            }
        ),
    }


def list_expiration_candidates(table) -> list[dict]:
    items: list[dict] = []
    for status in (PENDING_DOWNLOAD, OLD_KEY_DELETED_PENDING_DOWNLOAD):
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


def expire_credentials(table, config, item: dict) -> bool:
    """Delete the credential object and mark the record as expired."""
    delete_s3_file(config.s3_bucket, item["s3_key"])
    try:
        table.update_item(
            Key={"PK": item["PK"], "SK": item["SK"]},
            UpdateExpression=(
                "SET s3_file_deleted = :true, "
                "s3_file_deletion_timestamp = :timestamp, "
                "#status = :status"
            ),
            ConditionExpression="#status <> :expired_status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":true": True,
                ":timestamp": isoformat(utc_now()),
                ":status": EXPIRED_NO_DOWNLOAD,
                ":expired_status": EXPIRED_NO_DOWNLOAD,
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info("Credentials for %s already expired", item["PK"])
            return False
        raise

    subject, html = render_credentials_expired_email(
        username=item["username"],
        old_key_id=item["old_key_id"],
        support_email=config.support_email,
    )
    get_ses_client().send_email(
        Source=config.sender_email,
        Destination={"ToAddresses": [item["email"]]},
        Message={"Subject": {"Data": subject}, "Body": {"Html": {"Data": html}}},
    )
    return True


def delete_s3_file(bucket: str, s3_key: str) -> None:
    try:
        get_s3_client().delete_object(Bucket=bucket, Key=s3_key)
    except ClientError:
        logger.exception("Failed to delete expired credential object %s", s3_key)
        raise


def publish_s3_cleanup_metrics(expired: int) -> None:
    try:
        get_cloudwatch_client().put_metric_data(
            Namespace=ROTATION_NAMESPACE,
            MetricData=[
                {
                    "MetricName": "credentials_expired",
                    "Value": expired,
                    "Unit": "Count",
                    "Timestamp": utc_now(),
                }
            ],
        )
    except ClientError:
        logger.exception("Failed to publish S3 cleanup metrics")
