"""IAM credential download tracker Lambda."""

from __future__ import annotations

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from common.rotation_common import DOWNLOADED, isoformat, utc_now

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = None
dynamodb = None


def get_s3_client():
    global s3
    if s3 is None:
        s3 = boto3.client("s3")
    return s3


def get_dynamodb_resource():
    global dynamodb
    if dynamodb is None:
        dynamodb = boto3.resource("dynamodb")
    return dynamodb


def get_table():
    return get_dynamodb_resource().Table(os.environ["DYNAMODB_TABLE"])


def lambda_handler(event, context):  # noqa: ARG001
    """Handle a CloudTrail GetObject event for credential downloads."""
    s3_key = extract_s3_key(event)
    bucket = extract_bucket(event)
    event_time = event.get("detail", {}).get("eventTime") or isoformat(utc_now())
    ip_address = event.get("detail", {}).get("sourceIPAddress", "unknown")

    if not s3_key or not bucket:
        return {
            "statusCode": 200,
            "body": json.dumps(
                {"message": "Event does not contain a credential download"}
            ),
        }

    if not s3_key.startswith("credentials/"):
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Skipping non-credential object"}),
        }

    delete_s3_file(bucket, s3_key)
    updated = update_tracking_record(s3_key, event_time, ip_address)
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Download tracking completed",
                "s3_key": s3_key,
                "updated": updated,
            }
        ),
    }


def extract_bucket(event: dict) -> str | None:
    return event.get("detail", {}).get("requestParameters", {}).get("bucketName")


def extract_s3_key(event: dict) -> str | None:
    return event.get("detail", {}).get("requestParameters", {}).get("key")


def find_tracking_record_by_s3_key(s3_key: str) -> dict | None:
    response = get_table().query(
        IndexName="s3-key-index",
        KeyConditionExpression="s3_key = :s3_key",
        ExpressionAttributeValues={":s3_key": s3_key},
        Limit=1,
    )
    items = response.get("Items", [])
    return items[0] if items else None


def update_tracking_record(s3_key: str, download_time: str, ip_address: str) -> bool:
    """Mark the exact rotation record for ``s3_key`` as downloaded."""
    item = find_tracking_record_by_s3_key(s3_key)
    if not item:
        logger.warning("No tracking record found for %s", s3_key)
        return False

    try:
        get_table().update_item(
            Key={"PK": item["PK"], "SK": item["SK"]},
            UpdateExpression=(
                "SET downloaded = :true, "
                "download_timestamp = :ts, "
                "download_ip = :ip, "
                "s3_file_deleted = :true, "
                "s3_file_deletion_timestamp = :deleted_at, "
                "#status = :status"
            ),
            ConditionExpression="attribute_not_exists(downloaded) OR downloaded = :false",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":true": True,
                ":false": False,
                ":ts": download_time,
                ":ip": ip_address,
                ":deleted_at": isoformat(utc_now()),
                ":status": DOWNLOADED,
            },
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info("Download for %s was already recorded", s3_key)
            return False
        logger.exception("Failed to update tracking record for %s", s3_key)
        raise


def delete_s3_file(bucket: str, s3_key: str) -> None:
    """Delete the credential file before recording state so retries stay safe."""
    try:
        get_s3_client().delete_object(Bucket=bucket, Key=s3_key)
    except ClientError:
        logger.exception("Failed to delete S3 object %s", s3_key)
        raise
