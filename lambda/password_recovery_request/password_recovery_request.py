"""Anonymous access-key recovery request Lambda."""

from __future__ import annotations

import base64
import json
import logging
from datetime import timedelta
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from common.email import send_html_email
from common.notifications import render_self_service_reissue_email
from common.password_recovery_common import (
    isoformat,
    load_access_key_recovery_config,
    parse_iso8601,
    utc_now,
)
from common.rotation_common import (
    EMAIL_LOOKUP_INDEX_NAME,
    OLD_KEY_DELETED_PENDING_DOWNLOAD,
    PENDING_DOWNLOAD,
    PRESIGNED_URL_TTL_SECONDS,
    ROTATION_SORT_KEY_PREFIX,
    normalize_email,
    recovery_state_key,
    rotation_partition_key,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = None
dynamodb = None
s3 = None

RECOVERABLE_STATUSES = {PENDING_DOWNLOAD, OLD_KEY_DELETED_PENDING_DOWNLOAD}
GENERIC_RESPONSE = {
    "statusCode": 202,
    "headers": {"Content-Type": "application/json"},
    "body": json.dumps(
        {"message": "If eligible, a fresh credential download email will be sent."}
    ),
}


def get_iam_client():
    global iam
    if iam is None:
        iam = boto3.client("iam")
    return iam


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
    """Send a fresh download link for an eligible undownloaded rotated credential."""
    config = load_access_key_recovery_config()
    payload = parse_request_payload(event)
    if payload is None:
        return GENERIC_RESPONSE

    identifier = validate_identifier_payload(payload)
    if identifier is None:
        return GENERIC_RESPONSE

    table = get_dynamodb_resource().Table(config.dynamodb_table)
    resolved = resolve_target_user(table, identifier)
    if resolved is None:
        return GENERIC_RESPONSE

    username = resolved["username"]
    email = resolved["email"]

    items = list_user_rotation_items(table, username)
    rotation_item = find_latest_recoverable_rotation(items)
    if rotation_item is None:
        logger.info("No recoverable rotation found for %s", username)
        return GENERIC_RESPONSE

    if not credential_object_exists(config.s3_bucket, rotation_item["s3_key"]):
        logger.info(
            "Credential object missing for recovery request %s/%s",
            username,
            rotation_item["s3_key"],
        )
        return GENERIC_RESPONSE

    presigned_url = get_s3_client().generate_presigned_url(
        "get_object",
        Params={"Bucket": config.s3_bucket, "Key": rotation_item["s3_key"]},
        ExpiresIn=PRESIGNED_URL_TTL_SECONDS,
    )
    url_expires = isoformat(
        utc_now() + timedelta(seconds=PRESIGNED_URL_TTL_SECONDS)
    ).replace("+00:00", "Z")
    subject, html = render_self_service_reissue_email(
        username=username,
        old_key_id=rotation_item["old_key_id"],
        presigned_url=presigned_url,
        url_expires=url_expires,
        old_key_deleted=rotation_item["status"] == OLD_KEY_DELETED_PENDING_DOWNLOAD,
        support_email=config.support_email,
    )

    reservation = reserve_reissue_slot(
        table,
        username=username,
        email=email,
        source_ip=extract_source_ip(event),
        cooldown_minutes=config.recovery_request_cooldown_minutes,
        max_requests_per_day=config.recovery_max_requests_per_day,
    )
    if reservation is None:
        logger.info("Access-key recovery throttled for %s", username)
        return GENERIC_RESPONSE

    try:
        send_html_email(
            config=config.to_email_config(),
            to_addresses=[email],
            subject=subject,
            html_body=html,
            reply_to=[config.support_email],
        )
    except RuntimeError:
        release_reissue_slot(table, username=username, reservation=reservation)
        logger.exception("Failed to send access-key recovery email for %s", username)
        return GENERIC_RESPONSE

    record_successful_reissue(
        table,
        item=rotation_item,
        email=email,
        source_ip=extract_source_ip(event),
    )
    return GENERIC_RESPONSE


def parse_request_payload(event: dict[str, Any]) -> dict[str, Any] | None:
    body = event.get("body")
    if body is None:
        return None
    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            logger.info("Failed to decode base64 request body")
            return None
    if isinstance(body, dict):
        return body
    try:
        loaded = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        logger.info("Invalid JSON request body")
        return None
    return loaded if isinstance(loaded, dict) else None


def validate_identifier_payload(payload: dict[str, Any]) -> dict[str, str] | None:
    raw_username = payload.get("username")
    raw_email = payload.get("email")
    username = raw_username.strip() if isinstance(raw_username, str) else ""
    email = normalize_email(raw_email) if isinstance(raw_email, str) else ""

    if bool(username) == bool(email):
        return None
    if username:
        return {"username": username}
    if "@" not in email or len(email) > 254:
        return None
    return {"email": email}


def resolve_target_user(table, identifier: dict[str, str]) -> dict[str, str] | None:
    if "username" in identifier:
        return resolve_user_by_username(identifier["username"])
    return resolve_user_by_email(table, identifier["email"])


def resolve_user_by_username(username: str) -> dict[str, str] | None:
    try:
        response = get_iam_client().get_user(UserName=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return None
        raise

    email = get_user_email(username)
    if not email:
        logger.warning("Access-key recovery skipped for %s without email tag", username)
        return None
    return {"username": response["User"]["UserName"], "email": email}


def resolve_user_by_email(table, email: str) -> dict[str, str] | None:
    recoverable_items = [
        item
        for item in list_rotation_items_by_email(table, email)
        if item.get("status") in RECOVERABLE_STATUSES and item.get("s3_key")
    ]
    usernames = {
        item.get("username")
        for item in recoverable_items
        if isinstance(item.get("username"), str) and item["username"]
    }
    if len(usernames) != 1:
        if len(usernames) > 1:
            logger.warning("Multiple tracked IAM users share recovery email %s", email)
        return None

    latest = find_latest_recoverable_rotation(recoverable_items)
    if latest is None:
        return None
    current_user = resolve_user_by_username(latest["username"])
    if current_user is None:
        return None
    if normalize_email(current_user["email"]) != email:
        logger.info(
            "Recovery email no longer matches current IAM tag for %s",
            latest["username"],
        )
        return None
    return current_user


def get_user_email(username: str) -> str | None:
    try:
        response = get_iam_client().list_user_tags(UserName=username)
    except ClientError:
        logger.exception("Unable to read user tags for %s", username)
        return None
    for tag in response.get("Tags", []):
        if tag["Key"] == "email" and tag["Value"].strip():
            return tag["Value"].strip()
    return None


def list_user_rotation_items(table, username: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    query_args: dict[str, Any] = {
        "KeyConditionExpression": Key("PK").eq(rotation_partition_key(username))
        & Key("SK").begins_with(ROTATION_SORT_KEY_PREFIX)
    }
    while True:
        response = table.query(**query_args)
        items.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        query_args["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    return items


def list_rotation_items_by_email(table, email: str) -> list[dict[str, Any]]:
    try:
        indexed_items = query_all_items(
            table,
            {
                "IndexName": EMAIL_LOOKUP_INDEX_NAME,
                "KeyConditionExpression": Key("email_lookup").eq(email),
            },
        )
        if indexed_items:
            return indexed_items
        logger.info(
            "Falling back to status-index recovery lookup because no %s matches were found",
            EMAIL_LOOKUP_INDEX_NAME,
        )
        return legacy_recoverable_items_for_email(table, email)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in {
            "ResourceNotFoundException",
            "ValidationException",
        }:
            raise
        logger.warning(
            "Falling back to status-index recovery lookup because %s is unavailable",
            EMAIL_LOOKUP_INDEX_NAME,
        )
        return legacy_recoverable_items_for_email(table, email)


def legacy_recoverable_items_for_email(table, email: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for status in RECOVERABLE_STATUSES:
        response_items = query_all_items(
            table,
            {
                "IndexName": "status-index",
                "KeyConditionExpression": Key("status").eq(status),
            },
        )
        matches.extend(
            item
            for item in response_items
            if normalize_email(str(item.get("email", ""))) == email
        )
    return matches


def query_all_items(table, query_args: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    current_query_args = dict(query_args)
    while True:
        response = table.query(**current_query_args)
        items.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            return items
        current_query_args["ExclusiveStartKey"] = response["LastEvaluatedKey"]


def find_latest_recoverable_rotation(
    items: list[dict[str, Any]],
) -> dict[str, Any] | None:
    eligible = [
        item
        for item in items
        if item.get("status") in RECOVERABLE_STATUSES and item.get("s3_key")
    ]
    if not eligible:
        return None
    return max(
        eligible,
        key=lambda item: parse_rotation_time(item.get("rotation_initiated")),
    )


def parse_rotation_time(value: Any):
    if isinstance(value, str) and value:
        return parse_iso8601(value)
    return parse_iso8601("1970-01-01T00:00:00+00:00")


def reserve_reissue_slot(
    table,
    *,
    username: str,
    email: str,
    source_ip: str,
    cooldown_minutes: int,
    max_requests_per_day: int,
) -> dict[str, Any] | None:
    now = utc_now()
    timestamp = isoformat(now)
    state_key = recovery_state_key(username)
    state_item = table.get_item(Key=state_key, ConsistentRead=True).get("Item", {})
    recent_reissues = prune_recent_reissues(
        state_item.get("recent_self_service_reissues"), now=now
    )
    last_reissue = state_item.get("last_self_service_reissue_at")
    if (
        cooldown_minutes > 0
        and last_reissue
        and now - parse_iso8601(last_reissue) < timedelta(minutes=cooldown_minutes)
    ):
        return None
    if max_requests_per_day > 0 and len(recent_reissues) >= max_requests_per_day:
        return None

    current_version = int(state_item.get("reissue_version", 0))
    reservation = {
        "current_version": current_version,
        "reserved_version": current_version + 1,
        "last_reissue": last_reissue,
        "recent_reissues": recent_reissues,
        "last_reissue_request_ip": state_item.get("last_reissue_request_ip"),
    }
    try:
        table.update_item(
            Key=state_key,
            UpdateExpression=(
                "SET email = :email, "
                "email_lookup = :email_lookup, "
                "last_self_service_reissue_at = :timestamp, "
                "last_reissue_request_ip = :ip, "
                "recent_self_service_reissues = :recent, "
                "reissue_version = :new_version"
            ),
            ConditionExpression=(
                "attribute_not_exists(reissue_version) OR reissue_version = :expected_version"
            ),
            ExpressionAttributeValues={
                ":email": email,
                ":email_lookup": normalize_email(email),
                ":timestamp": timestamp,
                ":ip": source_ip,
                ":recent": [*recent_reissues, timestamp],
                ":expected_version": current_version,
                ":new_version": current_version + 1,
            },
        )
        return reservation
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        raise


def release_reissue_slot(
    table,
    *,
    username: str,
    reservation: dict[str, Any],
) -> None:
    try:
        table.update_item(
            Key=recovery_state_key(username),
            UpdateExpression=(
                "SET last_self_service_reissue_at = :last_reissue, "
                "last_reissue_request_ip = :last_ip, "
                "recent_self_service_reissues = :recent, "
                "reissue_version = :rollback_version"
            ),
            ConditionExpression="reissue_version = :reserved_version",
            ExpressionAttributeValues={
                ":last_reissue": reservation["last_reissue"],
                ":last_ip": reservation["last_reissue_request_ip"],
                ":recent": reservation["recent_reissues"],
                ":reserved_version": reservation["reserved_version"],
                ":rollback_version": reservation["current_version"],
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning(
                "Unable to roll back failed recovery reservation for %s because state changed",
                username,
            )
            return
        raise


def prune_recent_reissues(value: Any, *, now) -> list[str]:
    if not isinstance(value, list):
        return []
    cutoff = now - timedelta(days=1)
    return [
        entry
        for entry in value
        if isinstance(entry, str) and parse_iso8601(entry) >= cutoff
    ]


def credential_object_exists(bucket: str, s3_key: str) -> bool:
    try:
        get_s3_client().head_object(Bucket=bucket, Key=s3_key)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"404", "NoSuchKey", "NotFound"}:
            return False
        logger.exception("Failed to verify S3 object %s", s3_key)
        raise


def record_successful_reissue(
    table,
    *,
    item: dict[str, Any],
    email: str,
    source_ip: str,
) -> None:
    timestamp = isoformat(utc_now())
    table.update_item(
        Key={"PK": item["PK"], "SK": item["SK"]},
        UpdateExpression=(
            "SET email = :email, "
            "email_lookup = :email_lookup, "
            "last_self_service_reissue_at = :timestamp, "
            "last_reissue_request_ip = :ip, "
            "last_email_sent_at = :timestamp, "
            "email_sent_count = if_not_exists(email_sent_count, :zero) + :one, "
            "self_service_reissue_count = if_not_exists(self_service_reissue_count, :zero) + :one"
        ),
        ExpressionAttributeValues={
            ":email": email,
            ":email_lookup": normalize_email(email),
            ":timestamp": timestamp,
            ":ip": source_ip,
            ":zero": 0,
            ":one": 1,
        },
    )


def extract_source_ip(event: dict[str, Any]) -> str:
    headers = event.get("headers") or {}
    forwarded_for = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return event.get("requestContext", {}).get("http", {}).get("sourceIp", "unknown")
