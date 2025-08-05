#!/usr/bin/env python3
"""Rotate IAM access keys and store new credentials encrypted in S3.

This script creates a new access key for the specified IAM user, disables
existing keys, and stores the new credentials in a newly created S3 bucket.
The credentials file is encrypted at rest using AES-256 server-side
encryption. A pre-signed URL is generated for the stored credentials and
printed to stdout. The URL is valid for 14 days.
"""

import json
import logging
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError

_logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_iam_client = None
_s3_client = None


def get_iam_client():
    """Return cached IAM client."""
    global _iam_client
    if _iam_client is None:
        _iam_client = boto3.client("iam")
    return _iam_client


def get_s3_client():
    """Return cached S3 client."""
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client


def create_secure_bucket(bucket_name: str) -> None:
    """Create an S3 bucket with public access blocked."""
    s3 = get_s3_client()
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def store_credentials(bucket: str, key: str, credentials: dict) -> None:
    """Store credentials JSON in S3 using AES-256 server-side encryption."""
    s3 = get_s3_client()
    body = json.dumps(credentials).encode()
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ServerSideEncryption="AES256",
    )


def generate_presigned_url(bucket: str, key: str) -> str:
    """Generate a pre-signed URL valid for 14 days."""
    s3 = get_s3_client()
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=14 * 24 * 60 * 60,
    )


def rotate_and_store_credentials(user_name: str) -> str:
    """Rotate keys for ``user_name`` and return pre-signed download URL."""
    iam = get_iam_client()

    # List current keys
    existing = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

    # Create new key
    response = iam.create_access_key(UserName=user_name)
    new_key = response["AccessKey"]

    # Disable old keys
    for meta in existing:
        if meta["AccessKeyId"] != new_key["AccessKeyId"]:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=meta["AccessKeyId"],
                Status="Inactive",
            )

    bucket_name = f"iam-creds-{uuid4().hex}"
    create_secure_bucket(bucket_name)

    object_key = f"{new_key['AccessKeyId']}.json"
    store_credentials(
        bucket_name,
        object_key,
        {
            "UserName": user_name,
            "AccessKeyId": new_key["AccessKeyId"],
            "SecretAccessKey": new_key["SecretAccessKey"],
            "CreateDate": new_key["CreateDate"].isoformat(),
        },
    )

    url = generate_presigned_url(bucket_name, object_key)
    _logger.info("Pre-signed URL generated: %s", url)
    print(url)
    return url


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Rotate IAM keys and store in S3")
    parser.add_argument("username", help="IAM username to rotate keys for")
    args = parser.parse_args()

    try:
        rotate_and_store_credentials(args.username)
    except ClientError as exc:
        _logger.error("AWS error: %s", exc)
        raise
