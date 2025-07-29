#!/usr/bin/env python3
"""Rotate IAM secret access keys and store the new credentials in S3.

This script creates a new access key for the specified IAM user, deactivates the
old key if provided, and uploads the new credentials to a newly created S3
bucket. The bucket blocks public access and uses AES-256 server-side encryption.
A pre-signed URL valid for 14 days is generated for secure retrieval.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_iam_client = None
_s3_client = None


def get_iam_client():
    """Return a boto3 IAM client, creating it if needed."""
    global _iam_client
    if _iam_client is None:
        _iam_client = boto3.client("iam")
    return _iam_client


def get_s3_client():
    """Return a boto3 S3 client, creating it if needed."""
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client


def create_secure_bucket(bucket_name: str) -> str:
    """Create an S3 bucket with public access blocked and AES-256 encryption."""
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
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )
    return bucket_name


def rotate_and_store_credentials(
    old_key_id: Optional[str] = None, user_name: Optional[str] = None
) -> str:
    """Rotate an IAM user's access key and store the new credentials in S3."""
    iam = get_iam_client()
    s3 = get_s3_client()

    if user_name is None:
        user_name = iam.get_user()["User"]["UserName"]

    response = iam.create_access_key(UserName=user_name)
    new_key = response["AccessKey"]

    if old_key_id:
        try:
            iam.update_access_key(
                UserName=user_name, AccessKeyId=old_key_id, Status="Inactive"
            )
        except ClientError as exc:  # pragma: no cover - safety net
            logger.error("Failed to deactivate old key: %s", exc)

    bucket_name = create_secure_bucket(f"iam-key-backup-{int(time.time())}")
    file_key = f"{new_key['AccessKeyId']}.json"
    body = json.dumps(
        {
            "AccessKeyId": new_key["AccessKeyId"],
            "SecretAccessKey": new_key["SecretAccessKey"],
        }
    )

    s3.put_object(
        Bucket=bucket_name,
        Key=file_key,
        Body=body,
        ServerSideEncryption="AES256",
    )

    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket_name, "Key": file_key},
        ExpiresIn=14 * 24 * 60 * 60,
    )
    return url


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Rotate IAM credentials and store the secret in S3"
    )
    parser.add_argument(
        "--old-key-id", help="Existing access key ID to deactivate after rotation"
    )
    parser.add_argument("--user-name", help="IAM username (defaults to current user)")
    args = parser.parse_args()

    url = rotate_and_store_credentials(args.old_key_id, args.user_name)
    print(f"Pre-signed URL (valid for 14 days): {url}")


if __name__ == "__main__":
    main()
