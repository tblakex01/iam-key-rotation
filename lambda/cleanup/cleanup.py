"""
IAM Key Cleanup Lambda Function

Runs daily to delete old IAM access keys after the retention period expires.
Updates DynamoDB tracking records and publishes CloudWatch metrics.
"""

import json
import logging
import os
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")
cloudwatch = boto3.client("cloudwatch")

# Configuration from environment
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "iam-key-rotation-tracking")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "14"))

table = dynamodb.Table(DYNAMODB_TABLE)


def lambda_handler(event, context):
    """
    Delete old IAM keys that have exceeded the retention period.
    
    Args:
        event: EventBridge scheduled event
        context: Lambda context
        
    Returns:
        dict: Response with cleanup statistics
    """
    logger.info(f"Cleanup Lambda started (retention: {RETENTION_DAYS} days)")
    
    # Calculate cutoff timestamp (current time)
    cutoff_timestamp = int(datetime.utcnow().timestamp())
    
    # Scan for keys past deletion date (more efficient than multiple queries)
    try:
        response = table.scan(
            FilterExpression="old_key_deletion_date < :now AND old_key_deleted = :false",
            ExpressionAttributeValues={
                ":now": cutoff_timestamp,
                ":false": False
            }
        )
        
        items = response.get("Items", [])
        logger.info(f"Found {len(items)} old keys to clean up")
        
    except ClientError as e:
        logger.error(f"Error querying DynamoDB: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
    
    deleted = 0
    failed = 0
    errors = []
    
    for item in items:
        try:
            delete_old_key(item)
            deleted += 1
        except Exception as e:
            error_msg = f"Error deleting key for {item.get('username')}: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)
            failed += 1
    
    # Publish CloudWatch metrics
    publish_cleanup_metrics(deleted, failed)
    
    response = {
        "statusCode": 200 if not errors else 207,
        "body": json.dumps({
            "message": "Cleanup completed",
            "checked": len(items),
            "deleted": deleted,
            "failed": failed,
            "errors": errors if errors else None
        })
    }
    
    logger.info(f"Cleanup completed: {deleted} deleted, {failed} failed")
    return response


def delete_old_key(item):
    """
    Delete old IAM access key and update tracking record.
    
    Args:
        item: DynamoDB tracking record
    """
    username = item.get("username")
    old_key_id = item.get("old_key_id")
    downloaded = item.get("downloaded", False)
    
    logger.info(f"Deleting old key for user: {username}, Key: {old_key_id}, Downloaded: {downloaded}")
    
    # Delete the IAM access key
    try:
        iam.delete_access_key(
            UserName=username,
            AccessKeyId=old_key_id
        )
        logger.info(f"Deleted IAM key {old_key_id} for user {username}")
        
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.warning(f"Key {old_key_id} already deleted for {username}")
        else:
            logger.error(f"Error deleting IAM key: {e}")
            raise
    
    # Update DynamoDB record
    try:
        new_status = "completed" if downloaded else "expired_no_download"
        
        table.update_item(
            Key={"PK": item["PK"], "SK": item["SK"]},
            UpdateExpression=(
                "SET old_key_deleted = :true, "
                "old_key_deletion_timestamp = :ts, "
                "#status = :status"
            ),
            ExpressionAttributeNames={
                "#status": "status"
            },
            ExpressionAttributeValues={
                ":true": True,
                ":ts": datetime.utcnow().isoformat(),
                ":status": new_status
            }
        )
        
        logger.info(f"Updated tracking record for {username} to status: {new_status}")
        
    except ClientError as e:
        logger.error(f"Error updating DynamoDB: {e}")
        raise


def publish_cleanup_metrics(deleted, failed):
    """
    Publish cleanup metrics to CloudWatch.
    
    Args:
        deleted: Number of keys successfully deleted
        failed: Number of deletion failures
    """
    try:
        cloudwatch.put_metric_data(
            Namespace="IAM/KeyRotation",
            MetricData=[
                {
                    "MetricName": "keys_cleaned_up",
                    "Value": deleted,
                    "Unit": "Count",
                    "Timestamp": datetime.utcnow()
                },
                {
                    "MetricName": "cleanup_failures",
                    "Value": failed,
                    "Unit": "Count",
                    "Timestamp": datetime.utcnow()
                }
            ]
        )
        
        logger.info(f"Published cleanup metrics: {deleted} deleted, {failed} failed")
        
    except ClientError as e:
        logger.error(f"Error publishing metrics: {e}")
        # Don't raise - metrics are not critical
