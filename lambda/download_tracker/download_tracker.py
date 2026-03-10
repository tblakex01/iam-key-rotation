"""
IAM Key Download Tracker Lambda Function

Triggered by S3 GetObject events when user downloads credentials.
Updates DynamoDB tracking table and deletes S3 file for security.
"""

import json
import logging
import os
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

# Configuration from environment
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "iam-key-rotation-tracking")
table = dynamodb.Table(DYNAMODB_TABLE)


def lambda_handler(event, context):
    """
    Handle CloudTrail S3 GetObject event for credential downloads.
    
    Args:
        event: EventBridge event from CloudTrail
        context: Lambda context
        
    Returns:
        dict: Response with status and details
    """
    logger.info("Download tracker triggered")
    logger.info(f"Event: {json.dumps(event)}")
    
    processed = 0
    errors = []
    
    # EventBridge wraps CloudTrail events differently than S3 notifications
    try:
        # Extract CloudTrail event details from EventBridge
        detail = event.get("detail", {})
        
        # Get S3 details from CloudTrail event
        request_params = detail.get("requestParameters", {})
        bucket = request_params.get("bucketName")
        s3_key = request_params.get("key")
        event_time = detail.get("eventTime")
        
        # Extract IP address from CloudTrail event
        ip_address = detail.get("sourceIPAddress", "unknown")
        
        # Parse username from S3 key (format: credentials/username/timestamp-credentials.json)
        if not s3_key or not s3_key.startswith("credentials/"):
            logger.warning(f"Skipping non-credential file: {s3_key}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Not a credential file, skipping"})
            }
            
        parts = s3_key.split("/")
        if len(parts) < 3:
            logger.warning(f"Invalid S3 key format: {s3_key}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Invalid key format, skipping"})
            }
            
        username = parts[1]
        
        logger.info(f"Processing download for user: {username}, IP: {ip_address}")
        
        # Update DynamoDB - mark as downloaded
        update_tracking_record(username, event_time, ip_address)
        
        # Delete S3 file for security (one-time download)
        delete_s3_file(bucket, s3_key)
        
        processed = 1
        
    except Exception as e:
        error_msg = f"Error processing CloudTrail event: {str(e)}"
        logger.error(error_msg)
        errors.append(error_msg)
    
    response = {
        "statusCode": 200 if not errors else 207,
        "body": json.dumps({
            "message": "Download tracking completed",
            "processed": processed,
            "errors": errors if errors else None
        })
    }
    
    logger.info(f"Download tracker completed: {processed} processed, {len(errors)} errors")
    return response


def update_tracking_record(username, download_time, ip_address):
    """
    Update DynamoDB tracking record with download details.
    
    Args:
        username: IAM username
        download_time: ISO 8601 timestamp of download
        ip_address: Source IP address
    """
    try:
        # Query for the most recent rotation record for this user
        response = table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={
                ":pk": f"USER#{username}"
            },
            ScanIndexForward=False,  # Sort descending by SK (most recent first)
            Limit=1
        )
        
        if not response.get("Items"):
            logger.warning(f"No tracking record found for user: {username}")
            return
        
        item = response["Items"][0]
        pk = item["PK"]
        sk = item["SK"]
        
        # Update with download information
        table.update_item(
            Key={"PK": pk, "SK": sk},
            UpdateExpression=(
                "SET downloaded = :true, "
                "download_timestamp = :ts, "
                "download_ip = :ip, "
                "s3_file_deleted = :true, "
                "s3_file_deletion_timestamp = :del_ts, "
                "#status = :status"
            ),
            ExpressionAttributeNames={
                "#status": "status"
            },
            ExpressionAttributeValues={
                ":true": True,
                ":ts": download_time,
                ":ip": ip_address,
                ":del_ts": datetime.utcnow().isoformat(),
                ":status": "downloaded"
            }
        )
        
        logger.info(f"Updated tracking record for {username}: {pk}#{sk}")
        
    except ClientError as e:
        logger.error(f"DynamoDB error updating record for {username}: {e}")
        raise


def delete_s3_file(bucket, s3_key):
    """
    Delete S3 file after successful download (one-time download security).
    
    Args:
        bucket: S3 bucket name
        s3_key: S3 object key
    """
    try:
        s3.delete_object(Bucket=bucket, Key=s3_key)
        logger.info(f"Deleted S3 file: s3://{bucket}/{s3_key}")
        
    except ClientError as e:
        logger.error(f"Error deleting S3 file {s3_key}: {e}")
        raise
