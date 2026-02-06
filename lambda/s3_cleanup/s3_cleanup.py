"""
IAM Credentials S3 Cleanup Lambda Function

Runs daily to clean up expired S3 credential files and send final 
expiration notices to users who never downloaded their credentials.
Triggers on day NEW_KEY_RETENTION_DAYS (default: 45).
"""

import json
import logging
import os
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
ses = boto3.client("ses")
cloudwatch = boto3.client("cloudwatch")

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "iam-key-rotation-tracking")
S3_BUCKET = os.environ.get("S3_BUCKET")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
NEW_KEY_RETENTION_DAYS = int(os.environ.get("NEW_KEY_RETENTION_DAYS", "45"))
OLD_KEY_RETENTION_DAYS = int(os.environ.get("OLD_KEY_RETENTION_DAYS", "30"))

table = dynamodb.Table(DYNAMODB_TABLE)


def lambda_handler(event, context):
    """
    Clean up expired S3 credential files and notify users who never downloaded.
    
    Args:
        event: EventBridge scheduled event
        context: Lambda context
        
    Returns:
        dict: Response with cleanup statistics
    """
    logger.info(f"S3 cleanup Lambda started (retention: {NEW_KEY_RETENTION_DAYS} days)")
    
    # Scan for records where credentials have expired
    try:
        response = table.scan(
            FilterExpression=(
                "attribute_exists(rotation_initiated) AND "
                "downloaded = :false AND "
                "attribute_exists(s3_key)"
            ),
            ExpressionAttributeValues={
                ":false": False
            }
        )
        
        items = response.get("Items", [])
        logger.info(f"Found {len(items)} non-downloaded credentials to check")
        
    except ClientError as e:
        logger.error(f"Error scanning DynamoDB: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
    
    expired = 0
    skipped = 0
    errors = []
    
    now = datetime.utcnow()
    
    for item in items:
        try:
            # Calculate days since rotation
            rotation_timestamp = item.get("rotation_initiated")
            rotation_date = datetime.fromisoformat(rotation_timestamp)
            days_since_rotation = (now - rotation_date).days
            
            # Check if retention period has expired
            if days_since_rotation >= NEW_KEY_RETENTION_DAYS:
                logger.info(f"Expiring credentials for {item.get('username')} (day {days_since_rotation})")
                expire_credentials(item, days_since_rotation)
                expired += 1
            else:
                skipped += 1
                
        except Exception as e:
            error_msg = f"Error processing {item.get('username')}: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)
    
    # Publish CloudWatch metrics
    publish_s3_cleanup_metrics(expired)
    
    response = {
        "statusCode": 200 if not errors else 207,
        "body": json.dumps({
            "message": "S3 cleanup completed",
            "checked": len(items),
            "expired": expired,
            "skipped": skipped,
            "errors": errors if errors else None
        })
    }
    
    logger.info(f"S3 cleanup completed: {expired} expired, {skipped} skipped")
    return response


def expire_credentials(item, days_since_rotation):
    """
    Delete S3 file and send expiration notice.
    
    Args:
        item: DynamoDB tracking record
        days_since_rotation: Days since rotation started
    """
    username = item.get("username")
    email = item.get("email")
    s3_key = item.get("s3_key")
    old_key_id = item.get("old_key_id")
    rotation_initiated = item.get("rotation_initiated")
    
    logger.info(f"Expiring credentials for {username}: {s3_key}")
    
    # Delete S3 file if it still exists
    try:
        s3.head_object(Bucket=S3_BUCKET, Key=s3_key)
        s3.delete_object(Bucket=S3_BUCKET, Key=s3_key)
        logger.info(f"Deleted S3 file: s3://{S3_BUCKET}/{s3_key}")
        s3_deleted = True
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            logger.warning(f"S3 file already deleted: {s3_key}")
            s3_deleted = False
        else:
            logger.error(f"Error deleting S3 file: {e}")
            raise
    
    # Update DynamoDB record
    try:
        table.update_item(
            Key={"PK": item["PK"], "SK": item["SK"]},
            UpdateExpression=(
                "SET s3_file_deleted = :true, "
                "s3_file_deletion_timestamp = :ts, "
                "#status = :status"
            ),
            ExpressionAttributeNames={
                "#status": "status"
            },
            ExpressionAttributeValues={
                ":true": True,
                ":ts": datetime.utcnow().isoformat(),
                ":status": "expired_no_download"
            }
        )
        logger.info(f"Updated tracking record for {username} to expired_no_download")
    except ClientError as e:
        logger.error(f"Error updating DynamoDB: {e}")
        raise
    
    # Send expiration email
    send_expiration_email(
        username=username,
        email=email,
        old_key_id=old_key_id,
        rotation_date=rotation_initiated,
        days_since_rotation=days_since_rotation
    )


def send_expiration_email(username, email, old_key_id, rotation_date, days_since_rotation):
    """
    Send email notification that credentials have expired.
    
    Args:
        username: IAM username
        email: User email
        old_key_id: Old key ID that was rotated
        rotation_date: When rotation was initiated
        days_since_rotation: Days since rotation
    """
    rotation_date_str = datetime.fromisoformat(rotation_date).strftime("%B %d, %Y")
    old_key_deletion_date = datetime.fromisoformat(rotation_date) + timedelta(days=OLD_KEY_RETENTION_DAYS)
    old_key_deletion_str = old_key_deletion_date.strftime("%B %d, %Y")
    expiration_date = datetime.utcnow().strftime("%B %d, %Y")
    
    # Calculate how many reminders were sent
    reminder_count = days_since_rotation // 7
    
    subject = "[AWS-IAM-CREDS] CRITICAL - Your New Credentials Have Expired"
    
    html_body = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <h2 style="color: #cc0000;">🚨 CRITICAL: Credentials Expired</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>Your new AWS access key credentials have expired because they were not downloaded within the retention period.</p>
    
    <div style="background-color: #ffe6e6; border: 2px solid #cc0000; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <div style="display: flex; align-items: center;">
        <span style="font-size: 24px; margin-right: 10px;">❌</span>
        <div>
          <strong style="color: #cc0000; font-size: 16px;">ACCESS CREDENTIALS NO LONGER AVAILABLE</strong>
          <p style="margin: 5px 0 0 0; color: #721c24;">
            The download link has expired and the credentials file has been permanently deleted from our secure storage.
          </p>
        </div>
      </div>
    </div>
    
    <div style="background-color: #f8f9fa; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0;">Timeline Summary:</h3>
      <p style="margin: 5px 0;"><strong>Rotation Started:</strong> {rotation_date_str}</p>
      <p style="margin: 5px 0;"><strong>Old Key Deleted:</strong> {old_key_deletion_str}</p>
      <p style="margin: 5px 0;"><strong>Credentials Expired:</strong> {expiration_date}</p>
      <p style="margin: 5px 0;"><strong>Reminders Sent:</strong> {reminder_count}</p>
    </div>
    
    <div style="background-color: #fff3cd; border-left: 4px solid #ff9900; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #ff9900;">⚠️ What You Need To Do:</h3>
      <ol style="margin: 10px 0; padding-left: 20px;">
        <li><strong>Contact your security team immediately</strong> at <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a></li>
        <li>They will manually create new credentials for you</li>
        <li>Update all applications with the new key</li>
        <li>Respond promptly to future rotation notifications</li>
      </ol>
    </div>
    
    <div style="background-color: #e7f3ff; border-left: 4px solid #0073bb; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>ℹ️ Important:</strong></p>
      <p style="margin: 5px 0 0 0; color: #004085;">
        To prevent this in the future, please download your credentials within 7 days of receiving the initial notification.
      </p>
    </div>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
      <p style="font-size: 14px; color: #666;">
        <strong>Immediate Assistance Required:</strong> Contact 
        <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a>
      </p>
      <p style="font-size: 12px; color: #999;">
        This is an automated message from AWS IAM Key Rotation System.
      </p>
    </div>
    
  </div>
  
</body>
</html>
"""
    
    try:
        ses.send_email(
            Source=SENDER_EMAIL,
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_body}}
            }
        )
        logger.info(f"Expiration email sent to {username} ({email})")
    except ClientError as e:
        logger.error(f"Error sending expiration email to {email}: {e}")
        raise


def publish_s3_cleanup_metrics(expired):
    """
    Publish S3 cleanup metrics to CloudWatch.
    
    Args:
        expired: Number of expired credentials cleaned up
    """
    try:
        cloudwatch.put_metric_data(
            Namespace="IAM/KeyRotation",
            MetricData=[
                {
                    "MetricName": "credentials_expired",
                    "Value": expired,
                    "Unit": "Count",
                    "Timestamp": datetime.utcnow()
                }
            ]
        )
        logger.info(f"Published S3 cleanup metrics: {expired} expired")
    except ClientError as e:
        logger.error(f"Error publishing metrics: {e}")
