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
ses = boto3.client("ses")
cloudwatch = boto3.client("cloudwatch")

# Configuration from environment
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "iam-key-rotation-tracking")
OLD_KEY_RETENTION_DAYS = int(os.environ.get("OLD_KEY_RETENTION_DAYS", "30"))
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
S3_BUCKET = os.environ.get("S3_BUCKET")

table = dynamodb.Table(DYNAMODB_TABLE)


def lambda_handler(event, context):
    """
    Handle old key lifecycle: day 23 warnings and day 30 deletions.
    Runs daily to check all rotation records and take appropriate action.
    
    Args:
        event: EventBridge scheduled event
        context: Lambda context
        
    Returns:
        dict: Response with processing statistics
    """
    logger.info(f"Old key cleanup Lambda started (retention: {OLD_KEY_RETENTION_DAYS} days)")
    
    # Scan all rotation records
    try:
        response = table.scan(
            FilterExpression="attribute_exists(rotation_initiated) AND old_key_deleted = :false",
            ExpressionAttributeValues={
                ":false": False
            }
        )
        
        items = response.get("Items", [])
        logger.info(f"Found {len(items)} rotation records to process")
        
    except ClientError as e:
        logger.error(f"Error scanning DynamoDB: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
    
    warnings_sent = 0
    deleted = 0
    skipped = 0
    errors = []
    
    now = datetime.utcnow()
    warning_day = OLD_KEY_RETENTION_DAYS - 7  # Day 23 for 30-day retention
    
    for item in items:
        try:
            # Calculate days since rotation
            rotation_timestamp = item.get("rotation_initiated")
            rotation_date = datetime.fromisoformat(rotation_timestamp)
            days_since_rotation = (now - rotation_date).days
            
            # Day 23 (or warning_day): Send deletion warning
            if days_since_rotation == warning_day:
                logger.info(f"Sending day {warning_day} deletion warning for {item.get('username')}")
                send_deletion_warning(item, days_since_rotation)
                warnings_sent += 1
            # Day 30 (or retention day): Delete old key
            elif days_since_rotation >= OLD_KEY_RETENTION_DAYS:
                logger.info(f"Deleting old key for {item.get('username')} (day {days_since_rotation})")
                delete_old_key_and_notify(item)
                deleted += 1
            else:
                skipped += 1
                
        except Exception as e:
            error_msg = f"Error processing {item.get('username')}: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)
    
    # Publish CloudWatch metrics
    publish_cleanup_metrics(warnings_sent, deleted)
    
    response = {
        "statusCode": 200 if not errors else 207,
        "body": json.dumps({
            "message": "Old key cleanup completed",
            "checked": len(items),
            "warnings_sent": warnings_sent,
            "deleted": deleted,
            "skipped": skipped,
            "errors": errors if errors else None
        })
    }
    
    logger.info(f"Cleanup completed: {warnings_sent} warnings, {deleted} deleted, {skipped} skipped")
    return response


def send_deletion_warning(item, days_since_rotation):
    """
    Send 7-day warning before old key deletion.
    
    Args:
        item: DynamoDB tracking record
        days_since_rotation: Days since rotation started
    """
    username = item.get("username")
    email = item.get("email")
    old_key_id = item.get("old_key_id")
    old_key_deletion_date = item.get("old_key_deletion_date")
    
    # Format deletion date
    deletion_date_str = datetime.fromtimestamp(old_key_deletion_date).strftime("%B %d, %Y")
    
    subject = "[AWS-IAM-CREDS] Action Required - OLD Access Key Will Be Deleted in 7 Days"
    
    html_body = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2 style="color: #ff9900;">⚠️ OLD Access Key Deletion Scheduled</h2>
    <p>Hello <strong>{username}</strong>,</p>
    <p>This is a reminder that your OLD AWS access key will be automatically deleted in <strong>7 days</strong>.</p>
    
    <div style="background-color: #ffe6e6; border: 2px solid #cc0000; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <div style="display: flex; align-items: center;">
        <span style="font-size: 24px; margin-right: 10px;">🗑️</span>
        <div>
          <strong style="color: #cc0000; font-size: 16px;">ACTION REQUIRED: Verify Key Migration</strong>
          <p style="margin: 5px 0 0 0; color: #721c24;">
            Ensure all applications have been switched to the new access key before the old key is deleted.
          </p>
        </div>
      </div>
    </div>
    
    <div style="background-color: #f8f9fa; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>OLD Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Deletion Date:</strong> {deletion_date_str}</p>
      <p style="margin: 5px 0;"><strong>Days Remaining:</strong> 7 days</p>
    </div>
    
    <div style="background-color: #e7f3ff; border-left: 4px solid #0073bb; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #0073bb;">✅ Verification Checklist:</h3>
      <ol style="margin: 10px 0; padding-left: 20px;">
        <li>Verify all applications are using the new access key</li>
        <li>Check automated scripts and cron jobs</li>
        <li>Confirm CI/CD pipelines have been updated</li>
        <li>Test critical workflows before deletion</li>
      </ol>
    </div>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
      <p style="font-size: 14px; color: #666;">
        <strong>Need Help?</strong> Contact your security team at 
        <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a>
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
        logger.info(f"Deletion warning sent to {username} ({email})")
    except ClientError as e:
        logger.error(f"Error sending deletion warning to {email}: {e}")
        raise


def delete_old_key_and_notify(item):
    """
    Delete old IAM access key and update tracking record.
    
    Args:
        item: DynamoDB tracking record
    """
    username = item.get("username")
    old_key_id = item.get("old_key_id")
    downloaded = item.get("downloaded", False)
    
    downloaded = item.get("downloaded", False)
    s3_key = item.get("s3_key")
    
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
    
    # Send conditional email based on download status
    send_deletion_email(username, email, old_key_id, downloaded, s3_key)
        
    except ClientError as e:
        logger.error(f"Error updating DynamoDB: {e}")
        raise


def send_deletion_email(username, email, old_key_id, downloaded, s3_key):
    """
    Send email notification after old key deletion.
    Email content depends on whether new key was downloaded.
    
    Args:
        username: IAM username
        email: User email
        old_key_id: Deleted key ID
        downloaded: Whether new credentials were downloaded
        s3_key: S3 key path for credentials
    """
    deletion_timestamp = datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC")
    
    if downloaded:
        # Version 1: User downloaded new credentials
        subject = "[AWS-IAM-CREDS] OLD Access Key Successfully Deleted"
        
        download_date = "recently"  # Could be retrieved from DynamoDB if needed
        
        html_body = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2 style="color: #28a745;">✅ OLD Access Key Deleted</h2>
    <p>Hello <strong>{username}</strong>,</p>
    <p>Your OLD AWS access key has been successfully deleted as part of our security rotation policy.</p>
    
    <div style="background-color: #d4edda; border: 2px solid #28a745; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <strong style="color: #155724;">Key Rotation Complete</strong>
      <p style="margin: 5px 0 0 0; color: #155724;">
        The old key has been deleted and can no longer be used. You downloaded your new credentials {download_date}.
      </p>
    </div>
    
    <div style="background-color: #f8f9fa; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Deleted Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Deletion Date:</strong> {deletion_timestamp}</p>
    </div>
    
    <div style="background-color: #fff3cd; border-left: 4px solid #ff9900; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>⚠️ Important Reminder:</strong></p>
      <p style="margin: 5px 0 0 0; color: #856404;">
        If any applications are still using the old key, they will fail authentication.
      </p>
    </div>
  </div>
</body>
</html>
"""
    else:
        # Version 2: User DID NOT download new credentials - URGENT
        subject = "[AWS-IAM-CREDS] URGENT - OLD Access Key Deleted, NEW Key Not Downloaded"
        
        # Generate new presigned URL since they haven't downloaded yet
        try:
            s3 = boto3.client("s3")
            presigned_url = s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": S3_BUCKET, "Key": s3_key},
                ExpiresIn=604800  # 7 days
            )
            new_expiration = (datetime.utcnow() + timedelta(days=7)).strftime("%B %d, %Y")
        except:
            presigned_url = "[Contact security team for new credentials]"
            new_expiration = "N/A"
        
        html_body = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2 style="color: #cc0000;">🚨 URGENT: Action Required</h2>
    <p>Hello <strong>{username}</strong>,</p>
    <p>Your OLD AWS access key has been deleted, but <strong>our records show you have NOT downloaded your new credentials</strong>.</p>
    
    <div style="background-color: #ffe6e6; border: 2px solid #cc0000; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <strong style="color: #cc0000; font-size: 16px;">IMMEDIATE ACTION REQUIRED</strong>
      <p style="margin: 5px 0 0 0; color: #721c24;">
        Your old key is deleted. You must download your new credentials immediately.
      </p>
    </div>
    
    <div style="background-color: #f8f9fa; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Deleted Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Deletion Date:</strong> {deletion_timestamp}</p>
    </div>
    
    <div style="text-align: center; margin: 30px 0;">
      <a href="{presigned_url}" 
         style="background-color: #cc0000; color: white; padding: 15px 30px; text-decoration: none; 
                border-radius: 4px; font-size: 16px; font-weight: bold; display: inline-block;">
        📥 Download New Credentials NOW
      </a>
    </div>
    
    <p style="text-align: center; color: #cc0000; font-size: 14px;">
      ⚠️ This link expires on <strong>{new_expiration}</strong>
    </p>
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
        logger.info(f"Deletion email sent to {username} ({email}), downloaded={downloaded}")
    except ClientError as e:
        logger.error(f"Error sending deletion email to {email}: {e}")
        raise


def publish_cleanup_metrics(warnings, deleted):
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
                    "MetricName": "deletion_warnings_sent",
                    "Value": warnings,
                    "Unit": "Count",
                    "Timestamp": datetime.utcnow()
                },
                {
                    "MetricName": "old_keys_deleted",
                    "Value": deleted,
                    "Unit": "Count",
                    "Timestamp": datetime.utcnow()
                }
            ]
        )
        
        logger.info(f"Published cleanup metrics: {warnings} warnings, {deleted} deleted")
        
    except ClientError as e:
        logger.error(f"Error publishing metrics: {e}")
        # Don't raise - metrics are not critical
