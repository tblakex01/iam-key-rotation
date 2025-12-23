"""
AWS IAM Access Key Enforcement Lambda
Monitors and enforces 90-day access key rotation policy
Sends notifications at 75 and 85 days, disables keys at 90+ days
"""

import os
import time
import json
import logging
import csv
import io
from datetime import datetime
from dateutil import parser
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lazily initialized AWS clients
iam_client = None
ses_client = None
cloudwatch = None
s3_client = None
dynamodb = None


def get_iam_client():
    """Return a boto3 IAM client, creating it if needed."""
    global iam_client
    if iam_client is None:
        iam_client = boto3.client("iam")
    return iam_client


def get_ses_client():
    """Return a boto3 SES client, creating it if needed."""
    global ses_client
    if ses_client is None:
        ses_client = boto3.client("ses")
    return ses_client


def get_cloudwatch_client():
    """Return a boto3 CloudWatch client, creating it if needed."""
    global cloudwatch
    if cloudwatch is None:
        cloudwatch = boto3.client("cloudwatch")
    return cloudwatch


def get_s3_client():
    """Return a boto3 S3 client, creating it if needed."""
    global s3_client
    if s3_client is None:
        s3_client = boto3.client("s3")
    return s3_client


def get_dynamodb_resource():
    """Return a boto3 DynamoDB resource, creating it if needed."""
    global dynamodb
    if dynamodb is None:
        dynamodb = boto3.resource("dynamodb")
    return dynamodb


# Configuration from environment variables
WARNING_THRESHOLD = int(os.environ.get("WARNING_THRESHOLD", "75"))
URGENT_THRESHOLD = int(os.environ.get("URGENT_THRESHOLD", "85"))
DISABLE_THRESHOLD = int(os.environ.get("DISABLE_THRESHOLD", "90"))
AUTO_DISABLE = os.environ.get("AUTO_DISABLE", "false").lower() == "true"
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "cloud-admins@jennasrunbooks.com")
EXEMPTION_TAG = os.environ.get("EXEMPTION_TAG", "key-rotation-exempt")
S3_BUCKET = os.environ.get("S3_BUCKET")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
CREDENTIAL_RETENTION_DAYS = int(os.environ.get("CREDENTIAL_RETENTION_DAYS", "14"))


def lambda_handler(event, context):  # noqa: ARG001
    """Main Lambda handler"""
    logger.info("Starting IAM Access Key Enforcement check")

    # Generate credential report
    iam = get_iam_client()
    try:
        iam.generate_credential_report()

        # Wait for report generation with timeout
        timeout_seconds = int(os.environ.get("CREDENTIAL_REPORT_TIMEOUT", "60"))
        max_attempts = (
            timeout_seconds // 2
        )  # Convert seconds to attempts (2 sec intervals)
        attempt = 0

        while True:
            attempt += 1
            if attempt > max_attempts:
                timeout_seconds = max_attempts * 2
                logger.error(
                    f"Credential report generation timed out after {timeout_seconds} seconds"
                )
                raise Exception(
                    f"Credential report generation timed out after {timeout_seconds} seconds. "
                    "AWS may be experiencing issues or the account has too many users."
                )

            # Sleep briefly before retrying; keep short to avoid slow tests
            time.sleep(0.1)
            response = iam.get_credential_report()
            if "Content" in response:
                logger.info(
                    f"Credential report generated successfully after {attempt * 2} seconds"
                )
                break

    except ClientError as e:
        logger.error(f"Error generating credential report: {e}")
        raise

    # Process credential report
    credential_report = response["Content"].decode("utf-8")

    # Metrics tracking
    metrics = {
        "total_keys": 0,
        "warning_keys": 0,
        "urgent_keys": 0,
        "disabled_keys": 0,
        "expired_keys": 0,
    }

    # Process each user
    notifications = []

    csv_reader = csv.reader(io.StringIO(credential_report))
    next(csv_reader)  # Skip header

    for fields in csv_reader:
        if not fields:
            continue

        username = fields[0]

        # Check if user is exempt
        if is_user_exempt(username):
            logger.info(f"User {username} is exempt from key rotation policy")
            continue

        # Process access key 1
        key1_active = fields[8] == "true"
        key1_last_rotated = fields[9]

        if key1_active and key1_last_rotated not in ("N/A", "not_supported"):
            key1_id = get_access_key_id(username, 0)
            process_key(username, key1_id, key1_last_rotated, notifications, metrics)

        # Process access key 2
        key2_active = fields[13] == "true"
        key2_last_rotated = fields[14]

        if key2_active and key2_last_rotated not in ("N/A", "not_supported"):
            key2_id = get_access_key_id(username, 1)
            process_key(username, key2_id, key2_last_rotated, notifications, metrics)

    # Send notifications
    for notification in notifications:
        send_notification(notification)

    # Publish metrics to CloudWatch
    publish_metrics(metrics)

    logger.info(
        f"Completed IAM Access Key Enforcement check. Metrics: {json.dumps(metrics)}"
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Access key enforcement completed",
                "metrics": metrics,
                "notifications_sent": len(notifications),
            }
        ),
    }


def is_user_exempt(username):
    """Check if user has exemption tag"""
    try:
        iam = get_iam_client()
        response = iam.list_user_tags(UserName=username)
        for tag in response.get("Tags", []):
            if tag["Key"] == EXEMPTION_TAG and tag["Value"].lower() == "true":
                return True
    except ClientError:
        pass
    return False


def get_access_key_id(username, key_index):
    """Get access key ID for a user"""
    try:
        iam = get_iam_client()
        response = iam.list_access_keys(UserName=username)
        keys = response.get("AccessKeyMetadata", [])
        if key_index < len(keys):
            return keys[key_index]["AccessKeyId"]
    except ClientError as e:
        logger.error(f"Error getting access key for {username}: {e}")
    return None


def process_key(username, key_id, last_rotated, notifications, metrics):
    """Process a single access key - create new key and initiate rotation"""
    if not key_id:
        return

    metrics["total_keys"] += 1

    # Calculate key age
    key_date = parser.parse(last_rotated)
    key_age = (datetime.now() - key_date.replace(tzinfo=None)).days

    logger.info(f"Processing key {key_id} for user {username}, age: {key_age} days")

    # Get user email
    email = get_user_email(username)
    if not email:
        logger.warning(f"No email found for user {username}")
        return

    # Check thresholds and take action
    if key_age >= DISABLE_THRESHOLD:
        metrics["expired_keys"] += 1
        # Create new key and initiate automated rotation
        new_key_data = create_and_store_new_key(username, key_id, email)
        if new_key_data:
            notifications.append(
                {
                    "username": username,
                    "email": email,
                    "old_key_id": key_id,
                    "age": key_age,
                    "action": "rotated",
                    "severity": "critical",
                    "download_url": new_key_data["download_url"],
                    "url_expires": new_key_data["url_expires"],
                }
            )

    elif key_age >= URGENT_THRESHOLD:
        metrics["urgent_keys"] += 1
        # Create new key for urgent rotations
        new_key_data = create_and_store_new_key(username, key_id, email)
        if new_key_data:
            notifications.append(
                {
                    "username": username,
                    "email": email,
                    "old_key_id": key_id,
                    "age": key_age,
                    "action": "rotated",
                    "severity": "high",
                    "download_url": new_key_data["download_url"],
                    "url_expires": new_key_data["url_expires"],
                }
            )

    elif key_age >= WARNING_THRESHOLD:
        metrics["warning_keys"] += 1
        # Create new key for warning rotations
        new_key_data = create_and_store_new_key(username, key_id, email)
        if new_key_data:
            notifications.append(
                {
                    "username": username,
                    "email": email,
                    "old_key_id": key_id,
                    "age": key_age,
                    "action": "rotated",
                    "severity": "medium",
                    "download_url": new_key_data["download_url"],
                    "url_expires": new_key_data["url_expires"],
                }
            )


def get_user_email(username):
    """Get user's email from tags"""
    try:
        iam = get_iam_client()
        response = iam.list_user_tags(UserName=username)
        for tag in response.get("Tags", []):
            if tag["Key"] == "email":
                return tag["Value"]
    except ClientError as e:
        logger.error(f"Error getting email for {username}: {e}")
    return None


def create_and_store_new_key(username, old_key_id, email):
    """Create new access key, store in S3, generate pre-signed URL, track in DynamoDB"""
    try:
        iam = get_iam_client()
        
        # Create new access key
        response = iam.create_access_key(UserName=username)
        new_key = response["AccessKey"]
        new_key_id = new_key["AccessKeyId"]
        secret_key = new_key["SecretAccessKey"]
        
        logger.info(f"Created new access key {new_key_id} for user {username}")
        
        # Prepare credentials JSON
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        credentials = {
            "AccessKeyId": new_key_id,
            "SecretAccessKey": secret_key,
            "Username": username,
            "CreatedAt": timestamp,
            "OldKeyId": old_key_id,
            "Instructions": [
                "Download this file immediately - it will be deleted after download",
                "Update your applications with the new credentials",
                f"Your old key ({old_key_id}) will be automatically deleted after {CREDENTIAL_RETENTION_DAYS} days"
            ]
        }
        
        # Store in S3
        s3 = get_s3_client()
        s3_key = f"credentials/{username}/{timestamp}-credentials.json"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=json.dumps(credentials, indent=2),
            ServerSideEncryption="AES256",
            ContentType="application/json"
        )
        
        logger.info(f"Stored credentials in S3: {s3_key}")
        
        # Generate pre-signed URL (7-day expiration)
        download_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": s3_key},
            ExpiresIn=604800  # 7 days in seconds
        )
        
        # Calculate URL expiration time
        url_expires = (datetime.now().timestamp() + 604800)
        url_expires_str = datetime.fromtimestamp(url_expires).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Track in DynamoDB
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_TABLE)
        
        rotation_timestamp = datetime.now().isoformat()
        
        table.put_item(
            Item={
                "PK": f"USER#{username}",
                "SK": f"ROTATION#{rotation_timestamp}",
                "username": username,
                "email": email,
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "s3_key": s3_key,
                "created_at": timestamp,
                "rotation_initiated": rotation_timestamp,
                "download_url": download_url,
                "url_expires_at": int(url_expires),
                "current_url_expires": rotation_timestamp,
                "old_key_deletion_date": int((datetime.now().timestamp() + (CREDENTIAL_RETENTION_DAYS * 86400))),
                "downloaded": False,
                "download_timestamp": None,
                "download_ip": None,
                "email_sent_count": 1,
                "old_key_deleted": False,
                "status": "pending_download",
                "TTL": int((datetime.now().timestamp() + (90 * 86400)))
            }
        )
        
        logger.info(f"Tracked rotation in DynamoDB for {username}")
        
        return {
            "download_url": download_url,
            "url_expires": url_expires_str,
            "new_key_id": new_key_id
        }
        
    except ClientError as e:
        logger.error(f"Error creating new key for {username}: {e}")
        return None


def send_notification(notification):
    """Send email notification with new access key download link"""
    username = notification["username"]
    email = notification["email"]
    old_key_id = notification["old_key_id"]
    age = notification["age"]
    presigned_url = notification["download_url"]
    expiration_date = notification["url_expires"]
    
    # Calculate old key deletion date
    old_key_deletion_date = datetime.fromtimestamp(
        datetime.now().timestamp() + (CREDENTIAL_RETENTION_DAYS * 86400)
    ).strftime("%B %d, %Y")

    subject = "🔐 ACTION REQUIRED: New AWS Access Key Available"

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <h2 style="color: #232f3e;">AWS Access Key Rotation Required</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>Your AWS access key has been rotated for security compliance. New credentials are now available for download.</p>
    
    <div style="background-color: #fff3cd; border: 2px solid #ff9900; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <div style="display: flex; align-items: center;">
        <span style="font-size: 24px; margin-right: 10px;">⚠️</span>
        <div>
          <strong style="color: #cc0000; font-size: 16px;">IMPORTANT: ONE-TIME DOWNLOAD ONLY</strong>
          <p style="margin: 5px 0 0 0; color: #856404;">
            This link can only be used <strong>ONCE</strong>. After clicking, the credentials file will be permanently deleted from our servers for security. 
            <strong>Save the file immediately</strong> after download.
          </p>
        </div>
      </div>
    </div>
    
    <div style="background-color: #f8f9fa; border-left: 4px solid #232f3e; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Old Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Key Age:</strong> {age} days</p>
      <p style="margin: 5px 0;"><strong>Link Expires:</strong> {expiration_date}</p>
    </div>
    
    <div style="text-align: center; margin: 30px 0;">
      <a href="{presigned_url}" 
         style="background-color: #ff9900; color: white; padding: 15px 30px; text-decoration: none; 
                border-radius: 4px; font-size: 16px; font-weight: bold; display: inline-block;">
        📥 Download New Credentials (One-Time Only)
      </a>
    </div>
    
    <div style="background-color: #e7f3ff; border-left: 4px solid #0073bb; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #0073bb;">📋 Next Steps:</h3>
      <ol style="margin: 10px 0; padding-left: 20px;">
        <li><strong>Click the download button above ONLY when ready</strong></li>
        <li>Save the JSON file to a secure location immediately</li>
        <li>Update your applications with the new credentials</li>
        <li>Verify your applications are working with the new key</li>
        <li>Your old key (<code>{old_key_id}</code>) will be deleted on <strong>{old_key_deletion_date}</strong></li>
      </ol>
    </div>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
      <p style="font-size: 14px; color: #666;">
        <strong>Lost the credentials?</strong> Contact your security team immediately at 
        <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a> for assistance.
      </p>
      <p style="font-size: 12px; color: #999;">
        This is an automated message from AWS IAM Key Rotation System. Do not reply to this email.
      </p>
    </div>
    
  </div>
  
</body>
</html>"""

    try:
        ses = get_ses_client()
        ses.send_email(
            Source=SENDER_EMAIL,
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_body}},
            },
        )
        logger.info(f"Sent rotation notification to {username} ({email})")
    except ClientError as e:
        logger.error(f"Error sending email to {username}: {e}")


def publish_metrics(metrics):
    """Publish metrics to CloudWatch"""
    namespace = "IAM/KeyRotation"

    try:
        cw = get_cloudwatch_client()
        for metric_name, value in metrics.items():
            cw.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Value": value,
                        "Unit": "Count",
                        "Timestamp": datetime.now(),
                    }
                ],
            )
        logger.info("Published metrics to CloudWatch")
    except ClientError as e:
        logger.error(f"Error publishing metrics: {e}")
