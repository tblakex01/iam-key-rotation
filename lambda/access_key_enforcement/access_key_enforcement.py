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


# Configuration from environment variables
WARNING_THRESHOLD = int(os.environ.get("WARNING_THRESHOLD", "75"))
URGENT_THRESHOLD = int(os.environ.get("URGENT_THRESHOLD", "85"))
DISABLE_THRESHOLD = int(os.environ.get("DISABLE_THRESHOLD", "90"))
AUTO_DISABLE = os.environ.get("AUTO_DISABLE", "false").lower() == "true"
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "cloud-admins@jennasrunbooks.com")
EXEMPTION_TAG = os.environ.get("EXEMPTION_TAG", "key-rotation-exempt")


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
    """Process a single access key"""
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

        if AUTO_DISABLE:
            disable_key(username, key_id)
            metrics["disabled_keys"] += 1

            notifications.append(
                {
                    "username": username,
                    "email": email,
                    "key_id": key_id,
                    "age": key_age,
                    "action": "disabled",
                    "severity": "critical",
                }
            )
        else:
            notifications.append(
                {
                    "username": username,
                    "email": email,
                    "key_id": key_id,
                    "age": key_age,
                    "action": "expired",
                    "severity": "critical",
                }
            )

    elif key_age >= URGENT_THRESHOLD:
        metrics["urgent_keys"] += 1
        notifications.append(
            {
                "username": username,
                "email": email,
                "key_id": key_id,
                "age": key_age,
                "action": "urgent",
                "severity": "high",
            }
        )

    elif key_age >= WARNING_THRESHOLD:
        metrics["warning_keys"] += 1
        notifications.append(
            {
                "username": username,
                "email": email,
                "key_id": key_id,
                "age": key_age,
                "action": "warning",
                "severity": "medium",
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


def disable_key(username, key_id):
    """Disable an access key"""
    try:
        iam = get_iam_client()
        iam.update_access_key(UserName=username, AccessKeyId=key_id, Status="Inactive")
        logger.info(f"Disabled access key {key_id} for user {username}")
    except ClientError as e:
        logger.error(f"Error disabling key {key_id} for {username}: {e}")


def send_notification(notification):
    """Send email notification"""
    username = notification["username"]
    email = notification["email"]
    key_id = notification["key_id"]
    age = notification["age"]
    action = notification["action"]

    # Determine subject and message based on action
    if action == "disabled":
        subject = "CRITICAL: AWS Access Key Disabled"
        message = (
            f"Your access key {key_id} has been automatically "
            f"disabled after {age} days without rotation."
        )
    elif action == "expired":
        subject = "CRITICAL: AWS Access Key Expired"
        message = (
            f"Your access key {key_id} has expired ({age} days old) "
            f"and should be rotated immediately."
        )
    elif action == "urgent":
        subject = "URGENT: AWS Access Key Rotation Required"
        message = (
            f"Your access key {key_id} is {age} days old and will "
            f"expire in {DISABLE_THRESHOLD - age} days."
        )
    else:  # warning
        subject = "WARNING: AWS Access Key Rotation Recommended"
        message = (
            f"""Your access key {key_id} is {age} days old. Please rotate it soon."""
        )

    html_body = f"""
    <html>
    <body>
        <h2 style="color: {'red' if action in ['disabled', 'expired'] else 'orange'};">
            {subject}
        </h2>
        <p>Hello {username},</p>
        <p>{message}</p>

        <h3>How to Rotate Your Access Key:</h3>
        <ol>
            <li>Use the self-service key rotation script:
                <pre>python3 aws_iam_self_service_key_rotation.py -c</pre>
            </li>
            <li>Update your applications with the new key</li>
            <li>Deactivate the old key:
                <pre>python3 aws_iam_self_service_key_rotation.py -u {key_id} inactive</pre>
            </li>
            <li>After confirming everything works, delete the old key:
                <pre>python3 aws_iam_self_service_key_rotation.py -d {key_id}</pre>
            </li>
        </ol>

        <p>For assistance, please contact the Cloud Admins team.</p>

        <p style="font-size: 12px; color: #666;">
            This is an automated message from the AWS IAM Key Rotation Enforcement system.
        </p>
    </body>
    </html>
    """

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
        logger.info(f"Sent {action} notification to {username} ({email})")
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
