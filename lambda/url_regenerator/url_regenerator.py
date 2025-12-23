"""
IAM Key URL Regenerator Lambda Function

Runs daily to check for expiring pre-signed URLs and regenerate them
for users who haven't downloaded their credentials yet.
Sends reminder emails with new download links.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
ses = boto3.client("ses")

# Configuration from environment
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "iam-key-rotation-tracking")
S3_BUCKET = os.environ.get("S3_BUCKET")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")

table = dynamodb.Table(DYNAMODB_TABLE)


def lambda_handler(event, context):
    """
    Check for expiring URLs and regenerate for non-downloaded credentials.
    
    Args:
        event: EventBridge scheduled event
        context: Lambda context
        
    Returns:
        dict: Response with regeneration statistics
    """
    logger.info("URL regenerator started")
    
    today = datetime.utcnow().date().isoformat()
    
    # Query for URLs expiring today
    try:
        response = table.query(
            IndexName="url-expiration-index",
            KeyConditionExpression="current_url_expires = :today",
            FilterExpression="downloaded = :false",
            ExpressionAttributeValues={
                ":today": today,
                ":false": False
            }
        )
        
        items = response.get("Items", [])
        logger.info(f"Found {len(items)} expiring URLs for non-downloaded credentials")
        
    except ClientError as e:
        logger.error(f"Error querying DynamoDB: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
    
    regenerated = 0
    errors = []
    
    for item in items:
        try:
            regenerate_url_and_notify(item)
            regenerated += 1
        except Exception as e:
            error_msg = f"Error regenerating URL for {item.get('username')}: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)
    
    response = {
        "statusCode": 200 if not errors else 207,
        "body": json.dumps({
            "message": "URL regeneration completed",
            "checked": len(items),
            "regenerated": regenerated,
            "errors": errors if errors else None
        })
    }
    
    logger.info(f"URL regenerator completed: {regenerated}/{len(items)} regenerated")
    return response


def regenerate_url_and_notify(item):
    """
    Regenerate pre-signed URL and send reminder email.
    
    Args:
        item: DynamoDB tracking record
    """
    username = item.get("username")
    email = item.get("email")
    s3_key = item.get("s3_key")
    old_key_id = item.get("old_key_id")
    rotation_initiated = item.get("rotation_initiated")
    old_key_deletion_date = item.get("old_key_deletion_date")
    
    logger.info(f"Regenerating URL for user: {username}")
    
    # Check if S3 file still exists (may have been downloaded and deleted)
    try:
        s3.head_object(Bucket=S3_BUCKET, Key=s3_key)
        logger.info(f"S3 file exists for {username}: {s3_key}")
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            logger.warning(f"S3 file already deleted for {username}: {s3_key}. Skipping reminder.")
            # Update DynamoDB to reflect file was already downloaded/deleted
            table.update_item(
                Key={"PK": item["PK"], "SK": item["SK"]},
                UpdateExpression="SET #st = :status",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":status": "downloaded"}
            )
            return
        else:
            logger.error(f"Error checking S3 file existence: {e}")
            raise
    
    # Generate new pre-signed URL (7 days)
    try:
        presigned_url = s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": S3_BUCKET,
                "Key": s3_key
            },
            ExpiresIn=604800  # 7 days in seconds
        )
    except ClientError as e:
        logger.error(f"Error generating presigned URL: {e}")
        raise
    
    # Calculate new expiration date
    new_expiration = (datetime.utcnow() + timedelta(days=7)).date().isoformat()
    
    # Update DynamoDB record
    try:
        table.update_item(
            Key={"PK": item["PK"], "SK": item["SK"]},
            UpdateExpression=(
                "SET current_presigned_url = :url, "
                "current_url_expires = :exp, "
                "email_sent_count = email_sent_count + :one, "
                "emails = list_append(if_not_exists(emails, :empty_list), :new_email)"
            ),
            ExpressionAttributeValues={
                ":url": presigned_url,
                ":exp": new_expiration,
                ":one": 1,
                ":empty_list": [],
                ":new_email": [{
                    "sent_at": datetime.utcnow().isoformat(),
                    "type": "reminder_day_7",
                    "ses_message_id": None  # Will be updated after send
                }]
            }
        )
    except ClientError as e:
        logger.error(f"Error updating DynamoDB: {e}")
        raise
    
    # Send reminder email
    send_reminder_email(
        username=username,
        email=email,
        presigned_url=presigned_url,
        old_key_id=old_key_id,
        new_expiration=new_expiration,
        old_key_deletion_date=old_key_deletion_date
    )
    
    logger.info(f"URL regenerated and reminder sent for {username}")


def send_reminder_email(username, email, presigned_url, old_key_id, new_expiration, old_key_deletion_date):
    """
    Send reminder email with new download link.
    
    Args:
        username: IAM username
        email: User email address
        presigned_url: New pre-signed URL
        old_key_id: Old access key ID
        new_expiration: New URL expiration date
        old_key_deletion_date: When old key will be deleted
    """
    subject = "⏰ REMINDER: AWS Credentials Expiring in 7 Days"
    
    html_body = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <h2 style="color: #cc0000;">⚠️ Credentials Not Yet Downloaded</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>Our records show you have not downloaded your new AWS access key. Your old key will be automatically deleted in <strong>7 days</strong>.</p>
    
    <!-- CRITICAL WARNING BOX -->
    <div style="background-color: #fff3cd; border: 2px solid #ff9900; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <div style="display: flex; align-items: center;">
        <span style="font-size: 24px; margin-right: 10px;">⚠️</span>
        <div>
          <strong style="color: #cc0000; font-size: 16px;">REMINDER: ONE-TIME DOWNLOAD ONLY</strong>
          <p style="margin: 5px 0 0 0; color: #856404;">
            This link can only be used <strong>ONCE</strong>. The file will be permanently deleted after you click the download button. 
            <strong>Have your secure storage ready before clicking.</strong>
          </p>
        </div>
      </div>
    </div>
    
    <!-- Urgency Box -->
    <div style="background-color: #ffe6e6; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Old Key Deletion:</strong> {old_key_deletion_date}</p>
      <p style="margin: 5px 0;"><strong>Days Remaining:</strong> 7 days</p>
      <p style="margin: 5px 0;"><strong>New Link Expires:</strong> {new_expiration}</p>
    </div>
    
    <!-- Download Button -->
    <div style="text-align: center; margin: 30px 0;">
      <a href="{presigned_url}" 
         style="background-color: #cc0000; color: white; padding: 15px 30px; text-decoration: none; 
                border-radius: 4px; font-size: 16px; font-weight: bold; display: inline-block;">
        📥 Download Now - This is Your Last Chance
      </a>
    </div>
    
    <p style="text-align: center; color: #666; font-size: 14px; margin-top: 10px;">
      ⏰ This link expires in 7 days on <strong>{new_expiration}</strong>
    </p>
    
    <!-- Help -->
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
      <p style="font-size: 14px; color: #666;">
        <strong>Need Help?</strong> Contact 
        <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a>
      </p>
    </div>
    
  </div>
  
</body>
</html>
"""
    
    text_body = f"""
========================================
AWS CREDENTIALS - REMINDER
========================================

Hello {username},

Your new AWS access key has not been downloaded yet.

⚠️⚠️⚠️ CRITICAL WARNING ⚠️⚠️⚠️

THIS LINK CAN ONLY BE USED ONCE!

Download Link (ONE-TIME USE):
{presigned_url}

Old Key Deletion: {old_key_deletion_date}
Days Remaining: 7 days
Link Expires: {new_expiration}

Need Help? Contact: cloud-security@mvwc.com
========================================
"""
    
    try:
        response = ses.send_email(
            Source=SENDER_EMAIL,
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {
                    "Text": {"Data": text_body},
                    "Html": {"Data": html_body}
                }
            }
        )
        
        message_id = response.get("MessageId")
        logger.info(f"Reminder email sent to {username} ({email}), MessageId: {message_id}")
        
    except ClientError as e:
        logger.error(f"Error sending email to {email}: {e}")
        raise
