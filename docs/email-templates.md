# IAM Key Rotation Email Templates

## Initial Notification (Day 0) - HTML Version

```html
Subject: [AWS-IAM-CREDS] Day 0 - Action Required: Download Your New Access Key

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <!-- Header -->
    <h2 style="color: #232f3e;">AWS Access Key Rotation Required</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>Your AWS access key has been rotated for security compliance. New credentials are now available for download.</p>
    
    <!-- CRITICAL WARNING BOX -->
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
    
    <!-- Credentials Info -->
    <div style="background-color: #f8f9fa; border-left: 4px solid #232f3e; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Old Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Key Age:</strong> {key_age} days</p>
      <p style="margin: 5px 0;"><strong>Link Expires:</strong> {expiration_date}</p>
    </div>
    
    <!-- Download Button -->
    <div style="text-align: center; margin: 30px 0;">
      <a href="{presigned_url}" 
         style="background-color: #ff9900; color: white; padding: 15px 30px; text-decoration: none; 
                border-radius: 4px; font-size: 16px; font-weight: bold; display: inline-block;">
        📥 Download New Credentials (One-Time Only)
      </a>
    </div>
    
    <!-- Instructions -->
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
    
    <!-- Help Section -->
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
</html>
```

## Day 7 Reminder - HTML Version

```html
Subject: [AWS-IAM-CREDS] Day 7 Reminder - Action Required: Download Your New Access Key

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
      <p style="margin: 5px 0;"><strong>New Link Expires:</strong> {new_expiration_date}</p>
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
      ⏰ This link expires in 7 days on <strong>{new_expiration_date}</strong>
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
```

## Plain Text Version (Initial Notification)

```
========================================
AWS ACCESS KEY ROTATION REQUIRED
========================================

Hello {username},

Your AWS access key has been rotated for security compliance.

⚠️⚠️⚠️ CRITICAL WARNING ⚠️⚠️⚠️

THIS LINK CAN ONLY BE USED ONCE!

After you click the download link below, the credentials file will be 
PERMANENTLY DELETED from our servers for security purposes.

SAVE THE FILE IMMEDIATELY after download.

========================================

Old Key ID: {old_key_id}
Key Age: {key_age} days
Link Expires: {expiration_date}

Download Link (ONE-TIME USE ONLY):
{presigned_url}

========================================

NEXT STEPS:
1. Click the link ONLY when you're ready to save the file
2. Save the JSON file to a secure location immediately
3. Update your applications with the new credentials
4. Verify applications work with new key
5. Old key will be deleted on: {old_key_deletion_date}

Lost the credentials? Contact: cloud-security@mvwc.com

========================================
```

## Template Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `{username}` | IAM username | john.doe |
| `{old_key_id}` | Access key being rotated | AKIAOLD123... |
| `{new_key_id}` | New access key ID (in file) | AKIANEW456... |
| `{key_age}` | Days since old key created | 85 |
| `{presigned_url}` | One-time download link | https://s3... |
| `{expiration_date}` | When URL expires | January 6, 2025 |
| `{old_key_deletion_date}` | When old key gets deleted | January 6, 2025 |
| `{new_expiration_date}` | New URL expiration (reminder) | January 6, 2025 |

## Old Key Deletion Warning - HTML Version

```html
Subject: [AWS-IAM-CREDS] Action Required - OLD Access Key Will Be Deleted in 7 Days

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <h2 style="color: #ff9900;">⚠️ OLD Access Key Deletion Scheduled</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>This is a reminder that your OLD AWS access key will be automatically deleted in <strong>7 days</strong>.</p>
    
    <!-- CRITICAL WARNING BOX -->
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
    
    <!-- Key Info -->
    <div style="background-color: #f8f9fa; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>OLD Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Deletion Date:</strong> {old_key_deletion_date}</p>
      <p style="margin: 5px 0;"><strong>Days Remaining:</strong> 7 days</p>
    </div>
    
    <!-- Next Steps -->
    <div style="background-color: #e7f3ff; border-left: 4px solid #0073bb; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #0073bb;">✅ Verification Checklist:</h3>
      <ol style="margin: 10px 0; padding-left: 20px;">
        <li>Verify all applications are using the new access key</li>
        <li>Check automated scripts and cron jobs</li>
        <li>Confirm CI/CD pipelines have been updated</li>
        <li>Test critical workflows before deletion</li>
      </ol>
    </div>
    
    <!-- Help Section -->
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
      <p style="font-size: 14px; color: #666;">
        <strong>Need Help?</strong> Contact your security team at 
        <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a>
      </p>
      <p style="font-size: 12px; color: #999;">
        This is an automated message from AWS IAM Key Rotation System. Do not reply to this email.
      </p>
    </div>
    
  </div>
  
</body>
</html>
```

## Old Key Deleted (Downloaded Version) - HTML Version

```html
Subject: [AWS-IAM-CREDS] OLD Access Key Successfully Deleted

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <h2 style="color: #28a745;">✅ OLD Access Key Deleted</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>Your OLD AWS access key has been successfully deleted as part of our security rotation policy.</p>
    
    <!-- Success Box -->
    <div style="background-color: #d4edda; border: 2px solid #28a745; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <div style="display: flex; align-items: center;">
        <span style="font-size: 24px; margin-right: 10px;">✅</span>
        <div>
          <strong style="color: #155724; font-size: 16px;">Key Rotation Complete</strong>
          <p style="margin: 5px 0 0 0; color: #155724;">
            The old key has been deleted and can no longer be used. You downloaded your new credentials on <strong>{download_date}</strong>.
          </p>
        </div>
      </div>
    </div>
    
    <!-- Key Info -->
    <div style="background-color: #f8f9fa; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Deleted Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Deletion Date:</strong> {deletion_timestamp}</p>
      <p style="margin: 5px 0;"><strong>New Key Downloaded:</strong> {download_date}</p>
    </div>
    
    <!-- Reminder -->
    <div style="background-color: #fff3cd; border-left: 4px solid #ff9900; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>⚠️ Important Reminder:</strong></p>
      <p style="margin: 5px 0 0 0; color: #856404;">
        If any applications are still using the old key, they will fail authentication. 
        Ensure all systems have been updated to use the new credentials.
      </p>
    </div>
    
    <!-- Help Section -->
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
      <p style="font-size: 14px; color: #666;">
        <strong>Issues or Questions?</strong> Contact 
        <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a>
      </p>
      <p style="font-size: 12px; color: #999;">
        This is an automated message from AWS IAM Key Rotation System.
      </p>
    </div>
    
  </div>
  
</body>
</html>
```

## Old Key Deleted (NOT Downloaded Version) - HTML Version

```html
Subject: [AWS-IAM-CREDS] URGENT - OLD Access Key Deleted, NEW Key Not Downloaded

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <h2 style="color: #cc0000;">🚨 URGENT: Action Required</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>Your OLD AWS access key has been deleted, but <strong>our records show you have NOT downloaded your new credentials</strong>.</p>
    
    <!-- CRITICAL WARNING BOX -->
    <div style="background-color: #ffe6e6; border: 2px solid #cc0000; border-radius: 4px; padding: 15px; margin: 20px 0;">
      <div style="display: flex; align-items: center;">
        <span style="font-size: 24px; margin-right: 10px;">🚨</span>
        <div>
          <strong style="color: #cc0000; font-size: 16px;">IMMEDIATE ACTION REQUIRED</strong>
          <p style="margin: 5px 0 0 0; color: #721c24;">
            Your old key is deleted. You must download your new credentials immediately or you will lose access.
          </p>
        </div>
      </div>
    </div>
    
    <!-- Key Info -->
    <div style="background-color: #f8f9fa; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Deleted Key ID:</strong> <code>{old_key_id}</code></p>
      <p style="margin: 5px 0;"><strong>Deletion Date:</strong> {deletion_timestamp}</p>
      <p style="margin: 5px 0;"><strong>Credentials Expire:</strong> {credentials_expiration_date}</p>
    </div>
    
    <!-- Download Button -->
    <div style="text-align: center; margin: 30px 0;">
      <a href="{presigned_url}" 
         style="background-color: #cc0000; color: white; padding: 15px 30px; text-decoration: none; 
                border-radius: 4px; font-size: 16px; font-weight: bold; display: inline-block;">
        📥 Download New Credentials NOW - One-Time Use Only
      </a>
    </div>
    
    <p style="text-align: center; color: #cc0000; font-size: 14px; margin-top: 10px;">
      ⚠️ This link expires on <strong>{new_expiration_date}</strong>
    </p>
    
    <!-- Next Steps -->
    <div style="background-color: #e7f3ff; border-left: 4px solid #0073bb; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #0073bb;">📋 Immediate Steps:</h3>
      <ol style="margin: 10px 0; padding-left: 20px;">
        <li><strong>Click download button above immediately</strong></li>
        <li>Save credentials to secure location</li>
        <li>Update all applications with new key</li>
        <li>Contact security team if you need assistance</li>
      </ol>
    </div>
    
    <!-- Help Section -->
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
      <p style="font-size: 14px; color: #666;">
        <strong>Need Immediate Help?</strong> Contact 
        <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a>
      </p>
      <p style="font-size: 12px; color: #999;">
        This is an automated message from AWS IAM Key Rotation System.
      </p>
    </div>
    
  </div>
  
</body>
</html>
```

## Credentials Expired (Day 45) - HTML Version

```html
Subject: [AWS-IAM-CREDS] CRITICAL - Your New Credentials Have Expired

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  
  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    
    <h2 style="color: #cc0000;">🚨 CRITICAL: Credentials Expired</h2>
    
    <p>Hello <strong>{username}</strong>,</p>
    
    <p>Your new AWS access key credentials have expired because they were not downloaded within the retention period.</p>
    
    <!-- CRITICAL WARNING BOX -->
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
    
    <!-- Timeline -->
    <div style="background-color: #f8f9fa; border-left: 4px solid #cc0000; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0;">Timeline Summary:</h3>
      <p style="margin: 5px 0;"><strong>Rotation Started:</strong> {rotation_date}</p>
      <p style="margin: 5px 0;"><strong>Old Key Deleted:</strong> {old_key_deletion_date}</p>
      <p style="margin: 5px 0;"><strong>Credentials Expired:</strong> {expiration_date}</p>
      <p style="margin: 5px 0;"><strong>Reminders Sent:</strong> {reminder_count}</p>
    </div>
    
    <!-- Next Steps -->
    <div style="background-color: #fff3cd; border-left: 4px solid #ff9900; padding: 15px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #ff9900;">⚠️ What You Need To Do:</h3>
      <ol style="margin: 10px 0; padding-left: 20px;">
        <li><strong>Contact your security team immediately</strong> at <a href="mailto:cloud-security@mvwc.com">cloud-security@mvwc.com</a></li>
        <li>They will manually create new credentials for you</li>
        <li>Update all applications with the new key</li>
        <li>Respond promptly to future rotation notifications</li>
      </ol>
    </div>
    
    <!-- Important Notice -->
    <div style="background-color: #e7f3ff; border-left: 4px solid #0073bb; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>ℹ️ Important:</strong></p>
      <p style="margin: 5px 0 0 0; color: #004085;">
        To prevent this in the future, please download your credentials within 7 days of receiving the initial notification.
      </p>
    </div>
    
    <!-- Help Section -->
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
```

## Email Types

1. **Initial Notification (Day 0)** - Sent immediately when key is rotated
2. **7-Day Reminders (Dynamic)** - Sent every 7 days if user hasn't downloaded (Days 7, 14, 21, 28, 35, 42...)
3. **Old Key Deletion Warning (Day old_key_retention_days - 7)** - 7-day warning before old key is deleted
4. **Old Key Deleted (Day old_key_retention_days)** - Confirmation that old key was deleted (2 versions based on download status)
5. **Credentials Expired (Day new_key_retention_days)** - Sent if user never downloaded new credentials
