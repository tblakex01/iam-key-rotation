# IAM Key Rotation Email Templates

## Initial Notification (Day 0) - HTML Version

```html
Subject: 🔐 ACTION REQUIRED: New AWS Access Key Available

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
Subject: ⏰ REMINDER: AWS Credentials Expiring in 7 Days

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

## Email Types

1. **Initial Notification** - Sent immediately when key is rotated (Day 0)
2. **Day 7 Reminder** - Sent if user hasn't downloaded after 7 days
3. *(Future) Day 14 Final Warning* - For escalation path (not yet implemented)
