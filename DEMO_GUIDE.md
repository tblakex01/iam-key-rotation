# 🎯 IAM Key Rotation System Demo Guide

## Pre-Demo Checklist
- [ ] Infrastructure deployed via Terragrunt
- [ ] Test users exist with access keys
- [ ] AWS credential report includes test users (check beforehand!)
- [ ] AWS CLI configured with correct profile
- [ ] Email address configured to receive notifications

## 📋 Demo Flow Overview

1. **Show current state** - IAM users and keys
2. **Trigger rotation** - Invoke enforcement Lambda
3. **Show artifacts** - DynamoDB records, S3 files, CloudWatch logs
4. **Check email** - Demonstrate notification received
5. **Simulate day 7** - URL regenerator reminder (optional)
6. **Simulate day 14** - Cleanup old key (optional)

---

## 1️⃣ Show Current State

### Check IAM Test Users
```bash
# List test users
aws iam list-users \
  --profile dw-nonprod \
  --region us-east-1 \
  --query 'Users[?contains(UserName, `test`)].[UserName,CreateDate]' \
  --output table
```

### Check Existing Access Keys
```bash
# Show keys for test user
aws iam list-access-keys \
  --user-name iam-test-user-dev-1 \
  --profile dw-nonprod \
  --region us-east-1 \
  --output table

# Check key age (if they have existing keys)
aws iam get-access-key-last-used \
  --access-key-id AKIA... \
  --profile dw-nonprod \
  --region us-east-1
```

### Verify Infrastructure is Deployed
```bash
# Check Lambda functions exist
aws lambda list-functions \
  --profile dw-nonprod \
  --region us-east-1 \
  --query 'Functions[?contains(FunctionName, `iam`)].[FunctionName,Runtime,LastModified]' \
  --output table

# Expected functions:
# - iam-access-key-enforcement
# - iam-key-download-tracker
# - iam-key-url-regenerator
# - iam-key-cleanup
```

---

## 2️⃣ Trigger Automated Rotation

### Invoke Enforcement Lambda (Main Demo)
```bash
# Trigger key rotation enforcement
aws lambda invoke \
  --function-name iam-access-key-enforcement \
  --profile dw-nonprod \
  --region us-east-1 \
  /tmp/enforcement-output.json

# Show the output
cat /tmp/enforcement-output.json | jq '.'
```

**Expected Output:**
```json
{
  "statusCode": 200,
  "body": {
    "message": "Access key enforcement completed",
    "metrics": {
      "total_keys": 27,
      "warning_keys": 2,
      "urgent_keys": 0,
      "expired_keys": 0,
      "disabled_keys": 0
    },
    "notifications_sent": 2
  }
}
```

### What This Does (Explain to Audience)
- ✅ Scans all IAM users in the account
- ✅ Identifies keys ≥ 0 days old (test threshold)
- ✅ Creates new access key for each user
- ✅ Encrypts credentials (access key ID + secret)
- ✅ Stores in S3 with AES-256 encryption
- ✅ Generates 7-day pre-signed download URL
- ✅ Creates DynamoDB tracking record
- ✅ Sends HTML email with download link
- ✅ Publishes CloudWatch metrics

---

## 3️⃣ Show Artifacts Created

### Check DynamoDB Tracking Records
```bash
# Scan rotation tracking table
aws dynamodb scan \
  --table-name iam-key-rotation-tracking \
  --profile dw-nonprod \
  --region us-east-1 \
  --output json | jq '.Items[] | {
    username: .PK.S,
    old_key: .SK.S,
    new_key: .new_key_id.S,
    status: .status.S,
    downloaded: .downloaded.BOOL,
    url_expires: .current_url_expires.S,
    deletion_date: .old_key_deletion_date.S
  }'
```

**Key Fields to Point Out:**
- `PK` (username) + `SK` (old_key_id) - Composite key
- `new_key_id` - The newly created key
- `status: rotation_initiated` - Lifecycle state
- `downloaded: false` - Not yet downloaded
- `current_url_expires` - Day 7 reminder trigger date
- `old_key_deletion_date` - Day 14 cleanup date

### Verify S3 Encrypted Credentials
```bash
# List credentials in S3
aws s3 ls s3://iam-credentials-056598616360/credentials/ \
  --profile dw-nonprod \
  --recursive

# Show file details
aws s3 ls s3://iam-credentials-056598616360/credentials/ \
  --profile dw-nonprod \
  --recursive \
  --human-readable
```

**Expected Files:**
```
credentials/iam-test-user-dev-1_AKIA..._.csv
credentials/iam-test-user-dev-2_AKIA..._.csv
```

### Check CloudWatch Logs
```bash
# Tail enforcement Lambda logs
aws logs tail /aws/lambda/iam-access-key-enforcement \
  --profile dw-nonprod \
  --region us-east-1 \
  --since 5m \
  --follow
```

**Look For:**
- "Processing key ... for user ..."
- "Created new access key: AKIA..."
- "Stored credentials in S3: credentials/..."
- "Created DynamoDB tracking record"
- "Sent email notification to ..."

### View CloudWatch Metrics
```bash
# Get metric data for key rotation
aws cloudwatch get-metric-statistics \
  --namespace "IAM/KeyRotation" \
  --metric-name "warning_keys" \
  --dimensions Name=Environment,Value=dev \
  --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum \
  --profile dw-nonprod \
  --region us-east-1
```

---

## 4️⃣ Check Email Notification

### What to Show in Email
Open the email received at the configured address:

**Key Elements:**
- ✅ Professional HTML formatting with color-coded severity
- ✅ Clear subject line: "🔑 IAM Access Key Rotation Required"
- ✅ One-time download link (pre-signed URL)
- ✅ 7-day expiration warning
- ✅ Security instructions
- ✅ 14-day retention timeline
- ✅ Old key will be deleted after download

**Sample Email Content:**
```
Subject: 🔑 IAM Access Key Rotation Required - Action Required

Your IAM access key is 0 days old and requires rotation.

Download Your New Credentials:
[Download Link] (Valid for 7 days)

⚠️ IMPORTANT:
- This link can only be used ONCE
- Download will delete the file immediately
- Old key (AKIA...) will be deleted in 14 days
- New key details in downloaded CSV file

Timeline:
Day 0: ✅ New key created
Day 7: 📧 Reminder if not downloaded
Day 14: 🗑️ Old key automatically deleted
```

### Optional: Download Test
```bash
# If demonstrating download, use curl or browser
# After download, show:
```

```bash
# Verify file deleted from S3 after download
aws s3 ls s3://iam-credentials-056598616360/credentials/ \
  --profile dw-nonprod \
  --recursive
# (Should not show the downloaded file)

# Check DynamoDB updated
aws dynamodb get-item \
  --table-name iam-key-rotation-tracking \
  --key '{"PK":{"S":"iam-test-user-dev-1"},"SK":{"S":"AKIA..."}}' \
  --profile dw-nonprod \
  --region us-east-1 \
  | jq '.Item.downloaded.BOOL'
# Should show: true
```

---

## 5️⃣ Simulate Day 7 Reminder (Optional)

### Run Interactive Test Script
```bash
cd /home/ec2-user/GIT/iam-key-rotation/tests

# Run workflow test
python3 test_rotation_workflow.py

# Select option 1: Test Day 7 URL Expiration
```

**What This Does:**
1. Backdates DynamoDB `current_url_expires` to today
2. Sets `downloaded: false`
3. Invokes `iam-key-url-regenerator` Lambda
4. Generates new 7-day pre-signed URL
5. Sends reminder email

### Verify Reminder Sent
```bash
# Check URL regenerator logs
aws logs tail /aws/lambda/iam-key-url-regenerator \
  --profile dw-nonprod \
  --region us-east-1 \
  --since 2m

# Look for:
# "Found 1 records with expiring URLs"
# "Generated new pre-signed URL"
# "Sent reminder email to ..."
```

---

## 6️⃣ Simulate Day 14 Cleanup (Optional)

### Run Cleanup Test
```bash
cd /home/ec2-user/GIT/iam-key-rotation/tests

# Run workflow test
python3 test_rotation_workflow.py

# Select option 2: Test Day 14 Cleanup
```

**What This Does:**
1. Backdates DynamoDB `old_key_deletion_date` to past
2. Invokes `iam-key-cleanup` Lambda
3. Deletes the old IAM access key
4. Updates DynamoDB: `old_key_deleted: true`, `status: completed`

### Verify Old Key Deleted
```bash
# Check user's access keys
aws iam list-access-keys \
  --user-name iam-test-user-dev-1 \
  --profile dw-nonprod \
  --region us-east-1

# Should only show NEW key (old one deleted)

# Check DynamoDB status
aws dynamodb get-item \
  --table-name iam-key-rotation-tracking \
  --key '{"PK":{"S":"iam-test-user-dev-1"},"SK":{"S":"AKIA..."}}' \
  --profile dw-nonprod \
  --region us-east-1 \
  | jq '.Item | {status: .status.S, old_key_deleted: .old_key_deleted.BOOL}'

# Expected: {"status": "completed", "old_key_deleted": true}
```

---

## 🎨 Demo Talking Points

### Business Value
- **Eliminates manual rotation** - No more user scripts or manual processes
- **Security compliance** - Automated enforcement of key rotation policies
- **Audit trail** - Complete tracking in DynamoDB + CloudTrail logs
- **User experience** - Simple email with download link, one-time use
- **Cost effective** - Serverless architecture, pay per execution

### Technical Highlights
- **4 Lambda functions** orchestrated by EventBridge
- **S3 encryption** - AES-256 with pre-signed URLs
- **CloudTrail integration** - Real-time download detection
- **DynamoDB tracking** - Complete lifecycle management
- **Least privilege IAM** - Separate roles for each Lambda

### Security Features
- **One-time download** - S3 file deleted after first access
- **Time-bound URLs** - 7-day expiration on pre-signed URLs
- **Automatic cleanup** - Old keys deleted after 14 days
- **Tag-based exemption** - Service accounts can be excluded
- **Complete audit logging** - CloudTrail + CloudWatch

### Production Readiness
- **Multi-environment** - Terragrunt deployment structure
- **Configurable thresholds** - Test: 0/1/2 days, Prod: 75/85/90 days
- **CloudWatch alarms** - Proactive monitoring
- **Comprehensive docs** - All READMEs updated

---

## 🆘 Troubleshooting Demo Issues

### No notifications sent (notifications_sent: 0)
**Cause:** AWS credential report doesn't include test users yet (caching)
**Solution:** 
```bash
# Check credential report age
aws iam get-credential-report --profile dw-nonprod --region us-east-1 | jq '.GeneratedTime'

# If stale, wait a few hours or demo with existing real users
```

### Lambda invocation errors
```bash
# Check Lambda errors
aws lambda get-function \
  --function-name iam-access-key-enforcement \
  --profile dw-nonprod \
  --region us-east-1

# Review recent errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/iam-access-key-enforcement \
  --filter-pattern "ERROR" \
  --start-time $(date -u -d '1 hour ago' +%s)000 \
  --profile dw-nonprod \
  --region us-east-1
```

### No email received
- Check SES sender email is verified
- Check spam/junk folder
- Verify user has email tag in IAM: `Key=email,Value=your@email.com`
- Check Lambda logs for SES send confirmation

---

## 📊 Quick Reference Commands

### One-Liner Demo Sequence
```bash
# 1. Trigger rotation
aws lambda invoke --function-name iam-access-key-enforcement --profile dw-nonprod --region us-east-1 /tmp/out.json && cat /tmp/out.json | jq

# 2. Show DynamoDB records
aws dynamodb scan --table-name iam-key-rotation-tracking --profile dw-nonprod --region us-east-1 --max-items 3

# 3. Show S3 files
aws s3 ls s3://iam-credentials-056598616360/credentials/ --profile dw-nonprod

# 4. Check logs
aws logs tail /aws/lambda/iam-access-key-enforcement --profile dw-nonprod --since 5m
```

---

## ✅ Demo Success Criteria

- [x] Lambda invokes successfully
- [x] `notifications_sent > 0` in response
- [x] DynamoDB records created with correct schema
- [x] S3 credentials files exist and encrypted
- [x] Email received with download link
- [x] CloudWatch logs show detailed execution
- [x] CloudWatch metrics published
- [x] Day 7 reminder can be simulated
- [x] Day 14 cleanup can be simulated

---

**Good luck with the demo! 🏴‍☠️**
