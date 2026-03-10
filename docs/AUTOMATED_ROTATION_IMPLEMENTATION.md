# 🔄 Automated Key Rotation Implementation

## 🎯 Overview

This document describes the new **automated IAM key rotation** system that replaces manual script-based rotation with a fully automated workflow using S3, DynamoDB, and Lambda functions.

## 📋 What Changed

### **Before (Manual Process)**
```
Old Key → Email Warning → User Runs Script → User Manages Credentials
```

### **After (Automated Process)**
```
Old Key → Lambda Creates New Key → Store in S3 (encrypted) 
       → Email w/ One-Time Download Link → User Downloads 
       → File Auto-Deletes → Old Key Deleted After 14 Days
```

## 🏗️ New Infrastructure

### **S3 Bucket**
- **Name:** `iam-credentials-{account-id}`
- **Purpose:** Temporary encrypted storage for rotated credentials
- **Encryption:** AES-256 server-side encryption
- **Lifecycle:** Files deleted on download (not time-based)
- **Access:** Restricted to Lambda execution roles only

### **DynamoDB Table**
- **Name:** `iam-key-rotation-tracking`
- **Purpose:** Track rotation status, downloads, and URLs
- **Billing:** On-demand (pay per request)
- **Indexes:**
  - `status-index`: Query by rotation status
  - `url-expiration-index`: Query expiring URLs
- **TTL:** Auto-delete records 90 days after rotation

### **Lambda Functions**

#### 1. **iam-access-key-enforcement** (Modified)
- **Trigger:** EventBridge (6 hours in dev, configurable)
- **New Actions:**
  - Creates new IAM access keys at warning threshold
  - Encrypts and stores credentials in S3
  - Generates 7-day pre-signed URL
  - Writes tracking record to DynamoDB
  - Sends initial email with download link

#### 2. **iam-key-download-tracker** (New)
- **Trigger:** CloudTrail S3 Data Events → EventBridge
  - *Note: S3 bucket notifications don't support GetObject events, so we use CloudTrail to track S3 GetObject API calls*
- **Actions:**
  - Updates DynamoDB: marks as downloaded
  - Records IP address and timestamp
  - **Deletes S3 file immediately** (one-time download)

#### 3. **iam-key-url-regenerator** (New)
- **Trigger:** EventBridge (daily at 2 AM UTC)
- **Actions:**
  - Queries DynamoDB for expiring URLs (day 7)
  - Skips if already downloaded
  - Generates new 7-day pre-signed URL
  - Sends reminder email
  - Updates DynamoDB with new URL

#### 4. **iam-key-cleanup** (New)
- **Trigger:** EventBridge (daily at 3 AM UTC)
- **Actions:**
  - Queries for rotations >14 days old
  - Deletes old IAM access keys
  - Updates DynamoDB status
  - Publishes CloudWatch metrics

## 📧 Email Templates

### **Initial Notification (Day 0)**
- **Subject:** 🔐 ACTION REQUIRED: New AWS Access Key Available
- **Content:**
  - ⚠️ **ONE-TIME DOWNLOAD WARNING** (prominent)
  - Download link (7-day expiration)
  - Old key info and deletion date
  - Step-by-step instructions

### **Reminder (Day 7)**
- **Subject:** ⏰ REMINDER: AWS Credentials Expiring in 7 Days
- **Content:**
  - Urgency messaging
  - New download link (another 7 days)
  - Final warning about old key deletion
  - Help contact information

**Templates saved:** `docs/email-templates.md`

## 🗄️ DynamoDB Schema

```python
{
  "PK": "USER#username",
  "SK": "ROTATION#2024-12-23T00:00:00Z",
  
  # Key Information
  "username": "john.doe",
  "email": "john.doe@mvwc.com",
  "old_key_id": "AKIAOLD123",
  "new_key_id": "AKIANEW456",
  
  # Timeline
  "rotation_initiated": "2024-12-23T00:00:00Z",
  "current_url_expires": "2024-12-30T00:00:00Z",
  "old_key_deletion_date": "2025-01-06T00:00:00Z",
  
  # Status
  "status": "pending_download",  # or "downloaded", "expired_no_download"
  
  # S3 Info
  "s3_bucket": "iam-credentials-056598616360",
  "s3_key": "credentials/john.doe/2024-12-23-credentials.json.encrypted",
  "current_presigned_url": "https://...",
  
  # Tracking
  "downloaded": false,
  "download_timestamp": null,
  "download_ip": null,
  "email_sent_count": 1,
  "old_key_deleted": false,
  
  # Cleanup
  "TTL": 1738368000  # 90 days after rotation
}
```

## ⏱️ 14-Day Timeline

```
Day 0: Key Rotation
├─ Lambda creates new key
├─ Store encrypted in S3
├─ Generate pre-signed URL (expires day 7)
├─ Email #1: Initial notification
└─ DynamoDB: status=pending_download

Day 7: URL Expiration Check
├─ Downloaded? → Skip
├─ Not downloaded? → Continue
├─ Generate NEW pre-signed URL (expires day 14)
├─ Email #2: Reminder
└─ DynamoDB: reminder_count++

Day 14: Final Cleanup
├─ Delete old IAM key (regardless of download)
├─ DynamoDB: status=completed or expired_no_download
└─ (Future: SNS alert if not downloaded)
```

## 📁 New Files Created

### Terraform Infrastructure
```
terraform/iam/
├── s3.tf                          # S3 bucket configuration
├── dynamodb.tf                    # DynamoDB tracking table
├── download_tracker_lambda.tf     # Download tracker infrastructure
├── url_regenerator_lambda.tf      # URL regenerator infrastructure
├── cleanup_lambda.tf              # Cleanup Lambda infrastructure
├── lambda.tf                      # Modified: added S3/DynamoDB permissions
└── variables.tf                   # Modified: added new variables
```

### Lambda Functions
```
lambda/
├── download_tracker/
│   └── download_tracker.py        # NEW: Tracks downloads, deletes files
├── url_regenerator/
│   └── url_regenerator.py         # NEW: Regenerates URLs, sends reminders
└── cleanup/
    └── cleanup.py                 # NEW: Deletes old keys
```

### Documentation
```
docs/
├── email-templates.md             # Email templates with variables
└── AUTOMATED_ROTATION_IMPLEMENTATION.md  # This file
```

## 🚀 Deployment Steps

### 1. Navigate to Terragrunt Directory
```bash
cd /home/ec2-user/GIT/iam-key-rotation/terragrunt/mvw-dw-nonprod/us-east-1/dev/iam-key-rotation
```

### 2. Review Changes
```bash
terragrunt plan
```

**Expected new resources:**
- S3 bucket: `iam-credentials-056598616360`
- DynamoDB table: `iam-key-rotation-tracking`
- 3 new Lambda functions
- S3 event notification
- 2 new EventBridge schedules
- Updated IAM policies

### 3. Deploy Infrastructure
```bash
terragrunt apply
```

**Deployment time:** ~2-3 minutes

### 4. Verify Deployment
```bash
# Check S3 bucket
aws s3 ls --profile dw-nonprod | grep iam-credentials

# Check DynamoDB table
aws dynamodb describe-table \
  --table-name iam-key-rotation-tracking \
  --profile dw-nonprod \
  --region us-east-1

# Check all Lambda functions
aws lambda list-functions \
  --profile dw-nonprod \
  --region us-east-1 \
  --query 'Functions[?starts_with(FunctionName, `iam-`)].FunctionName'
```

## 🧪 Testing the New System

### Test 1: Trigger Rotation Manually
```bash
# Invoke enforcement Lambda
aws lambda invoke \
  --function-name iam-access-key-enforcement \
  --region us-east-1 \
  --profile dw-nonprod \
  /tmp/lambda-output.json

cat /tmp/lambda-output.json
```

**Expected:** New key created, S3 file uploaded, email sent

### Test 2: Verify S3 Storage
```bash
aws s3 ls s3://iam-credentials-056598616360/credentials/ \
  --profile dw-nonprod \
  --recursive
```

**Expected:** See credential files for test users

### Test 3: Check DynamoDB Tracking
```bash
aws dynamodb scan \
  --table-name iam-key-rotation-tracking \
  --profile dw-nonprod \
  --region us-east-1 \
  --max-items 5
```

**Expected:** See rotation records with status=pending_download

### Test 4: Download Credentials
1. Check your Gmail inbox (bspeagle@gmail.com)
2. Click the download link in the email
3. Verify file downloads
4. **Check S3 - file should be DELETED**

```bash
# Should return empty or not found
aws s3 ls s3://iam-credentials-056598616360/credentials/iam-test-user-dev-1/ \
  --profile dw-nonprod
```

### Test 5: Verify Download Tracking
```bash
aws dynamodb scan \
  --table-name iam-key-rotation-tracking \
  --profile dw-nonprod \
  --region us-east-1 \
  --filter-expression "downloaded = :true" \
  --expression-attribute-values '{":true":{"BOOL":true}}'
```

**Expected:** Record shows downloaded=true, download_ip, timestamp

## 🔧 Configuration Variables

Add to `terragrunt/mvw-dw-nonprod/us-east-1/dev/iam-key-rotation/config.hcl`:

```hcl
locals {
  # ... existing config ...
  
  # NEW: Credential retention configuration
  credential_retention_days = 14  # 14 days = 2 URLs @ 7 days each
}
```

## 📊 CloudWatch Metrics

### New Metrics (Published by cleanup Lambda)
- `IAM/KeyRotation/keys_cleaned_up`: Count of keys deleted
- `IAM/KeyRotation/cleanup_failures`: Failed deletions

### Existing Metrics (Still Published)
- `IAM/KeyRotation/total_keys`
- `IAM/KeyRotation/warning_keys`
- `IAM/KeyRotation/urgent_keys`
- `IAM/KeyRotation/expired_keys`
- `IAM/KeyRotation/disabled_keys`

## 🛡️ Security Features

### ✅ Implemented
- Server-side encryption (AES-256) for S3
- Pre-signed URLs with 7-day expiration
- One-time download (file deleted after access)
- DynamoDB encryption at rest
- Least-privilege IAM policies
- Complete audit trail in DynamoDB
- CloudTrail logging of all S3 access

### 🔮 Future Enhancements (Not in Scope Yet)
- SNS notifications for non-downloads
- Security team escalation at day 14
- Weekly compliance reports
- Dashboard for tracking system

## 💰 Cost Estimate

**Monthly cost for 100 users (estimated):**
```
S3 Storage: $0.023/GB × 0.1GB            = $0.002
S3 Requests: $0.0004/1K × 1K              = $0.40
DynamoDB: On-demand × 1K writes/reads     = $1.25
Lambda: 4 functions × 100 invokes         = $0.20
Total:                                    ≈ $2/month
```

## 🚨 Breaking Changes

### What's Different
1. **No more manual scripts** - Users click email links instead
2. **One-time downloads** - Can't re-download from same link
3. **Automated key creation** - Lambda creates keys, not users
4. **14-day grace period** - Old keys deleted automatically

### Migration Notes
- Existing deployed infrastructure is NOT affected
- New resources added alongside existing ones
- Test thoroughly in dev before production
- Users will need training on new email-based process

## 📞 Support

**Questions or issues?**
- Contact: cloud-security@mvwc.com
- Escalation: Deploy issues to #infrastructure channel

---

**Created:** December 23, 2025  
**Author:** beepboop (Windsurf AI)  
**Status:** Ready for dev deployment
