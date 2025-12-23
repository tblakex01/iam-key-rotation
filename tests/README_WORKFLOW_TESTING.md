# IAM Key Rotation Workflow Testing

## Overview

This interactive test script simulates the **14-day automated rotation lifecycle** by backdating DynamoDB timestamps and invoking the URL regenerator (day 7) and cleanup (day 14) Lambda functions. Use this to validate the complete automated workflow without waiting 14 days.

## Quick Start

```bash
# Navigate to tests directory
cd /path/to/iam-key-rotation/tests

# Install dependencies
pip3 install boto3 rich

# Run interactive tests
python3 test_rotation_workflow.py
```

## What It Tests

### 1. Day 7 Reminder (URL Regenerator)
- Backdates DynamoDB record to simulate 7 days old
- Sets `downloaded: false` to trigger reminder
- Invokes `iam-key-url-regenerator` Lambda
- Verifies:
  - New pre-signed URL generated
  - Reminder email sent
  - DynamoDB updated with new expiration

### 2. Day 14 Cleanup (Old Key Deletion)
- Backdates DynamoDB record to simulate 14+ days old
- Invokes `iam-key-cleanup` Lambda
- Verifies:
  - Old IAM access key deleted
  - DynamoDB marked `old_key_deleted: true`
  - Status updated to `completed`

## Prerequisites

**1. Infrastructure must be deployed:**
```bash
cd terragrunt/mvw-dw-nonprod/us-east-1/dev/iam-key-rotation
terragrunt apply
```

**2. Initial rotation must be triggered:**
```bash
# Run enforcement Lambda to create rotation records
aws lambda invoke \
  --function-name iam-access-key-enforcement \
  --profile dw-nonprod \
  --region us-east-1 \
  /tmp/enforcement-output.json

# Wait for AWS credential report to include test users (may take hours)
# Or test with existing real users who have rotation records
```

**3. Python dependencies installed:**
```bash
pip3 install boto3 rich
```

**4. AWS credentials configured:**
```bash
aws configure --profile dw-nonprod
```

## Test Scenarios

**Option 1: Test Day 7 Only**
- Choose option 1
- Check email for reminder with new download link

**Option 2: Test Day 14 Only**
- Choose option 2
- Verify old IAM key is actually deleted

**Option 3: Full Workflow**
- Choose option 3
- Runs both tests in sequence
- Simulates complete 14-day cycle

## What to Expect

### Day 7 Reminder
```
✅ Email sent with subject: "⏰ REMINDER: AWS Credentials Expiring in 7 Days"
✅ New pre-signed URL with 7-day expiration
✅ DynamoDB email_sent_count incremented
```

### Day 14 Cleanup
```
✅ Old IAM key deleted from AWS
✅ DynamoDB status: "completed"
✅ old_key_deleted: true
```

## Troubleshooting

**"No test record found"**
- Run the main enforcement Lambda first to create a rotation record

**"Old key doesn't exist"**
- That's fine - the test already deleted it or it was cleaned up

**Lambda invocation errors**
- Check Lambda logs: `aws logs tail /aws/lambda/iam-key-url-regenerator --follow`
- Verify IAM permissions

## Clean Up

The script only manipulates DynamoDB timestamps - it doesn't create new keys or resources. No cleanup needed!

## Important Notes

- **Uses existing DynamoDB records** - enforcement Lambda must run first to create records
- **Simulates time passage** by backdating `current_url_expires` and `old_key_deletion_date` timestamps
- **Safe to run multiple times** - only modifies DynamoDB timestamps, doesn't create new resources
- **Test records only** - queries for users with `rotation_initiated` status
- **AWS credential report caching** - test users may take hours to appear in credential reports
- **Evening testing** - AWS credential reports refresh faster during off-peak hours

## System Architecture Context

This test script validates 2 of 4 Lambda functions in the automated rotation system:
- ✅ **Enforcement Lambda** - Creates keys (run manually to generate test data)
- ⏭️ **Download Tracker** - Triggered by actual S3 GetObject (not testable via script)
- ✅ **URL Regenerator** - Tested via option 1 (day 7 reminder)
- ✅ **Cleanup Lambda** - Tested via option 2 (day 14 deletion)

**Complete workflow:**
1. Day 0: Enforcement creates key → S3 → DynamoDB → Email
2. Day 1-7: User downloads → CloudTrail → Download Tracker → Delete S3
3. Day 7: URL Regenerator sends reminder (if not downloaded)
4. Day 14: Cleanup deletes old IAM key
