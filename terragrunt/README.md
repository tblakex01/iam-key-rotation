# 🚀 Terragrunt Multi-Environment Deployment

This directory contains Terragrunt configurations for deploying the **fully automated IAM Key Rotation system** across multiple AWS accounts and regions. The system includes 4 Lambda functions, S3 encrypted storage, DynamoDB tracking, CloudTrail monitoring, and EventBridge orchestration.

## 📁 Directory Structure

```
terragrunt/
├── root.terragrunt.hcl                    # Root configuration with remote state
├── your-account-name/                     # Your AWS account directory
│   ├── account.hcl                        # Account-specific settings
│   └── us-east-1/
│       ├── region.hcl                     # Region-specific settings  
│       └── dev/
│           ├── env.hcl                    # Environment configuration
│           └── iam-key-rotation/
│               └── terragrunt.hcl         # Service deployment config
```

## 🧪 Test Environment Setup

The `dev` environment is configured for **IMMEDIATE TESTING** with:

### **Test Users Created:**
- `iam-test-user-dev-1` - Normal test user with automated key creation
- `iam-test-user-dev-2` - Test user (explicitly not exempt)  
- `iam-test-exempt-user-dev` - Test exemption functionality

### **Ultra-Fast Testing Thresholds:**
- **Warning**: 0 days (trigger rotation immediately)
- **Urgent**: 1 day (urgent notices at 1 day old)
- **Disable**: 2 days (old key deleted after 2 days)
- **Auto-disable**: `false` (manual deletion for safety)
- **Retention**: 14 days (production-like cleanup workflow)

### **Automated System Components:**
- **4 Lambda Functions**: enforcement, download_tracker, url_regenerator, cleanup
- **2 S3 Buckets**: credentials storage (encrypted), CloudTrail logs
- **1 DynamoDB Table**: rotation tracking with composite keys and GSI indexes
- **CloudTrail**: S3 Data Events for download detection
- **EventBridge Rules**: Daily enforcement, day 7 reminders, day 14 cleanup

### **Enhanced Monitoring:**
- **Schedule**: Every 6 hours (for faster testing feedback)
- **Logging**: Detailed CloudWatch logs for all 4 Lambdas
- **Alarms**: Sensitive thresholds for quick issue detection

## 🚀 Deployment Commands

### **Initial Setup (First Time Only):**

```bash
# 1. Copy example configuration files and customize for your organization
cp terragrunt/your-account-name/account.hcl.example terragrunt/your-account-name/account.hcl
cp terragrunt/your-account-name/us-east-1/dev/iam-key-rotation/config.hcl.example \
   terragrunt/your-account-name/us-east-1/dev/iam-key-rotation/config.hcl

# 2. Edit account.hcl with your AWS account details
# Update: account_name, account_id, profile

# 3. Edit config.hcl with your organization settings  
# Update: sender_email, test user emails, common_tags
```

### **Deploy Dev Environment:**

```bash
# Navigate to the service directory
cd terragrunt/your-account-name/us-east-1/dev/iam-key-rotation/

# Initialize Terragrunt (creates S3 bucket, DynamoDB table, etc.)
terragrunt init

# Plan the deployment (review what will be created)
terragrunt plan

# Apply the deployment 
terragrunt apply
```

### **Useful Terragrunt Commands:**

```bash
# View the generated terraform.tfvars
cat terraform.tfvars

# Check current state
terragrunt show

# Destroy the deployment (cleanup)
terragrunt destroy

# Format all HCL files
terragrunt hclfmt

# Validate configuration
terragrunt validate
```

## ⚙️ Configuration Management

### **Environment-Specific Settings:**

Each environment (`dev`, `staging`, `prod`) has its own `env.hcl` file with:
- IAM policy thresholds
- Auto-disable settings
- Test user configurations
- Lambda settings
- CloudWatch alarm thresholds

### **Account-Specific Settings:**

Each account has an `account.hcl` file with:
- AWS account ID and profile
- Account-wide security settings
- Cost center and billing information

### **Region-Specific Settings:**

Each region has a `region.hcl` file with:
- Availability zones
- SES configuration
- Backup and DR settings

## 🔧 Customization

### **Adding New Environments:**

1. **Create environment directory:**
   ```bash
   mkdir -p your-account-name/us-east-1/staging
   ```

2. **Create env.hcl:**
   ```bash
   cp your-account-name/us-east-1/dev/env.hcl your-account-name/us-east-1/staging/env.hcl
   ```

3. **Update settings** in `staging/env.hcl`

4. **Create service deployment:**
   ```bash
   mkdir -p your-account-name/us-east-1/staging/iam-key-rotation
   cp your-account-name/us-east-1/dev/iam-key-rotation/terragrunt.hcl \
      your-account-name/us-east-1/staging/iam-key-rotation/
   ```

### **Adding New Regions:**

1. **Create region directory:**
   ```bash
   mkdir -p your-account-name/us-west-2
   ```

2. **Create region.hcl:**
   ```bash
   cp your-account-name/us-east-1/region.hcl your-account-name/us-west-2/region.hcl
   ```

3. **Update region** in `us-west-2/region.hcl`

## 🔐 Security Notes

### **Test Users Only:**
- **NEVER** add real user emails to test environments
- All test notifications go to your email address
- Test users are clearly marked with `purpose = "iam-key-rotation-testing"`

### **Safe Testing:**
- `auto_disable = false` prevents accidental key disabling
- Shorter thresholds (30/45/60 days) for faster testing
- More frequent Lambda execution for immediate feedback

### **Production Deployment:**
When ready for production:
1. Create production environment configuration
2. Set production thresholds (75/85/90 days)
3. Consider enabling `auto_disable = true` for strict enforcement (optional)
4. Configure real user email addresses in IAM tags
5. Set daily execution schedule: `rate(1 day)`
6. Keep 14-day retention for old key cleanup
7. Verify SES sender email is production-ready
8. Configure SNS topics for CloudWatch alarms

## 📊 Monitoring

### **CloudWatch Log Groups:**
- `/aws/lambda/iam-access-key-enforcement` - Enforcement Lambda logs
- `/aws/lambda/iam-key-download-tracker` - Download tracking logs
- `/aws/lambda/iam-key-url-regenerator` - Day 7 reminder logs
- `/aws/lambda/iam-key-cleanup` - Day 14 cleanup logs

### **CloudWatch Metrics:**
- **Namespace**: `IAM/KeyRotation`
- **Metrics**: `total_keys`, `warning_keys`, `urgent_keys`, `expired_keys`
- **Alarms**: Expired keys threshold, non-compliant users

### **DynamoDB Tracking:**
- Table: `iam-key-rotation-tracking`
- Tracks: rotation status, download status, timestamps, old key deletion
- GSI: `status-index` for querying by rotation status

### **S3 Storage:**
- Credentials bucket: `iam-credentials-{account-id}`
- CloudTrail logs: `iam-credentials-cloudtrail-{account-id}`

### **Email Notifications:**
- SES-powered HTML email templates
- Day 0: Rotation initiated with download link
- Day 7: Reminder if credentials not downloaded
- Email tracking in DynamoDB

## 🔄 State Management

Terragrunt automatically manages:
- **S3 Backend**: `iam-key-rotation-{account-name}-tfstate`
- **DynamoDB Locks**: `iam-key-rotation-{account-name}-terraform-locks`  
- **State Isolation**: Each environment has separate state files
- **Automatic Tagging**: All resources tagged with environment info

## 🆘 Troubleshooting

### **Common Issues:**

**S3 bucket already exists:**
```bash
# Check if bucket exists in different region
aws s3api list-buckets --query 'Buckets[?contains(Name, `iam-key-rotation`)]'
```

**Permission errors:**
```bash
# Verify AWS profile is configured
aws sts get-caller-identity --profile your-aws-profile
```

**Terragrunt cache issues:**
```bash
# Clean cache and retry
rm -rf .terragrunt-cache
terragrunt init
```

### **Validation:**

**Test enforcement Lambda (triggers rotation):**
```bash
aws lambda invoke \
  --function-name iam-access-key-enforcement \
  --profile your-aws-profile \
  --region us-east-1 \
  /tmp/test-output.json && cat /tmp/test-output.json
```

**Run workflow tests (day 7/14 simulation):**
```bash
cd /path/to/repo
python3 tests/test_rotation_workflow.py
```

**Check DynamoDB for rotation records:**
```bash
aws dynamodb scan \
  --table-name iam-key-rotation-tracking \
  --profile your-aws-profile \
  --region us-east-1
```

**Verify S3 credentials exist:**
```bash
aws s3 ls s3://iam-credentials-YOUR-ACCOUNT-ID/credentials/ \
  --profile your-aws-profile
```

**Check CloudWatch logs (all Lambdas):**
```bash
# Enforcement Lambda
aws logs tail /aws/lambda/iam-access-key-enforcement --follow --profile your-aws-profile

# Download Tracker
aws logs tail /aws/lambda/iam-key-download-tracker --follow --profile your-aws-profile

# URL Regenerator
aws logs tail /aws/lambda/iam-key-url-regenerator --follow --profile your-aws-profile

# Cleanup Lambda
aws logs tail /aws/lambda/iam-key-cleanup --follow --profile your-aws-profile
```
