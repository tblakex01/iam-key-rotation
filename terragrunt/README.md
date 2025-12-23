# 🚀 Terragrunt Multi-Environment Deployment

This directory contains Terragrunt configurations for deploying the IAM Key Rotation system across multiple AWS accounts and regions.

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

The `dev` environment is configured for **SAFE TESTING** with:

### **Test Users Created:**
- `iam-test-user-dev-1` - Normal test user
- `iam-test-user-dev-2` - Test user (explicitly not exempt)  
- `iam-test-exempt-user-dev` - Test exemption functionality

### **Safe Testing Thresholds:**
- **Warning**: 30 days (instead of 75)
- **Urgent**: 45 days (instead of 85)
- **Disable**: 60 days (instead of 90)
- **Auto-disable**: `false` (no automatic disabling)

### **Enhanced Monitoring:**
- **Schedule**: Every 6 hours (instead of daily)
- **Logging**: DEBUG level for detailed feedback
- **Alarms**: More sensitive thresholds for quick feedback

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
2. Set realistic thresholds (75/85/90 days)
3. Enable `auto_disable = true` for strict enforcement
4. Configure real user email addresses
5. Set daily execution schedule

## 📊 Monitoring

### **CloudWatch Resources:**
- **Log Group**: `/aws/lambda/iam-access-key-enforcement`
- **Metrics Namespace**: `IAM/KeyRotation`
- **Alarms**: Expired keys and urgent notifications

### **SNS Notifications:**
- Auto-created SNS topic per environment
- Email notifications for CloudWatch alarms
- SES email notifications to users

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

**Test Lambda function:**
```bash
aws lambda invoke \
  --function-name iam-access-key-enforcement \
  --profile your-aws-profile \
  --region us-east-1 \
  /tmp/test-output.json
```

**Check CloudWatch logs:**
```bash
aws logs filter-log-events \
  --log-group-name "/aws/lambda/iam-access-key-enforcement" \
  --profile your-aws-profile \
  --region us-east-1
```
