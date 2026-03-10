# 🚀 AWS IAM Key Rotation - Complete Deployment Guide

This guide covers the **complete end-to-end deployment** of the AWS IAM Key Rotation system, including all manual prerequisites and configuration steps not handled by Terraform.

## 📋 Prerequisites Checklist

Before deploying, ensure you have:

- [ ] **AWS CLI configured** with appropriate credentials
- [ ] **Terraform 1.5+** installed
- [ ] **IAM permissions** for infrastructure deployment
- [ ] **SES service access** in your target region
- [ ] **Python 3.9+** for testing scripts locally

## 🏗️ Phase 1: Infrastructure Deployment

### 1.1 Configure Terragrunt Variables

**⚠️ IMPORTANT: This repo is public - never commit sensitive information!**

```bash
# Copy example files and customize for your organization
cp terragrunt/your-account-name/account.hcl.example terragrunt/your-account-name/account.hcl
cp terragrunt/your-account-name/us-east-1/dev/iam-key-rotation/config.hcl.example \
   terragrunt/your-account-name/us-east-1/dev/iam-key-rotation/config.hcl
```

Edit `config.hcl` with your organization's settings:

```hcl
# Required: Update with your organization's email
sender_email = "security-alerts@yourcompany.com"

# Optional: Customize thresholds
warning_threshold  = 75    # Days before warning
urgent_threshold   = 85    # Days before urgent notice  
disable_threshold  = 90    # Days before auto-disable
auto_disable      = true   # Enable automatic key disabling

# Optional: SNS topic for CloudWatch alarms
alarm_sns_topic   = "arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:iam-alerts"

# Required: Update user list with your IAM users
user_info = {
  "john.doe" = {
    email = "john.doe@yourcompany.com"
  }
  "jane.smith" = {
    email = "jane.smith@yourcompany.com"
    user_tags = {
      "department" = "engineering"
    }
  }
}
```

### 1.2 Deploy Infrastructure

```bash
# Navigate to your deployment directory
cd terragrunt/your-account-name/us-east-1/dev/iam-key-rotation/

# Initialize Terragrunt
terragrunt init

# Review the deployment plan
terragrunt plan

# Deploy (creates Lambda, IAM roles, CloudWatch, etc.)
terragrunt apply
```

**✅ What this creates:**
- Lambda function for daily enforcement
- EventBridge rule for daily execution
- CloudWatch Log Groups and Alarms
- IAM users with email tags
- Complete monitoring infrastructure

## 🔧 Phase 2: Manual Configuration

### 2.1 SES Email Verification (Required)

The Lambda function needs permission to send emails from your specified sender address.

#### Option A: Verify Individual Email Address
```bash
# Verify your sender email address
aws ses verify-email-identity \
  --email-address "security-alerts@yourcompany.com" \
  --region us-east-1

# Check verification status
aws ses get-identity-verification-attributes \
  --identities "security-alerts@yourcompany.com" \
  --region us-east-1
```

#### Option B: Verify Entire Domain (Recommended for production)
```bash
# Verify your entire domain
aws ses verify-domain-identity \
  --domain "yourcompany.com" \
  --region us-east-1

# Get DNS records to add to your domain
aws ses get-identity-verification-attributes \
  --identities "yourcompany.com" \
  --region us-east-1
```

**📧 Add the TXT record to your DNS:**
```
_amazonses.yourcompany.com TXT "generated-verification-token"
```

### 2.2 Configure SES Sending Limits (Production)

For production use, request increased SES sending limits:

```bash
# Check current limits
aws ses get-send-quota --region us-east-1

# For production, request limit increase via AWS Support:
# - Daily sending quota: 200+ emails/day
# - Sending rate: 1+ email/second
```

### 2.3 SNS Topic Setup (Optional but Recommended)

Create SNS topics for CloudWatch alarm notifications:

```bash
# Create SNS topic for critical alerts
aws sns create-topic \
  --name iam-key-rotation-alerts \
  --region us-east-1

# Subscribe your team email to the topic
aws sns subscribe \
  --topic-arn "arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:iam-key-rotation-alerts" \
  --protocol email \
  --notification-endpoint "devops@yourcompany.com"

# Confirm the subscription via email
```

Update your `config.hcl`:
```hcl
alarm_sns_topic = "arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:iam-key-rotation-alerts"
```

Then re-apply Terragrunt:
```bash
terragrunt apply
```

### 2.4 Tag Existing IAM Users (If Any)

For existing IAM users not managed by Terraform, add required tags:

```bash
# Add email tag to existing users
aws iam tag-user \
  --user-name existing-user \
  --tags Key=email,Value=existing-user@yourcompany.com

# Optional: Add exemption for service accounts
aws iam tag-user \
  --user-name service-account \
  --tags Key=key-rotation-exempt,Value=true
```

## 🧪 Phase 3: Testing & Validation

### 3.1 Test Lambda Function

```bash
# Invoke the Lambda function manually
aws lambda invoke \
  --function-name iam-access-key-enforcement \
  --payload '{}' \
  /tmp/test-output.json

# Check the output
cat /tmp/test-output.json

# Check CloudWatch logs
aws logs describe-log-streams \
  --log-group-name "/aws/lambda/iam-access-key-enforcement" \
  --order-by LastEventTime \
  --descending
```

### 3.2 Test Self-Service Scripts

```bash
# Set up Python environment
python3 -m venv venv
source venv/bin/activate
cd scripts
pip install -r requirements.txt

# Test key rotation script
python3 aws_iam_self_service_key_rotation.py -l

# Test compliance report
python3 aws_iam_compliance_report.py --summary-only
```

### 3.3 Verify CloudWatch Metrics

Check that metrics are being published:

```bash
# List available metrics
aws cloudwatch list-metrics \
  --namespace "IAM/KeyRotation" \
  --region us-east-1

# Get recent metric data
aws cloudwatch get-metric-statistics \
  --namespace "IAM/KeyRotation" \
  --metric-name total_keys \
  --dimensions Name=FunctionName,Value=iam-access-key-enforcement \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum
```

## 🔄 Phase 4: Ongoing Operations

### 4.1 User Management Workflow

**Adding New Users:**
1. Add user to `config.hcl` in `user_info` map
2. Run `terragrunt apply`
3. User will automatically get login profile created
4. Share temporary password with user (shown in Terragrunt output)

**Removing Users:**
1. Remove user from `config.hcl`
2. Run `terragrunt apply`
3. Cleanup script automatically removes profiles, MFA, and keys

### 4.2 Monitoring & Alerting

**CloudWatch Dashboards:**
- Navigate to CloudWatch → Dashboards
- Create custom dashboard with `IAM/KeyRotation` metrics
- Monitor: `total_keys`, `expired_keys`, `urgent_keys`

**Key Metrics to Watch:**
- `expired_keys` > 0 (critical - immediate action required)
- `urgent_keys` > 5 (warning - users need notification)
- `disabled_keys` > 0 (info - automatic enforcement triggered)

### 4.3 Script Distribution

Distribute self-service scripts to users:

```bash
# Create distribution package
tar -czf iam-tools.tar.gz scripts/ requirements.txt README.md

# Or use Git for distribution
git clone https://github.com/your-org/iam-key-rotation.git
cd iam-key-rotation/scripts
pip install -r requirements.txt
```

## 🛠️ Troubleshooting

### Common Issues

**SES "Email address not verified" error:**
```bash
# Check verification status
aws ses get-identity-verification-attributes \
  --identities "your-email@company.com"

# Re-verify if needed
aws ses verify-email-identity --email-address "your-email@company.com"
```

**Lambda timeout errors:**
- Check CloudWatch logs for credential report generation delays
- Increase timeout in `terraform/iam/lambda.tf` if needed (current: 300s)

**No metrics appearing:**
- Ensure Lambda has `cloudwatch:PutMetricData` permissions
- Check IAM policy in `terraform/iam/lambda.tf`

**Users not receiving emails:**
- Verify users have `email` tag set
- Check SES sending limits and bounce/complaint rates
- Review CloudWatch logs for SES errors

### Log Analysis

```bash
# View recent Lambda logs
aws logs filter-log-events \
  --log-group-name "/aws/lambda/iam-access-key-enforcement" \
  --start-time $(date -d '1 day ago' +%s)000

# Search for specific errors
aws logs filter-log-events \
  --log-group-name "/aws/lambda/iam-access-key-enforcement" \
  --filter-pattern "ERROR"
```

## 🔐 Security Considerations

### Production Hardening

1. **Least Privilege IAM:**
   - Review IAM policies in `terraform/iam/lambda.tf`
   - Ensure Lambda only has required permissions

2. **Network Security:**
   - Consider VPC deployment for Lambda
   - Use VPC endpoints for AWS service access

3. **Monitoring & Audit:**
   - Enable CloudTrail for API call logging
   - Set up log aggregation (ELK, Splunk, etc.)
   - Regular security reviews of exempted users

4. **Backup & Recovery:**
   - Regular Terraform state backups
   - Document restore procedures
   - Test disaster recovery scenarios

## 📞 Support & Maintenance

### Regular Tasks

**Weekly:**
- Review CloudWatch metrics and alarms
- Check for failed Lambda executions
- Audit user exemptions and email tags

**Monthly:**
- Review and update compliance thresholds if needed
- Audit SES sending statistics and reputation
- Update Python dependencies in Lambda

**Quarterly:**
- Review IAM policies for least privilege
- Audit overall system effectiveness
- Update documentation and runbooks

### Getting Help

For issues with this deployment:

1. **Check CloudWatch Logs** first for error details
2. **Review GitHub Issues** in the repository
3. **Consult AWS Documentation** for service-specific issues
4. **Contact your DevOps/Security team** for organization-specific configuration

---

## 🎯 Summary

After completing this deployment guide, you'll have:

✅ **Fully automated IAM key rotation enforcement**  
✅ **Self-service tools for users**  
✅ **Comprehensive monitoring and alerting**  
✅ **Enterprise-grade compliance reporting**  
✅ **Production-ready security controls**

The system will automatically monitor key ages daily and notify users via email when rotation is needed, with optional automatic disabling of expired keys.

**Next Steps:** Distribute the self-service scripts to your users and monitor the CloudWatch metrics to ensure everything is working as expected!
