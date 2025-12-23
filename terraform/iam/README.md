# 🔧 IAM Key Rotation Automation Module

<div align="center">

[![Terraform](https://img.shields.io/badge/Terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)](https://aws.amazon.com/)

</div>

## Overview 🎯
This Terraform module deploys a **fully automated IAM access key rotation system** with secure credential storage, download tracking, and lifecycle management. The system automatically creates new keys, stores them encrypted in S3 with pre-signed URLs, tracks downloads via CloudTrail, sends reminders, and cleans up old keys after 14 days.

## Features ✨
- **Fully Automated Key Creation**: Creates new IAM keys when old keys reach threshold
- **Secure S3 Storage**: Encrypted credential files with AES-256 encryption
- **Pre-signed URLs**: 7-day expiration with automatic URL regeneration
- **Download Tracking**: CloudTrail S3 Data Events detect when credentials are downloaded
- **One-Time Use**: S3 files deleted immediately after download
- **Smart Reminders**: Day 7 reminder emails with renewed URLs if not downloaded
- **Automatic Cleanup**: Day 14 deletion of old keys after rotation
- **DynamoDB Tracking**: Complete lifecycle tracking with composite keys and GSI indexes
- **Multi-Threshold Alerts**: Configurable warning/urgent/disable thresholds
- **Email Notifications**: SES-powered HTML email templates with download links
- **CloudWatch Integration**: Metrics, logs, and alarms for all 4 Lambda functions
- **User Exemption System**: Tag-based exemption for service accounts
- **Test User Management**: Optional test users with automated key creation

## Architecture 🏗️
```mermaid
graph TB
    subgraph "Lambda Functions"
        Enforcement[Enforcement Lambda]
        DownloadTracker[Download Tracker]
        URLRegenerator[URL Regenerator]
        Cleanup[Cleanup Lambda]
    end
    
    subgraph "Storage"
        S3Creds[S3 Credentials Bucket]
        S3Trail[S3 CloudTrail Logs]
        DDB[(DynamoDB Table)]
    end
    
    subgraph "Event Processing"
        EB1[EventBridge Daily]
        EB2[EventBridge Day 7]
        EB3[EventBridge Day 14]
        CT[CloudTrail S3 Events]
    end
    
    IAM[IAM Users & Keys]
    SES[SES Email]
    CW[CloudWatch]
    
    EB1 -->|Daily| Enforcement
    Enforcement -->|Create Key| IAM
    Enforcement -->|Store| S3Creds
    Enforcement -->|Track| DDB
    Enforcement -->|Email| SES
    
    S3Creds -->|GetObject| CT
    CT -->|Trigger| DownloadTracker
    DownloadTracker -->|Update| DDB
    DownloadTracker -->|Delete| S3Creds
    
    EB2 -->|Day 7| URLRegenerator
    URLRegenerator -->|Query| DDB
    URLRegenerator -->|Regenerate| S3Creds
    URLRegenerator -->|Remind| SES
    
    EB3 -->|Day 14| Cleanup
    Cleanup -->|Scan| DDB
    Cleanup -->|Delete Old Key| IAM
    Cleanup -->|Update Status| DDB
    
    Enforcement --> CW
    DownloadTracker --> CW
    URLRegenerator --> CW
    Cleanup --> CW
    CT --> S3Trail
```

## Usage 📋
```hcl
module "iam_key_rotation" {
  source = "./terraform/iam"

  # Email Configuration
  sender_email = "security-team@yourcompany.com"

  # Key Age Thresholds (days)
  warning_threshold = 75
  urgent_threshold  = 85
  disable_threshold = 90
  
  # Auto-disable expired keys
  auto_disable = false  # Set to true for strict enforcement

  # Schedule (daily recommended for production)
  schedule_expression = "rate(1 day)"

  # Resource tags
  common_tags = {
    Environment = "prod"
    Project     = "security-compliance"
    ManagedBy   = "terraform"
  }

  # Test users for validation (optional)
  user_info = {
    "test-user-1" = {
      email = "security-team@yourcompany.com"
      user_tags = {
        "purpose" = "iam-key-rotation-testing"
      }
    }
  }
}
```

## Requirements 📌

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.16.2 |

## Providers 🏢

| Name | Version |
|------|---------|
| aws | >= 5.16.2 |
| archive | >= 2.0 |

## Resources 🔨

### Lambda Functions
| Name | Type |
|------|------|
| [aws_lambda_function.access_key_enforcement](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.download_tracker](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.url_regenerator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.cleanup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |

### Storage & Tracking
| Name | Type |
|------|------|
| [aws_s3_bucket.credentials](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.cloudtrail_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_versioning.credentials](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.credentials](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_dynamodb_table.key_rotation_tracking](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table) | resource |

### Event Processing
| Name | Type |
|------|------|
| [aws_cloudtrail.s3_data_events](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail) | resource |
| [aws_cloudwatch_event_rule.daily_enforcement](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.url_regenerator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.cleanup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.download_detection](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.lambda_targets](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |

### IAM & Permissions
| Name | Type |
|------|------|
| [aws_iam_role.lambda_execution_roles](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_policy.lambda_policies](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_lambda_permission.eventbridge_invoke](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |

### Monitoring
| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.lambda_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_metric_alarm.expired_keys_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.non_compliant_users_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |

### Test Infrastructure
| Name | Type |
|------|------|
| [aws_iam_user.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user) | resource |
| [aws_iam_access_key.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key) | resource |

## Inputs 📥

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| common_tags | Map of common tags to apply to all resources | `map(any)` | `{}` | no |
| warning_threshold | Number of days before access key expiration to send warning | `number` | `75` | no |
| urgent_threshold | Number of days before access key expiration to send urgent notice | `number` | `85` | no |
| disable_threshold | Number of days after which access keys are disabled | `number` | `90` | no |
| auto_disable | Whether to automatically disable expired access keys | `bool` | `false` | no |
| sender_email | Email address to send notifications from (must be verified in SES) | `string` | `"security-team@yourcompany.com"` | no |
| exemption_tag | Tag key to check for access key rotation exemptions | `string` | `"key-rotation-exempt"` | no |
| schedule_expression | CloudWatch Events schedule expression for Lambda execution | `string` | `"rate(1 day)"` | no |
| alarm_sns_topic | SNS topic ARN for CloudWatch alarms (optional) | `string` | `""` | no |
| user_info | Map of AWS IAM usernames, email address tags and custom user tags | `map(object({email = string, user_tags = optional(map(string))}))` | See variables.tf | no |

## Outputs 📤

| Name | Description |
|------|-------------|
| **Lambda Functions** | |
| lambda_function_name | Name of the enforcement Lambda function |
| lambda_function_arn | ARN of the enforcement Lambda function |
| download_tracker_function_name | Name of the download tracker Lambda |
| url_regenerator_function_name | Name of the URL regenerator Lambda |
| cleanup_function_name | Name of the cleanup Lambda |
| **Storage & Tracking** | |
| credentials_bucket_name | S3 bucket name for encrypted credentials |
| credentials_bucket_arn | ARN of the credentials S3 bucket |
| cloudtrail_bucket_name | S3 bucket name for CloudTrail logs |
| tracking_table_name | DynamoDB table name for rotation tracking |
| tracking_table_arn | ARN of the DynamoDB tracking table |
| **EventBridge Rules** | |
| eventbridge_rule_name | Name of the daily enforcement EventBridge rule |
| url_regenerator_rule_name | Name of the day 7 reminder EventBridge rule |
| cleanup_rule_name | Name of the day 14 cleanup EventBridge rule |
| **Monitoring** | |
| lambda_log_group | CloudWatch log group for enforcement Lambda |
| expired_keys_alarm_name | Name of the expired keys CloudWatch alarm |
| non_compliant_users_alarm_name | Name of the non-compliant users alarm |
| **Test Infrastructure** | |
| iam_users | Map of created test IAM users |
| test_user_access_keys | Access key IDs for test users |
| test_user_access_key_secrets | Access key secrets for test users (sensitive) |
| **System Configuration** | |
| configuration_summary | Summary of thresholds and settings |
| key_rotation_system_summary | Complete system summary with all component names |

## Example 💡
```hcl
# Development environment with safe testing settings
module "iam_key_rotation_dev" {
  source = "./terraform/iam"

  # Safe testing thresholds
  warning_threshold = 30   # 30 days for faster testing
  urgent_threshold  = 45   # 45 days for faster testing  
  disable_threshold = 60   # 60 days for faster testing
  auto_disable      = false # No auto-disable in dev
  
  # More frequent checks for testing
  schedule_expression = "rate(6 hours)"
  
  # Email configuration
  sender_email = "dev-security@yourcompany.com"
  
  # Test users
  user_info = {
    "iam-test-user-1" = {
      email = "dev-security@yourcompany.com"
      user_tags = {
        "purpose"     = "iam-key-rotation-testing"
        "environment" = "dev"
      }
    }
  }
  
  common_tags = {
    Environment = "dev"
    Project     = "iam-key-rotation"
    ManagedBy   = "terraform"
    Purpose     = "security-testing"
  }
}

# Production environment with strict enforcement
module "iam_key_rotation_prod" {
  source = "./terraform/iam"

  # Production thresholds
  warning_threshold = 75
  urgent_threshold  = 85
  disable_threshold = 90
  auto_disable      = true  # Strict enforcement in prod
  
  # Daily execution
  schedule_expression = "rate(1 day)"
  
  # Production email
  sender_email = "security-alerts@yourcompany.com"
  
  # SNS integration for critical alerts
  alarm_sns_topic = "arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:security-alerts"
  
  common_tags = {
    Environment = "prod"
    Project     = "iam-key-rotation"
    ManagedBy   = "terraform"
    CriticalityLevel = "high"
  }
}
```

## Best Practices 🎯
- **Start with testing**: Deploy in dev environment with `auto_disable = false` first
- **Verify SES setup**: Ensure sender email is verified in SES before deployment
- **Use exemption tags**: Tag service accounts with `key-rotation-exempt = "true"`
- **Monitor CloudWatch logs**: Regularly check Lambda execution logs for issues
- **Test email delivery**: Validate email notifications reach intended recipients
- **Gradual rollout**: Test with individual users before organization-wide deployment
- **Regular key rotation**: Establish organizational policies for regular key rotation

## Security Considerations 🔒
- **Least privilege IAM**: Lambda uses minimal required permissions for IAM and SES operations
- **No hardcoded credentials**: All configuration via environment variables and tags
- **Audit logging**: All actions logged to CloudWatch for security audit trails  
- **Email security**: Uses SES with verified sender addresses to prevent spoofing
- **Tag-based exemptions**: Secure exemption system for critical service accounts
- **Optional auto-disable**: Can be disabled for safety during initial deployment

## Troubleshooting 🔍
Common issues and their solutions:

1. **Lambda function fails with SES permissions error**
   - Verify sender email is verified in SES
   - Check IAM policy includes SES send permissions
   - Ensure SES is available in your deployment region

2. **No email notifications received**
   - Check CloudWatch logs for Lambda execution errors
   - Verify recipient email addresses in user tags
   - Check SES sending limits and bounce rates

3. **Users not found in credential report**
   - Verify IAM users exist and have access keys
   - Check if credential report generation is completing successfully
   - Ensure Lambda has proper IAM permissions

4. **Auto-disable not working**
   - Verify `auto_disable` variable is set to `true`
   - Check Lambda IAM permissions include key deletion rights
   - Review CloudWatch logs for error messages

## Related Modules 🔗
- [IAM User Management Scripts](../../scripts/) - Self-service tools for key rotation
- [IAM Compliance Reporting](../../scripts/aws_iam_compliance_report.py) - Detailed compliance reports
- [Password Reset Tools](../../scripts/aws_iam_user_password_reset.py) - User password management

---

<div align="center">

**[ [Back to Top](#-iam-key-rotation-enforcement-module) ]**

</div>
