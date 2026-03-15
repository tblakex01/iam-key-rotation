# Terraform Module: IAM Key Rotation

This module implements the IAM key-rotation platform. It is intended to be consumed by Terragrunt for environment deployments.

## What The Module Creates

- five Lambda functions for enforcement, download tracking, reminders, old-key cleanup, and credential expiry
- an encrypted S3 bucket for temporary credential delivery
- a DynamoDB tracking table with:
  - `status-index`
  - `s3-key-index`
- EventBridge schedules and CloudTrail data-event wiring
- CloudWatch alarms, dashboard, and Lambda async failure DLQ
- optional explicitly managed IAM users

## Required Inputs

- `name_prefix`
- `environment_name`
- `account_id`
- `aws_region`
- `sender_email`
- `alarm_sns_topic`

Everything else is either environment tuning or an explicit opt-in, including `managed_user_info`.

## Notable Guarantees

- no default IAM users
- no Terraform-managed IAM access keys
- no access-key secrets in outputs
- no stored live pre-signed URLs in DynamoDB
- environment-scoped resource names

## Example

```hcl
module "iam_key_rotation" {
  source = "../../terraform/iam"

  name_prefix      = "iam-key-rotation"
  environment_name = "nonprod"
  account_id       = "123456789012"
  aws_region       = "us-east-1"
  sender_email     = "security@example.com"
  alarm_sns_topic  = "arn:aws:sns:us-east-1:123456789012:iam-key-rotation-alerts"

  common_tags = {
    Application = "iam-key-rotation"
    Environment = "nonprod"
    ManagedBy   = "terragrunt"
  }

  managed_user_info = {
    "iam-test-user-1" = {
      email = "security@example.com"
      user_tags = {
        purpose = "iam-key-rotation-testing"
      }
    }
  }
}
```

## Outputs

Key outputs include:

- enforcement and supporting Lambda ARNs
- bucket and table names
- operations dashboard name
- Lambda failure DLQ name
- the `iam_users` map for explicitly managed users

## Validation

```bash
terraform -chdir=terraform/iam fmt -check -recursive
terraform -chdir=terraform/iam init -backend=false -input=false
terraform -chdir=terraform/iam validate
terraform -chdir=terraform/iam plan -input=false -lock=false
```
