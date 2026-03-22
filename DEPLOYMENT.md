# Deployment Guide

This repository is deployed through Terragrunt. Direct `terraform apply` against the module is intentionally undocumented for environment rollouts.

## Prerequisites

- Terraform `>= 1.5`
- Terragrunt
- AWS credentials for the target account and region
- Verified SES sender address or domain in the target region
- An SNS topic for alarms

## 1. Configure The Environment

Create the account and service config files from the checked-in examples:

```bash
cp terragrunt/mvw-dw-nonprod/account.hcl.example terragrunt/mvw-dw-nonprod/account.hcl
cp terragrunt/mvw-dw-nonprod/us-east-1/dev/iam-key-rotation/config.hcl.example \
  terragrunt/mvw-dw-nonprod/us-east-1/dev/iam-key-rotation/config.hcl
```

Update:

- `account_name`
- `account_id`
- `profile`
- `sender_email`
- `support_email`
- `alarm_sns_topic`
- self-service recovery rate limits if the environment needs non-default values
- `managed_user_info`
- threshold values if the environment differs from the defaults

## 2. Plan The Environment

```bash
cd terragrunt/mvw-dw-nonprod/us-east-1/dev/iam-key-rotation
terragrunt hclfmt
terragrunt init
terragrunt plan
```

Review the plan for:

- environment-specific resource names using `${name_prefix}-${environment_name}`
- the HTTP API, stage, and recovery Lambda resources for `POST /access-key-recovery/request`
- CloudWatch alarms routed to the configured SNS topic
- the Lambda failure DLQ and dashboard resources
- only the intended IAM users under `managed_user_info`

## 3. Apply The Environment

```bash
terragrunt apply
```

## 4. Post-Deploy Verification

Run the following checks after the first apply:

```bash
terragrunt output
aws cloudwatch list-dashboards --query 'DashboardEntries[?contains(DashboardName, `iam-key-rotation`)]'
aws sqs get-queue-attributes --queue-url <lambda-failures-dlq-url> --attribute-names ApproximateNumberOfMessages
```

Confirm:

- the dashboard exists
- all Lambda log groups are present
- the access-key recovery API invoke URL is present in `terragrunt output`
- alarms target the configured SNS topic
- the DLQ is empty
- the DynamoDB table and credentials bucket names are environment-scoped

## Staged Rollout

### Dev

- Use a test-only `managed_user_info` set.
- Keep `auto_disable = false`.
- Trigger Lambdas manually and validate email delivery plus download tracking.
- Exercise the self-service recovery path against a pending-download test record and confirm the first successful download still deletes the S3 object.

### Non-Prod

- Use representative thresholds and real integration paths.
- Validate alarm delivery, DLQ behavior, and runbook steps.
- Confirm the reminder, old-key deletion, and final expiration flows against test users.

### Prod

- Use the production sender address and SNS routing.
- Keep managed IAM users explicit and minimal.
- Schedule a staffed rollout window and watch the dashboard, alarms, and DLQ after first apply.

## Rollback

Infrastructure rollback is a normal Terragrunt change:

```bash
terragrunt plan
terragrunt apply
```

If the issue is operational rather than structural, prefer the runbook in [`docs/OPERATIONS_RUNBOOK.md`](/Users/nizda/Dev/cc/iam-key-rotation/docs/OPERATIONS_RUNBOOK.md) over tearing infrastructure down.
