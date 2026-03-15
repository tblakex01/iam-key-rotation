# Production Readiness Review

Use this checklist before the first production rollout.

- [x] Terraform no longer creates default IAM users or access keys.
- [x] Access-key secrets are not exposed in Terraform outputs.
- [x] Live pre-signed URLs are not persisted in DynamoDB.
- [x] Download tracking correlates by exact `s3_key`.
- [x] Credential objects are not version-recoverable in the primary path.
- [x] Runtime configuration validates required inputs up front.
- [x] Rotation, reminder, cleanup, and expiry flows are idempotent in the shipped path.
- [x] CloudWatch alarms exist for Lambda errors, throttles, and DLQ visibility.
- [x] Alarm routing is explicit through `alarm_sns_topic`.
- [x] A CloudWatch dashboard exists for lifecycle health.
- [x] CI enforces Python and Terraform quality gates.
- [x] Deployment guidance is Terragrunt-first and environment-scoped.
- [x] An operations runbook exists for Lambda failures and manual recovery.

Open questions before rollout:

- confirm SES is production-ready in the target region
- confirm the SNS topic subscribers are the correct on-call rotation
- confirm a non-prod environment has exercised the full 0/7/23/30/45-day lifecycle
