# Operations Runbook

## Signals To Watch

- CloudWatch alarms routed to `alarm_sns_topic`
- CloudWatch dashboard `${name_prefix}-${environment_name}-operations`
- SQS DLQ `${name_prefix}-${environment_name}-lambda-failures`

## Common Incidents

### Lambda Error Alarm

1. Open the alarm and identify the failing function.
2. Check the corresponding CloudWatch log group.
3. If the invocation failed after a destructive action:
   - rerun the Lambda only after confirming the state transition is idempotent
   - the cleanup and download-tracking paths are designed to self-heal on retries
4. If the failure was configuration-driven, fix Terragrunt config and redeploy.

### Lambda Throttle Alarm

1. Check concurrent executions and recent traffic.
2. Inspect CloudWatch metrics for the affected function.
3. Raise reserved concurrency or reduce schedule/event pressure if needed.

### DLQ Alarm

1. Read the DLQ messages.
2. Identify the function name and original event.
3. Fix the underlying issue first.
4. Replay only after the code or configuration issue is corrected.

### Rotation Stuck Pending Download

1. Query the DynamoDB record by `PK` / `SK` or by `s3_key`.
2. Confirm whether the credential object still exists in S3.
3. If the old key is already deleted and the object still exists, trigger the reminder Lambda or generate a temporary replacement URL manually.
4. If the credential object is gone and the record never updated, inspect download-tracker logs and DLQ messages.

## Manual Recovery

### Reissue A Reminder

- Invoke the reminder Lambda with a normal scheduled payload after confirming the record is still in a reminder-eligible status.

### Complete An Old-Key Deletion

- If IAM deletion succeeded but the DynamoDB update failed, rerun the cleanup Lambda. The deletion path is idempotent and tolerates `NoSuchEntity`.

### Final Expiry Cleanup

- If the S3 object is already gone but the record is still active, rerun the S3 cleanup Lambda. The record update is the important recovery step.

## Guardrails

- Do not hand-edit DynamoDB unless normal Lambda retries and a rerun cannot reconcile the state.
- Do not re-enable S3 object versioning on the credentials bucket.
- Do not add IAM access-key creation back into Terraform.
