# Lambda function outputs
output "lambda_function_arn" {
  description = "ARN of the IAM access key enforcement Lambda function"
  value       = aws_lambda_function.access_key_enforcement.arn
}

output "lambda_function_name" {
  description = "Name of the IAM access key enforcement Lambda function"
  value       = aws_lambda_function.access_key_enforcement.function_name
}

output "lambda_log_group" {
  description = "CloudWatch log group for the Lambda function"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

# IAM role outputs
output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_exec.arn
}

# EventBridge rule outputs
output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule for daily execution"
  value       = aws_cloudwatch_event_rule.daily_check.name
}

# CloudWatch alarm outputs
output "expired_keys_alarm_name" {
  description = "Name of the expired keys CloudWatch alarm"
  value       = aws_cloudwatch_metric_alarm.expired_keys_alarm.alarm_name
}

output "non_compliant_users_alarm_name" {
  description = "Name of the non-compliant users CloudWatch alarm"
  value       = aws_cloudwatch_metric_alarm.non_compliant_users_alarm.alarm_name
}

# IAM users outputs
output "iam_users" {
  description = "Map of created IAM users"
  value = {
    for name, user in aws_iam_user.this :
    name => {
      arn  = user.arn
      name = user.name
      tags = user.tags
    }
  }
}

# Configuration summary
output "configuration_summary" {
  description = "Summary of Lambda configuration"
  value = {
    warning_threshold = var.warning_threshold
    urgent_threshold  = var.urgent_threshold
    disable_threshold = var.disable_threshold
    auto_disable      = var.auto_disable
    sender_email      = var.sender_email
    schedule          = var.schedule_expression
  }
}

# Output access key information for testing
output "test_user_access_keys" {
  description = "Access key information for test users (for testing purposes only)"
  value = {
    for username, key in aws_iam_access_key.this : username => {
      access_key_id = key.id
      creation_date = key.create_date
      # Note: secret is not output for security (stored in terraform state only)
    }
  }
  sensitive = false
}

# Output access key secrets (marked sensitive so they don't show in logs)
output "test_user_access_key_secrets" {
  description = "Access key secrets for test users (sensitive - for testing only)"
  value = {
    for username, key in aws_iam_access_key.this : username => key.secret
  }
  sensitive = true
}

# S3 bucket outputs
output "credentials_bucket_name" {
  description = "Name of the S3 bucket storing encrypted credentials"
  value       = aws_s3_bucket.credentials.id
}

output "credentials_bucket_arn" {
  description = "ARN of the credentials S3 bucket"
  value       = aws_s3_bucket.credentials.arn
}

# DynamoDB table outputs
output "tracking_table_name" {
  description = "Name of the DynamoDB tracking table"
  value       = aws_dynamodb_table.key_rotation_tracking.name
}

output "tracking_table_arn" {
  description = "ARN of the DynamoDB tracking table"
  value       = aws_dynamodb_table.key_rotation_tracking.arn
}

# New Lambda function outputs
output "download_tracker_function_arn" {
  description = "ARN of the download tracker Lambda function"
  value       = aws_lambda_function.download_tracker.arn
}

output "url_regenerator_function_arn" {
  description = "ARN of the URL regenerator Lambda function"
  value       = aws_lambda_function.url_regenerator.arn
}

output "cleanup_function_arn" {
  description = "ARN of the cleanup Lambda function"
  value       = aws_lambda_function.cleanup.arn
}

# Complete system summary
output "key_rotation_system_summary" {
  description = "Complete summary of the automated key rotation system"
  value = {
    enforcement_lambda    = aws_lambda_function.access_key_enforcement.function_name
    download_tracker      = aws_lambda_function.download_tracker.function_name
    url_regenerator       = aws_lambda_function.url_regenerator.function_name
    cleanup_lambda        = aws_lambda_function.cleanup.function_name
    credentials_bucket    = aws_s3_bucket.credentials.id
    tracking_table        = aws_dynamodb_table.key_rotation_tracking.name
    retention_days        = var.credential_retention_days
    sender_email          = var.sender_email
  }
}