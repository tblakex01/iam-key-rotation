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
  value       = aws_iam_role.lambda_execution_role.arn
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