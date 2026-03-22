locals {
  lambda_monitor_targets = {
    enforcement = aws_lambda_function.access_key_enforcement.function_name
    recovery    = aws_lambda_function.access_key_recovery_request.function_name
    download    = aws_lambda_function.download_tracker.function_name
    reminder    = aws_lambda_function.url_regenerator.function_name
    cleanup     = aws_lambda_function.cleanup.function_name
    s3_cleanup  = aws_lambda_function.s3_cleanup.function_name
  }
}

resource "aws_sqs_queue" "lambda_failures" {
  name                       = "${local.resource_prefix}-lambda-failures"
  kms_master_key_id          = aws_kms_key.data.arn
  visibility_timeout_seconds = 60
  message_retention_seconds  = 1209600

  tags = var.common_tags
}

resource "aws_sqs_queue_policy" "lambda_failures" {
  queue_url = aws_sqs_queue.lambda_failures.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaAsyncDestinations"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.lambda_failures.arn
      }
    ]
  })
}

resource "aws_lambda_function_event_invoke_config" "async_destinations" {
  for_each = {
    enforcement = aws_lambda_function.access_key_enforcement.function_name
    recovery    = aws_lambda_function.access_key_recovery_request.function_name
    download    = aws_lambda_function.download_tracker.function_name
    reminder    = aws_lambda_function.url_regenerator.function_name
    cleanup     = aws_lambda_function.cleanup.function_name
    s3_cleanup  = aws_lambda_function.s3_cleanup.function_name
  }

  function_name          = each.value
  maximum_retry_attempts = 2

  destination_config {
    on_failure {
      destination = aws_sqs_queue.lambda_failures.arn
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = local.lambda_monitor_targets

  alarm_name          = "${each.value}-errors"
  alarm_description   = "Alert when ${each.value} reports Lambda errors."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_sns_topic]

  dimensions = {
    FunctionName = each.value
  }

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  for_each = local.lambda_monitor_targets

  alarm_name          = "${each.value}-throttles"
  alarm_description   = "Alert when ${each.value} is throttled."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_sns_topic]

  dimensions = {
    FunctionName = each.value
  }

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_dlq_messages" {
  alarm_name          = "${local.resource_prefix}-lambda-failures-visible"
  alarm_description   = "Alert when Lambda async failure messages are present in the DLQ."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_sns_topic]

  dimensions = {
    QueueName = aws_sqs_queue.lambda_failures.name
  }

  tags = var.common_tags
}

resource "aws_cloudwatch_dashboard" "key_rotation" {
  dashboard_name = "${local.resource_prefix}-operations"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Rotation Lifecycle Metrics"
          region  = var.aws_region
          view    = "timeSeries"
          stacked = false
          metrics = [
            ["IAM/KeyRotation", "warning_keys"],
            [".", "urgent_keys"],
            [".", "expired_keys"],
            [".", "old_keys_deleted"],
            [".", "credentials_expired"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Lambda Errors"
          region  = var.aws_region
          view    = "timeSeries"
          stacked = false
          metrics = [
            for function_name in values(local.lambda_monitor_targets) :
            ["AWS/Lambda", "Errors", "FunctionName", function_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Lambda Throttles"
          region  = var.aws_region
          view    = "timeSeries"
          stacked = false
          metrics = [
            for function_name in values(local.lambda_monitor_targets) :
            ["AWS/Lambda", "Throttles", "FunctionName", function_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Lambda Failure DLQ"
          region  = var.aws_region
          view    = "timeSeries"
          stacked = false
          metrics = [
            [
              "AWS/SQS",
              "ApproximateNumberOfMessagesVisible",
              "QueueName",
              aws_sqs_queue.lambda_failures.name,
            ]
          ]
        }
      },
    ]
  })
}
