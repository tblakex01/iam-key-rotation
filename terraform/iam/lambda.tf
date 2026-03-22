# IAM Access Key Enforcement Lambda Function

# Lambda execution role
resource "aws_iam_role" "lambda_exec" {
  name = "${local.access_key_function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.common_tags
}

# Lambda policy for IAM operations
#checkov:skip=CKV_AWS_286:IAM credential report and CloudWatch custom metric APIs require wildcard resources by AWS design.
#checkov:skip=CKV_AWS_287:The wildcard statements are limited to AWS APIs that do not support resource scoping.
#checkov:skip=CKV_AWS_289:The policy scopes user operations to account users and conditions wildcard-only APIs.
#checkov:skip=CKV_AWS_355:GenerateCredentialReport, GetCredentialReport, and PutMetricData do not support resource ARNs.
resource "aws_iam_policy" "lambda_iam_policy" {
  name        = "${local.access_key_function_name}-policy"
  description = "IAM policy for access key enforcement Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.access_key_function_name}",
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.access_key_function_name}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:ListUserTags",
          "iam:UpdateAccessKey",
          "iam:CreateAccessKey",
          "iam:GetUser"
        ]
        Resource = "arn:aws:iam::${var.account_id}:user/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.credentials.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.key_rotation_tracking.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ses:FromAddress" = var.sender_email
          }
        }
      },
      {
        Sid    = "PublishCloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "IAM/KeyRotation"
          }
        }
      },
      {
        Sid    = "AllowXRayWrites"
        Effect = "Allow"
        Action = [
          "xray:PutTelemetryRecords",
          "xray:PutTraceSegments"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowLambdaDlqWrites"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_failures.arn
      },
      {
        Sid    = "AllowKmsUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = aws_kms_key.data.arn
      }
    ]
  })

  tags = var.common_tags
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  policy_arn = aws_iam_policy.lambda_iam_policy.arn
  role       = aws_iam_role.lambda_exec.name
}

# Package Lambda function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "access_key_enforcement.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# Lambda function
#checkov:skip=CKV_AWS_117:These functions call AWS public APIs only; VPC placement would add NAT and ENI failure modes without reducing exposure.
#checkov:skip=CKV_AWS_272:Deployment artifacts are built outside AWS Signer; enforcing code signing here would break unsigned CI deploys.
resource "aws_lambda_function" "access_key_enforcement" {
  filename                       = data.archive_file.lambda_zip.output_path
  function_name                  = local.access_key_function_name
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "access_key_enforcement.access_key_enforcement.lambda_handler"
  source_code_hash               = data.archive_file.lambda_zip.output_base64sha256
  runtime                        = "python3.11"
  timeout                        = 300
  memory_size                    = 256
  kms_key_arn                    = aws_kms_key.data.arn
  reserved_concurrent_executions = local.lambda_reserved_concurrency.access_key_enforcement

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_failures.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      WARNING_THRESHOLD      = var.warning_threshold
      URGENT_THRESHOLD       = var.urgent_threshold
      DISABLE_THRESHOLD      = var.disable_threshold
      AUTO_DISABLE           = var.auto_disable
      SENDER_EMAIL           = var.sender_email
      EXEMPTION_TAG          = var.exemption_tag
      S3_BUCKET              = aws_s3_bucket.credentials.id
      DYNAMODB_TABLE         = aws_dynamodb_table.key_rotation_tracking.name
      NEW_KEY_RETENTION_DAYS = var.new_key_retention_days
      OLD_KEY_RETENTION_DAYS = var.old_key_retention_days
    }
  }

  tags = var.common_tags

  depends_on = [
    aws_iam_role_policy_attachment.lambda_policy_attachment,
    aws_cloudwatch_log_group.lambda_logs
  ]
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.access_key_function_name}"
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}

# EventBridge rule to trigger Lambda daily
resource "aws_cloudwatch_event_rule" "daily_check" {
  name                = local.enforcement_rule_name
  description         = "Trigger IAM key enforcement check daily"
  schedule_expression = var.schedule_expression

  tags = var.common_tags
}

# EventBridge target
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.daily_check.name
  target_id = "${local.access_key_function_name}-target"
  arn       = aws_lambda_function.access_key_enforcement.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.access_key_enforcement.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_check.arn
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "expired_keys_alarm" {
  alarm_name          = local.expired_alarm_name
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "expired_keys"
  namespace           = "IAM/KeyRotation"
  period              = "86400" # 1 day
  statistic           = "Maximum"
  threshold           = "0"
  alarm_description   = "Alert when users have expired access keys"
  alarm_actions       = [var.alarm_sns_topic]

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "non_compliant_users_alarm" {
  alarm_name          = local.urgent_alarm_name
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "urgent_keys"
  namespace           = "IAM/KeyRotation"
  period              = "86400" # 1 day
  statistic           = "Maximum"
  threshold           = "5"
  alarm_description   = "Alert when more than 5 users have keys approaching expiration"
  alarm_actions       = [var.alarm_sns_topic]

  tags = var.common_tags
}
