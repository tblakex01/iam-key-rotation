# IAM Access Key Enforcement Lambda Function

# Data sources for current region and account
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Lambda execution role
resource "aws_iam_role" "lambda_execution_role" {
  name = "iam-key-enforcement-lambda-role"

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
resource "aws_iam_policy" "lambda_iam_policy" {
  name        = "iam-key-enforcement-policy"
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
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/iam-access-key-enforcement",
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/iam-access-key-enforcement:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "iam:ListAccessKeys",
          "iam:ListUserTags",
          "iam:UpdateAccessKey"
        ]
        Resource = "*"
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
      }
    ]
  })

  tags = var.common_tags
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  policy_arn = aws_iam_policy.lambda_iam_policy.arn
  role       = aws_iam_role.lambda_execution_role.name
}

# Package Lambda function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "../../lambda/access_key_enforcement"
  output_path = "access_key_enforcement.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# Lambda function
resource "aws_lambda_function" "access_key_enforcement" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "iam-access-key-enforcement"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "access_key_enforcement.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      WARNING_THRESHOLD = var.warning_threshold
      URGENT_THRESHOLD  = var.urgent_threshold
      DISABLE_THRESHOLD = var.disable_threshold
      AUTO_DISABLE      = var.auto_disable
      SENDER_EMAIL      = var.sender_email
      EXEMPTION_TAG     = var.exemption_tag
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
  name              = "/aws/lambda/iam-access-key-enforcement"
  retention_in_days = 30

  tags = var.common_tags
}

# EventBridge rule to trigger Lambda daily
resource "aws_cloudwatch_event_rule" "daily_check" {
  name                = "iam-key-enforcement-daily"
  description         = "Trigger IAM key enforcement check daily"
  schedule_expression = var.schedule_expression

  tags = var.common_tags
}

# EventBridge target
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.daily_check.name
  target_id = "iam-key-enforcement-target"
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
  alarm_name          = "iam-expired-keys-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "expired_keys"
  namespace           = "IAM/KeyRotation"
  period              = "86400" # 1 day
  statistic           = "Maximum"
  threshold           = "0"
  alarm_description   = "Alert when users have expired access keys"
  alarm_actions       = var.alarm_sns_topic != "" ? [var.alarm_sns_topic] : []

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "non_compliant_users_alarm" {
  alarm_name          = "iam-non-compliant-users-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "urgent_keys"
  namespace           = "IAM/KeyRotation"
  period              = "86400" # 1 day
  statistic           = "Maximum"
  threshold           = "5"
  alarm_description   = "Alert when more than 5 users have keys approaching expiration"
  alarm_actions       = var.alarm_sns_topic != "" ? [var.alarm_sns_topic] : []

  tags = var.common_tags
}