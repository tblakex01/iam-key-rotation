#===================================#
#      CLEANUP LAMBDA               #
#===================================#

# IAM role for cleanup Lambda
resource "aws_iam_role" "cleanup_exec" {
  name = "${local.cleanup_name}-role"

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

# IAM policy for cleanup Lambda
resource "aws_iam_role_policy" "cleanup_policy" {
  name = "${local.cleanup_name}-policy"
  role = aws_iam_role.cleanup_exec.id

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
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.cleanup_name}",
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.cleanup_name}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ]
        Resource = [
          aws_dynamodb_table.key_rotation_tracking.arn,
          "${aws_dynamodb_table.key_rotation_tracking.arn}/index/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys"
        ]
        Resource = "arn:aws:iam::${var.account_id}:user/*"
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
          "s3:HeadObject"
        ]
        Resource = "${aws_s3_bucket.credentials.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = aws_kms_key.data.arn
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_failures.arn
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTelemetryRecords",
          "xray:PutTraceSegments"
        ]
        Resource = "*"
      }
    ]
  })
}

# Package Lambda function code
data "archive_file" "cleanup_lambda" {
  type        = "zip"
  source_dir  = var.cleanup_source_dir
  output_path = "cleanup.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# Lambda function
#checkov:skip=CKV_AWS_117:These functions call AWS public APIs only; VPC placement would add NAT and ENI failure modes without reducing exposure.
#checkov:skip=CKV_AWS_272:Deployment artifacts are built outside AWS Signer; enforcing code signing here would break unsigned CI deploys.
resource "aws_lambda_function" "cleanup" {
  filename                       = data.archive_file.cleanup_lambda.output_path
  function_name                  = local.cleanup_name
  role                           = aws_iam_role.cleanup_exec.arn
  handler                        = "cleanup.cleanup.lambda_handler"
  source_code_hash               = data.archive_file.cleanup_lambda.output_base64sha256
  runtime                        = "python3.11"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.data.arn
  reserved_concurrent_executions = local.lambda_reserved_concurrency.cleanup

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_failures.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      DYNAMODB_TABLE         = aws_dynamodb_table.key_rotation_tracking.name
      OLD_KEY_RETENTION_DAYS = var.old_key_retention_days
      SENDER_EMAIL           = var.sender_email
      S3_BUCKET              = aws_s3_bucket.credentials.id
    }
  }

  tags = var.common_tags

  depends_on = [
    aws_cloudwatch_log_group.cleanup
  ]
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "cleanup" {
  name              = "/aws/lambda/${local.cleanup_name}"
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}

# EventBridge rule to trigger daily at 3 AM UTC
resource "aws_cloudwatch_event_rule" "cleanup_schedule" {
  name                = local.cleanup_rule_name
  description         = "Trigger cleanup of expired IAM keys"
  schedule_expression = "cron(0 3 * * ? *)" # 3 AM UTC daily

  tags = var.common_tags
}

# EventBridge target
resource "aws_cloudwatch_event_target" "cleanup" {
  rule      = aws_cloudwatch_event_rule.cleanup_schedule.name
  target_id = "${local.cleanup_name}-target"
  arn       = aws_lambda_function.cleanup.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_cleanup" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cleanup.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cleanup_schedule.arn
}
