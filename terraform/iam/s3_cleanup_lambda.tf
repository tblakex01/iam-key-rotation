# S3 Credentials Cleanup Lambda
# Handles day 45 expiration - deletes S3 files and sends final expiration notices

# IAM role for S3 cleanup Lambda
resource "aws_iam_role" "s3_cleanup_exec" {
  name = "${local.s3_cleanup_name}-role"

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

# IAM policy for S3 cleanup Lambda
resource "aws_iam_policy" "s3_cleanup_policy" {
  name        = "${local.s3_cleanup_name}-policy"
  description = "Policy for S3 cleanup Lambda function"

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
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.s3_cleanup_name}",
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.s3_cleanup_name}:*"
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
          "s3:DeleteObject",
          "s3:HeadObject"
        ]
        Resource = "${aws_s3_bucket.credentials.arn}/*"
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

# Attach policy to role
resource "aws_iam_role_policy_attachment" "s3_cleanup_policy_attachment" {
  policy_arn = aws_iam_policy.s3_cleanup_policy.arn
  role       = aws_iam_role.s3_cleanup_exec.name
}

# Package Lambda function code
data "archive_file" "s3_cleanup_lambda" {
  type        = "zip"
  source_dir  = var.s3_cleanup_source_dir
  output_path = "s3_cleanup.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# Lambda function
#checkov:skip=CKV_AWS_117:These functions call AWS public APIs only; VPC placement would add NAT and ENI failure modes without reducing exposure.
#checkov:skip=CKV_AWS_272:Deployment artifacts are built outside AWS Signer; enforcing code signing here would break unsigned CI deploys.
resource "aws_lambda_function" "s3_cleanup" {
  filename                       = data.archive_file.s3_cleanup_lambda.output_path
  function_name                  = local.s3_cleanup_name
  role                           = aws_iam_role.s3_cleanup_exec.arn
  handler                        = "s3_cleanup.s3_cleanup.lambda_handler"
  source_code_hash               = data.archive_file.s3_cleanup_lambda.output_base64sha256
  runtime                        = "python3.11"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.data.arn
  reserved_concurrent_executions = local.lambda_reserved_concurrency.s3_cleanup

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_failures.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      DYNAMODB_TABLE         = aws_dynamodb_table.key_rotation_tracking.name
      S3_BUCKET              = aws_s3_bucket.credentials.id
      SENDER_EMAIL           = var.sender_email
      NEW_KEY_RETENTION_DAYS = var.new_key_retention_days
      OLD_KEY_RETENTION_DAYS = var.old_key_retention_days
    }
  }

  tags = var.common_tags

  depends_on = [
    aws_iam_role_policy_attachment.s3_cleanup_policy_attachment,
    aws_cloudwatch_log_group.s3_cleanup
  ]
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "s3_cleanup" {
  name              = "/aws/lambda/${local.s3_cleanup_name}"
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}

# EventBridge rule to trigger daily at 4 AM UTC
resource "aws_cloudwatch_event_rule" "s3_cleanup_schedule" {
  name                = local.s3_cleanup_rule_name
  description         = "Trigger S3 credentials cleanup for expired files"
  schedule_expression = "cron(0 4 * * ? *)" # 4 AM UTC daily

  tags = var.common_tags
}

# EventBridge target
resource "aws_cloudwatch_event_target" "s3_cleanup_target" {
  rule      = aws_cloudwatch_event_rule.s3_cleanup_schedule.name
  target_id = "${local.s3_cleanup_name}-target"
  arn       = aws_lambda_function.s3_cleanup.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_s3_cleanup" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_cleanup.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_cleanup_schedule.arn
}
