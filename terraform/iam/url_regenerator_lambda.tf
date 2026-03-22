#===================================#
#    URL REGENERATOR LAMBDA         #
#===================================#

# IAM role for URL regenerator Lambda
resource "aws_iam_role" "url_regenerator_exec" {
  name = "${local.url_regenerator_name}-role"

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

# IAM policy for URL regenerator Lambda
#checkov:skip=CKV_AWS_355:SES delivery is constrained by sender identity and X-Ray telemetry APIs do not support resource scoping.
#checkov:skip=CKV_AWS_290:X-Ray telemetry APIs require wildcard resources; SES delivery is constrained by sender identity.
resource "aws_iam_role_policy" "url_regenerator_policy" {
  name = "${local.url_regenerator_name}-policy"
  role = aws_iam_role.url_regenerator_exec.id

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
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.url_regenerator_name}",
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.url_regenerator_name}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:HeadObject"
        ]
        Resource = "${aws_s3_bucket.credentials.arn}/*"
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
data "archive_file" "url_regenerator_lambda" {
  type        = "zip"
  source_dir  = var.url_regenerator_source_dir
  output_path = "url_regenerator.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# Lambda function
#checkov:skip=CKV_AWS_117:These functions call AWS public APIs only; VPC placement would add NAT and ENI failure modes without reducing exposure.
#checkov:skip=CKV_AWS_272:Deployment artifacts are built outside AWS Signer; enforcing code signing here would break unsigned CI deploys.
resource "aws_lambda_function" "url_regenerator" {
  filename                       = data.archive_file.url_regenerator_lambda.output_path
  function_name                  = local.url_regenerator_name
  role                           = aws_iam_role.url_regenerator_exec.arn
  handler                        = "url_regenerator.url_regenerator.lambda_handler"
  source_code_hash               = data.archive_file.url_regenerator_lambda.output_base64sha256
  runtime                        = "python3.11"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.data.arn
  reserved_concurrent_executions = local.lambda_reserved_concurrency.url_regenerator

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
    aws_cloudwatch_log_group.url_regenerator
  ]
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "url_regenerator" {
  name              = "/aws/lambda/${local.url_regenerator_name}"
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}

# EventBridge rule to trigger daily at 2 AM UTC
resource "aws_cloudwatch_event_rule" "url_regenerator_schedule" {
  name                = local.url_regenerator_rule_name
  description         = "Trigger URL regeneration for expiring pre-signed URLs"
  schedule_expression = "cron(0 2 * * ? *)" # 2 AM UTC daily

  tags = var.common_tags
}

# EventBridge target
resource "aws_cloudwatch_event_target" "url_regenerator" {
  rule      = aws_cloudwatch_event_rule.url_regenerator_schedule.name
  target_id = "${local.url_regenerator_name}-target"
  arn       = aws_lambda_function.url_regenerator.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_url_regenerator" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.url_regenerator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.url_regenerator_schedule.arn
}
