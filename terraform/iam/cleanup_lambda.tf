#===================================#
#      CLEANUP LAMBDA               #
#===================================#

# IAM role for cleanup Lambda
resource "aws_iam_role" "cleanup_exec" {
  name = "iam-key-cleanup-lambda-role"

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
  name = "cleanup-lambda-policy"
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
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
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
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
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
resource "aws_lambda_function" "cleanup" {
  filename         = data.archive_file.cleanup_lambda.output_path
  function_name    = "iam-key-cleanup"
  role            = aws_iam_role.cleanup_exec.arn
  handler         = "cleanup.lambda_handler"
  source_code_hash = data.archive_file.cleanup_lambda.output_base64sha256
  runtime         = "python3.11"
  timeout         = 300  # 5 minutes for processing multiple deletions
  memory_size     = 512

  environment {
    variables = {
      DYNAMODB_TABLE     = aws_dynamodb_table.key_rotation_tracking.name
      RETENTION_DAYS     = var.credential_retention_days
    }
  }

  tags = var.common_tags
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "cleanup" {
  name              = "/aws/lambda/${aws_lambda_function.cleanup.function_name}"
  retention_in_days = 30

  tags = var.common_tags
}

# EventBridge rule to trigger daily at 3 AM UTC
resource "aws_cloudwatch_event_rule" "cleanup_schedule" {
  name                = "iam-key-cleanup-daily"
  description         = "Trigger cleanup of expired IAM keys"
  schedule_expression = "cron(0 3 * * ? *)"  # 3 AM UTC daily

  tags = var.common_tags
}

# EventBridge target
resource "aws_cloudwatch_event_target" "cleanup" {
  rule      = aws_cloudwatch_event_rule.cleanup_schedule.name
  target_id = "cleanup-lambda"
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
