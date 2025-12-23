#===================================#
#    URL REGENERATOR LAMBDA         #
#===================================#

# IAM role for URL regenerator Lambda
resource "aws_iam_role" "url_regenerator_exec" {
  name = "iam-key-url-regenerator-lambda-role"

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
resource "aws_iam_role_policy" "url_regenerator_policy" {
  name = "url-regenerator-lambda-policy"
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
        Resource = "arn:aws:logs:*:*:*"
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
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser"
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
resource "aws_lambda_function" "url_regenerator" {
  filename         = data.archive_file.url_regenerator_lambda.output_path
  function_name    = "iam-key-url-regenerator"
  role            = aws_iam_role.url_regenerator_exec.arn
  handler         = "url_regenerator.lambda_handler"
  source_code_hash = data.archive_file.url_regenerator_lambda.output_base64sha256
  runtime         = "python3.11"
  timeout         = 300  # 5 minutes for processing multiple users
  memory_size     = 512

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.key_rotation_tracking.name
      S3_BUCKET      = aws_s3_bucket.credentials.id
      SENDER_EMAIL   = var.sender_email
    }
  }

  tags = var.common_tags
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "url_regenerator" {
  name              = "/aws/lambda/${aws_lambda_function.url_regenerator.function_name}"
  retention_in_days = 30

  tags = var.common_tags
}

# EventBridge rule to trigger daily at 2 AM UTC
resource "aws_cloudwatch_event_rule" "url_regenerator_schedule" {
  name                = "iam-key-url-regenerator-daily"
  description         = "Trigger URL regeneration for expiring pre-signed URLs"
  schedule_expression = "cron(0 2 * * ? *)"  # 2 AM UTC daily

  tags = var.common_tags
}

# EventBridge target
resource "aws_cloudwatch_event_target" "url_regenerator" {
  rule      = aws_cloudwatch_event_rule.url_regenerator_schedule.name
  target_id = "url-regenerator-lambda"
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
