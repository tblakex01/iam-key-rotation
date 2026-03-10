#===================================#
#    DOWNLOAD TRACKER LAMBDA        #
#===================================#

# IAM role for download tracker Lambda
resource "aws_iam_role" "download_tracker_exec" {
  name = "iam-key-download-tracker-lambda-role"

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

# IAM policy for download tracker Lambda
resource "aws_iam_role_policy" "download_tracker_policy" {
  name = "download-tracker-lambda-policy"
  role = aws_iam_role.download_tracker_exec.id

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
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.credentials.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Query",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.key_rotation_tracking.arn
      }
    ]
  })
}

# Package Lambda function code
data "archive_file" "download_tracker_lambda" {
  type        = "zip"
  source_dir  = var.download_tracker_source_dir
  output_path = "download_tracker.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# Lambda function
resource "aws_lambda_function" "download_tracker" {
  filename         = data.archive_file.download_tracker_lambda.output_path
  function_name    = "iam-key-download-tracker"
  role            = aws_iam_role.download_tracker_exec.arn
  handler         = "download_tracker.lambda_handler"
  source_code_hash = data.archive_file.download_tracker_lambda.output_base64sha256
  runtime         = "python3.11"
  timeout         = 30
  memory_size     = 256

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.key_rotation_tracking.name
    }
  }

  tags = var.common_tags
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "download_tracker" {
  name              = "/aws/lambda/${aws_lambda_function.download_tracker.function_name}"
  retention_in_days = 30

  tags = var.common_tags
}

# Note: Lambda permission for EventBridge is in s3.tf with CloudTrail resources
