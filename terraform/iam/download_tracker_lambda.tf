#===================================#
#    DOWNLOAD TRACKER LAMBDA        #
#===================================#

# IAM role for download tracker Lambda
resource "aws_iam_role" "download_tracker_exec" {
  name = "${local.download_tracker_name}-role"

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
  name = "${local.download_tracker_name}-policy"
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
        Resource = [
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.download_tracker_name}",
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.download_tracker_name}:*"
        ]
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
        Resource = [
          aws_dynamodb_table.key_rotation_tracking.arn,
          "${aws_dynamodb_table.key_rotation_tracking.arn}/index/s3-key-index"
        ]
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
data "archive_file" "download_tracker_lambda" {
  type        = "zip"
  source_dir  = var.download_tracker_source_dir
  output_path = "download_tracker.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# Lambda function
#checkov:skip=CKV_AWS_117:These functions call AWS public APIs only; VPC placement would add NAT and ENI failure modes without reducing exposure.
#checkov:skip=CKV_AWS_272:Deployment artifacts are built outside AWS Signer; enforcing code signing here would break unsigned CI deploys.
resource "aws_lambda_function" "download_tracker" {
  filename                       = data.archive_file.download_tracker_lambda.output_path
  function_name                  = local.download_tracker_name
  role                           = aws_iam_role.download_tracker_exec.arn
  handler                        = "download_tracker.download_tracker.lambda_handler"
  source_code_hash               = data.archive_file.download_tracker_lambda.output_base64sha256
  runtime                        = "python3.11"
  timeout                        = 30
  memory_size                    = 256
  kms_key_arn                    = aws_kms_key.data.arn
  reserved_concurrent_executions = local.lambda_reserved_concurrency.download_tracker

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_failures.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.key_rotation_tracking.name
      S3_BUCKET      = aws_s3_bucket.credentials.id
    }
  }

  tags = var.common_tags

  depends_on = [
    aws_cloudwatch_log_group.download_tracker
  ]
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "download_tracker" {
  name              = "/aws/lambda/${local.download_tracker_name}"
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}

# Note: Lambda permission for EventBridge is in s3.tf with CloudTrail resources
