#===========================================#
#    ACCESS KEY RECOVERY REQUEST LAMBDA     #
#===========================================#

resource "aws_iam_role" "access_key_recovery_exec" {
  name = "${local.access_key_recovery_name}-role"

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

#checkov:skip=CKV_AWS_355:SES and X-Ray write APIs in this policy do not support resource scoping.
resource "aws_iam_role_policy" "access_key_recovery_policy" {
  name = "${local.access_key_recovery_name}-policy"
  role = aws_iam_role.access_key_recovery_exec.id

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
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.access_key_recovery_name}",
          "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${local.access_key_recovery_name}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:ListUserTags"
        ]
        Resource = "arn:aws:iam::${var.account_id}:user/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
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
          "s3:GetObject"
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

data "archive_file" "access_key_recovery_request_lambda" {
  type        = "zip"
  source_dir  = var.access_key_recovery_source_dir
  output_path = "access_key_recovery_request.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

#checkov:skip=CKV_AWS_117:This function calls AWS public APIs only; VPC placement would add NAT and ENI failure modes without reducing exposure.
#checkov:skip=CKV_AWS_272:Deployment artifacts are built outside AWS Signer; enforcing code signing here would break unsigned CI deploys.
resource "aws_lambda_function" "access_key_recovery_request" {
  filename                       = data.archive_file.access_key_recovery_request_lambda.output_path
  function_name                  = local.access_key_recovery_name
  role                           = aws_iam_role.access_key_recovery_exec.arn
  handler                        = "password_recovery_request.password_recovery_request.lambda_handler"
  source_code_hash               = data.archive_file.access_key_recovery_request_lambda.output_base64sha256
  runtime                        = "python3.11"
  timeout                        = 60
  memory_size                    = 256
  kms_key_arn                    = aws_kms_key.data.arn
  reserved_concurrent_executions = local.lambda_reserved_concurrency.access_key_recovery

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_failures.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = merge(
      {
        DYNAMODB_TABLE                               = aws_dynamodb_table.key_rotation_tracking.name
        S3_BUCKET                                    = aws_s3_bucket.credentials.id
        SENDER_EMAIL                                 = var.sender_email
        SUPPORT_EMAIL                                = coalesce(var.support_email, var.sender_email)
        ACCESS_KEY_RECOVERY_REQUEST_COOLDOWN_MINUTES = tostring(var.access_key_recovery_request_cooldown_minutes)
        ACCESS_KEY_RECOVERY_MAX_REQUESTS_PER_DAY     = tostring(var.access_key_recovery_max_requests_per_day)
      },
      var.ses_region == null ? {} : { SES_REGION = var.ses_region },
      var.ses_configuration_set == null ? {} : { SES_CONFIGURATION_SET = var.ses_configuration_set }
    )
  }

  tags = var.common_tags

  depends_on = [
    aws_cloudwatch_log_group.access_key_recovery_request
  ]
}

resource "aws_cloudwatch_log_group" "access_key_recovery_request" {
  name              = "/aws/lambda/${local.access_key_recovery_name}"
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}
