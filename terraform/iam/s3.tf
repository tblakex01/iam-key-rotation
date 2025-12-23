#===================================#
#     IAM CREDENTIALS S3 BUCKET     #
#===================================#

# S3 bucket for storing encrypted IAM credentials
resource "aws_s3_bucket" "credentials" {
  bucket = "iam-credentials-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.common_tags,
    {
      Name        = "IAM Key Rotation Credentials"
      Purpose     = "Temporary storage for rotated IAM access keys"
      Sensitivity = "High"
    }
  )
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for accidental deletion protection
resource "aws_s3_bucket_versioning" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption with AWS managed keys
resource "aws_s3_bucket_server_side_encryption_configuration" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Lifecycle policy to clean up old versions and incomplete uploads
resource "aws_s3_bucket_lifecycle_configuration" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  # Clean up old versions after 1 day (since files are deleted on download)
  rule {
    id     = "delete-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  # Abort incomplete multipart uploads after 1 day
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "iam-credentials-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = merge(
    var.common_tags,
    {
      Name    = "IAM Credentials CloudTrail Logs"
      Purpose = "CloudTrail logs for download tracking"
    }
  )
}

# CloudTrail log bucket policy
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# CloudTrail for S3 data events (tracks GetObject for download detection)
resource "aws_cloudtrail" "s3_data_events" {
  name                          = "iam-credentials-download-tracking"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_logging                = true

  event_selector {
    read_write_type           = "ReadOnly"
    include_management_events = false

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.credentials.arn}/credentials/*"]
    }
  }

  tags = var.common_tags
  
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# EventBridge rule to capture CloudTrail S3 GetObject events
resource "aws_cloudwatch_event_rule" "s3_download_events" {
  name        = "iam-credentials-download-events"
  description = "Capture S3 GetObject events for credential downloads"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject"]
      requestParameters = {
        bucketName = [aws_s3_bucket.credentials.id]
      }
    }
  })

  tags = var.common_tags
}

# EventBridge target to trigger download tracker Lambda
resource "aws_cloudwatch_event_target" "download_tracker" {
  rule      = aws_cloudwatch_event_rule.s3_download_events.name
  target_id = "download-tracker-lambda"
  arn       = aws_lambda_function.download_tracker.arn
}

# Lambda permission for EventBridge to invoke download tracker
resource "aws_lambda_permission" "allow_eventbridge_download_tracker" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.download_tracker.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_download_events.arn
}

# Bucket policy - restrict access to Lambda execution roles only
resource "aws_s3_bucket_policy" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaReadWrite"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.lambda_exec.arn,
            aws_iam_role.download_tracker_exec.arn
          ]
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.credentials.arn}/*"
      },
      {
        Sid    = "AllowLambdaListBucket"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.lambda_exec.arn,
            aws_iam_role.download_tracker_exec.arn
          ]
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.credentials.arn
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.credentials.arn,
          "${aws_s3_bucket.credentials.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
