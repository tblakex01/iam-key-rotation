#===================================#
#     IAM CREDENTIALS S3 BUCKET     #
#===================================#

#checkov:skip=CKV_AWS_21:Credential objects must become irrecoverable after deletion, so versioning stays suspended on this bucket.
#checkov:skip=CKV_AWS_144:Cross-region replication is intentionally omitted for short-lived credential material.
#checkov:skip=CKV2_AWS_62:Download tracking is implemented through CloudTrail data events instead of native bucket notifications.
# S3 bucket for storing encrypted IAM credentials
resource "aws_s3_bucket" "credentials" {
  bucket = local.credentials_bucket_name

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

# Keep only the current object version so a deleted credential file cannot be restored.
resource "aws_s3_bucket_versioning" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  versioning_configuration {
    status = "Suspended"
  }
}

# Server-side encryption with a customer-managed key
resource "aws_s3_bucket_server_side_encryption_configuration" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "credentials" {
  bucket        = aws_s3_bucket.credentials.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access/credentials/"
}

# Lifecycle policy to clean up old versions and incomplete uploads
resource "aws_s3_bucket_lifecycle_configuration" "credentials" {
  bucket = aws_s3_bucket.credentials.id

  # Abort incomplete multipart uploads after 1 day
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

#checkov:skip=CKV_AWS_144:Cross-region replication is not required for derived audit logs in this module.
#checkov:skip=CKV2_AWS_62:This bucket is an audit sink and does not need native event notifications.
# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = local.cloudtrail_bucket_name

  tags = merge(
    var.common_tags,
    {
      Name    = "IAM Credentials CloudTrail Logs"
      Purpose = "CloudTrail logs for download tracking"
    }
  )
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-cloudtrail-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket        = aws_s3_bucket.cloudtrail_logs.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access/cloudtrail/"
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
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${var.account_id}/*"
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
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  sns_topic_name                = local.alarm_sns_topic_name
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.data.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn

  event_selector {
    read_write_type           = "ReadOnly"
    include_management_events = false

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.credentials.arn}/credentials/*"]
    }
  }

  tags = var.common_tags

  depends_on = [
    aws_cloudwatch_log_group.cloudtrail,
    aws_iam_role_policy.cloudtrail_logs,
    aws_s3_bucket_policy.cloudtrail_logs,
  ]
}

# EventBridge rule to capture CloudTrail S3 GetObject events
resource "aws_cloudwatch_event_rule" "s3_download_events" {
  name        = local.download_events_rule_name
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
  target_id = "${local.download_tracker_name}-target"
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
            aws_iam_role.download_tracker_exec.arn,
            aws_iam_role.url_regenerator_exec.arn,
            aws_iam_role.cleanup_exec.arn,
            aws_iam_role.s3_cleanup_exec.arn
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
            aws_iam_role.download_tracker_exec.arn,
            aws_iam_role.url_regenerator_exec.arn,
            aws_iam_role.cleanup_exec.arn,
            aws_iam_role.s3_cleanup_exec.arn
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
        Action = "s3:*"
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
