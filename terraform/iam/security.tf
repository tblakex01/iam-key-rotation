resource "aws_kms_key" "data" {
  description             = "CMK for IAM key rotation data stores and delivery paths."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.cloudtrail_trail_arn
          }
        }
      },
      {
        Sid    = "AllowCloudTrailGrantManagement"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = true
          }
          StringEquals = {
            "aws:SourceArn" = local.cloudtrail_trail_arn
          }
        }
      }
    ]
  })

  tags = var.common_tags
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.resource_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}

resource "aws_kms_key" "logs" {
  description             = "CMK for IAM key rotation CloudWatch logs."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:CreateGrant",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:*"
          }
          Bool = {
            "kms:GrantIsForAWSResource" = true
          }
        }
      }
    ]
  })

  tags = var.common_tags
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.resource_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

#checkov:skip=CKV_AWS_18:This bucket is the terminal S3 server access log sink.
#checkov:skip=CKV_AWS_144:Cross-region replication is not required for derived access logs in this module.
#checkov:skip=CKV2_AWS_62:Access logs are exported here; event notifications are not an operational requirement.
resource "aws_s3_bucket" "access_logs" {
  bucket = local.access_logs_bucket_name

  tags = merge(
    var.common_tags,
    {
      Name    = "IAM Key Rotation Access Logs"
      Purpose = "Terminal sink for S3 server access logs"
    }
  )
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
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

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3AccessLogsDelivery"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs.arn}/s3-access/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = [
              aws_s3_bucket.credentials.arn,
              aws_s3_bucket.cloudtrail_logs.arn,
            ]
          }
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = local.cloudtrail_log_group_name
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}

resource "aws_iam_role" "cloudtrail_logs" {
  name = "${local.trail_name}-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })

  tags = var.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "${local.trail_name}-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}
