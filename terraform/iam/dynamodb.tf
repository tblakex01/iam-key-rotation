#===================================#
#    IAM KEY ROTATION TRACKING      #
#===================================#

# DynamoDB table for tracking IAM key rotations
resource "aws_dynamodb_table" "key_rotation_tracking" {
  name         = local.tracking_table_name
  billing_mode = "PAY_PER_REQUEST" # On-demand pricing
  hash_key     = "PK"
  range_key    = "SK"

  # Primary key structure: PK = USER#username, SK = ROTATION#timestamp
  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # GSI for querying by status
  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "rotation_initiated"
    type = "S"
  }

  attribute {
    name = "s3_key"
    type = "S"
  }

  # Global Secondary Index: Query by status
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "rotation_initiated"
    projection_type = "ALL"
  }

  # Global Secondary Index: Query by exact credential object key
  global_secondary_index {
    name            = "s3-key-index"
    hash_key        = "s3_key"
    projection_type = "ALL"
  }

  # Enable TTL for automatic cleanup of old records (90 days after rotation)
  ttl {
    attribute_name = "TTL"
    enabled        = true
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = true
  }

  # Enable encryption at rest
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  tags = merge(
    var.common_tags,
    {
      Name    = "IAM Key Rotation Tracking"
      Purpose = "Track rotation status and download metrics"
    }
  )
}

# CloudWatch alarm for tracking table throttling
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttles" {
  alarm_name          = local.dynamodb_alarm_name
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Alert when DynamoDB table is being throttled"
  alarm_actions       = [var.alarm_sns_topic]

  dimensions = {
    TableName = aws_dynamodb_table.key_rotation_tracking.name
  }

  tags = var.common_tags
}
