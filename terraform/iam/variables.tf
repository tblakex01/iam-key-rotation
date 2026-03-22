variable "name_prefix" {
  description = "Stable service prefix used when naming resources."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment_name" {
  description = "Deployment environment name such as dev, nonprod, or prod."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment_name))
    error_message = "environment_name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "account_id" {
  description = "AWS account ID for the target environment."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^\\d{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "aws_region" {
  description = "AWS region for the target environment."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d$", var.aws_region))
    error_message = "aws_region must be a valid AWS region like us-east-1."
  }
}

variable "common_tags" {
  description = "Common tags applied to all managed resources."
  type        = map(string)
  default     = {}
}

variable "managed_user_info" {
  description = "Explicit map of IAM users to manage in this environment."
  type = map(object({
    email     = string
    user_tags = optional(map(string), {})
  }))
  default = {}
}

variable "warning_threshold" {
  description = "Number of days before access key expiration to send warning."
  type        = number
  default     = 75
}

variable "urgent_threshold" {
  description = "Number of days before access key expiration to send urgent notice."
  type        = number
  default     = 85
}

variable "disable_threshold" {
  description = "Number of days after which access keys are disabled."
  type        = number
  default     = 90
}

variable "auto_disable" {
  description = "Whether to automatically disable expired access keys."
  type        = bool
  default     = false
}

variable "sender_email" {
  description = "Verified SES sender email address used for notifications."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.sender_email))
    error_message = "sender_email must be a valid email address."
  }
}

variable "exemption_tag" {
  description = "Tag key checked for access key rotation exemptions."
  type        = string
  default     = "key-rotation-exempt"
}

variable "schedule_expression" {
  description = "EventBridge schedule expression for the enforcement Lambda."
  type        = string
  default     = "rate(1 day)"
}

variable "alarm_sns_topic" {
  description = "SNS topic ARN used for all CloudWatch alarm notifications."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:sns:[a-z0-9-]+:\\d{12}:.+$", var.alarm_sns_topic))
    error_message = "alarm_sns_topic must be a valid SNS topic ARN."
  }
}

variable "lambda_source_dir" {
  description = "Source directory for the shared Lambda package."
  type        = string
  default     = "../../lambda"
}

variable "download_tracker_source_dir" {
  description = "Source directory for the shared Lambda package."
  type        = string
  default     = "../../lambda"
}

variable "url_regenerator_source_dir" {
  description = "Source directory for the shared Lambda package."
  type        = string
  default     = "../../lambda"
}

variable "cleanup_source_dir" {
  description = "Source directory for the shared Lambda package."
  type        = string
  default     = "../../lambda"
}

variable "s3_cleanup_source_dir" {
  description = "Source directory for the shared Lambda package."
  type        = string
  default     = "../../lambda"
}

variable "access_key_recovery_source_dir" {
  description = "Source directory for the shared Lambda package."
  type        = string
  default     = "../../lambda"
}

variable "new_key_retention_days" {
  description = "Number of days to retain new key credentials in S3."
  type        = number
  default     = 45
}

variable "old_key_retention_days" {
  description = "Number of days before deleting the old IAM access key after rotation."
  type        = number
  default     = 30
}

variable "support_email" {
  description = "Optional support contact shown in credential recovery emails. Defaults to sender_email."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.support_email == null || can(
      regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.support_email)
    )
    error_message = "support_email must be null or a valid email address."
  }
}

variable "ses_region" {
  description = "Optional SES region override for email sending."
  type        = string
  default     = null
  nullable    = true
}

variable "ses_configuration_set" {
  description = "Optional SES configuration set name for notification delivery."
  type        = string
  default     = null
  nullable    = true
}

variable "access_key_recovery_request_cooldown_minutes" {
  description = "Cooldown between successful self-service access-key recovery emails for a user."
  type        = number
  default     = 15

  validation {
    condition     = var.access_key_recovery_request_cooldown_minutes >= 0
    error_message = "access_key_recovery_request_cooldown_minutes must be greater than or equal to 0."
  }
}

variable "access_key_recovery_max_requests_per_day" {
  description = "Maximum successful self-service access-key recovery emails allowed per user in a rolling 24-hour window."
  type        = number
  default     = 5

  validation {
    condition     = var.access_key_recovery_max_requests_per_day >= 0
    error_message = "access_key_recovery_max_requests_per_day must be greater than or equal to 0."
  }
}

variable "access_key_recovery_stage_name" {
  description = "Stage name for the HTTP API serving self-service access-key recovery requests."
  type        = string
  default     = "$default"

  validation {
    condition     = trimspace(var.access_key_recovery_stage_name) != ""
    error_message = "access_key_recovery_stage_name must not be empty."
  }
}

variable "access_key_recovery_api_rate_limit" {
  description = "Steady-state request rate limit per second for the self-service access-key recovery API."
  type        = number
  default     = 10

  validation {
    condition     = var.access_key_recovery_api_rate_limit > 0
    error_message = "access_key_recovery_api_rate_limit must be greater than 0."
  }
}

variable "access_key_recovery_api_burst_limit" {
  description = "Burst request limit for the self-service access-key recovery API."
  type        = number
  default     = 20

  validation {
    condition     = var.access_key_recovery_api_burst_limit > 0
    error_message = "access_key_recovery_api_burst_limit must be greater than 0."
  }
}
