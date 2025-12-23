variable "common_tags" {
  type = map(any)
  default = {
    resource-owner   = "aws-landing-zone@jennasrunbooks.com"
    environment-type = "lab"
    provisioner      = "terraform"
    repo             = "aws-security"
  }
}

# Lambda configuration variables
variable "warning_threshold" {
  description = "Number of days before access key expiration to send warning"
  type        = number
  default     = 75
}

variable "urgent_threshold" {
  description = "Number of days before access key expiration to send urgent notice"
  type        = number
  default     = 85
}

variable "disable_threshold" {
  description = "Number of days after which access keys are disabled"
  type        = number
  default     = 90
}

variable "auto_disable" {
  description = "Whether to automatically disable expired access keys"
  type        = bool
  default     = false
}

variable "sender_email" {
  description = "Email address to send notifications from (must be verified in SES)"
  type        = string
  default     = "cloud-admins@jennasrunbooks.com"
}

variable "exemption_tag" {
  description = "Tag key to check for access key rotation exemptions"
  type        = string
  default     = "key-rotation-exempt"
}

variable "schedule_expression" {
  description = "CloudWatch Events schedule expression for Lambda execution"
  type        = string
  default     = "rate(1 day)"
}

variable "alarm_sns_topic" {
  description = "SNS topic ARN for CloudWatch alarms (optional)"
  type        = string
  default     = ""
}

variable "lambda_source_dir" {
  description = "Source directory for Lambda function code"
  type        = string
  default     = "../../lambda/access_key_enforcement"
}

variable "scripts_path" {
  description = "Path to the scripts directory for provisioners"
  type        = string
  default     = "../../scripts"
}

variable "credential_retention_days" {
  description = "Number of days to retain credentials before deleting old IAM key (14 days = 2 URLs with 7-day expiration each)"
  type        = number
  default     = 14
}

variable "download_tracker_source_dir" {
  description = "Source directory for download tracker Lambda code"
  type        = string
  default     = "../../lambda/download_tracker"
}

variable "url_regenerator_source_dir" {
  description = "Source directory for URL regenerator Lambda code"
  type        = string
  default     = "../../lambda/url_regenerator"
}

variable "cleanup_source_dir" {
  description = "Source directory for cleanup Lambda code"
  type        = string
  default     = "../../lambda/cleanup"
}
