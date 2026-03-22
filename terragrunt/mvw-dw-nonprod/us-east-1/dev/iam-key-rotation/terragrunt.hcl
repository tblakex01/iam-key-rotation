# ---------------------------------------------------------------------------------------------------------------------
# IAM KEY ROTATION SERVICE CONFIGURATION
# Terragrunt configuration for deploying IAM key rotation enforcement
# ---------------------------------------------------------------------------------------------------------------------

include "root" {
  path = find_in_parent_folders("root.terragrunt.hcl")
}

locals {
  # Import parent configurations
  account_vars = read_terragrunt_config(find_in_parent_folders("account.hcl"))
  region_vars  = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  env_vars     = read_terragrunt_config(find_in_parent_folders("env.hcl"))

  # Import service-specific configuration
  config_vars = read_terragrunt_config("config.hcl")

  # Extract configuration with validation
  account_name = local.account_vars.locals.account_name
  region       = local.region_vars.locals.region
  environment  = local.env_vars.locals.environment

  # Service-specific settings
  service_name = "iam-key-rotation"

  # Validate required configuration exists
  _validate_sender_email = local.config_vars.locals.sender_email != "" ? true : tobool("sender_email cannot be empty")
}

# Terraform module source
terraform {
  source = "${get_repo_root()}/terraform/iam"

  # Pass source paths as environment variables
  extra_arguments "source_paths" {
    commands = ["plan", "apply", "destroy"]
    env_vars = {
      TF_VAR_lambda_source_dir              = "${get_repo_root()}/lambda"
      TF_VAR_access_key_recovery_source_dir = "${get_repo_root()}/lambda"
      TF_VAR_download_tracker_source_dir    = "${get_repo_root()}/lambda"
      TF_VAR_url_regenerator_source_dir     = "${get_repo_root()}/lambda"
      TF_VAR_cleanup_source_dir             = "${get_repo_root()}/lambda"
      TF_VAR_s3_cleanup_source_dir          = "${get_repo_root()}/lambda"
    }
  }
}

# Inputs that pass variables to Terraform module
inputs = {
  name_prefix      = local.service_name
  environment_name = local.environment
  account_id       = local.account_vars.locals.account_id
  aws_region       = local.region

  # Common resource tags
  common_tags = local.config_vars.locals.common_tags

  # IAM Key Rotation Policy Configuration
  warning_threshold   = local.config_vars.locals.warning_threshold
  urgent_threshold    = local.config_vars.locals.urgent_threshold
  disable_threshold   = local.config_vars.locals.disable_threshold
  auto_disable        = local.config_vars.locals.auto_disable
  exemption_tag       = local.config_vars.locals.exemption_tag
  sender_email        = local.config_vars.locals.sender_email
  support_email       = try(local.config_vars.locals.support_email, local.config_vars.locals.sender_email)
  alarm_sns_topic     = local.config_vars.locals.alarm_sns_topic
  schedule_expression = local.config_vars.locals.schedule_expression

  # Self-service access-key recovery API configuration
  ses_configuration_set                        = try(local.config_vars.locals.ses_configuration_set, null)
  access_key_recovery_request_cooldown_minutes = try(local.config_vars.locals.access_key_recovery_request_cooldown_minutes, 15)
  access_key_recovery_max_requests_per_day     = try(local.config_vars.locals.access_key_recovery_max_requests_per_day, 5)

  # Retention Configuration
  new_key_retention_days = local.config_vars.locals.new_key_retention_days
  old_key_retention_days = local.config_vars.locals.old_key_retention_days

  # Explicit IAM users managed in this environment
  managed_user_info = local.config_vars.locals.managed_user_info
}
