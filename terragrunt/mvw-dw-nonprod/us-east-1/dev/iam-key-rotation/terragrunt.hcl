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
      TF_VAR_lambda_source_dir             = "${get_repo_root()}/lambda/access_key_enforcement"
      TF_VAR_download_tracker_source_dir   = "${get_repo_root()}/lambda/download_tracker"
      TF_VAR_url_regenerator_source_dir    = "${get_repo_root()}/lambda/url_regenerator"
      TF_VAR_cleanup_source_dir            = "${get_repo_root()}/lambda/cleanup"
      TF_VAR_s3_cleanup_source_dir         = "${get_repo_root()}/lambda/s3_cleanup"
      TF_VAR_scripts_path                  = "${get_repo_root()}/scripts"
    }
  }
}

# Inputs that pass variables to Terraform module
inputs = {
  # Common resource tags
  common_tags = local.config_vars.locals.common_tags
  
  # IAM Key Rotation Policy Configuration
  warning_threshold      = local.config_vars.locals.warning_threshold
  urgent_threshold       = local.config_vars.locals.urgent_threshold  
  disable_threshold      = local.config_vars.locals.disable_threshold
  auto_disable           = local.config_vars.locals.auto_disable
  exemption_tag          = local.config_vars.locals.exemption_tag
  sender_email           = local.config_vars.locals.sender_email
  schedule_expression    = local.config_vars.locals.schedule_expression
  alarm_sns_topic        = local.config_vars.locals.alarm_sns_topic
  
  # Retention Configuration
  new_key_retention_days = local.config_vars.locals.new_key_retention_days
  old_key_retention_days = local.config_vars.locals.old_key_retention_days
  
  # Test Users Configuration (SAFE FOR TESTING)
  user_info = local.config_vars.locals.user_info
}
