# ---------------------------------------------------------------------------------------------------------------------
# ROOT TERRAGRUNT CONFIGURATION
# This is the root configuration that all child terragrunt configurations will inherit from.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  # Core application settings
  app_name = "iam-key-rotation"
  
  # Get account-level variables
  account_vars = read_terragrunt_config(find_in_parent_folders("account.hcl"))
  
  # Get region-level variables  
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  # Get environment-level variables
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  
  # Extract variables
  account_name = local.account_vars.locals.account_name
  account_id   = local.account_vars.locals.account_id
  profile      = local.account_vars.locals.profile
  region       = local.region_vars.locals.region  
  environment  = local.env_vars.locals.environment
  
  # Terraform state configuration - Use existing pattern from ace-terraform-live
  tf_state_bucket    = "mvwc-terraform-state-datawarehouse-${local.region}"
  tf_state_key_path  = "${path_relative_to_include()}/terraform.tfstate"
  tf_locks_table     = "terraform-locks"
}

# Generate Terraform configuration with provider requirements
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.16.2"
    }
  }
  required_version = ">= 1.5.0"
}

provider "aws" {
  region  = "${local.region}"
  profile = "${local.profile}"

  default_tags {
    tags = {
      Application = "${local.app_name}"
      Environment = "${local.environment}"
      Account     = "${local.account_name}"
      Region      = "${local.region}"
      ManagedBy   = "terragrunt"
      Repository  = "iam-key-rotation"
    }
  }
}
EOF
}

# Configure Terragrunt to automatically store tfstate files in an S3 bucket
remote_state {
  backend = "s3"
  config = {
    encrypt        = true
    bucket         = local.tf_state_bucket
    key            = local.tf_state_key_path
    region         = local.region
    dynamodb_table = local.tf_locks_table
    profile        = local.profile
    
    # S3 bucket versioning and lifecycle
    s3_bucket_tags = {
      Application = local.app_name
      Environment = local.environment
      Account     = local.account_name
      ManagedBy   = "terragrunt"
    }
    
    # DynamoDB table tags
    dynamodb_table_tags = {
      Application = local.app_name
      Environment = local.environment
      Account     = local.account_name
      ManagedBy   = "terragrunt"
    }
  }
  
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

# Global Terraform configuration
terraform {
  # Require minimum Terraform version
  extra_arguments "common_vars" {
    commands = ["plan", "apply", "destroy", "refresh", "import", "push", "validate"]
    
    env_vars = {
      TF_CLI_ARGS = "-no-color"
    }
  }
  
  # Clean up .terragrunt-cache on destroy
  after_hook "cleanup_cache" {
    commands     = ["destroy"]
    execute      = ["find", "${get_terragrunt_dir()}", "-type", "d", "-name", ".terragrunt-cache", "-prune", "-exec", "rm", "-rf", "{}", ";"]
    run_on_error = true
  }
}
