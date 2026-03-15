terraform {
  required_version = ">= 1.5.0"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }

    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.16.2"
    }
  }
}
