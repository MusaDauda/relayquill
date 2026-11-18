terraform {
  required_version = ">= 1.14"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Application = "relayquill"
      Deployment  = var.deployment_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
