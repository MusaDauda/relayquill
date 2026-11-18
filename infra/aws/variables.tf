variable "allowed_ingress_cidrs" {
  description = "IPv4 CIDR blocks permitted to reach the public HTTPS load balancer."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "availability_zones" {
  description = "Three availability zones used for multi-AZ subnet and broker quorum placement."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  validation {
    condition     = length(var.availability_zones) == 3
    error_message = "Exactly three availability zones are required for the broker quorum."
  }
}

variable "aws_region" {
  description = "Target AWS region for the optional AWS release topology."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z-]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region identifier."
  }
}

variable "broker_ami_id" {
  description = "Pinned Linux AMI ID used for the three private NATS JetStream broker instances."
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.broker_ami_id))
    error_message = "broker_ami_id must be a valid EC2 AMI ID (ami-...)."
  }
}

variable "broker_instance_type" {
  description = "EC2 instance type for each private JetStream broker node."
  type        = string
  default     = "t4g.small"
}

variable "broker_volume_size_gb" {
  description = "Encrypted gp3 EBS volume size in GiB for each broker node JetStream store."
  type        = number
  default     = 50

  validation {
    condition     = var.broker_volume_size_gb >= 20 && var.broker_volume_size_gb <= 4096
    error_message = "broker_volume_size_gb must be between 20 and 4096 GiB."
  }
}

variable "database_allocated_storage_gb" {
  description = "Initial allocated gp3 storage in GiB for the private PostgreSQL 18 instance."
  type        = number
  default     = 50

  validation {
    condition     = var.database_allocated_storage_gb >= 20 && var.database_allocated_storage_gb <= 16384
    error_message = "database_allocated_storage_gb must be between 20 and 16384 GiB."
  }
}

variable "database_instance_class" {
  description = "RDS instance class for private PostgreSQL 18."
  type        = string
  default     = "db.t4g.medium"
}

variable "database_multi_az" {
  description = "Enable synchronous Multi-AZ standby for RDS PostgreSQL 18."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Enable deletion protection on stateful RDS and load balancer resources."
  type        = bool
  default     = true
}

variable "deployment_name" {
  description = "Unique deployment identifier used to prefix AWS resource names."
  type        = string
  default     = "relayquill-prod"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,40}$", var.deployment_name))
    error_message = "deployment_name must be lowercase alphanumeric and hyphens (2-41 chars)."
  }
}

variable "eks_cluster_name" {
  description = "Optional EKS cluster name used to scope EKS Pod Identity associations when deploying on EKS."
  type        = string
  default     = "relayquill-eks"
}

variable "environment" {
  description = "Target deployment environment label."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "internal_domain_name" {
  description = "Private Route53 zone domain for internal broker cluster DNS names."
  type        = string
  default     = "internal.relayquill.local"
}

variable "postgres_engine_version" {
  description = "PostgreSQL 18 engine version string supported by AWS RDS in the target region."
  type        = string
  default     = "18.1"
}

variable "public_api_domain" {
  description = "Public DNS hostname for direct machine producer API access."
  type        = string
}

variable "public_console_domain" {
  description = "Public DNS hostname for the operator console and same-origin /api/* routes."
  type        = string
}

variable "public_ingress_domain" {
  description = "Public DNS hostname for the independent provider-ingress listener."
  type        = string
}

variable "public_receiver_domain" {
  description = "Public DNS hostname for the independent example receiver listener."
  type        = string
}

variable "public_zone_id" {
  description = "Existing Route53 public hosted zone ID for ACM validation and public alias records."
  type        = string
}

variable "secret_recovery_window_days" {
  description = "Secrets Manager recovery window in days before permanent container deletion."
  type        = number
  default     = 30

  validation {
    condition     = var.secret_recovery_window_days >= 7 && var.secret_recovery_window_days <= 30
    error_message = "secret_recovery_window_days must be between 7 and 30."
  }
}

variable "single_nat_gateway" {
  description = "Use one shared NAT Gateway instead of one per AZ (set false for HA production)."
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "IPv4 CIDR block for the isolated Relayquill VPC."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}
