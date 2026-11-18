output "alb_arn" {
  description = "ARN of the public HTTPS Application Load Balancer."
  value       = aws_lb.public.arn
}

output "alb_dns_name" {
  description = "Public DNS hostname of the Application Load Balancer."
  value       = aws_lb.public.dns_name
}

output "broker_endpoints" {
  description = "Private internal DNS names and instance IDs of the three broker nodes."
  value = {
    for name, rec in aws_route53_record.broker_internal : name => {
      fqdn        = rec.fqdn
      instance_id = aws_instance.broker[name].id
    }
  }
}

output "database_endpoint" {
  description = "Private writer endpoint of the PostgreSQL 18 RDS instance."
  value       = aws_db_instance.main.endpoint
}

output "database_resource_id" {
  description = "AWS RDS resource ID used to scope rds-db:connect IAM policies."
  value       = aws_db_instance.main.resource_id
}

output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key protecting secrets and volumes."
  value       = aws_kms_key.secrets.arn
}

output "private_app_subnet_ids" {
  description = "IDs of the private application subnets across three AZs."
  value       = [for s in aws_subnet.private_app : s.id]
}

output "private_data_subnet_ids" {
  description = "IDs of the isolated private data subnets across three AZs."
  value       = [for s in aws_subnet.private_data : s.id]
}

output "public_subnet_ids" {
  description = "IDs of the public ingress subnets across three AZs."
  value       = [for s in aws_subnet.public : s.id]
}

output "secret_container_arns" {
  description = "Non-secret ARNs of provisioned AWS Secrets Manager containers."
  value       = { for k, s in aws_secretsmanager_secret.containers : k => s.arn }
}

output "target_group_arns" {
  description = "ARNs of the ALB target groups for console, API, receiver, and provider ingress."
  value = {
    api              = aws_lb_target_group.api.arn
    console          = aws_lb_target_group.console.arn
    provider_ingress = aws_lb_target_group.provider_ingress.arn
    receiver         = aws_lb_target_group.receiver.arn
  }
}

output "vpc_id" {
  description = "ID of the isolated Relayquill VPC."
  value       = aws_vpc.main.id
}

output "workload_role_arns" {
  description = "Map of Relayquill role names to their least-privilege IAM role ARNs."
  value       = { for k, r in aws_iam_role.workload : k => r.arn }
}
