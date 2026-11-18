# Optional AWS Deployment Infrastructure

> **Note:** Production Relayquill requires **zero managed services**. The primary self-hosted production deployment targets (`infra/compose.prod.yaml` and `infra/kubernetes/overlays/selfhosted/`) run 100% on standard open-source PostgreSQL 18, a 3-node self-hosted Go/NATS JetStream quorum, and static Nginx + Node 24 TypeScript workers. See [self-hosted-production.md](../../docs/self-hosted-production.md) for the vendor-neutral production guide.

This directory contains an **optional** Terraform configuration for provisioning AWS infrastructure (VPC, private RDS PostgreSQL 18 with IAM auth, three isolated private JetStream broker EC2 hosts, public HTTPS ALB, KMS, and empty Secrets Manager containers).

## Security Invariants

- **No secrets in Terraform state:** Zero `random_password`, `tls_private_key`, or `aws_secretsmanager_secret_version` resources exist here. RDS uses `manage_master_user_password = true`, and application/broker secret containers are populated out-of-band by an isolated secret issuer.
- **No public database or broker listeners:** PostgreSQL and NATS JetStream reside in `private_data` subnets without public IPs or internet routes.
- **Least-privilege IAM:** Each role (`api`, `relay`, `fanout`, `sender`, `coordinator`, `migrator`, `recovery`, `signing_issuer`, `receiver`, `provider_ingress`) receives scoped `rds-db:connect` for its exact database user and narrow Secrets Manager read access only where required.

## Usage

1. Pre-create the encrypted S3 state bucket and DynamoDB lock table referenced in `config/release.backend.hcl` (never use the application database as the Terraform backend).
2. Create an untracked `.tfvars` file (never commit `.tfvars` to Git) supplying `broker_ami_id`, `public_zone_id`, `public_console_domain`, `public_api_domain`, `public_receiver_domain`, and `public_ingress_domain`.
3. Validate and inspect a saved plan before applying:

```bash
terraform -chdir=infra/aws fmt -check -recursive
terraform -chdir=infra/aws init -backend-config=../../config/release.backend.hcl
terraform -chdir=infra/aws validate
terraform -chdir=infra/aws plan -var-file=prod.tfvars -out=tfplan.bin
```

## Main Cost Drivers & Teardown

- Multi-AZ RDS PostgreSQL 18 (`db.t4g.medium`) + automated backups
- Three NAT Gateways (set `single_nat_gateway = true` for staging) and Interface VPC Endpoints (`ecr.api`, `ecr.dkr`, `secretsmanager`, `ssm`, `sts`, `logs`)
- Three private EC2 broker nodes (`t4g.small`) with encrypted `gp3` EBS volumes
- Public Application Load Balancer

Before running `terraform destroy`, pause admission and sending at the application gate, drain active sender deliveries, capture final recovery snapshots if required by retention policy, and verify all resources matching `Deployment = var.deployment_name` are inventoried.
