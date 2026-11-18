resource "aws_db_subnet_group" "main" {
  description = "Private data subnets for Relayquill PostgreSQL 18."
  name        = "${var.deployment_name}-pg-subnets"
  subnet_ids  = [for s in aws_subnet.private_data : s.id]

  tags = {
    Name = "${var.deployment_name}-pg-subnets"
  }
}

resource "aws_db_parameter_group" "main" {
  description = "PostgreSQL 18 parameter group enforcing TLS and SCRAM-SHA-256."
  family      = "postgres18"
  name        = "${var.deployment_name}-pg18-params"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "main" {
  allocated_storage                   = var.database_allocated_storage_gb
  backup_retention_period             = 14
  copy_tags_to_snapshot               = true
  db_name                             = "relayquill"
  db_subnet_group_name                = aws_db_subnet_group.main.name
  deletion_protection                 = var.deletion_protection
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  engine                              = "postgres"
  engine_version                      = var.postgres_engine_version
  final_snapshot_identifier           = "${var.deployment_name}-pg-final"
  iam_database_authentication_enabled = true
  identifier                          = "${var.deployment_name}-pg"
  instance_class                      = var.database_instance_class
  kms_key_id                          = aws_kms_key.secrets.arn
  manage_master_user_password         = true
  master_user_secret_kms_key_id       = aws_kms_key.secrets.arn
  multi_az                            = var.database_multi_az
  parameter_group_name                = aws_db_parameter_group.main.name
  publicly_accessible                 = false
  skip_final_snapshot                 = false
  storage_encrypted                   = true
  storage_type                        = "gp3"
  username                            = "postgres"
  vpc_security_group_ids              = [aws_security_group.database.id]

  tags = {
    Name = "${var.deployment_name}-pg"
  }
}
