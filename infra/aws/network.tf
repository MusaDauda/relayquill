locals {
  az_map = {
    for idx, az in var.availability_zones : tostring(idx) => {
      az               = az
      public_cidr      = cidrsubnet(var.vpc_cidr, 4, idx)
      private_app_cidr = cidrsubnet(var.vpc_cidr, 4, idx + 4)
      private_db_cidr  = cidrsubnet(var.vpc_cidr, 4, idx + 8)
    }
  }

  nat_keys = var.single_nat_gateway ? toset(["0"]) : toset(keys(local.az_map))

  interface_endpoints = toset([
    "ecr.api",
    "ecr.dkr",
    "secretsmanager",
    "ssm",
    "sts",
    "logs"
  ])

  db_client_roles = {
    api              = aws_security_group.api.id
    relay            = aws_security_group.relay.id
    fanout           = aws_security_group.fanout.id
    sender           = aws_security_group.sender.id
    coordinator      = aws_security_group.coordinator.id
    admin            = aws_security_group.admin.id
    receiver         = aws_security_group.receiver.id
    provider_ingress = aws_security_group.provider_ingress.id
  }

  broker_client_roles = {
    relay  = aws_security_group.relay.id
    fanout = aws_security_group.fanout.id
    admin  = aws_security_group.admin.id
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.deployment_name}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-igw"
  }
}

resource "aws_subnet" "public" {
  for_each = local.az_map

  availability_zone       = each.value.az
  cidr_block              = each.value.public_cidr
  map_public_ip_on_launch = false
  vpc_id                  = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-public-${each.value.az}"
    Tier = "public"
  }
}

resource "aws_subnet" "private_app" {
  for_each = local.az_map

  availability_zone       = each.value.az
  cidr_block              = each.value.private_app_cidr
  map_public_ip_on_launch = false
  vpc_id                  = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-app-${each.value.az}"
    Tier = "private-app"
  }
}

resource "aws_subnet" "private_data" {
  for_each = local.az_map

  availability_zone       = each.value.az
  cidr_block              = each.value.private_db_cidr
  map_public_ip_on_launch = false
  vpc_id                  = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-data-${each.value.az}"
    Tier = "private-data"
  }
}

resource "aws_eip" "nat" {
  for_each = local.nat_keys

  domain = "vpc"

  tags = {
    Name = "${var.deployment_name}-nat-eip-${each.key}"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  for_each = local.nat_keys

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id

  tags = {
    Name = "${var.deployment_name}-nat-${each.key}"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.deployment_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  route_table_id = aws_route_table.public.id
  subnet_id      = each.value.id
}

resource "aws_route_table" "private_app" {
  for_each = local.az_map

  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[var.single_nat_gateway ? "0" : each.key].id
  }

  tags = {
    Name = "${var.deployment_name}-app-rt-${each.key}"
  }
}

resource "aws_route_table_association" "private_app" {
  for_each = aws_subnet.private_app

  route_table_id = aws_route_table.private_app[each.key].id
  subnet_id      = each.value.id
}

# Data subnets have no internet or NAT default route; only local VPC and Gateway endpoints.
resource "aws_route_table" "private_data" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-data-rt"
  }
}

resource "aws_route_table_association" "private_data" {
  for_each = aws_subnet.private_data

  route_table_id = aws_route_table.private_data.id
  subnet_id      = each.value.id
}

resource "aws_security_group" "alb" {
  name        = "${var.deployment_name}-alb-sg"
  description = "Public HTTPS ALB ingress boundary."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-alb-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each = toset(var.allowed_ingress_cidrs)

  cidr_ipv4         = each.value
  description       = "HTTPS ingress to public ALB"
  from_port         = 443
  ip_protocol       = "tcp"
  security_group_id = aws_security_group.alb.id
  to_port           = 443
}

resource "aws_security_group" "console" {
  name        = "${var.deployment_name}-console-sg"
  description = "Static console reverse proxy."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-console-sg"
  }
}

resource "aws_security_group" "api" {
  name        = "${var.deployment_name}-api-sg"
  description = "Relayquill HTTP API process."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-api-sg"
  }
}

resource "aws_security_group" "relay" {
  name        = "${var.deployment_name}-relay-sg"
  description = "Outbox relay worker."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-relay-sg"
  }
}

resource "aws_security_group" "fanout" {
  name        = "${var.deployment_name}-fanout-sg"
  description = "JetStream pull fanout worker."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-fanout-sg"
  }
}

resource "aws_security_group" "sender" {
  name        = "${var.deployment_name}-sender-sg"
  description = "Constrained webhook sender worker."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-sender-sg"
  }
}

resource "aws_security_group" "coordinator" {
  name        = "${var.deployment_name}-coordinator-sg"
  description = "Reaper, retention, and projection coordinator worker."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-coordinator-sg"
  }
}

resource "aws_security_group" "admin" {
  name        = "${var.deployment_name}-admin-sg"
  description = "Privileged migration, broker setup, and recovery jobs."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-admin-sg"
  }
}

resource "aws_security_group" "receiver" {
  name        = "${var.deployment_name}-receiver-sg"
  description = "Independent example receiver authority."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-receiver-sg"
  }
}

resource "aws_security_group" "provider_ingress" {
  name        = "${var.deployment_name}-provider-ingress-sg"
  description = "Independent Stripe/Paystack provider ingress."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-provider-ingress-sg"
  }
}

resource "aws_security_group" "broker" {
  name        = "${var.deployment_name}-broker-sg"
  description = "Private 3-node NATS JetStream broker quorum."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-broker-sg"
  }
}

resource "aws_security_group" "database" {
  name        = "${var.deployment_name}-database-sg"
  description = "Private RDS PostgreSQL 18 instance."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-database-sg"
  }
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.deployment_name}-vpce-sg"
  description = "AWS PrivateLink interface endpoints."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-vpce-sg"
  }
}

# ALB -> Console / API / Receiver / Provider Ingress
resource "aws_vpc_security_group_egress_rule" "alb_to_console" {
  description                  = "ALB to console"
  from_port                    = 8080
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.console.id
  security_group_id            = aws_security_group.alb.id
  to_port                      = 8080
}

resource "aws_vpc_security_group_ingress_rule" "console_from_alb" {
  description                  = "Console from ALB"
  from_port                    = 8080
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id
  security_group_id            = aws_security_group.console.id
  to_port                      = 8080
}

resource "aws_vpc_security_group_egress_rule" "alb_to_api" {
  description                  = "ALB to API"
  from_port                    = 8005
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.api.id
  security_group_id            = aws_security_group.alb.id
  to_port                      = 8005
}

resource "aws_vpc_security_group_ingress_rule" "api_from_alb" {
  description                  = "API from ALB"
  from_port                    = 8005
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id
  security_group_id            = aws_security_group.api.id
  to_port                      = 8005
}

resource "aws_vpc_security_group_egress_rule" "console_to_api" {
  description                  = "Console proxy to API"
  from_port                    = 8005
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.api.id
  security_group_id            = aws_security_group.console.id
  to_port                      = 8005
}

resource "aws_vpc_security_group_ingress_rule" "api_from_console" {
  description                  = "API from console proxy"
  from_port                    = 8005
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.console.id
  security_group_id            = aws_security_group.api.id
  to_port                      = 8005
}

resource "aws_vpc_security_group_egress_rule" "alb_to_receiver" {
  description                  = "ALB to independent receiver"
  from_port                    = 19095
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.receiver.id
  security_group_id            = aws_security_group.alb.id
  to_port                      = 19095
}

resource "aws_vpc_security_group_ingress_rule" "receiver_from_alb" {
  description                  = "Receiver from ALB"
  from_port                    = 19095
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id
  security_group_id            = aws_security_group.receiver.id
  to_port                      = 19095
}

resource "aws_vpc_security_group_egress_rule" "alb_to_provider_ingress" {
  description                  = "ALB to provider ingress"
  from_port                    = 19096
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.provider_ingress.id
  security_group_id            = aws_security_group.alb.id
  to_port                      = 19096
}

resource "aws_vpc_security_group_ingress_rule" "provider_ingress_from_alb" {
  description                  = "Provider ingress from ALB"
  from_port                    = 19096
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id
  security_group_id            = aws_security_group.provider_ingress.id
  to_port                      = 19096
}

resource "aws_vpc_security_group_egress_rule" "provider_ingress_to_api" {
  description                  = "Provider ingress forwarder to Relayquill API"
  from_port                    = 8005
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.api.id
  security_group_id            = aws_security_group.provider_ingress.id
  to_port                      = 8005
}

resource "aws_vpc_security_group_ingress_rule" "api_from_provider_ingress" {
  description                  = "API from provider ingress forwarder"
  from_port                    = 8005
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.provider_ingress.id
  security_group_id            = aws_security_group.api.id
  to_port                      = 8005
}

# Scoped Database 5432 rules
resource "aws_vpc_security_group_ingress_rule" "db_from_roles" {
  for_each = local.db_client_roles

  description                  = "PostgreSQL TLS from ${each.key}"
  from_port                    = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = each.value
  security_group_id            = aws_security_group.database.id
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "roles_to_db" {
  for_each = local.db_client_roles

  description                  = "Egress to private PostgreSQL 5432"
  from_port                    = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.database.id
  security_group_id            = each.value
  to_port                      = 5432
}

# Scoped NATS 4222 client + 6222 route mTLS rules
resource "aws_vpc_security_group_ingress_rule" "broker_from_clients" {
  for_each = local.broker_client_roles

  description                  = "NATS native TLS client port from ${each.key}"
  from_port                    = 4222
  ip_protocol                  = "tcp"
  referenced_security_group_id = each.value
  security_group_id            = aws_security_group.broker.id
  to_port                      = 4222
}

resource "aws_vpc_security_group_egress_rule" "clients_to_broker" {
  for_each = local.broker_client_roles

  description                  = "Egress to NATS native TLS 4222"
  from_port                    = 4222
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.broker.id
  security_group_id            = each.value
  to_port                      = 4222
}

resource "aws_vpc_security_group_ingress_rule" "broker_routes_in" {
  description                  = "Broker cluster mTLS routes ingress"
  from_port                    = 6222
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.broker.id
  security_group_id            = aws_security_group.broker.id
  to_port                      = 6222
}

resource "aws_vpc_security_group_egress_rule" "broker_routes_out" {
  description                  = "Broker cluster mTLS routes egress"
  from_port                    = 6222
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.broker.id
  security_group_id            = aws_security_group.broker.id
  to_port                      = 6222
}

# VPC endpoint egress for private AWS API calls (Secrets Manager, ECR, STS, SSM)
resource "aws_vpc_security_group_ingress_rule" "vpce_from_vpc" {
  cidr_ipv4         = var.vpc_cidr
  description       = "HTTPS from VPC to PrivateLink endpoints"
  from_port         = 443
  ip_protocol       = "tcp"
  security_group_id = aws_security_group.vpc_endpoints.id
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "broker_to_vpce" {
  description                  = "Broker egress to AWS PrivateLink endpoints"
  from_port                    = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.vpc_endpoints.id
  security_group_id            = aws_security_group.broker.id
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "roles_to_vpce" {
  for_each = local.db_client_roles

  description                  = "Role egress to AWS PrivateLink endpoints"
  from_port                    = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.vpc_endpoints.id
  security_group_id            = each.value
  to_port                      = 443
}

# Sender outbound HTTPS 443 to public destinations (enforced by app DNS/IP pinning and optional egress firewall)
resource "aws_vpc_security_group_egress_rule" "sender_https_outbound" {
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Webhook delivery HTTPS egress (enforced by application DNS/IP pinning)"
  from_port         = 443
  ip_protocol       = "tcp"
  security_group_id = aws_security_group.sender.id
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "sender_dns_udp" {
  cidr_ipv4         = var.vpc_cidr
  description       = "DNS UDP to VPC resolver"
  from_port         = 53
  ip_protocol       = "udp"
  security_group_id = aws_security_group.sender.id
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "sender_dns_tcp" {
  cidr_ipv4         = var.vpc_cidr
  description       = "DNS TCP to VPC resolver"
  from_port         = 53
  ip_protocol       = "tcp"
  security_group_id = aws_security_group.sender.id
  to_port           = 53
}

resource "aws_vpc_endpoint" "s3" {
  route_table_ids   = concat([aws_route_table.private_data.id], [for rt in aws_route_table.private_app : rt.id])
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  vpc_id            = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-s3-vpce"
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  private_dns_enabled = true
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  subnet_ids          = [for s in aws_subnet.private_app : s.id]
  vpc_endpoint_type   = "Interface"
  vpc_id              = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_name}-${replace(each.key, ".", "-")}-vpce"
  }
}
