locals {
  # Empty secret containers only. Secret values are written out-of-band by an isolated issuer
  # so zero passwords, private keys, or NKey seeds ever enter Terraform state.
  secret_containers = {
    auth_session_hmac = {
      name        = "${var.deployment_name}/auth/session-hmac"
      description = "API session and CSRF HMAC key container"
    }
    nats_rq_relay = {
      name        = "${var.deployment_name}/nats/rq_relay_nkey"
      description = "NKey seed container for relay worker"
    }
    nats_rq_fanout = {
      name        = "${var.deployment_name}/nats/rq_fanout_nkey"
      description = "NKey seed container for fanout worker"
    }
    nats_rq_admin = {
      name        = "${var.deployment_name}/nats/rq_admin_nkey"
      description = "NKey seed container for broker management admin"
    }
    broker_broker_1_tls = {
      name        = "${var.deployment_name}/broker/broker-1-tls"
      description = "TLS server and route identity bundle container for broker-1"
    }
    broker_broker_2_tls = {
      name        = "${var.deployment_name}/broker/broker-2-tls"
      description = "TLS server and route identity bundle container for broker-2"
    }
    broker_broker_3_tls = {
      name        = "${var.deployment_name}/broker/broker-3-tls"
      description = "TLS server and route identity bundle container for broker-3"
    }
    receiver_signing = {
      name        = "${var.deployment_name}/receiver/signing-keys"
      description = "Independent example receiver verification key container"
    }
    provider_ingress_stripe = {
      name        = "${var.deployment_name}/provider-ingress/stripe-webhook-secret"
      description = "Independent provider-ingress Stripe signing secret container"
    }
    provider_ingress_paystack = {
      name        = "${var.deployment_name}/provider-ingress/paystack-secret"
      description = "Independent provider-ingress Paystack HMAC secret container"
    }
    provider_ingress_producer = {
      name        = "${var.deployment_name}/provider-ingress/producer-credential"
      description = "Independent provider-ingress Relayquill producer credential container"
    }
  }
}

resource "aws_kms_key" "secrets" {
  description             = "Customer-managed KMS key for Relayquill secrets and persistent storage."
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = {
    Name = "${var.deployment_name}-kms"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.deployment_name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_secretsmanager_secret" "containers" {
  for_each = local.secret_containers

  description             = each.value.description
  kms_key_id              = aws_kms_key.secrets.arn
  name                    = each.value.name
  recovery_window_in_days = var.secret_recovery_window_days

  tags = {
    ContainerKey = each.key
  }
}
