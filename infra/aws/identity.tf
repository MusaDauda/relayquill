data "aws_caller_identity" "current" {}

locals {
  workload_roles = {
    api = {
      db_users        = ["rq_api"]
      namespace       = "relayquill-app"
      service_account = "relayquill-api"
      secret_prefixes = ["session/", "auth/"]
    }
    relay = {
      db_users        = ["rq_relay"]
      namespace       = "relayquill-app"
      service_account = "relayquill-relay"
      secret_prefixes = ["nats/rq_relay"]
    }
    fanout = {
      db_users        = ["rq_fanout"]
      namespace       = "relayquill-app"
      service_account = "relayquill-fanout"
      secret_prefixes = ["nats/rq_fanout"]
    }
    sender = {
      db_users        = ["rq_sender"]
      namespace       = "relayquill-app"
      service_account = "relayquill-sender"
      secret_prefixes = ["endpoints/", "signing/"]
    }
    coordinator = {
      db_users        = ["rq_coordinator"]
      namespace       = "relayquill-app"
      service_account = "relayquill-coordinator"
      secret_prefixes = []
    }
    migrator = {
      db_users        = ["rq_migrator", "receiver_migrator", "provider_migrator"]
      namespace       = "relayquill-app"
      service_account = "relayquill-migrator"
      secret_prefixes = ["nats/rq_admin"]
    }
    recovery = {
      db_users        = ["rq_recovery"]
      namespace       = "relayquill-app"
      service_account = "relayquill-recovery"
      secret_prefixes = []
    }
    signing_issuer = {
      db_users        = ["rq_signing_issuer"]
      namespace       = "relayquill-app"
      service_account = "relayquill-signing-issuer"
      secret_prefixes = ["endpoints/", "signing/", "producers/"]
    }
    receiver = {
      db_users        = ["receiver_runtime"]
      namespace       = "relayquill-receiver"
      service_account = "relayquill-receiver"
      secret_prefixes = ["receiver/"]
    }
    provider_ingress = {
      db_users        = ["provider_runtime"]
      namespace       = "relayquill-ingress"
      service_account = "relayquill-provider-ingress"
      secret_prefixes = ["provider-ingress/"]
    }
  }

  secret_readers = {
    for k, v in local.workload_roles : k => v
    if length(v.secret_prefixes) > 0
  }
}

data "aws_iam_policy_document" "eks_pod_identity_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    effect  = "Allow"

    principals {
      identifiers = ["pods.eks.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_iam_role" "workload" {
  for_each = local.workload_roles

  assume_role_policy = data.aws_iam_policy_document.eks_pod_identity_trust.json
  name               = "${var.deployment_name}-${replace(each.key, "_", "-")}-role"
}

data "aws_iam_policy_document" "rds_iam_connect" {
  for_each = local.workload_roles

  statement {
    actions = ["rds-db:connect"]
    effect  = "Allow"
    resources = [
      for db_user in each.value.db_users :
      "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/${db_user}"
    ]
  }
}

resource "aws_iam_role_policy" "rds_iam_connect" {
  for_each = local.workload_roles

  name   = "rds-iam-connect"
  policy = data.aws_iam_policy_document.rds_iam_connect[each.key].json
  role   = aws_iam_role.workload[each.key].id
}

data "aws_iam_policy_document" "workload_secrets_read" {
  for_each = local.secret_readers

  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    effect = "Allow"
    resources = [
      for prefix in each.value.secret_prefixes :
      "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${var.deployment_name}/${prefix}*"
    ]
  }

  statement {
    actions   = ["kms:Decrypt"]
    effect    = "Allow"
    resources = [aws_kms_key.secrets.arn]

    condition {
      test     = "StringEquals"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
      variable = "kms:ViaService"
    }
  }
}

resource "aws_iam_role_policy" "workload_secrets_read" {
  for_each = local.secret_readers

  name   = "secrets-read"
  policy = data.aws_iam_policy_document.workload_secrets_read[each.key].json
  role   = aws_iam_role.workload[each.key].id
}

resource "aws_eks_pod_identity_association" "workload" {
  for_each = local.workload_roles

  cluster_name    = var.eks_cluster_name
  namespace       = each.value.namespace
  role_arn        = aws_iam_role.workload[each.key].arn
  service_account = each.value.service_account
}

# Dedicated EC2 role per broker node so each host reads only its own TLS/route secret container.
data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      identifiers = ["ec2.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_iam_role" "broker_node" {
  for_each = toset(["broker-1", "broker-2", "broker-3"])

  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  name               = "${var.deployment_name}-${each.key}-role"
}

data "aws_iam_policy_document" "broker_node_secrets" {
  for_each = toset(["broker-1", "broker-2", "broker-3"])

  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    effect = "Allow"
    resources = [
      aws_secretsmanager_secret.containers["broker_${replace(each.key, "-", "_")}_tls"].arn
    ]
  }

  statement {
    actions   = ["kms:Decrypt"]
    effect    = "Allow"
    resources = [aws_kms_key.secrets.arn]

    condition {
      test     = "StringEquals"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
      variable = "kms:ViaService"
    }
  }
}

resource "aws_iam_role_policy" "broker_node_secrets" {
  for_each = toset(["broker-1", "broker-2", "broker-3"])

  name   = "broker-own-tls-secret"
  policy = data.aws_iam_policy_document.broker_node_secrets[each.key].json
  role   = aws_iam_role.broker_node[each.key].id
}

resource "aws_iam_role_policy_attachment" "broker_ssm" {
  for_each = toset(["broker-1", "broker-2", "broker-3"])

  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.broker_node[each.key].name
}

resource "aws_iam_instance_profile" "broker_node" {
  for_each = toset(["broker-1", "broker-2", "broker-3"])

  name = "${var.deployment_name}-${each.key}-profile"
  role = aws_iam_role.broker_node[each.key].name
}
