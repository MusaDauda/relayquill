locals {
  broker_nodes = {
    "broker-1" = {
      az_index = "0"
      az       = var.availability_zones[0]
    }
    "broker-2" = {
      az_index = "1"
      az       = var.availability_zones[1]
    }
    "broker-3" = {
      az_index = "2"
      az       = var.availability_zones[2]
    }
  }
}

resource "aws_instance" "broker" {
  for_each = local.broker_nodes

  ami                         = var.broker_ami_id
  associate_public_ip_address = false
  ebs_optimized               = true
  iam_instance_profile        = aws_iam_instance_profile.broker_node[each.key].name
  instance_type               = var.broker_instance_type
  subnet_id                   = aws_subnet.private_data[each.value.az_index].id
  vpc_security_group_ids      = [aws_security_group.broker.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.secrets.arn
    volume_size = 16
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.deployment_name}-${each.key}"
    Role = "broker"
  }
}

resource "aws_ebs_volume" "jetstream_store" {
  for_each = local.broker_nodes

  availability_zone = each.value.az
  encrypted         = true
  kms_key_id        = aws_kms_key.secrets.arn
  size              = var.broker_volume_size_gb
  type              = "gp3"

  tags = {
    Name = "${var.deployment_name}-${each.key}-jetstream"
    Node = each.key
  }
}

resource "aws_volume_attachment" "jetstream_store" {
  for_each = local.broker_nodes

  device_name = "/dev/xvdf"
  instance_id = aws_instance.broker[each.key].id
  volume_id   = aws_ebs_volume.jetstream_store[each.key].id
}

resource "aws_route53_record" "broker_internal" {
  for_each = local.broker_nodes

  name    = "${each.key}.${var.internal_domain_name}"
  records = [aws_instance.broker[each.key].private_ip]
  ttl     = 60
  type    = "A"
  zone_id = aws_route53_zone.internal.zone_id
}
