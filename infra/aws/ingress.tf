resource "aws_route53_zone" "internal" {
  name = var.internal_domain_name

  vpc {
    vpc_id = aws_vpc.main.id
  }

  tags = {
    Name = "${var.deployment_name}-internal-zone"
  }
}

resource "aws_acm_certificate" "public" {
  domain_name = var.public_console_domain
  subject_alternative_names = [
    var.public_api_domain,
    var.public_receiver_domain,
    var.public_ingress_domain
  ]
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.deployment_name}-public-cert"
  }
}

resource "aws_route53_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.public.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.public_zone_id
}

resource "aws_acm_certificate_validation" "public" {
  certificate_arn         = aws_acm_certificate.public.arn
  validation_record_fqdns = [for r in aws_route53_record.acm_validation : r.fqdn]
}

resource "aws_lb" "public" {
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
  idle_timeout               = 120
  internal                   = false
  load_balancer_type         = "application"
  name                       = "${var.deployment_name}-alb"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = [for s in aws_subnet.public : s.id]

  tags = {
    Name = "${var.deployment_name}-alb"
  }
}

resource "aws_lb_target_group" "console" {
  name        = "${var.deployment_name}-console-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    healthy_threshold   = 2
    interval            = 15
    matcher             = "200"
    path                = "/healthz"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "api" {
  name        = "${var.deployment_name}-api-tg"
  port        = 8005
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    healthy_threshold   = 2
    interval            = 15
    matcher             = "200"
    path                = "/api/v1/health/ready"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "receiver" {
  name        = "${var.deployment_name}-rc-tg"
  port        = 19095
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    healthy_threshold   = 2
    interval            = 15
    matcher             = "200"
    path                = "/health/ready"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "provider_ingress" {
  name        = "${var.deployment_name}-pi-tg"
  port        = 19096
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    healthy_threshold   = 2
    interval            = 15
    matcher             = "200"
    path                = "/health/ready"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  certificate_arn   = aws_acm_certificate_validation.public.certificate_arn
  load_balancer_arn = aws_lb.public.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "api_same_origin" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    target_group_arn = aws_lb_target_group.api.arn
    type             = "forward"
  }

  condition {
    host_header {
      values = [var.public_console_domain]
    }
  }

  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}

resource "aws_lb_listener_rule" "api_machine" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 15

  action {
    target_group_arn = aws_lb_target_group.api.arn
    type             = "forward"
  }

  condition {
    host_header {
      values = [var.public_api_domain]
    }
  }

  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}

resource "aws_lb_listener_rule" "console" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20

  action {
    target_group_arn = aws_lb_target_group.console.arn
    type             = "forward"
  }

  condition {
    host_header {
      values = [var.public_console_domain]
    }
  }
}

resource "aws_lb_listener_rule" "receiver" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 30

  action {
    target_group_arn = aws_lb_target_group.receiver.arn
    type             = "forward"
  }

  condition {
    host_header {
      values = [var.public_receiver_domain]
    }
  }
}

resource "aws_lb_listener_rule" "provider_ingress" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 40

  action {
    target_group_arn = aws_lb_target_group.provider_ingress.arn
    type             = "forward"
  }

  condition {
    host_header {
      values = [var.public_ingress_domain]
    }
  }
}

resource "aws_route53_record" "public_domains" {
  for_each = toset([
    var.public_console_domain,
    var.public_api_domain,
    var.public_receiver_domain,
    var.public_ingress_domain
  ])

  name    = each.value
  type    = "A"
  zone_id = var.public_zone_id

  alias {
    evaluate_target_health = true
    name                   = aws_lb.public.dns_name
    zone_id                = aws_lb.public.zone_id
  }
}
