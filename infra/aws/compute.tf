resource "aws_ecs_cluster" "c" {
  name = var.prefix
  setting {
    name  = "containerInsights"
    value = "enhanced"
  }
}

resource "aws_cloudwatch_log_group" "lg" {
  name              = "/meridian/${var.prefix}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.k.arn
}

locals {
  secret_env = { "oidc-client-secret" = "OIDC_CLIENT_SECRET", "lodestar-webhook-secret" = "LODESTAR_WEBHOOK_SECRET" }
  env = [
    { name = "MERIDIAN_CONFIG", value = "/app/config/examples/aws.yaml" },
    { name = "MERIDIAN_CLOUD", value = "aws" },
    { name = "MERIDIAN_LAKE_ROOT", value = "s3://${aws_s3_bucket.lake.bucket}" },
    { name = "MERIDIAN_LANDING_ROOT", value = "s3://${aws_s3_bucket.landing.bucket}" },
    { name = "MERIDIAN_QUEUE_URL", value = aws_sqs_queue.landing.url },
    { name = "MERIDIAN_ATHENA_DB", value = aws_glue_catalog_database.db.name },
    { name = "MERIDIAN_ATHENA_WG", value = aws_athena_workgroup.wg.name },
    { name = "BEDROCK_REGION", value = var.bedrock_region },
    { name = "BEDROCK_FAST_MODEL", value = var.bedrock_fast_model },
    { name = "BEDROCK_DEEP_MODEL", value = var.bedrock_deep_model },
    { name = "MERIDIAN_DB_HOST", value = aws_rds_cluster.db.endpoint },
    { name = "MERIDIAN_LOG_FORMAT", value = "json" },
    { name = "MERIDIAN_PUBLIC_URL", value = var.public_url },
    { name = "OIDC_ISSUER", value = var.oidc_issuer },
    { name = "OIDC_CLIENT_ID", value = var.oidc_client_id },
    { name = "LODESTAR_URL", value = var.lodestar_url },
    { name = "LODESTAR_ORG", value = var.lodestar_org },
  ]
  secrets = concat(
    [for k, v in aws_secretsmanager_secret.s : { name = lookup(local.secret_env, k, upper(replace("MERIDIAN_${k}", "-", "_"))), valueFrom = v.arn }],
    [{ name = "MERIDIAN_DB_CREDENTIALS", valueFrom = aws_rds_cluster.db.master_user_secret[0].secret_arn }]
  )
  roles = {
    api       = { cmd = ["serve", "--host", "0.0.0.0", "--port", "8090"], cpu = 1024, mem = 2048, count = 2, role = aws_iam_role.app.arn }
    worker    = { cmd = ["worker"], cpu = 1024, mem = 2048, count = 2, role = aws_iam_role.app.arn }
    agents    = { cmd = ["agents"], cpu = 512, mem = 1024, count = 1, role = aws_iam_role.agents.arn }
    scheduler = { cmd = ["scheduler"], cpu = 512, mem = 1024, count = 1, role = aws_iam_role.agents.arn }
    syslog    = { cmd = ["syslog", "--source", "syslog", "--port", "5514"], cpu = 256, mem = 512, count = 2, role = aws_iam_role.app.arn }
    collector = { cmd = ["collect"], cpu = 256, mem = 512, count = 1, role = aws_iam_role.app.arn }
  }
}

resource "aws_ecs_task_definition" "t" {
  for_each                 = local.roles
  family                   = "${var.prefix}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.mem
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = each.value.role
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([{
    name                   = each.key
    image                  = var.image
    command                = each.value.cmd
    essential              = true
    readonlyRootFilesystem = true
    user                   = "meridian"
    environment            = local.env
    secrets                = local.secrets
    portMappings           = each.key == "api" ? [{ containerPort = 8090, protocol = "tcp" }] : (each.key == "syslog" ? [{ containerPort = 5514, protocol = "udp" }, { containerPort = 5514, protocol = "tcp" }] : [])
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp" }]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { awslogs-group = aws_cloudwatch_log_group.lg.name, awslogs-region = var.region, awslogs-stream-prefix = each.key }
    }
  }])
  volume { name = "tmp" }
}

resource "aws_ecs_service" "s" {
  for_each        = local.roles
  name            = each.key
  cluster         = aws_ecs_cluster.c.id
  task_definition = aws_ecs_task_definition.t[each.key].arn
  desired_count   = each.value.count
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }
  dynamic "load_balancer" {
    for_each = each.key == "api" ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.api.arn
      container_name   = "api"
      container_port   = 8090
    }
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}

# Internal ALB for the console, API and MCP endpoints (publish through your SSO-aware edge if needed)
resource "aws_lb" "api" {
  name                       = "${var.prefix}-api"
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = aws_subnet.private[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "api" {
  name        = "${var.prefix}-api"
  port        = 8090
  protocol    = "HTTP"
  vpc_id      = aws_vpc.v.id
  target_type = "ip"
  health_check {
    path    = "/readyz"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# Ingestion workers scale on landing-queue depth
resource "aws_appautoscaling_target" "worker" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.c.name}/${aws_ecs_service.s["worker"].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = 2
  max_capacity       = 20
}

resource "aws_appautoscaling_policy" "worker" {
  name               = "landing-depth"
  service_namespace  = "ecs"
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension
  policy_type        = "TargetTrackingScaling"
  target_tracking_scaling_policy_configuration {
    target_value = 50
    customized_metric_specification {
      metric_name = "ApproximateNumberOfMessagesVisible"
      namespace   = "AWS/SQS"
      statistic   = "Average"
      dimensions {
        name  = "QueueName"
        value = aws_sqs_queue.landing.name
      }
    }
  }
}
