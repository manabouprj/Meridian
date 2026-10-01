# Offline plan test with mocked providers: `tofu test` / `terraform test` (no credentials, nothing created).
# Catches expression, wiring and plan-time validation errors that `validate` cannot see.
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_availability_zones" {
    defaults = { names = ["me-central-1a", "me-central-1b", "me-central-1c"] }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:me-central-1:111122223333:key/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/meridian-mock" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:me-central-1:111122223333:meridian-mock" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::meridian-mock" }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:me-central-1:111122223333:loadbalancer/app/meridian-api/0000" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:me-central-1:111122223333:targetgroup/meridian-api/0000" }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:me-central-1:111122223333:secret:meridian/mock-AbCdEf" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:me-central-1:111122223333:cluster/meridian" }
  }
  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws:ecs:me-central-1:111122223333:task-definition/meridian:1" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:me-central-1:111122223333:log-group:/meridian/meridian" }
  }
  mock_resource "aws_athena_workgroup" {
    defaults = { arn = "arn:aws:athena:me-central-1:111122223333:workgroup/meridian" }
  }
  mock_resource "aws_rds_cluster" {
    defaults = {
      arn                = "arn:aws:rds:me-central-1:111122223333:cluster:meridian-db"
      master_user_secret = [{ secret_arn = "arn:aws:secretsmanager:me-central-1:111122223333:secret:rds!cluster-AbCdEf", kms_key_id = "", secret_status = "active" }]
    }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}
mock_provider "random" {}

variables {
  lodestar_url       = "https://lodestar.internal.example"
  prefix             = "meridian"
  region             = "me-central-1"
  bedrock_region     = "me-central-1"
  bedrock_fast_model = "global.anthropic.claude-haiku-4-5-test"
  bedrock_deep_model = "global.anthropic.claude-sonnet-5-5-test"
  image              = "111122223333.dkr.ecr.me-central-1.amazonaws.com/meridian:1.0.0"
  certificate_arn    = "arn:aws:acm:me-central-1:111122223333:certificate/00000000-0000-0000-0000-000000000000"
  public_url         = "https://meridian.example"
  oidc_issuer        = "https://login.example/v2.0"
  oidc_client_id     = "00000000-0000-0000-0000-000000000000"
  client_cidrs       = ["10.0.0.0/8"]
}

run "plan" {
  command = plan

  assert {
    condition     = aws_lb.api.internal
    error_message = "the ALB must be internal"
  }
  assert {
    condition     = length([for r in aws_security_group.app.ingress : r if r.protocol == "-1"]) == 0
    error_message = "no all-protocol ingress rules on the app security group"
  }
  assert {
    condition     = aws_s3_bucket.lake.object_lock_enabled
    error_message = "the lake must have Object Lock"
  }
  assert {
    condition     = aws_sqs_queue.landing.visibility_timeout_seconds == 900
    error_message = "landing queue visibility must cover a batch"
  }
}

run "rotation_and_extra_secrets" {
  command = plan
  variables {
    lake_expire_days          = 400
    lake_expire_days_by_class = { "3002" = 2555 }
    extra_secrets             = ["okta-token"]
    landing_writer_sources    = ["k8s"]
  }
  assert {
    condition     = length([for r in aws_s3_bucket_lifecycle_configuration.lake.rule : r if startswith(r.id, "expire-cls-")]) == 12
    error_message = "one expiry rule per OCSF class"
  }
  assert {
    condition     = one([for r in aws_s3_bucket_lifecycle_configuration.lake.rule : r.expiration[0].days if r.id == "expire-cls-3002"]) == 2555
    error_message = "the per-class override wins"
  }
  assert {
    condition     = contains(keys(aws_secretsmanager_secret.s), "okta-token") && contains(keys(aws_secretsmanager_secret.s), "ingest-tokens")
    error_message = "extra and ingest-token secrets are created"
  }
  assert {
    condition     = aws_iam_policy.landing_writer["k8s"].name == "meridian-landing-writer-k8s"
    error_message = "one writer policy per external source"
  }
}

run "expiry_shorter_than_worm_is_refused" {
  command = plan
  variables {
    lake_expire_days = 30
  }
  expect_failures = [var.lake_expire_days]
}
