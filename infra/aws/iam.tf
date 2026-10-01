data "aws_caller_identity" "me" {}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "exec" {
  name               = "${var.prefix}-ecs-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "exec" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "exec_secrets" {
  name = "secrets"
  role = aws_iam_role.exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [for s in aws_secretsmanager_secret.s : s.arn] },
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_rds_cluster.db.master_user_secret[0].secret_arn] },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [aws_kms_key.k.arn] }
    ]
  })
}

# Task role for ingestion / API / scheduler: lake + landing + queue + Athena/Glue (no model access)
resource "aws_iam_role" "app" {
  name               = "${var.prefix}-app"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "app" {
  name = "lake"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["${aws_s3_bucket.landing.arn}/*", "${aws_s3_bucket.lake.arn}/*"] },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = [aws_s3_bucket.landing.arn, aws_s3_bucket.lake.arn] },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"], Resource = [aws_s3_bucket.athena.arn, "${aws_s3_bucket.athena.arn}/*"] },
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"], Resource = [aws_sqs_queue.landing.arn] },
      { Effect = "Allow", Action = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution"], Resource = [aws_athena_workgroup.wg.arn] },
      { Effect = "Allow", Action = ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"], Resource = [
        "arn:aws:glue:${var.region}:${data.aws_caller_identity.me.account_id}:catalog",
        "arn:aws:glue:${var.region}:${data.aws_caller_identity.me.account_id}:database/${aws_glue_catalog_database.db.name}",
      "arn:aws:glue:${var.region}:${data.aws_caller_identity.me.account_id}:table/${aws_glue_catalog_database.db.name}/*"] },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = [aws_kms_key.k.arn] }
    ]
  })
}

# Agent task role: the same read access PLUS model invocation, limited to the approved models
resource "aws_iam_role" "agents" {
  name               = "${var.prefix}-agents"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "agents" {
  name = "agents"
  role = aws_iam_role.agents.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # bedrock-runtime InvokeModel / Converse with cross-region inference profiles: the policy must allow the
      # inference-profile ARN AND the foundation-model ARNs in every destination region (var.bedrock_model_arns).
      { Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      Resource = var.bedrock_model_arns },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket"], Resource = [aws_s3_bucket.lake.arn, "${aws_s3_bucket.lake.arn}/*"] },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"], Resource = [aws_s3_bucket.athena.arn, "${aws_s3_bucket.athena.arn}/*"] },
      { Effect = "Allow", Action = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution"], Resource = [aws_athena_workgroup.wg.arn] },
      { Effect = "Allow", Action = ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"], Resource = ["*"] },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = [aws_kms_key.k.arn] }
    ]
  })
}

# Response role: ONLY the API task (which executes human-approved actions) can contain AWS resources,
# and only resources tagged meridian-containable=true (opt-in per account / workload).
resource "aws_iam_role_policy" "response" {
  name = "response"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["iam:UpdateAccessKey"], Resource = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:user/*",
      Condition = { StringEquals = { "iam:ResourceTag/meridian-containable" = "true" } } },
      { Effect = "Allow", Action = ["ec2:ModifyInstanceAttribute"], Resource = "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:instance/*",
      Condition = { StringEquals = { "aws:ResourceTag/meridian-containable" = "true" } } }
    ]
  })
}

resource "aws_secretsmanager_secret" "s" {
  for_each   = toset(concat(local.core_secrets, var.extra_secrets))
  name       = "${var.prefix}/${each.key}"
  kms_key_id = aws_kms_key.k.arn
}

locals {
  core_secrets = ["api-keys", "session-secret", "ingest-secret", "ingest-tokens", "edl-token", "metrics-token", "agent-tokens",
  "oidc-client-secret", "lodestar-webhook-secret"]
}

# ---------------- landing writers: least-privilege policies for shippers that write batches directly
data "aws_iam_policy_document" "landing_writer" {
  for_each = toset(var.landing_writer_sources)
  statement {
    sid       = "WriteOwnPrefixOnly"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.landing.arn}/${each.key}/*"]
  }
  statement {
    sid       = "EncryptWithTheLakeKey"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
    resources = [aws_kms_key.k.arn]
  }
}

resource "aws_iam_policy" "landing_writer" {
  for_each    = toset(var.landing_writer_sources)
  name        = "${var.prefix}-landing-writer-${each.key}"
  description = "Write MERIDIAN landing batches for source ${each.key} only"
  policy      = data.aws_iam_policy_document.landing_writer[each.key].json
}
