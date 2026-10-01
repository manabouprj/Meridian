resource "random_string" "sfx" {
  length  = 6
  special = false
  upper   = false
}

locals {
  trail_accounts = length(var.cloudtrail_account_ids) > 0 ? var.cloudtrail_account_ids : [data.aws_caller_identity.me.account_id]
}

# Key policy: the account administers the key (IAM policies grant use to the task roles), and the AWS services
# that write MERIDIAN data with it are named explicitly - without these grants the log group cannot be created,
# S3 cannot notify the encrypted queue and CloudTrail cannot write to the landing bucket.
data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.me.account_id}:root"]
    }
  }
  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.me.account_id}:log-group:*"]
    }
  }
  statement {
    sid       = "S3EventNotificationsToEncryptedSQS"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.me.account_id]
    }
  }
  statement {
    sid       = "CloudTrailToLanding"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = [for a in local.trail_accounts : "arn:aws:cloudtrail:*:${a}:trail/*"]
    }
  }
}

resource "aws_kms_key" "k" {
  description         = "MERIDIAN lake, queue, database and secrets"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms.json
}

# Landing bucket: TLS only; CloudTrail (this account or the organisation trail account) may deliver under AWSLogs/
data "aws_iam_policy_document" "landing" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.landing.arn, "${aws_s3_bucket.landing.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.landing.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = local.trail_accounts
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.landing.arn}/AWSLogs/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = local.trail_accounts
    }
  }
}

resource "aws_s3_bucket_policy" "landing" {
  bucket = aws_s3_bucket.landing.id
  policy = data.aws_iam_policy_document.landing.json
}

data "aws_iam_policy_document" "lake_tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.lake.arn, "${aws_s3_bucket.lake.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "lake" {
  bucket = aws_s3_bucket.lake.id
  policy = data.aws_iam_policy_document.lake_tls.json
}

resource "aws_kms_alias" "k" {
  name          = "alias/${var.prefix}"
  target_key_id = aws_kms_key.k.key_id
}

# ---------------- landing zone (raw batches, replayable)
resource "aws_s3_bucket" "landing" {
  bucket = "${var.prefix}-landing-${random_string.sfx.result}"
}

resource "aws_s3_bucket_versioning" "landing" {
  bucket = aws_s3_bucket.landing.id
  versioning_configuration { status = "Enabled" }
}

# ---------------- lake (Parquet, OCSF-flat) with Object Lock = WORM retention for audit
resource "aws_s3_bucket" "lake" {
  bucket              = "${var.prefix}-lake-${random_string.sfx.result}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "lake" {
  bucket = aws_s3_bucket.lake.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "lake" {
  bucket = aws_s3_bucket.lake.id
  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.lake_retention_days
    }
  }
}

resource "aws_s3_bucket" "athena" {
  bucket = "${var.prefix}-athena-${random_string.sfx.result}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  for_each = { landing = aws_s3_bucket.landing.id, lake = aws_s3_bucket.lake.id, athena = aws_s3_bucket.athena.id }
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "pab" {
  for_each                = { landing = aws_s3_bucket.landing.id, lake = aws_s3_bucket.lake.id, athena = aws_s3_bucket.athena.id }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

locals {
  # OCSF classes MERIDIAN writes (meridian/ocsf.py CLASSES); class 0 = Base Event (kept, not yet classified)
  ocsf_classes = ["0", "1001", "1007", "2004", "3001", "3002", "3005", "4001", "4002", "4003", "4009", "6003"]
  # end of life per class: the per-class override, else lake_expire_days; 0 = keep
  lake_expiry = { for c in local.ocsf_classes : c => lookup(var.lake_expire_days_by_class, c, var.lake_expire_days) }
}

resource "aws_s3_bucket_lifecycle_configuration" "lake" {
  bucket = aws_s3_bucket.lake.id
  rule {
    id     = "tiering"
    status = "Enabled"
    filter { prefix = "events/" }
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 180
      storage_class = "GLACIER_IR"
    }
    noncurrent_version_expiration { noncurrent_days = 7 }
  }
  # Rotation: one rule per class, so different log types can live for different periods. Object Lock still
  # refuses deletion inside the WORM period, which the variable validation makes the minimum.
  dynamic "rule" {
    for_each = { for c, d in local.lake_expiry : c => d if d > 0 }
    content {
      id     = "expire-cls-${rule.key}"
      status = "Enabled"
      filter { prefix = "events/cls=${rule.key}/" }
      expiration { days = rule.value }
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "landing" {
  bucket = aws_s3_bucket.landing.id
  rule {
    id     = "expire-raw"
    status = "Enabled"
    filter {}
    expiration { days = 90 }
    noncurrent_version_expiration { noncurrent_days = 7 }
  }
}

# ---------------- new landing batch -> SQS -> ingestion workers (ECS service autoscaled on queue depth)
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.prefix}-landing-dlq"
  kms_master_key_id         = aws_kms_key.k.id
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "landing" {
  name                       = "${var.prefix}-landing"
  kms_master_key_id          = aws_kms_key.k.id
  visibility_timeout_seconds = 900
  redrive_policy             = jsonencode({ deadLetterTargetArn = aws_sqs_queue.dlq.arn, maxReceiveCount = 5 })
}

resource "aws_sqs_queue_policy" "landing" {
  queue_url = aws_sqs_queue.landing.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.landing.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_s3_bucket.landing.arn } }
    }]
  })
}

resource "aws_s3_bucket_notification" "landing" {
  bucket = aws_s3_bucket.landing.id
  queue {
    queue_arn = aws_sqs_queue.landing.arn
    events    = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_sqs_queue_policy.landing]
}

# ---------------- Glue catalog + Athena: the lake as a table (partition projection - no crawlers)
resource "aws_glue_catalog_database" "db" {
  name = var.prefix
}

locals {
  columns = {
    time                = "timestamp", class_uid = "int", class_name = "string", activity_name = "string", severity_id = "tinyint",
    status              = "string", product = "string", source = "string", user = "string", user_domain = "string", src_ip = "string",
    src_port            = "int", src_country = "string", dst_ip = "string", dst_port = "int", dst_domain = "string", device = "string",
    device_id           = "string", device_ip = "string", process_name = "string", process_cmdline = "string",
    parent_process_name = "string", file_name = "string", file_path = "string", file_sha256 = "string", file_md5 = "string",
    url                 = "string", http_method = "string", dns_query = "string", action = "string", auth_protocol = "string", mfa = "boolean",
    app_name            = "string", cloud_account = "string", cloud_region = "string", api_operation = "string", resource = "string",
    message             = "string", tags = "string", ioc_hits = "string", event_uid = "string", raw = "string"
  }
  column_order = ["time", "class_uid", "class_name", "activity_name", "severity_id", "status", "product", "source", "user",
    "user_domain", "src_ip", "src_port", "src_country", "dst_ip", "dst_port", "dst_domain", "device", "device_id", "device_ip",
    "process_name", "process_cmdline", "parent_process_name", "file_name", "file_path", "file_sha256", "file_md5", "url",
    "http_method", "dns_query", "action", "auth_protocol", "mfa", "app_name", "cloud_account", "cloud_region", "api_operation",
  "resource", "message", "tags", "ioc_hits", "event_uid", "raw"]
}

resource "aws_glue_catalog_table" "events" {
  name          = "events"
  database_name = aws_glue_catalog_database.db.name
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    "classification"            = "parquet"
    "projection.enabled"        = "true"
    "projection.cls.type"       = "enum"
    "projection.cls.values"     = join(",", local.ocsf_classes)
    "projection.dt.type"        = "date"
    "projection.dt.format"      = "yyyy-MM-dd"
    "projection.dt.range"       = "2024-01-01,NOW"
    "projection.hr.type"        = "integer"
    "projection.hr.range"       = "0,23"
    "projection.hr.digits"      = "2"
    "storage.location.template" = "s3://${aws_s3_bucket.lake.bucket}/events/cls=$${cls}/dt=$${dt}/hr=$${hr}"
  }
  partition_keys {
    name = "cls"
    type = "int"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }
  partition_keys {
    name = "hr"
    type = "string"
  }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/events/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
    dynamic "columns" {
      for_each = local.column_order
      content {
        name = columns.value
        type = local.columns[columns.value]
      }
    }
  }
}

resource "aws_athena_workgroup" "wg" {
  name          = var.prefix
  force_destroy = false
  configuration {
    enforce_workgroup_configuration    = true
    bytes_scanned_cutoff_per_query     = 107374182400 # 100 GB guard rail per query
    publish_cloudwatch_metrics_enabled = true
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.k.arn
      }
    }
  }
}

# ---------------- operational store: Aurora PostgreSQL Serverless v2
resource "aws_db_subnet_group" "db" {
  name       = "${var.prefix}-db"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "db" {
  name   = "${var.prefix}-db"
  vpc_id = aws_vpc.v.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_rds_cluster" "db" {
  cluster_identifier            = "${var.prefix}-db"
  engine                        = "aurora-postgresql"
  engine_version                = "16.6"
  database_name                 = "meridian"
  master_username               = "meridian_admin"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.k.key_id
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.k.arn
  db_subnet_group_name          = aws_db_subnet_group.db.name
  vpc_security_group_ids        = [aws_security_group.db.id]
  backup_retention_period       = 35
  deletion_protection           = true
  copy_tags_to_snapshot         = true
  serverlessv2_scaling_configuration {
    min_capacity = 0.5
    max_capacity = 8
  }
}

resource "aws_rds_cluster_instance" "db" {
  count              = 2
  identifier         = "${var.prefix}-db-${count.index}"
  cluster_identifier = aws_rds_cluster.db.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.db.engine
  engine_version     = aws_rds_cluster.db.engine_version
}
