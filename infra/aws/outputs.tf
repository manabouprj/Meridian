output "lake_bucket" { value = aws_s3_bucket.lake.bucket }
output "landing_bucket" { value = aws_s3_bucket.landing.bucket }
output "landing_queue_url" { value = aws_sqs_queue.landing.url }
output "athena_database" { value = aws_glue_catalog_database.db.name }
output "athena_workgroup" { value = aws_athena_workgroup.wg.name }
output "api_internal_dns" { value = aws_lb.api.dns_name }
output "db_endpoint" { value = aws_rds_cluster.db.endpoint }
output "agents_role_arn" { value = aws_iam_role.agents.arn }
output "ecs_cluster" { value = aws_ecs_cluster.c.name }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "app_security_group_id" { value = aws_security_group.app.id }
output "kms_key_arn" { value = aws_kms_key.k.arn }
output "landing_writer_policy_arns" {
  description = "Per-source managed policies to attach to external shippers' roles"
  value       = { for k, p in aws_iam_policy.landing_writer : k => p.arn }
}
