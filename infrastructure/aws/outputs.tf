output "cloudtrail_name" {
  value       = aws_cloudtrail.main.name
  description = "CloudTrail trail name."
}

output "cloudtrail_log_bucket" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "S3 bucket that stores CloudTrail logs."
}

output "cloudwatch_log_group" {
  value       = aws_cloudwatch_log_group.cloudtrail.name
  description = "CloudWatch log group used for CloudTrail searches."
}

output "honeytoken_secret_arn" {
  value       = aws_secretsmanager_secret.honeytoken.arn
  description = "ARN of the monitored decoy secret."
}

output "honeytoken_alert_topic_arn" {
  value       = aws_sns_topic.honeytoken_alerts.arn
  description = "SNS topic receiving honeytoken alerts."
}

output "experiment_buckets" {
  value       = { for purpose, bucket in aws_s3_bucket.experiment : purpose => bucket.id }
  description = "Private buckets used for critical, staging, and simulated-egress data."
}

output "data_seed_s3_uri" {
  value       = "s3://${aws_s3_bucket.experiment["critical"].id}/${aws_s3_object.data_seed.key}"
  description = "Synthetic data honeytoken used as an R1 seed."
}

output "critical_object_s3_uri" {
  value       = "s3://${aws_s3_bucket.experiment["critical"].id}/${aws_s3_object.critical.key}"
  description = "Synthetic manually classified D-Taint source."
}

output "research_role_arns" {
  value = {
    actor_a        = aws_iam_role.actor_a.arn
    pivot_b        = aws_iam_role.pivot_b.arn
    pivot_c        = aws_iam_role.pivot_c.arn
    grant_target   = aws_iam_role.grant_target.arn
    background_bot = aws_iam_role.background_bot.arn
  }
  description = "IAM roles used by S1-a and S1-b."
}

output "persistence_user_name" {
  value       = aws_iam_user.persistence.name
  description = "Lab-only IAM user whose access-key lifecycle is used for R3 probing."
}

output "athena_workgroup" {
  value       = aws_athena_workgroup.research.name
  description = "Athena workgroup for CloudTrail and normalized-event queries."
}

output "athena_database" {
  value       = aws_glue_catalog_database.research.name
  description = "Glue/Athena database for raw and normalized research events."
}

output "athena_results_bucket" {
  value       = aws_s3_bucket.analytics.id
  description = "S3 bucket for Athena results and future normalized CEM Parquet files."
}
