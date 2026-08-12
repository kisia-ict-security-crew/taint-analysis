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
