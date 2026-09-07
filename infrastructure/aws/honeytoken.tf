resource "aws_secretsmanager_secret" "honeytoken" {
  name                    = var.honeytoken_name
  description             = "DECOY ONLY - access is monitored and must be investigated"
  recovery_window_in_days = 30

  tags = {
    SecurityControl = "Honeytoken"
    DataClass       = "Decoy"
  }
}

resource "aws_sns_topic" "honeytoken_alerts" {
  name              = "${var.name_prefix}-honeytoken-alerts"
  kms_master_key_id = aws_kms_key.cloudtrail.id
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.honeytoken_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "eventbridge_sns" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.honeytoken_alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        aws_cloudwatch_event_rule.honeytoken_access.arn,
        aws_cloudwatch_event_rule.data_seed_access.arn,
      ]
    }
  }
}

resource "aws_sns_topic_policy" "honeytoken_alerts" {
  arn    = aws_sns_topic.honeytoken_alerts.arn
  policy = data.aws_iam_policy_document.eventbridge_sns.json
}

resource "aws_cloudwatch_event_rule" "honeytoken_access" {
  name        = "${var.name_prefix}-honeytoken-access"
  description = "Detects read attempts against the decoy Secrets Manager secret"
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["secretsmanager.amazonaws.com"]
      eventName   = ["GetSecretValue", "DescribeSecret"]
      requestParameters = {
        secretId = [aws_secretsmanager_secret.honeytoken.arn, var.honeytoken_name]
      }
    }
  })
}

resource "aws_cloudwatch_event_rule" "data_seed_access" {
  name        = "${var.name_prefix}-data-seed-access"
  description = "Detects GetObject calls against the synthetic data seed"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject"]
      requestParameters = {
        bucketName = [aws_s3_bucket.experiment["critical"].id]
        key        = [var.data_seed_key]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "honeytoken_alert" {
  rule      = aws_cloudwatch_event_rule.honeytoken_access.name
  target_id = "SendToSns"
  arn       = aws_sns_topic.honeytoken_alerts.arn

  input_transformer {
    input_paths = {
      account    = "$.account"
      event_name = "$.detail.eventName"
      event_time = "$.detail.eventTime"
      principal  = "$.detail.userIdentity.arn"
      secret_id  = "$.detail.requestParameters.secretId"
      source_ip  = "$.detail.sourceIPAddress"
    }
    input_template = <<-EOT
      "AWS HONEYTOKEN ALERT\nAccount: <account>\nTime: <event_time>\nAction: <event_name>\nPrincipal: <principal>\nSource IP: <source_ip>\nSecret: <secret_id>\n\nTreat this as a security incident until proven otherwise."
    EOT
  }
}

resource "aws_cloudwatch_event_target" "data_seed_alert" {
  rule      = aws_cloudwatch_event_rule.data_seed_access.name
  target_id = "SendDataSeedToSns"
  arn       = aws_sns_topic.honeytoken_alerts.arn

  input_transformer {
    input_paths = {
      account    = "$.account"
      event_name = "$.detail.eventName"
      event_time = "$.detail.eventTime"
      principal  = "$.detail.userIdentity.arn"
      bucket     = "$.detail.requestParameters.bucketName"
      key        = "$.detail.requestParameters.key"
      source_ip  = "$.detail.sourceIPAddress"
    }
    input_template = <<-EOT
      "AWS DATA SEED ALERT\nAccount: <account>\nTime: <event_time>\nAction: <event_name>\nPrincipal: <principal>\nSource IP: <source_ip>\nObject: s3://<bucket>/<key>\n\nThis event is an R1-success candidate only when the API outcome is successful."
    EOT
  }
}
