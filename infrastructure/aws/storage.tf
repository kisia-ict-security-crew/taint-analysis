locals {
  experiment_bucket_purposes = toset(["critical", "staging", "egress"])
}

resource "aws_s3_bucket" "experiment" {
  for_each = local.experiment_bucket_purposes

  bucket_prefix = "${var.name_prefix}-${each.key}-${local.account_id}-"
  force_destroy = var.allow_experiment_bucket_destroy

  tags = {
    ExperimentRole = each.key
    DataClass      = each.key == "critical" ? "SyntheticCritical" : "SyntheticDerived"
  }
}

resource "aws_s3_bucket_public_access_block" "experiment" {
  for_each = aws_s3_bucket.experiment

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "experiment" {
  for_each = aws_s3_bucket.experiment

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "experiment" {
  for_each = aws_s3_bucket.experiment

  bucket = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "experiment_bucket" {
  for_each = aws_s3_bucket.experiment

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]
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

resource "aws_s3_bucket_policy" "experiment" {
  for_each = aws_s3_bucket.experiment

  bucket = each.value.id
  policy = data.aws_iam_policy_document.experiment_bucket[each.key].json
}

resource "aws_s3_object" "data_seed" {
  bucket       = aws_s3_bucket.experiment["critical"].id
  key          = var.data_seed_key
  content      = "customer_id,email,api_key\nDECOY-001,decoy@example.invalid,DECOY_ONLY_NOT_VALID\n"
  content_type = "text/csv"
  kms_key_id   = aws_kms_key.cloudtrail.arn

  tags = {
    SecurityControl = "DataSeed"
    TaintRole       = "C-and-D-seed"
  }
}

resource "aws_s3_object" "critical" {
  bucket       = aws_s3_bucket.experiment["critical"].id
  key          = var.critical_object_key
  content      = "customer_id,risk_tier\nSYNTHETIC-001,high\nSYNTHETIC-002,medium\n"
  content_type = "text/csv"
  kms_key_id   = aws_kms_key.cloudtrail.arn

  tags = {
    DataClass = "SyntheticCritical"
    TaintRole = "D-seed"
  }
}
