resource "aws_s3_bucket" "analytics" {
  # The AWS provider limits bucket_prefix to 37 characters and appends a
  # random suffix that provides global uniqueness. Do not include account_id.
  bucket_prefix = "${var.name_prefix}-analytics-"
  force_destroy = var.allow_experiment_bucket_destroy
}

resource "aws_s3_bucket_public_access_block" "analytics" {
  bucket                  = aws_s3_bucket.analytics.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "analytics_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.analytics.arn, "${aws_s3_bucket.analytics.arn}/*"]
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

resource "aws_s3_bucket_policy" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  policy = data.aws_iam_policy_document.analytics_bucket.json
}

resource "aws_glue_catalog_database" "research" {
  name        = replace("${var.name_prefix}_research", "-", "_")
  description = "CloudTrail raw data and normalized CEM research tables"
}

resource "aws_athena_workgroup" "research" {
  name          = "${var.name_prefix}-research"
  description   = "Queries for CloudTrail probes and normalized CEM events"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.analytics.id}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.cloudtrail.arn
      }
    }
  }
}

resource "aws_athena_named_query" "cloudtrail_table_ddl" {
  name        = "00_create_cloudtrail_raw_table"
  description = "Run once, then add date partitions for the probe window"
  database    = aws_glue_catalog_database.research.name
  workgroup   = aws_athena_workgroup.research.id

  query = <<-SQL
    CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_raw (
      eventversion STRING,
      useridentity STRUCT<type:STRING,principalid:STRING,arn:STRING,accountid:STRING,accesskeyid:STRING,username:STRING,sessioncontext:STRUCT<sessionissuer:STRUCT<type:STRING,principalid:STRING,arn:STRING,accountid:STRING,username:STRING>,attributes:STRUCT<creationdate:STRING,mfaauthenticated:STRING>,sourceidentity:STRING>>,
      eventtime STRING,
      eventsource STRING,
      eventname STRING,
      awsregion STRING,
      sourceipaddress STRING,
      useragent STRING,
      errorcode STRING,
      errormessage STRING,
      requestparameters STRING,
      responseelements STRING,
      additionaleventdata STRING,
      requestid STRING,
      eventid STRING,
      readonly STRING,
      resources ARRAY<STRUCT<arn:STRING,accountid:STRING,type:STRING>>,
      eventtype STRING,
      apiversion STRING,
      recipientaccountid STRING,
      sharedeventid STRING,
      vpcendpointid STRING,
      eventcategory STRING,
      addendum STRUCT<reason:STRING,updatedfields:STRING,originalrequestid:STRING,originaleventid:STRING>
    )
    PARTITIONED BY (region STRING, year STRING, month STRING, day STRING)
    ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION 's3://${aws_s3_bucket.cloudtrail.id}/AWSLogs/${local.account_id}/CloudTrail/'
    TBLPROPERTIES ('classification'='cloudtrail');
  SQL
}
