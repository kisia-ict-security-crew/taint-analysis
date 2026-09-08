terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" { region = var.region }
variable "region" {
  type    = string
  default = "ap-northeast-2"
}
variable "name" {
  type    = string
  default = "taint-runtime"
}
variable "researcher_arns" {
  description = "Explicit IAM user/role ARNs allowed to start fresh experimental sessions. Never use an account-wide wildcard."
  type        = list(string)
  validation {
    condition     = length(var.researcher_arns) > 0 && alltrue([for arn in var.researcher_arns : can(regex("^arn:[^:]+:iam::[0-9]{12}:(role|user)/[^*]+$", arn))])
    error_message = "Provide one or more exact IAM role/user ARNs."
  }
}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_dynamodb_table" "state" {
  name         = "${var.name}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
  # No TTL: expiration of credentials must not erase historical taint.
}
resource "aws_s3_bucket" "data" { bucket_prefix = "${var.name}-" }
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "TLSOnly"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_object" "seed" {
  for_each = {
    "honey"    = "DECOY_ONLY_NOT_A_CREDENTIAL\n"
    "critical" = "SYNTHETIC_IMPORTANT_DATA\n"
  }
  bucket  = aws_s3_bucket.data.id
  key     = "seeds/${each.key}.csv"
  content = each.value
  tags = {
    "taint-d"    = "true"
    "taint-seed" = each.key
  }
}
resource "aws_dynamodb_table_item" "mine" {
  for_each = {
    honey = {
      key            = aws_s3_object.seed["honey"].key
      mine_id        = "aws-s3-honey-001"
      emit_c_on_read = true
      emit_d         = true
    }
    critical = {
      key            = aws_s3_object.seed["critical"].key
      mine_id        = "aws-s3-critical-001"
      emit_c_on_read = false
      emit_d         = true
    }
  }
  table_name = aws_dynamodb_table.state.name
  hash_key   = aws_dynamodb_table.state.hash_key
  item = jsonencode({
    id             = { S = "mine:s3:${aws_s3_bucket.data.id}/${each.value.key}" }
    spec_version   = { S = "cloud-mine/v1alpha1" }
    mine_id        = { S = each.value.mine_id }
    kind           = { S = "aws.s3-object" }
    resource       = { S = "s3:${aws_s3_bucket.data.id}/${each.value.key}" }
    trigger        = { S = "read-success" }
    emit_c_on_read = { BOOL = each.value.emit_c_on_read }
    emit_d         = { BOOL = each.value.emit_d }
  })
}
resource "aws_iam_role" "broker" {
  name = "${var.name}-broker"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role" "worker" {
  name = "${var.name}-worker"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { AWS = concat(var.researcher_arns, [aws_iam_role.broker.arn]) }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role_policy" "worker" {
  role = aws_iam_role.worker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "execute-api:Invoke", Resource = "${aws_api_gateway_rest_api.broker.execution_arn}/lab/POST/action" },
    # Even future attached Allow policies cannot grant this session raw S3/STS/state access.
    { Effect = "Deny", NotAction = "execute-api:Invoke", Resource = "*" }
  ] })
}
resource "aws_cloudwatch_log_group" "broker" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = 7
}
resource "aws_iam_role_policy" "broker" {
  role = aws_iam_role.broker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], Resource = aws_dynamodb_table.state.arn },
    { Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.data.arn}/*" },
    { Effect = "Allow", Action = ["s3:PutObject", "s3:PutObjectTagging"], Resource = "${aws_s3_bucket.data.arn}/derived/*" },
    { Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.worker.arn },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.broker.arn}:*" }
  ] })
}
data "archive_file" "broker" {
  type        = "zip"
  source_file = "${path.module}/broker.py"
  output_path = "${path.module}/broker.zip"
}
resource "aws_lambda_function" "broker" {
  function_name    = var.name
  role             = aws_iam_role.broker.arn
  runtime          = "python3.12"
  handler          = "broker.handler"
  filename         = data.archive_file.broker.output_path
  source_code_hash = data.archive_file.broker.output_base64sha256
  timeout          = 20
  memory_size      = 256
  # Serialization is enforced by the DynamoDB monitor lease in broker.py.
  # Do not reserve Lambda concurrency: accounts with a total limit of 10 must
  # retain all 10 as unreserved capacity and cannot allocate even one here.
  environment {
    variables = {
      TABLE                 = aws_dynamodb_table.state.name
      BUCKET                = aws_s3_bucket.data.id
      WORKER_ROLE           = aws_iam_role.worker.arn
      CALLER_SESSION_PREFIX = "arn:${data.aws_partition.current.partition}:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.worker.name}/"
    }
  }
  depends_on = [aws_iam_role_policy.broker, aws_cloudwatch_log_group.broker]
}
resource "aws_api_gateway_rest_api" "broker" {
  name = var.name
  endpoint_configuration { types = ["REGIONAL"] }
}
resource "aws_api_gateway_resource" "action" {
  rest_api_id = aws_api_gateway_rest_api.broker.id
  parent_id   = aws_api_gateway_rest_api.broker.root_resource_id
  path_part   = "action"
}
resource "aws_api_gateway_method" "action" {
  rest_api_id   = aws_api_gateway_rest_api.broker.id
  resource_id   = aws_api_gateway_resource.action.id
  http_method   = "POST"
  authorization = "AWS_IAM"
}
resource "aws_api_gateway_integration" "action" {
  rest_api_id             = aws_api_gateway_rest_api.broker.id
  resource_id             = aws_api_gateway_resource.action.id
  http_method             = aws_api_gateway_method.action.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.broker.invoke_arn
}
resource "aws_lambda_permission" "gateway" {
  statement_id  = "GatewayOnly"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.broker.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.broker.execution_arn}/*/POST/action"
}
resource "aws_api_gateway_deployment" "broker" {
  rest_api_id = aws_api_gateway_rest_api.broker.id
  triggers = {
    redeployment = sha1(jsonencode([aws_api_gateway_method.action, aws_api_gateway_integration.action]))
  }
  lifecycle { create_before_destroy = true }
}
resource "aws_api_gateway_stage" "lab" {
  rest_api_id   = aws_api_gateway_rest_api.broker.id
  deployment_id = aws_api_gateway_deployment.broker.id
  stage_name    = "lab"
}
output "endpoint" { value = "${aws_api_gateway_stage.lab.invoke_url}/action" }
output "worker_role" { value = aws_iam_role.worker.arn }
output "bucket" { value = aws_s3_bucket.data.id }
output "state_table" { value = aws_dynamodb_table.state.name }
