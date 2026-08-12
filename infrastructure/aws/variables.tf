variable "aws_region" {
  description = "AWS region in which regional resources are created."
  type        = string
  default     = "ap-northeast-2"
}

variable "name_prefix" {
  description = "Prefix used for resource names."
  type        = string
  default     = "taint-analysis"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,30}$", var.name_prefix))
    error_message = "name_prefix must contain 3-30 lowercase letters, numbers, or hyphens."
  }
}

variable "alert_email" {
  description = "Email address that receives honeytoken alerts. Leave empty to create only the SNS topic."
  type        = string
  default     = ""

  validation {
    condition     = var.alert_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be empty or a valid email address."
  }
}

variable "honeytoken_name" {
  description = "Deceptive Secrets Manager path monitored for access."
  type        = string
  default     = "/honeytoken/prod/legacy-api-key"

  validation {
    condition     = startswith(var.honeytoken_name, "/honeytoken/")
    error_message = "honeytoken_name must start with /honeytoken/."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period."
  type        = number
  default     = 90
}

variable "allow_log_bucket_destroy" {
  description = "Allow Terraform to delete the log bucket and its objects. Enable only during teardown."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to all supported resources."
  type        = map(string)
  default = {
    Project   = "taint-analysis"
    ManagedBy = "Terraform"
    Purpose   = "security-research"
  }
}
