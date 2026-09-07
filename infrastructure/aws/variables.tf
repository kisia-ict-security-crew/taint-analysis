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

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a retention value supported by CloudWatch Logs."
  }
}

variable "allow_log_bucket_destroy" {
  description = "Allow Terraform to delete the log bucket and its objects. Enable only during teardown."
  type        = bool
  default     = false
}

variable "allow_experiment_bucket_destroy" {
  description = "Allow Terraform to delete objects in disposable experiment and Athena result buckets during teardown."
  type        = bool
  default     = true
}

variable "data_seed_key" {
  description = "Object key of the data honeytoken. The object contains synthetic data only."
  type        = string
  default     = "decoy/customer-export.csv"
}

variable "critical_object_key" {
  description = "Object key used as the manually classified D-Taint source. The object contains synthetic data only."
  type        = string
  default     = "classified/customer-records.csv"
}

variable "monthly_budget_usd" {
  description = "Optional monthly AWS cost budget. Set to 0 to disable AWS Budgets resources."
  type        = number
  default     = 20

  validation {
    condition     = var.monthly_budget_usd >= 0
    error_message = "monthly_budget_usd must be zero or greater."
  }
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
