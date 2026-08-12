variable "location" {
  type    = string
  default = "koreacentral"
}

variable "project_name" {
  type    = string
  default = "taintlab"
}

variable "honey_secret_value" {
  type      = string
  sensitive = true
}