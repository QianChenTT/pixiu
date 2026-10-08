variable "alert_email" {
  description = "Where budget alerts go. Set it in terraform.tfvars, which stays out of the repo"
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly spend across every account in the organization that triggers the alerts"
  type        = number
  default     = 20
}

variable "log_retention_days" {
  description = "How long CloudTrail log files are kept before they expire"
  type        = number
  default     = 365
}

variable "account_emails" {
  description = "Root email address of each account this folder creates. Each must be one no AWS account has ever used. Set them in terraform.tfvars, which stays out of the repo"
  type = object({
    log_archive = string
    security    = string
    range       = string
  })
}

variable "admin_group" {
  description = "Display name of the IAM Identity Center group that gets admin access to the new accounts"
  type        = string
}

variable "admin_permission_set" {
  description = "Name of the IAM Identity Center permission set that group gets in the new accounts"
  type        = string
}

variable "archive_bucket" {
  description = "Name of the log archive bucket (infra/security prints it). Leave it out until that bucket exists: the trail keeps writing to the old bucket in this account"
  type        = string
  default     = null
}
