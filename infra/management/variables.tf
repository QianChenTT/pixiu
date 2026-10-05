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
